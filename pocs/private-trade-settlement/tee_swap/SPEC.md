---
title: "Cross-Chain Private Atomic Swap"
status: Draft
version: 0.1.0
authors: []
created: 2025-02-12
ethsystems_use_case: "https://github.com/ethsystems/map/blob/master/use-cases/private-trade-settlement.md"
ethsystems_approach: "https://github.com/ethsystems/map/blob/master/approaches/approach-private-trade-settlement.md"
---

# TEE-Coordinated Private Atomic Swap Protocol

## Overview

A protocol for atomic cross-chain swaps of private UTXO notes using stealth addresses and time-locked dual spending conditions. Designed for Delivery-vs-Payment settlement between institutional counterparties.

**Trust model**: Users MUST NOT share spending keys. TEE coordinates but cannot steal funds. Hardware manufacturer trust is required.

---

## Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

---

## Data Types

### Time-Locked Note

```
Note {
    chainId: uint256,         // Network identifier (binds note to a specific chain)
    value: uint64,            // Amount
    assetId: bytes32,         // Asset identifier (USD, BOND, etc.)
    owner: bytes32,           // Primary owner (stealth address)
    fallbackOwner: bytes32,   // Original owner (refund path)
    timeout: uint256,         // Timestamp when fallback becomes valid
    salt: bytes32             // Blinding factor
}
```

**Derived values:**

- `commitment = H("tee_swap.commitment", chainId, value, assetId, owner, fallbackOwner, timeout, salt)`
- `nullifier = H("tee_swap.nullifier", commitment, salt)`

### Stealth Address Components

```
MetaAddress {
    sk_meta: bytes32,         // Meta private key (never shared)
    pk_meta: Point            // Meta public key (published)
}

EphemeralKey {
    r: bytes32,               // Ephemeral private key
    R: Point                  // R = r·G (ephemeral public key)
}

StealthAddress {
    pk_stealth: Point         // One-time address
    sk_stealth: bytes32       // Derived by recipient only
}
```

**Derivation:**

```
Sender (knows pk_meta_recipient, generates r):
  shared_secret = ECDH(r, pk_meta_recipient) = r·pk_meta
  pk_stealth = pk_meta + H("tee_swap.stealth", shared_secret)·G

Recipient (knows sk_meta, receives R):
  shared_secret = ECDH(sk_meta, R) = sk_meta·R
  sk_stealth = sk_meta + H("tee_swap.stealth", shared_secret)
```

### On-Chain State (per network)

Each network maintains a private UTXO contract per asset:

```solidity
bytes32 public immutable assetId;              // Asset this contract manages
mapping(bytes32 => bool) public commitments;   // All note commitments ever inserted
mapping(bytes32 => bool) public roots;         // Valid Merkle roots (historical)
mapping(bytes32 => bool) public nullifiers;    // All nullifiers ever submitted (spent notes)
```

**Invariant:** Each commitment in the tree maps to exactly one nullifier (`H("tee_swap.nullifier", commitment, salt)`). Once that nullifier appears in the set, the note MUST NOT be spent again via any path.

**Transaction flow:**

1. **Create note:** insert `commitment` into `commitments`
2. **Spend note:** verify ZK proof, check `nullifier ∉ nullifiers`, add `nullifier` to `nullifiers`

---

### Swap State

**Swap ID derivation:**

The `swapId` is a deterministic commitment to the agreed swap terms. Both parties independently compute it from the negotiated parameters during intent matching (before the protocol begins):

```
swapId = H("tee_swap.swap_id",
    valueA, assetIdA, chainIdA,         // Party A's leg (what A locks for B)
    valueB, assetIdB, chainIdB,         // Party B's leg (what B locks for A)
    timeout,                            // Agreed swap expiry
    pk_meta_A, pk_meta_B,              // Both parties' meta public keys
    nonce                               // Random nonce for uniqueness per deal
)
```

Because the `swapId` is derived from the terms, it acts as a mutual commitment: both parties can only produce the same `swapId` if they agree on every parameter. The TEE can later recompute it from `noteDetails` to verify that locked notes match the agreed terms (see Phase 2, step 5).

---

## Atomic Swap Protocol

### Phase 1: Lock Notes to Stealth Addresses

Each party creates a time-locked note for the counterparty and generates a deposit proof. The proof extends the standard note-creation circuit with stealth address derivation and three binding commitments. These commitments enable the TEE to verify correctness in Phase 2 without accessing any private key or computing any elliptic curve operation.

**Deposit circuit:**

```
Public inputs:
  commitment            // New note commitment (inserted into commitments)
  chainId               // Network identifier (contract verifies it matches its own chain ID)
  timeout               // Time-lock expiry (0 for standard notes, >0 for swap notes)
  pk_stealth            // Stealth address (note owner). Safe to publish: unlinkable without R
  h_swap                // H("tee_swap.bind_swap", swapId, salt): binds the deposit to a specific swap
  h_R                   // H("tee_swap.bind_R", R): binds the proof to a specific ephemeral public key
  h_meta                // H("tee_swap.bind_meta", pk_meta_counterparty, salt): binds to the intended counterparty
  h_enc                 // H("tee_swap.bind_enc", encrypted_salt): binds to a correctly encrypted salt

Private inputs:
  swapId                // Swap identifier (agreed off-chain)
  r                     // Ephemeral private key (never leaves the prover)
  pk_meta_counterparty  // Counterparty's meta public key
  value, assetId, fallbackOwner, salt                      // Note fields
  encrypted_salt        // Pre-computed by prover

Circuit constraints:
  1. commitment == H("tee_swap.commitment", chainId, value, assetId, pk_stealth, fallbackOwner, timeout, salt)
  2. pk_stealth == pk_meta_counterparty + H("tee_swap.stealth", r · pk_meta_counterparty)·G
  3. h_swap == H("tee_swap.bind_swap", swapId, salt)
  4. h_R == H("tee_swap.bind_R", r·G)
  5. h_meta == H("tee_swap.bind_meta", pk_meta_counterparty, salt)
  6. h_enc == H("tee_swap.bind_enc", encrypted_salt)
     where encrypted_salt == salt XOR H("tee_swap.salt_enc", r · pk_meta_counterparty)
```

Constraint 2 guarantees the stealth address is correctly derived. Constraint 3 binds the deposit to a specific swap, preventing reuse of the same deposit across swaps. Constraints 4-6 produce binding commitments that the TEE can open and verify in Phase 2. The ECDH shared secret (`r · pk_meta_counterparty`) is computed once inside the circuit and reused for both stealth derivation (constraint 2) and salt encryption (constraint 6).

If the note is funded by spending an existing note, the circuit MUST also prove standard spend operations (Merkle inclusion, nullifier correctness, ownership of the spent note).

> **Why `H("tee_swap.nullifier", commitment, salt)` and not `Hash(commitment, spendingKey)`?** The nullifier MUST be unique per note AND independent of which spending path is used. If the nullifier varied by spending key, the owner path and fallback path would produce different nullifiers for the same note, enabling a double-spend where Party B claims and Party A refunds the same note. With `H("tee_swap.nullifier", commitment, salt)`, the nullifier is canonical: whichever path is used first, the second attempt is rejected by the nullifier set.

**Party A (swapping USD for BOND):**

```
1. Generate ephemeral key pair (r_A, R_A = r_A·G) and random salt_A
2. Compute:
   - shared_secret_AB = r_A · pk_meta_B
   - pk_stealth_B = pk_meta_B + H("tee_swap.stealth", shared_secret_AB)·G
   - encrypted_salt_A = salt_A XOR H("tee_swap.salt_enc", shared_secret_AB)
3. Create time-locked note:
   - chainId = Network 1 chain ID
   - owner = pk_stealth_B (B can claim with stealth key)
   - fallbackOwner = pk_A (A can refund after timeout)
   - timeout = now + 48h
   - salt = salt_A
4. Generate deposit proof (see circuit above):
   - Public inputs: commitment_A, chainId, pk_stealth_B, H("tee_swap.bind_swap", swapId, salt_A), H("tee_swap.bind_R", R_A), H("tee_swap.bind_meta", pk_meta_B, salt_A), H("tee_swap.bind_enc", encrypted_salt_A)
   - Nullifies old note (old nullifier added to nullifiers)
   - Inserts new commitment into commitments
   - Contract verifies chainId matches its own chain ID
5. Submit proof on Network 1 (USD chain)
6. Send to TEE (via attested channel): (swapId, nonce, R_A, encrypted_salt_A, pk_meta_B, noteDetails_A)
```

Party B will mirror the same operations.

---

### Phase 2: TEE Verification

The TEE combines on-chain proof data with off-chain submissions to verify swap correctness. The deposit proofs have already been verified on-chain by the ZK verifier contract, which guarantees the mathematical correctness of stealth address derivation and salt encryption (Phase 1 circuit constraints 1-6). The TEE's role is to verify that the off-chain data matches the on-chain binding commitments, and that the swap terms are compatible.

```
TEE receives via attested channel:
  - From Party A: (swapId, nonce, R_A, encrypted_salt_A, pk_meta_B, noteDetails_A)
  - From Party B: (swapId, nonce, R_B, encrypted_salt_B, pk_meta_A, noteDetails_B)

TEE reads from on-chain (public inputs of verified deposit proofs):
  - From Network 1: commitment_A, chainId_A, pk_stealth_B, h_swap_A, h_R_A, h_meta_A, h_enc_A
  - From Network 2: commitment_B, chainId_B, pk_stealth_A, h_swap_B, h_R_B, h_meta_B, h_enc_B

TEE MUST verify:

  1. Deposit proofs exist and are verified on their respective chains

  2. Swap binding (both deposits reference the same swap):
     - H("tee_swap.bind_swap", swapId, noteDetails_A.salt) == h_swap_A
     - H("tee_swap.bind_swap", swapId, noteDetails_B.salt) == h_swap_B

  3. Commitment correctness (noteDetails match on-chain commitments):
     - H("tee_swap.commitment", noteDetails_A) == commitment_A
     - H("tee_swap.commitment", noteDetails_B) == commitment_B

  4. Binding commitment openings (off-chain data matches on-chain commitments):
     - H("tee_swap.bind_R", R_A) == h_R_A
     - H("tee_swap.bind_meta", pk_meta_B, noteDetails_A.salt) == h_meta_A
     - H("tee_swap.bind_enc", encrypted_salt_A) == h_enc_A
     (same three checks for Party B's data against h_R_B, h_meta_B, h_enc_B)

  5. Swap terms match agreed deal (swapId encodes the terms):
     - Recompute: expected_swapId = H("tee_swap.swap_id",
         noteDetails_A.value, noteDetails_A.assetId, noteDetails_A.chainId,
         noteDetails_B.value, noteDetails_B.assetId, noteDetails_B.chainId,
         timeout, pk_meta_A, pk_meta_B, nonce)
     - Verify: expected_swapId == swapId
     This guarantees the locked notes match the terms both parties committed
     to during intent matching. If either party deviates (e.g., locks 80 USD
     instead of the agreed 100 USD), the recomputed swapId will differ and
     the TEE rejects the swap.
  6. Both notes have matching timeout
  7. Timeout has not expired
```

**Why binding commitments are trustworthy.** The on-chain ZK verifier has already proved that `h_R`, `h_meta`, and `h_enc` are internally consistent with the same ephemeral key `r` and `pk_meta_counterparty` used in the deposit (circuit constraints 2-6). The TEE only needs to open these commitments via hash comparisons — no elliptic curve operations. A party cannot substitute different off-chain values without failing the hash check against the on-chain binding commitments.

If all checks pass, the TEE proceeds to Phase 3.

> **RPC trust assumption:** Step 1 relies on an external RPC endpoint (e.g., Infura, Alchemy) to read on-chain state. The TEE trusts the RPC provider to return correct commitment data. A compromised or malicious RPC could feed false state, causing the TEE to approve a swap against a non-existent commitment. To tighten this, a light client such as [Helios](https://github.com/a16z/helios) could run inside the TEE, verifying state proofs against the consensus and eliminating RPC trust entirely.

---

### Phase 3: Atomic Revelation

The TEE publishes both ephemeral keys and encrypted salts to an on-chain announcement contract. Both parties MUST monitor this contract. The announcement reveals only ephemeral public keys (random curve points) and encrypted salts (random-looking 32-byte values) — no amounts, asset types, or party identities.

```solidity
function announceSwap(
    bytes32 swapId,
    bytes ephemeralKey_A,         // R_A (Party B uses to derive sk_stealth)
    bytes ephemeralKey_B,         // R_B (Party A uses to derive sk_stealth)
    bytes32 encrypted_salt_A,     // salt_A encrypted for Party B
    bytes32 encrypted_salt_B      // salt_B encrypted for Party A
) external onlyTEE {
    require(!announcements[swapId].revealed, "already revealed");
    announcements[swapId] = SwapAnnouncement({
        ephemKey_A: ephemeralKey_A,
        ephemKey_B: ephemeralKey_B,
        encSalt_A: encrypted_salt_A,
        encSalt_B: encrypted_salt_B,
        revealed: true
    });
    emit SwapRevealed(swapId);
}
```

The `require(!revealed)` guard prevents duplicate announcements, including from a rolled-back TEE.

**Protocol atomicity** derives from three properties working together: (1) revealing both stealth constructions publicly gives both parties the ability to claim, (2) if the TEE never reveals, both parties refund via `fallbackOwner`, and (3) the `timeout` prevents indefinite lockup. The outcome is always all-or-nothing — both parties can claim or both refund — regardless of whether notes are on the same network or different networks.

---

### Phase 4: Claim or Refund

Parties SHOULD stagger their claim transactions with a random delay after the announcement (see T7) and wait for announcement finality before submitting a claim proof.

**Claim path (shown for Party B claiming USD; Party A mirrors on Network 2):**

```
1. Read R_A and encrypted_salt_A from announcement contract
2. Compute shared secret: shared_secret_AB = sk_meta_B · R_A
3. Decrypt salt: salt_A = encrypted_salt_A XOR H("tee_swap.salt_enc", shared_secret_AB)
4. Derive stealth key: sk_stealth_B = sk_meta_B + H("tee_swap.stealth", shared_secret_AB)
5. Reconstruct note details from swap terms + decrypted salt, compute commitment and nullifier
6. Generate ZK proof (Merkle inclusion, nullifier correctness, ownership via sk_stealth_B)
7. Submit proof. Nullifier is added to nullifiers
```

**Refund path (TEE failed to reveal before timeout):**

```
1. Wait until block.timestamp > timeout
2. The refunding party already knows salt and all note details (they created the note)
3. Generate ZK proof (Merkle inclusion, nullifier correctness, ownership via sk_fallback)
   - timeout is a public output; the verifier contract checks block.timestamp > timeout
4. Submit proof. Nullifier is added to nullifiers
```

Both paths produce the same nullifier for a given note. If one party claims, the other's refund is rejected by the nullifier set for double-spend protection.

---

## Annex A: Threat Model

### T1: TEE Steals User Funds

**Attack:** TEE attempts to spend users' notes.

**Mitigation:** Mitigated.

- Users never share spending keys (sk_meta, r) with the TEE
- TEE receives: ephemeral public keys (R), encrypted salts, and plaintext note details (which contain no private keys)
- TEE cannot derive stealth private keys: sk_stealth = sk_meta + H("tee_swap.stealth", shared_secret) requires sk_meta, which the TEE does not possess
- Deposit proof correctness (stealth address derivation, salt encryption) is verified on-chain by the ZK verifier, not by the TEE. The TEE only opens binding commitments via hash comparisons
- Worst case: TEE refuses to reveal keys. Users refund after timeout

**Impact if TEE compromised:** Censorship only, not theft.

---

### T2: Hardware Manufacturer Compromise

**Attack:** Intel/AMD/AWS extracts plaintext from TEE during execution.

**Mitigation:** Partially mitigated.

- No cryptographic defense against manufacturer
- Institutional users may accept this risk (already trust HSMs from same vendors)
- Multi-TEE approach: require M-of-N TEEs from different manufacturers

**Impact:** Manufacturer sees swap amounts and parties (privacy loss), but cannot steal (no spending keys).

---

### T3: Partial Revelation Attack

**Attack:** TEE reveals R_A (Party B claims USD) but crashes before revealing R_B (Party A can't claim BOND).

**Mitigation:** Mitigated.

- TEE reveals both R_A and R_B in a single atomic operation (both or neither)
- Atomicity enforced by TEE, not by blockchain. Works cross-chain
- If TEE fails before revelation, timeout refunds activate for both parties
- Announcement can be on-chain (either network) or off-chain service

**Impact:** No vulnerability. Atomicity guaranteed by TEE's single revelation operation, independent of whether notes are on same network or different networks.

---

### T4: Front-Running Announcement

**Attack:** MEV bot sees announcement transaction in mempool, tries to claim notes before legitimate parties.

**Mitigation:** Mitigated.

- Only recipient with sk_meta can derive sk_stealth from revealed R
- Attacker seeing R_A cannot derive sk_stealth_B without sk_meta_B
- Announcement reveals public key R, not private key

**Impact:** No vulnerability. Stealth address crypto prevents front-running.

---

### T5: TEE Censorship / Selective Reveal

**Attack:** TEE reveals keys for one party but refuses to reveal for the other.

**Mitigation:** Partially mitigated.

- Announcement contract enforces atomic revelation (both keys or neither)
- Timeout refunds provide escape hatch if TEE goes offline
- TEE can censor by never revealing at all. Users wait until timeout

**Impact:** Temporary denial of service. Users always recover funds via timeout.

---

### T6: Timeout Too Short

**Attack:** Malicious party sets timeout = now + 1 minute, immediately refunds after locking.

**Mitigation:** Mitigated.

- TEE MUST verify timeout is reasonable (e.g., minimum 24-48h)
- TEE MUST reject swaps with insufficient timeout window
- Both parties' notes MUST have matching timeout

**Impact:** Prevented by TEE validation.

---

### T7: Anonymity Set Attacks

**Attack:** Observer links swap notes to each other or to claim transactions via timing, timeout values, or on-chain metadata.

**Mitigation:** Partially mitigated.

- `timeout` is a public input in both deposit and spend circuits. Notes with `timeout > 0` are identifiable as swap (time-locked) notes; notes with `timeout = 0` are standard notes. This is an accepted trade-off: during the swap window, an observer can see that a locked note exists and when it expires, but not who owns it, what it contains, or who the counterparty is.
- **Deposit timing correlation:** Both parties lock notes within a narrow window. An observer monitoring multiple chains can correlate two deposits by timing and matching timeout values, linking the two legs of a swap with high confidence. This reveals that a swap occurred and approximately when, but not the amounts, asset types, or participant identities.
- **Spending path indistinguishability:** Both claim and refund paths expose the same public inputs (`nullifier`, `root`, `timeout`), producing identical on-chain footprints. An observer cannot distinguish claims from refunds.
- **Nullifier-commitment unlinkability:** The nullifier is derived from `H("tee_swap.nullifier", commitment, salt)` where `salt` is private. An observer cannot link a nullifier back to a specific commitment in the tree.
- **Re-potting:** After claiming a swap note (`timeout > 0`), the recipient SHOULD spend it into a fresh note with `timeout = 0`. Because the spend circuit keeps the commitment private (only the nullifier and root are public), the new note is indistinguishable from any standard note and re-enters the general anonymity set.
- **Claim staggering:** Parties SHOULD introduce a random delay (minutes to hours) between the TEE announcement and their claim submission to avoid timing correlation. The timeout window (48h) provides ample room for this.

**What is leaked:**

| Leaked                                                | Hidden                                         |
| ----------------------------------------------------- | ---------------------------------------------- |
| A time-locked note exists                             | Amount and asset type                          |
| When it expires (timeout)                             | Owner / recipient identity                     |
| Probabilistic link between two swap legs (via timing) | Which note was spent (nullifier unlinkability) |

**Impact:** Swap notes are transiently distinguishable during the lock window. After settlement and re-potting, they dissolve back into the general anonymity set. The residual leakage is that an observer can detect a swap occurred and approximately when, but learns nothing about the participants or economic terms.

---

### T8: Announcement Location Disagreement

**Attack:** Parties monitor different announcement locations, miss the revelation.

**Mitigation:** Mitigated.

- Announcement location agreed upon during swap negotiation
- Can be on-chain contract (either network) or off-chain service
- Both parties MUST monitor the same location
- If party misses announcement, timeout refund available

**Impact:** Coordination issue, not security issue. Parties can always refund if they miss announcement.

---

## Annex B: Hash Domain Separation

All hashes MUST use an explicit domain tag as the first argument to prevent cross-purpose collisions in a cross-chain context:

| Domain     | Tag                     | Purpose                                         |
| ---------- | ----------------------- | ----------------------------------------------- |
| Commitment | `"tee_swap.commitment"` | Note commitment derivation                      |
| Nullifier  | `"tee_swap.nullifier"`  | Nullifier derivation                            |
| Stealth    | `"tee_swap.stealth"`    | Stealth address key derivation                  |
| Salt       | `"tee_swap.salt_enc"`   | Salt encryption key derivation                  |
| Bind swap  | `"tee_swap.bind_swap"`  | Binding commitment over swap ID                 |
| Bind R     | `"tee_swap.bind_R"`     | Binding commitment over ephemeral key           |
| Bind meta  | `"tee_swap.bind_meta"`  | Binding commitment over counterparty            |
| Bind enc   | `"tee_swap.bind_enc"`   | Binding commitment over encrypted salt          |
| Swap ID    | `"tee_swap.swap_id"`    | Deterministic swap identifier from agreed terms |

Convention: `H(domain, ...)` denotes `Hash(domain_tag ‖ ...)` where `‖` is concatenation.

> **Why domain separation?** Without it, a hash computed for one purpose (e.g., a commitment) could collide with a hash computed for another purpose (e.g., a nullifier or stealth key). In a cross-chain protocol, this risk is amplified. Domain tags ensure each hash is unambiguously scoped to its intended use.

---

## Annex C: TEE Key Management

The TEE submits swap announcements on-chain (Phase 3). Rather than funding an EOA directly, the TEE operates through a smart account (EIP-4337), which solves gas funding, signature scheme flexibility, and key rotation in one abstraction.

```
1. TEE signs UserOp with enclave key
2. Bundler submits UserOp to EntryPoint
3. EntryPoint calls SmartAccount.validateUserOp()   // verifies TEE signature
4. EntryPoint calls SmartAccount.execute()
5.   SmartAccount calls AnnouncementContract.announceSwap()
```

The announcement contract authenticates via `require(msg.sender == teeSmartAccount)`. The smart account address is permanent — key rotation happens internally (`rotateSigner(newPubKey)`) without updating any external contract. A paymaster sponsors gas, so the TEE never holds ETH. The bundler and paymaster are untrusted: they relay and sponsor but cannot forge or influence execution.

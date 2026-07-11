---
title: "Resilient Civic Participation"
status: Draft
version: 0.1.0
authors: ["Aaryamann"]
created: 2026-05-18
ethsystems_use_case: "https://github.com/ethsystems/map/blob/master/use-cases/resilient-civic-participation.md"
ethsystems_approach: "https://github.com/ethsystems/map/blob/master/approaches/approach-civic-participation.md"
---

# Resilient Civic Participation: Protocol Specification

## Problem Statement

Civic petitions need signers to prove a stated eligibility criterion without revealing their identity or other petitions they have signed. The outcome must remain verifiable from L1 plus blob payloads during EIP-4844 retention, or from a voluntary blob archive after retention. Sybil resistance comes from an external credential layer.

A credentialed petition system, composed with the ResilientIdentity (RI) credential layer, anchors per-petition state in an on-chain Indexed Merkle Tree (IMT) and publishes per-signature data on EIP-4844 blob carriers. After the dispute window closes, one resolution SNARK settles the outcome over the on-chain record and the blob payloads of active batches. Each signer maintains a Forward-Secure Ratchet Tree (FSRT) chain that advances past each signed slot, overwriting prior seed material.

This specification covers petition-style threshold-per-class outcomes: one signature per signer, per-class threshold tallying with regulated visibility. Single-choice, ranked, weighted, and event-count-bounded outcome shapes listed in the umbrella `REQUIREMENTS.md` are out of scope for this approach.

### Constraints

- **Privacy.** Cross-process and within-process unlinkability across the public record. Signer identity stays hidden. The per-record `class_tag` is public outcome metadata that supports per-class threshold accounting and regulator visibility; no other attribute value is exposed.
- **Regulatory.** Outcome publicly verifiable from L1 plus blob payloads (or a voluntary blob archive once retention expires). Per-class threshold breakdowns come from the predicate's class-binding clause and the Resolver's class-counted outcome bits.
- **Operational.** After enrollment, signers generate proofs from local state and public on-chain/RI data, without further RI issuer interaction. Outcome reconstructible from L1 plus blob payloads during EIP-4844 retention, or from a voluntary blob archive once the dispute window closes.
- **Trust.** RI provides Sybil resistance. Only signers hold FSRT seed material. The signer's submission path assumes at least one reachable honest relay.

### System Overview

- Organizer registers a petition under an RI root `R` and escrows the bounty.
- Signer builds a signer SNARK against `R` and sends it to a Relayer.
- Relayer aggregates signer SNARKs into a batch SNARK, then posts it on-chain alongside the EIP-4844 blob carrying the records.
- During the dispute window, a Disputant MAY submit KZG openings to repudiate a batch. After the window closes, the Resolver submits the resolution SNARK and the Registry pays the bounty.

## Approach

Rejected alternatives:

| Alternative | Reason rejected |
|-------------|-----------------|
| Operator-stored signed lists with KYC | Operator state becomes a compelled-disclosure surface; outcome guarantees are lost when the operator goes offline. |
| ZK with issuer-online revocation | Outcome verifiability depends on continued issuer cooperation; an adversarial issuer blocks participation. |
| Static identity commitment under one long-lived secret | Device compromise at `T_compromise` reveals every past signing identifier under one static-commitment opening. |
| Per-signature on-chain transactions | Per-signature gas cost exceeds the budget for petitions at the scale of national or supranational civic instruments. |

## Protocol Design

### Participants and Roles

| Component | Role |
|-----------|------|
| Signer | Holds an RI credential and an FSRT chain bound through that credential. Produces a single signer SNARK per petition signed. |
| Organizer | Registers a petition under an RI root `R` and escrows the resolution bounty. |
| Relayer | Aggregates signer SNARKs into a batch SNARK and publishes the EIP-4844 blob. |
| Resolver | Computes and submits the resolution SNARK after the dispute window opens. Claims the escrowed bounty on first valid submission. |
| Disputant | Submits a point-evaluation dispute against a published batch during the dispute window. |
| Petition Registry | L1 smart contract holding petition state, IMT roots, batch records, and resolution outputs. |
| RI Credential Layer | Provides the credential tree `R` over RI identities and their attribute commitments. |

### Lifecycle

| From | To | Trigger |
|------|----|---------|
| `Registered` | `SigningOpen` | atomic with registration call |
| `SigningOpen` | `SigningClosed` | first transaction at block `>= close_at_block` |
| `SigningClosed` | `Cooldown` | atomic with `SigningClosed` entry |
| `Cooldown` | `DisputeWindow` | first transaction at block `>= close_at_block + 2h` |
| `DisputeWindow` | `Resolved` | valid resolution SNARK submission at block `>= close_at_block + 14 days` |
| `DisputeWindow` | `Unresolved` | `markUnresolved(petition_id)` at block `>= close_at_block + 14 days + 1 hour grace`; replaces `running_root` with the tombstone marker |

The Registry MUST enforce the current `state` at every entry point.

### Flows

#### Signer Enrollment

1. Signer MUST sample `s_0` from a CSPRNG with at least 254 bits of entropy.
2. Signer MUST derive `(v_i, s_{i+1})` for `i in [0, 2^24)` by inductive sponge expansion.
3. Signer MUST build a depth-24 Poseidon1 Merkle tree over `{v_i}`; the root is `chain_root`.
4. Signer MUST compute `attr_hash = Poseidon1(DOMAIN_ATTR, attr_0, ..., attr_{n-1}, chain_root, attr_version, identity_secret)` and submit it with the RI enrollment proof; RI appends a leaf under `attr_hash`. `identity_secret` is an independent CSPRNG-sampled per-signer secret.
5. Signer MUST discard `s_1, ..., s_{2^24 - 1}` and intermediate Merkle nodes, and MUST retain `(s_curr = s_0, t = 0, caterpillar, chain_root, attr_version)` per [Off-Chain Signer State](#off-chain-signer-state).

#### Petition Registration

1. Organizer constructs `(R, predicate_def, salt, class_set, class_thresholds, class_index, close_at_block)` and calls `register(petition_data, B)`.
2. Registry MUST structurally validate the predicate and class-binding clause, MUST recompute and assert `predicate_hash`, MUST derive `petition_id`, MUST assign `slot = S` then increment `S`, MUST snapshot `alpha_at_registration`, and MUST assert `B >= alpha_at_registration * N_expected * predicate_op_count`.
3. Registry MUST initialise `running_root`, `identity_tag_set_root`, `leaf_count` and MUST emit `PetitionRegistered`.

The signing window MUST satisfy `close_at_block - registration_block <= 11.5 days * BLOCKS_PER_DAY`. Organizer MUST select an `R` that has been published on RI for at least 30 days. Each `class_thresholds[i]` MUST be at least 1; a zero threshold would collapse the resolution SNARK's per-class predicate to `true` regardless of participation and would zero the bounty floor.

#### Per-Signature Generation

1. Signer MUST read `(slot, R, predicate_def, salt, class_index)` for petition `X` and MUST advance the chain locally from `t` to `slot(X)`, setting `s_curr <- s_{slot(X)}`.
2. `(v_slot, _) = Poseidon1Sponge.absorb(DOMAIN_FSRT_PRG, s_slot).squeeze(2)`; `class_tag = attr[class_index]`.
3. `nullifier = Poseidon1(DOMAIN_NULLIFIER, v_slot, petition_id, class_index, class_tag, identity_secret)`; `identity_tag = Poseidon1(DOMAIN_IDTAG, v_slot, petition_id)`.
4. Signer MUST build the signer SNARK and MUST submit it with `(nullifier, identity_tag, class_tag)` to a relayer.
5. After L1 finality of the carrying batch, signer MUST advance the caterpillar frontier and set `t <- slot + 1`, and MAY advance `s_curr` past `s_slot` for use in signing other petitions. Signer MUST retain `s_slot` and the Merkle path from `v_slot` to `chain_root` in `pending_retention` (see [Off-Chain Signer State](#off-chain-signer-state)) until block `close_at_block + 14 days`; at or after that block, the carrying batch is no longer rollbackable and the signer MUST overwrite the retained `s_slot` and Merkle path. Retention is required because a later in-window dispute against an earlier batch cascades into repudiation of every subsequent active batch (see [Dispute](#dispute)), and the signer needs `s_slot` plus the Merkle path to rebuild the signer SNARK for resubmission. Worst-case retention is bounded by 11.5 days (maximum signing window) + 14 days (dispute window) = 25.5 days from signing. The signer MUST journal each transition to fsync'd storage before the corresponding signing counts as complete.

`class_tag` is exposed as a public input on the signer SNARK and is published per-record in the blob payload. This is intentional public outcome metadata. The cost is reflected in the signer-level unlinkability bound (see [Guarantees](#guarantees)), where `k` is restricted to RI signers whose `attr[class_index]` matches each petition's published `class_tag`.

#### Batch Publication

1. Relayer MUST collect signer SNARKs targeting `(petition_id, R, predicate_hash, class_index, slot)` and extract `(nullifier_i, identity_tag_i, class_tag_i)` per position.
2. Records MUST be ordered by `leaf_i = Poseidon1(DOMAIN_LEAF, nullifier_i, class_tag_i)` ascending and serialised; `batch_versioned_hash` is computed.
3. Relayer MUST build the batch SNARK with `prior_leaf_count` and `new_leaf_count = prior_leaf_count + batch_size`, then submit `tx(blob, batch SNARK)`. Relayers MUST retain blob bytes locally until L1 finality.
4. Registry MUST verify the SNARK, MUST revert on failure or on `batch_size` outside `[1, BATCH_SIZE_MAX]`, MUST assert petition bindings and prior-state equality, MUST update state, and MUST emit `BatchPublished`.

#### Dispute

1. Disputant submits `dispute(petition_id, batch_index, position_i, position_j, violation_type, opening_proofs)` at block `< close_at_block + 14 days`. `position_j` is `None` for violation `0x01` and `Some(j)` for `0x02` and `0x03`. The record content at each position MUST be derived by the Registry from `opening_proofs` rather than submitted separately. Registry MUST reject dispute submissions at block `>= close_at_block + 14 days`; the dispute window upper bound matches the block at which `resolve` opens, so a late dispute cannot invalidate a Resolver's prior-state binding mid-flight.
2. Registry MUST validate openings via the `0x0A` precompile against `batch_versioned_hash`, MUST derive the record content for `position_i` (and `position_j` where applicable) from the openings, MUST apply the violation predicate against that derived content, MUST set the BatchRecord state at `batch_index` to `Repudiated`, MUST set every BatchRecord at index `> batch_index` whose state is `Active` to `Repudiated` (those records' `prior_running_root` is no longer canonical), MUST roll back `running_root`, `identity_tag_set_root`, and `leaf_count` to the values held by the immediately preceding active batch (or the initial empty-IMT state if no such predecessor exists), and MUST emit `BatchRepudiated`.

`batch_index` in `BatchPublished` events and in subsequent `dispute` calls is the storage position of the BatchRecord. Storage positions are assigned monotonically by append and never decrease, even across rollbacks. Repudiated BatchRecords remain at their original storage positions and are rejected by the `Active`-state precondition on `dispute`.

Violation types:

| Type | Name | Opening | Predicate |
|------|------|---------|-----------|
| `0x01` | class-tag-out-of-set | record `i` (4 field elements) | `class_tag_i` lies outside `class_set` |
| `0x02` | intra-batch-duplicate-identity-tag | records `i` and `j != i` | `identity_tag_i == identity_tag_j` |
| `0x03` | leaf-ordering-violation | records `i` and `i + 1` | `leaf_i >= leaf_{i+1}` under canonical BN254 ordering |

#### Resolution

1. Resolver MUST read `(running_root, leaf_count, R, predicate_hash, class_set, class_thresholds, class_index)` and MUST reconstruct `L = {leaf_1, ..., leaf_{leaf_count}}` from blobs of active batches.
2. For each `c in class_set`, `count[c] = |{leaf in L : class_tag(leaf) = c}|`; `b_per_class[i] = (count[class_set[i]] >= class_thresholds[i])`; `b = AND_i b_per_class[i]`.
3. At block `>= close_at_block + 14 days`, Resolver MUST submit the resolution SNARK; Registry MUST reject earlier submissions. Registry MUST validate the proof and MUST emit `PetitionResolved` and `BountyPaid`. First valid submission claims the bounty.

For batches whose `submitted_at_block` precedes resolution by more than 4096 epochs, the EIP-4844 blob is no longer retained on the consensus layer and Resolver MUST obtain its payload from a voluntary blob archive. The batch SNARK commitments on L1 still bind blob contents to `batch_versioned_hash`, so any archive copy is verifiable against the on-chain record.

After `close_at_block + 14 days + 1 hour` with no valid resolution, any party MAY call `markUnresolved(petition_id)`. The Registry MUST refund the bounty (less a gas rebate to the caller, capped at 1% of the total bounty so a caller cannot starve the Organizer of their refund) to the Organizer, MUST replace `running_root` with the tombstone marker, MUST transition the petition state to `Unresolved`, and MUST emit `PetitionUnresolved`. This call is only permitted when the petition's state is `DisputeWindow`; the 14-day timer makes any earlier state unreachable. The 1-hour grace after the resolution deadline gives a Resolver exclusive access to the bounty so a `markUnresolved` caller cannot tombstone the petition in the same block where a valid resolution first becomes possible.

### Data Structures

#### Predicate

Predicates are postfix expressions over `attr_vector`, evaluated inside the signer SNARK; the grammar is adapted from OpenAC. Comparators are `==`, `<=`, `>=`; logical ops are `AND`, `OR`, `NOT`.

Per-attribute type tags: `INT64` (unsigned 64-bit comparators), `HASH` (equality-only), `BOOL` (equality-only). Bounds: `1 <= predicate_tuple_count <= 20`, `1 <= predicate_op_count <= 20`; the signer SNARK pads to `L_max = 20` operations for constant-time evaluation.

Every petition's predicate MUST be *class-bound*: every minimal satisfying assignment MUST force `attr[class_index]` into `class_set`. The Registry MUST validate this structurally at registration via a taint analysis where `PUSH_TUPLE(t)` is *Bound* iff `tuples[t].claim_index == class_index`, `tuples[t].comparator == EQ`, and `tuples[t].operand in class_set`; `AND(a, b)` is Bound iff at least one of `a`, `b` is Bound; `OR(a, b)` is Bound iff both `a` and `b` are Bound; `NOT(a)` re-tags Bound as Tainted; any other combination of Bound and non-Bound operands yields Tainted. The top-level evaluation MUST be Bound. The signer SNARK enforces the per-signer specialisation: `attrs[class_index] == class_tag` is checked directly, and at least one binding tuple MUST have `operand == class_tag`, so every accepted signature carries a `class_tag in class_set`.

`predicate_hash = Poseidon1(DOMAIN_PRED, canonical_predicate_def, petition_id, salt)`; `salt` is a 32-byte nonce registered with the petition definition.

```
predicate_def := tuple_count u8
                 tuple[tuple_count]
                 op_count u8
                 op[op_count]

tuple        := claim_index u8                   // in [0, n)
                operand     bytes32              // big-endian
                type_tag    u8                   // 0x01=INT64, 0x02=HASH, 0x03=BOOL
                comparator  u8                   // 0x10===, 0x11=<=, 0x12=>=

op           := op_code u8                       // 0x20=PUSH_TUPLE, 0x21=AND,
                                                 //   0x22=OR, 0x23=NOT, 0xFF=NOP
                operand u8                       // for PUSH_TUPLE: tuple index;
                                                 //   zero otherwise
```

Serialised length `1 + tuple_count * 35 + 1 + op_count * 2`, capped at 1024 bytes. In the signer SNARK, `canonical_predicate_def` is absorbed as 34 BN254 scalars: 31-byte big-endian segments, final segment zero-padded, a two-byte big-endian length marker occupying segment 0's first two content bytes (leaving 29 content bytes for predicate bytes in segment 0 and 31 in segments 1..34), each segment reduced modulo the BN254 scalar field order. The two-byte length marker eliminates the modular-256 collision space a one-byte marker would admit at the 1024-byte upper bound.

#### Petition Record

```
PetitionRecord:
    petition_id            bytes32
    slot                   uint32
    R                      bytes32
    predicate_def          bytes
    predicate_hash         bytes32
    salt                   bytes32
    class_set              uint16[]
    class_thresholds       uint64[]
    class_index            uint8
    close_at_block         uint64
    bounty                 uint256
    alpha_at_registration  uint64
    organizer              address
    running_root           bytes32
    identity_tag_set_root  bytes32
    leaf_count             uint64
    resolution_proof       bytes
    b                      bool
    b_per_class            bool[]
    state                  PetitionState
```

`PetitionState in {Registered, SigningOpen, SigningClosed, Cooldown, DisputeWindow, Resolved, Unresolved}`.

#### Batch Record

```
BatchRecord:
    petition_id               bytes32
    batch_index               uint32
    batch_versioned_hash      bytes32
    new_running_root          bytes32
    new_identity_tag_set_root bytes32
    relayer                   address
    submitted_at_block        uint64
    state                     BatchState
```

`BatchState in {Active, Repudiated}`.

#### Global Registry State

```
GlobalState:
    S            uint32     // FSRT slot counter; monotone
    alpha        uint64     // bounty calibration parameter
    alpha_min    uint64     // governance lower bound on alpha
    alpha_max    uint64     // governance upper bound on alpha
    srs_hash     bytes32    // pinned identifier of the UltraHonk SRS
    chain_id     uint64
    n            uint8
```

Minimum-bounty calibration: `N_expected = 10 * sum(class_thresholds)`; `B_min = alpha * N_expected * predicate_op_count`. The Registry MUST keep `alpha_min <= alpha <= alpha_max`; updates bind petitions registered after the update.

Petition identifier derivation proceeds in three steps:

1. `predicate_hash_pre_id = Poseidon1(DOMAIN_PRED, canonical_predicate_def, 0, salt)`, computed with the literal scalar `0` as the placeholder `petition_id`.
2. `petition_id = keccak256(DOMAIN_PETITION, chain_id, registry_address, organizer, S_at_registration, predicate_hash_pre_id, close_at_block)`.
3. The final `predicate_hash = Poseidon1(DOMAIN_PRED, canonical_predicate_def, petition_id, salt)` is recomputed with the now-known `petition_id` and stored on the petition record.

The tombstone marker is the BN254 scalar `0x0000...0001`.

#### Blob Payload

Each batch occupies one EIP-4844 blob carrying up to 1000 records, each consuming 4 BLS12-381 field elements:

```
RecordEntry (96 bytes across 4 BLS12-381 field elements):
    nullifier_bytes      32
    identity_tag_bytes   32
    class_tag_bytes      2        // big-endian uint16
    record_padding       30       // zero
```

Each BLS12-381 field element is `0x00` top byte plus 31 content bytes; for `(i, j) in [0, 1000) x [0, 4)`, `field_element_index(i, j) = 4i + j` and `field_element_bytes(i, j) = 0x00 || record_bytes(i)[31j : min(31(j+1), 96)]`, with `j = 3` zero-padded to 31 content bytes.

Cross-field binding: Batch SNARK constraint 8. Blob retention: 4096 epochs (EIP-4844 default) from each batch's publication block.

#### Off-Chain Signer State

A signer MUST maintain the following local state (840B fixed plus ~812B per in-flight petition in `pending_retention`):

| Field | Size | Role |
|-------|------|------|
| `s_curr` | 32B | Ratchet head |
| `t` | 4B | Next slot index |
| `caterpillar` | 768B | Right-sibling frontier toward leaf `t` |
| `chain_root` | 32B | Bound in `attr_hash` |
| `attr_version` | 4B | Bound in `attr_hash` |
| `pending_retention` | ~812B per entry | Per in-flight petition: `(petition_id, slot, s_slot, merkle_path_to_chain_root[24], retain_until_block)`; each entry held until `retain_until_block = close_at_block + 14 days` then overwritten |

`caterpillar` stores 24 BN254 scalars (32-byte big-endian); empty levels hold the empty-subtree Poseidon1 hash; frontier update is `O(log N)` per chain advance [Szydlo]. `attr_version` starts at `0` and increments on each re-enrollment posting a new `attr_hash` leaf.

#### Events

Events (`petition_id` indexed in every event except `AlphaUpdated`, which has no `petition_id`; `batch_index` indexed in `BatchPublished` and `BatchRepudiated`):

- `PetitionRegistered(petition_id, slot, R, predicate_hash, class_set, class_thresholds, class_index, close_at_block, B)`
- `BatchPublished(petition_id, batch_index, batch_versioned_hash, new_running_root, new_identity_tag_set_root, new_leaf_count)`
- `BatchRepudiated(petition_id, batch_index, new_running_root, new_identity_tag_set_root, new_leaf_count)`
- `PetitionResolved(petition_id, b, b_per_class)`
- `PetitionUnresolved(petition_id)`
- `BountyPaid(petition_id, recipient, amount)` and `BountyRefunded(petition_id, recipient, amount)`
- `AlphaUpdated(old_alpha, new_alpha)`

## Cryptographic Details

### Primitives

| Primitive | Parameters |
|-----------|------------|
| Poseidon1 permutation (Grassi et al. 2019) | BN254 Fr; `t = 5`; `R_F = 8`, `R_P = 60`; S-box `x^5`; BN254 width-5 MDS and round constants |
| Poseidon1 sponge | Rate `r = 4`, capacity `c = 1`; `0x80`-prefixed length-padding to a multiple of `r` scalars |
| BLS12-381 KZG (EIP-4844) | Trusted setup pinned at deployment; SRS identified by `srs_hash` in `GlobalState` |
| UltraHonk SNARK (Aztec Barretenberg) | Over BN254 KZG; recursive verification |
| Indexed Merkle Tree (Aztec) | Poseidon1 hashing; depth 24; sorted-linked-list leaves `(value, next_index, next_value)` |
| Forward-secure ratchet (Bellare-Yee 2003) | Length-doubling PRG instantiated by the Poseidon1 sponge |
| Caterpillar Merkle frontier (Szydlo) | Log-space Merkle traversal across depth 24 |
| Keccak-256 (FIPS 202) | `petition_id` derivation; event topic hashing |

### Domain Separators

The protocol uses small distinct BN254 scalar constants for Poseidon1-based domain separation:

| Tag | Value |
|---|---|
| `DOMAIN_NULLIFIER` | `1` |
| `DOMAIN_IDTAG` | `2` |
| `DOMAIN_LEAF` | `3` |
| `DOMAIN_FSRT_PRG` | `4` |
| `DOMAIN_PRED` | `5` |
| `DOMAIN_ATTR` | `6` |
| `DOMAIN_BATCH_SNARK` | `7` |
| `DOMAIN_PETITION` | `8` |
| `DOMAIN_RESOLUTION_SNARK` | `9` |

The `keccak256`-based `petition_id` derivation (see [Global Registry State](#global-registry-state)) uses a distinct 32-byte tag `DOMAIN_PETITION_ID = keccak256("RCP/petition_id/v1")` to provide cryptographic separation in the Keccak hash function context where small-integer prefixes would otherwise collide with naturally-occurring input bytes.

Implementations MUST embed these constants at compile time. The Noir circuits (`circuits/lib/src/domain.nr`), the Rust crate (`src/poseidon.rs`), and the on-chain registry (`contracts/src/PetitionRegistry.sol`) MUST agree byte-for-byte on every constant.

### FSRT Chain

Depth-24 Poseidon1 Merkle tree over `N = 2^24` per-slot values from `(v_i, s_{i+1}) = Poseidon1Sponge.absorb(DOMAIN_FSRT_PRG, s_i).squeeze(2)` for `i in [0, N)`. `chain_root` binds into `attr_hash` at RI enrollment. After each finalised signing at slot `k` for petition `X`, the signer MUST, in order: copy `(s_k, merkle_path_k_to_chain_root)` into `pending_retention` with retain-until block `close_at_block(X) + 14 days`; derive `(_, s_{k+1}) = Poseidon1Sponge.absorb(DOMAIN_FSRT_PRG, s_k).squeeze(2)`; set `s_curr <- s_{k+1}` (overwriting `s_k` in the main chain head while leaving the retained copy intact); call `caterpillar.advance(k)`; and set `t <- k + 1`. The transition MUST be journaled to fsync'd storage before it counts as final. At or after `close_at_block(X) + 14 days`, the signer MUST overwrite the retained `(s_k, merkle_path)` entry. `t` is monotone; the global slot counter `S` is bounded by `N - 1 = 2^24 - 1`.

### Signer SNARK

UltraHonk; zero-knowledge.

**Public inputs (ordered):** `R`, `petition_id`, `predicate_hash`, `class_index`, `class_tag`, `slot`, `nullifier`, `identity_tag`.

**Private inputs:** `identity_secret`, `attr_vector`, `attr_version`, `chain_root`, RI Merkle path to the `attr_hash` leaf in `R`, `s_slot`, Merkle path from `v_slot` to `chain_root`, predicate-evaluation stack trace (`op_codes`, `op_operands`, `op_count`, `tuple_*`, `tuple_count`), `salt`. The signer SNARK reconstructs `canonical_predicate_def` from the witnessed predicate program and hashes it, so it is not supplied as a separate input.

**Circuit constraints:**

1. `attr_hash = Poseidon1(DOMAIN_ATTR, attr_0, ..., attr_{n-1}, chain_root, attr_version, identity_secret)` opens the leaf at the provided RI Merkle path to `R`. `identity_secret` is bound into the RI leaf so an attacker who learns `s_0` alone cannot enroll under the same RI leaf as the victim.
2. `predicate_hash = Poseidon1(DOMAIN_PRED, canonical_predicate_def, petition_id, salt)`.
3. `attr_vector` satisfies `canonical_predicate_def` under postfix evaluation.
4. `attrs[class_index] == class_tag` holds directly, and at least one tuple in `predicate_def` matches `(claim_index = class_index, comparator = EQ, operand = class_tag)`. Combined with the Registry's structural class-binding check at registration (every minimal satisfying assignment of the predicate forces `attr[class_index]` into `class_set`), this guarantees `class_tag in class_set` for every accepted signature.
5. `(v_slot, _) = Poseidon1Sponge.absorb(DOMAIN_FSRT_PRG, s_slot).squeeze(2)`.
6. `v_slot` opens at index `slot` in `chain_root` under the provided Merkle path; `chain_root` equals the value bound through `attr_hash`.
7. `nullifier = Poseidon1(DOMAIN_NULLIFIER, v_slot, petition_id, class_index, class_tag, identity_secret)`. Combined with `identity_secret`'s presence in `attr_hash`, this enforces "one signature per RI leaf per petition" even when `s_0` is compromised in isolation.
8. `identity_tag = Poseidon1(DOMAIN_IDTAG, v_slot, petition_id)`.

### Batch SNARK

UltraHonk; recursive. `BATCH_SIZE_MAX = 100`.

**Public inputs (ordered):** `petition_id`, `R`, `predicate_hash`, `class_index`, `slot`, `batch_size`, `prior_running_root`, `new_running_root`, `prior_identity_tag_set_root`, `new_identity_tag_set_root`, `prior_leaf_count`, `new_leaf_count`, `batch_versioned_hash`, `bls_fields[BATCH_SIZE_MAX * 4]`, `signer_vk_hash`. The `bls_fields` array carries the per-position BLS12-381 field-element decompositions used by constraint 8; positions in `[batch_size, BATCH_SIZE_MAX)` decode to `(0, 0, 0)`. `signer_vk_hash` binds the recursion to a deploy-pinned signer verification key: the Registry MUST assert equality against a constructor-supplied `pinned_signer_vk_hash` immutable.

**Private inputs:** per position `i in [0, batch_size)`, the signer SNARK proof and tuple `(nullifier_i, identity_tag_i, class_tag_i)`; IMT insertion proofs against `prior_running_root` and `prior_identity_tag_set_root`; cross-field decomposition witnesses per [Blob Payload](#blob-payload).

**Circuit constraints:**

1. `1 <= batch_size <= BATCH_SIZE_MAX`.
2. Each signer SNARK verifies under public inputs `(R, petition_id, predicate_hash, class_index, class_tag_i, slot, nullifier_i, identity_tag_i)`.
3. `nullifier_i` and `identity_tag_i` (`i in [0, batch_size)`) are pairwise distinct.
4. `nullifier_i` is non-member of `prior_running_root`; `identity_tag_i` of `prior_identity_tag_set_root`.
5. `leaf_i = Poseidon1(DOMAIN_LEAF, nullifier_i, class_tag_i)` is strictly increasing in `i`.
6. `new_running_root` and `new_identity_tag_set_root` result from inserting `leaf_i` and `identity_tag_i` (respectively) into the prior roots in this order.
7. `new_leaf_count = prior_leaf_count + batch_size`.
8. `batch_versioned_hash` opens at canonical evaluation points to BLS12-381 field elements decoding under [Blob Payload](#blob-payload) to `(nullifier_i, identity_tag_i, class_tag_i)` for `i in [0, batch_size)`; positions in `[batch_size, BATCH_SIZE_MAX)` decode to `(0, 0, 0)`. Cross-field binding: each in-circuit BN254 scalar has a big-endian 32-byte decomposition, byte-range-checked, equal to the corresponding BLS12-381 field element.

**Blob binding mechanism.** The binding between the BN254 batch SNARK and the BLS12-381 KZG commitment in `batch_versioned_hash` is split across two trust domains. Inside the circuit, constraint 8 establishes byte-level equality between BN254 record scalars and the `bls_fields` public-input array of BLS12-381 field elements. On L1, during `publishBatch`, the Registry calls the `0x0A` KZG point-evaluation precompile once per `bls_fields` entry against `batch_versioned_hash` at canonical evaluation points, closing the binding from the BLS12-381 commitment side. No BLS12-381 KZG verification happens inside the SNARK; the curve crossing is resolved by exposing the BLS12-381 field elements as public inputs and verifying them against the blob commitment on-chain.

### Resolution SNARK

UltraHonk; zero-knowledge.

**Public inputs (ordered):** `predicate_hash`, `R`, `running_root`, `leaf_count`, `class_set[CLASS_MAX]`, `class_set_len`, `class_thresholds[CLASS_MAX]`, `b`, `b_per_class[CLASS_MAX]`, `class_index`. `class_set` and `class_thresholds` are zero-padded to a fixed-size `CLASS_MAX` array; `class_set_len <= CLASS_MAX` selects the active prefix. `class_index` is bound to the petition's stored value at registration via the Registry's resolution-prior-state check; positions in `[class_set_len, CLASS_MAX)` of `b_per_class` MUST decode to `0`.

**Private inputs:** leaf set `L = {leaf_1, ..., leaf_{leaf_count}}` underlying `running_root`; IMT membership proof per leaf; the witness pair `(nullifier_j, class_tag_j)` with `leaf_j = Poseidon1(DOMAIN_LEAF, nullifier_j, class_tag_j)`.

**Circuit constraints:**

1. `|L| = leaf_count`.
2. `leaf_j` are pairwise distinct.
3. Each `leaf_j` opens `running_root` under the IMT membership proof.
4. `leaf_j = Poseidon1(DOMAIN_LEAF, nullifier_j, class_tag_j)` with the witnessed pair.
5. `class_set[0 .. class_set_len]` is strictly increasing.
6. For every `j in [1, leaf_count]`, `class_tag_j` equals at least one `class_set[k]` for `k in [0, class_set_len)`. An off-class leaf admitted into `running_root` (e.g. via a predicate the Registry should have rejected) cannot be discarded by the Resolution SNARK; if such a leaf exists, the petition can only exit via `markUnresolved` after the 14-day timer.
7. For `i in [0, class_set_len)`: `count_i = card{ j in [1, leaf_count] : class_tag_j = class_set[i] }`; `b_per_class[i] = 1` iff `count_i >= class_thresholds[i]`.
8. `b = AND_{i in [0, class_set_len)} b_per_class[i]`.

## Security Model

### Threat Model

Adversary capabilities:

- Passive observation of L1 indefinitely, the blob carrier during the EIP-4844 retention window, and any voluntary blob archive thereafter.
- Compelled key disclosure of any non-signer party (Organizer, Relayer, Resolver, Disputant, archiver).
- Compelled key disclosure or device compromise of a signer, yielding `(identity_secret, attr_vector, RI Merkle path, s_curr, t, caterpillar, chain_root, pending_retention)` before or after the ratchet for slot `s_slot`.
- Cross-petition correlation against any observable, including predicate-match intersections.
- Sybil enrolment of multiple RI identities.
- Absence of an honest disputant; published batches may go unchallenged for the duration of the dispute window.

Honest-party assumptions: Poseidon1 sponge security and UltraHonk soundness; EIP-4844 blob commitment binding; L1 censorship-resistant inclusion and finality; permissionless Relayer entry such that Signers can resubmit on Relayer-side censorship; Sybil resistance from RI.

Out of scope: network transport anonymity beyond what Tor or an equivalent provides; real-time device compromise during the `pending_retention` window for `s_slot`; forensic recovery of overwritten storage on commodity media without `TRIM`.

### Guarantees

- **Per-petition forward secrecy.** An adversary holding post-signing runtime state, `identity_secret`, `attr_vector`, the RI Merkle path, `pending_retention`, and the full blob and L1 archives recovers `v_{k'}`, `s_{k'}`, or any value computationally non-trivial in `v_{k'}` (including the slot-`k'` nullifier and identity tag) for any slot `k' < t` whose `pending_retention` entry has already been overwritten with advantage at most `(t - k') * eps_sponge`, under the Poseidon1-sponge PRG assumption. Slots with live `pending_retention` entries are recovered directly from that buffer.
- **Signer-level unlinkability.** For petitions `X1`, `X2` and records `r_1 in batch_{X1}`, `r_2 in batch_{X2}`, the adversary's advantage in deciding "same signer" exceeds `1/k - negl` only when it holds at least one of `v_{slot(X1)}` or `v_{slot(X2)}`. `k` is the cardinality of Signers in `R` whose `attr_vector` satisfies both predicates and whose `attr[class_index]` matches each petition's published `class_tag`. The public per-record `class_tag` is what restricts `k` to class-matched signers rather than all signers matching both predicates.
- **One signature per RI leaf per petition.** For petition `X` and RI leaf `L_RI`, at most one record in `running_root` derives from `L_RI` after batching and dispute resolution.
- **Outcome verifiability.** A verifier holding L1 chain state, the SRS identified by `srs_hash`, and the Poseidon1 parameter set re-verifies the resolution SNARK, confirming `b` and `b_per_class`.
- **In-window dispute soundness.** A batch's contribution to `running_root` is removed only when the disputant produces valid KZG openings against `batch_versioned_hash` and evidence satisfying one of the enumerated violation predicates.
- **Domain separation.** Reuse across petitions is rejected because `petition_id` derivation binds `chain_id` and `registry_address` (so two deployments produce distinct `petition_id`s for the same organizer inputs), and each signer SNARK exposes `(petition_id, slot, class_tag, nullifier, identity_tag)` as public inputs. The Poseidon1 domain constants ([Domain Separators](#domain-separators)) are small integers chosen to be pairwise distinct within this protocol; they do not provide cross-protocol separation on their own, and applications combining RCP with other Poseidon1-based protocols on the same field MUST rely on the `petition_id` binding for separation.

### Observability

| Party | What it sees during a normal signing |
|-------|--------------------------------------|
| Organizer | Petition's public parameters and the on-chain bounty escrow |
| RI credential operator | Per-RI-identity attribute commitments and the enrollment trail under `R` |
| Signer | Their own `identity_secret`, `attr_vector`, RI Merkle path, FSRT runtime state, derived `(nullifier, identity_tag, class_tag)` values |
| Relayer (at the anonymous-transport exit boundary) | The signer SNARK and the `(nullifier, identity_tag, class_tag)` tuple per submission; the resulting batch SNARK and blob payload contents; the relayer's own network origin |
| Anonymous-transport peer (Tor or equivalent) | Entry peer: signer network origin only. Exit peer: signer SNARK and tuple delivered to the relayer. |
| Disputant, Resolver | Public blob contents (within retention window or from voluntary archive) |
| Ethereum observer | Batch SNARK public inputs; resolution SNARK public inputs; petition record fields |

## Terminology

| Term | Definition |
|------|------------|
| Class | Value in `class_set` partitioning signatures for threshold accounting (e.g., an EU member state for an ECI petition). |
| Outcome bits | `b` and `b_per_class` emitted by the resolution SNARK. |

## References

### Normative

- [BCP 14 / RFC 2119](https://www.rfc-editor.org/rfc/rfc2119), [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)
- [EIP-4844: Shard Blob Transactions](https://eips.ethereum.org/EIPS/eip-4844)
- [EIP-7805: Fork-Choice enforced Inclusion Lists (FOCIL)](https://eips.ethereum.org/EIPS/eip-7805)
- [Grassi, Khovratovich, Rechberger, Roy, Schofnegger, "Poseidon: A New Hash Function for Zero-Knowledge Proof Systems", USENIX Security 2021](https://eprint.iacr.org/2019/458)
- [Bellare and Yee, "Forward-Security in Private-Key Cryptography", CT-RSA 2003](https://eprint.iacr.org/2001/035)
- [Szydlo, "Merkle Tree Traversal in Log Space and Time", EUROCRYPT 2004](https://iacr.org/archive/eurocrypt2004/30270536/szydlo-loglog.pdf)
- [Aztec Labs, "UltraHonk", Barretenberg](https://github.com/AztecProtocol/barretenberg)
- [Barreto and Naehrig, "Pairing-Friendly Elliptic Curves of Prime Order", SAC 2005](https://eprint.iacr.org/2005/133)
- [NIST FIPS PUB 202, "SHA-3 Standard"](https://doi.org/10.6028/NIST.FIPS.202)
- [ResilientIdentity Protocol Specification](../../private-identity/resilient-private-identity/SPEC.md)

### Informative

- [Aztec Network, "Indexed Merkle Trees"](https://docs.aztec.network/aztec/concepts/storage/trees/indexed_merkle_tree)
- [Privacy and Scaling Explorations, "OpenAC: Open Design for Transparent and Lightweight Anonymous Credentials", zkID Working Group, 2024](https://eprint.iacr.org/2026/251)

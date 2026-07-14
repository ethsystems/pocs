---
title: "Shielded Pool: PIR + Epoch Nullifiers Extension"
status: Draft
version: 0.1.0
authors: []
created: 2026-05-19
ethsystems_use_case: "https://github.com/ethsystems/map/blob/master/use-cases/private-stablecoins.md"
ethsystems_approach: "https://github.com/ethsystems/map/blob/master/approaches/approach-private-payments.md"
---

# Shielded Pool: PIR + Epoch Nullifiers Extension

## Overview

The parent shielded-pool design leaves two concerns unaddressed.

State-read privacy. Before spending, the wallet fetches the input note's Merkle path from on-chain state. That RPC read reveals the queried leaf index, which under KYC links to a real identity. The parent `REQUIREMENTS.md` flags this; the parent SPEC does not specify how the wallet performs the read.

Nullifier-set bloat. The on-chain nullifier set grows linearly with history and is never pruned. At Visa-scale throughput (~150 M tx/day, 32 B per nullifier) this is ~5 GB/day in raw nullifier bytes alone, before tree overhead. Beyond the multi-terabyte range the set of entities able to host it shrinks to a few well-resourced providers; see Bowe and Miers (ePrint 2025/2031) for fuller analysis.

This extension addresses both. PIR over the pre-spend tree reads hides which leaf the wallet queried from the serving node, breaking the leaf-index-to-identity link. Epoch-based nullifiers bound the active on-chain set: past epochs are anchored by one Merkle root each, with tree content hosted by the same off-chain state-replica server that answers PIR queries.

A per-note recursive chain proof (IVC) keeps per-spend work bounded: the wallet extends it one step per rollover, and the spend circuit recursively verifies one chain proof instead of inlining `k` non-membership checks. The commitment binds `epoch_created` so the verifier can enforce that the chain covers the note's full lifetime. Deposit and attestation flows are otherwise unchanged.

Non-membership witnesses for unspent (phantom) epochs carry no on-chain footprint, so they are served in clear; PIR is reserved for the commitment-path read. This relaxes full oblivious synchronization in exchange for far fewer private queries per spend (see Off-Chain State-Replica Server and Limitations).

The spend itself is split across two proofs produced by different parties: a spend proof from the wallet (commitment membership, chain-proof recursion, nullifier derivation) and an insertion proof from the relayer (advancing the active-tree root). The public nullifier list binds them on-chain.

---

## Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

---

## Proof System Requirements

This extension is proof-system agnostic. Required capabilities: an EVM-verifiable outer artifact with a succinct on-chain verifier (cost depends only on public-input length, not on circuit size), in-circuit recursive verification of the system's own proofs, the ability to bind a verifying key as a circuit value, zero-knowledge for spend proofs (chain-update proofs need not be zk), and support for branching the recursive verify on a base case (via circuit-level conditionals or a sentinel proof).

Notation: `assert recursive_verify(inner_vk, inner_statement, inner_proof)` denotes the in-circuit primitive asserting that `inner_proof` is a valid proof of `inner_statement` under `inner_vk`. All three are witnesses to the outer circuit; the outer circuit MAY re-expose any of them as its own public inputs depending on what the consuming verifier (on-chain contract or outer recursion layer) must bind to. `FixedVK` is the chain-update circuit's verifying key, fixed at deployment.

Reference instantiation (non-normative): Noir (`std::verify_proof`) with the Aztec `bb_proof_verification` library on UltraHonk, using `noir-recursive-no-zk` for chain-update artifacts and `evm` for the outer spend artifact. Halo2, Plonky2/3, Nova-family folding, Risc0, and SP1 are also candidates.

---

## Diff vs Parent

| Parent primitive | Status |
|---|---|
| `Note` data structure | Extended: includes `epoch_created` |
| `Commitment` derivation | Extended: `c = poseidon(token, amount, owner_pubkey, salt, epoch_created)` |
| `Nullifier` derivation | Extended: `η_e = poseidon(commitment, spending_key, epoch_id)` |
| Attestation registry and flows | Unchanged |
| `Deposit` flow | Extended: circuit enforces `epoch_created == currentEpoch` on the new commitment |
| `Private Transfer` flow | Extended: commitment-tree path read via PIR; spend circuit recursively verifies one per-input-note chain proof and emits public `η_active_i`; a separate relayer-produced insertion proof advances `activeNullifierRoot` and `activeLeafCount` |
| `Withdraw` flow | Extended: same PIR path read, chain-proof verification, and relayer-produced insertion proof as `Transfer` |
| Commitment tree retrieval | Alternate fetch path (PIR-served raw nodes) |
| Historical root retrieval | Light-client-verified (replaces implicit trusted RPC) |
| `ShieldedPool` on-chain state | Extended: `currentEpoch`, `frozenNullifierRoots`, `activeNullifierRoot`, `activeLeafCount`, `rolloverEpoch()`; spend tx supplies per-input-note `epoch_created`; the relayer's insertion proof supplies `(pre_active_root, post_active_root, pre_leaf_count)` and the contract advances the active tree |
| Per-note chain proof | New: maintained off-chain by the wallet; extended one step per epoch rollover (or `k` steps at wake-up after offline periods) |
| Insertion proof | New: per-spend proof produced by the relayer; proves the indexed-tree insertion of the public `η_active_i` list; no spending-key data |

---

## Approach

| Gap | Primitive |
|---|---|
| State-read privacy | InsPIRe ([eprint 2025/1352](https://eprint.iacr.org/2025/1352)): single-server PIR with silent preprocessing |
| Database layout | Raw flattened Merkle node arrays per [`tree-pir`](https://github.com/brech1/tree-pir); wallet fetches `log(N)` sibling nodes per spend via batched PIR query. Commitment tree is a LeanIMT (append-only, membership only); active and frozen nullifier trees are indexed Merkle trees (sorted leaves with `next_value`/`next_index` pointers, supporting sorted-low-leaf non-membership and insertion) |
| Root authenticity | Light client (e.g. Helios) verifies `commitment_root` and `frozenNullifierRoots[e]` against consensus; paths are reconstructed against these roots in wallet and circuit |
| Nullifier bloat | Coarse epoch-based nullifiers; cross-epoch non-membership folded into a per-note recursive chain proof (IVC), verified once by the spend circuit regardless of note age |
| Spend-time per-note coverage | Commitment binds `epoch_created`, letting the verifier enforce chain coverage over the note's full lifetime |
| Phantom-epoch query privacy | Nullifiers for unspent (phantom) epochs never touch the chain, so their non-membership witnesses are served in clear; PIR is reserved for the commitment read |
| Active-tree update decoupling | Spend circuit emits the public `η_active_i` list; a separate insertion proof produced by the relayer (or state-replica) advances `activeNullifierRoot` and `activeLeafCount`. The contract binds the two proofs by matching their η lists |

Artifact roles: inner (chain-update, consumed recursively by the spend proof), outer spend (verified on-chain), outer insertion (verified on-chain). PIR parameters are inherited from InsPIRe.

---

## Data Types

### Note (extended)

```
Note {
    token:         address    // ERC-20 token contract
    amount:        u128
    owner_pubkey:  Point      // spending public key of owner
    salt:          Field      // random salt
    epoch_created: u64        // value of currentEpoch at the moment this note was committed
}
```

### Commitment (extended)

```
commitment = poseidon(token, amount, owner_pubkey, salt, epoch_created)
```

### Nullifier (extended)

```
η_e = poseidon(commitment, spending_key, epoch_id)
```

`epoch_id` is advanced by `rolloverEpoch()`; distinct values yield distinct nullifiers for the same note across epochs.

### Chain proof (new)

A `ChainProof` attests that a note is non-spent through some past epoch. Produced by the chain-update circuit, maintained off-chain by the wallet.

Public inputs:

```
ChainProof.public_inputs {
    commitment:              Field   // the note this chain attests about
    epoch_created:           u64     // bound into commitment
    epoch_validated_through: u64     // next epoch needing non-membership; equals currentEpoch when fully caught up (epoch_created ≤ epoch_validated_through ≤ currentEpoch)
    accumulator:             Field   // running Poseidon hash over frozen roots used to build this chain
}
```

Epochs in `[epoch_created, epoch_validated_through - 1]` have been folded into `accumulator` and checked for non-membership.

- Genesis: `epoch_validated_through == epoch_created`, `accumulator == 0`.
- Step:

```
accumulator_new = poseidon2(accumulator_prev, frozenNullifierRoots[epoch_validated_through_prev])
epoch_validated_through_new = epoch_validated_through_prev + 1
```

At spend time the contract recomputes the expected accumulator from `frozenNullifierRoots[epoch_created .. currentEpoch - 1]` and reverts on mismatch.

---

## On-Chain State

`ShieldedPool` MUST add:

```solidity
uint64  public currentEpoch;
mapping(uint64 => bytes32) public frozenNullifierRoots;
// Active-epoch nullifier set is an indexed Merkle tree; the contract holds
// only the current root and a leaf counter, advanced by each spend and reset on rollover.
bytes32 public activeNullifierRoot;
uint64  public activeLeafCount;   // next free slot = canonical append index; starts at 1 (index 0 = genesis leaf)
bytes32 public constant EMPTY_IMT_ROOT = /* root of the genesis-leaf-only indexed Merkle tree, fixed at deployment */;

/// PoC: owner-only. Production: decentralized trigger.
function rolloverEpoch() external onlyOwner;

/// View helper: recomputes the chain accumulator the spend circuit must match.
function expectedChainAccumulator(uint64 epochCreated) external view returns (bytes32);
```

The active-epoch nullifier set is an indexed Merkle tree: leaves are sorted by value and each leaf carries a `(next_value, next_index)` pointer to the next-larger leaf. Absence of η is proven with a `low_leaf` where `low_leaf.value < η < low_leaf.next_value`. Index 0 holds a genesis leaf `(0, 0, 0)`, the bootstrap low-leaf covering `[0, +inf)`, so the first insertion always has a predecessor to mutate; real nullifiers therefore occupy indices `1, 2, ...` and `activeLeafCount` starts at 1 (the genesis-leaf-only tree's root is `EMPTY_IMT_ROOT`). Inserting η mutates two leaves: the predecessor (its `next_value`/`next_index` repoint to η) and a freshly written leaf at the next free slot. The relayer's insertion proof performs these insertions (see Insertion Circuit), so the contract sees only `(pre_active_root, post_active_root, pre_leaf_count)` and accepts the transition by verifying that proof. A valid sorted-low-leaf insertion is itself a non-membership proof of η in the prior tree, so no separate `activeNullifiers` mapping or uniqueness check is needed. On-chain active-tree state is one `bytes32` and one counter; per-leaf state is held off-chain and reconstructible from event logs.

Canonical append. New leaves are placed at sequential indices starting from `activeLeafCount`, so the post-root is a deterministic function of the inserted-nullifier sequence. A replica replaying the emitted nullifiers in block-then-input order reproduces the identical tree and root. The circuit enforces both the sequential index and that the target slot was empty, so a spend cannot overwrite an existing nullifier leaf.

On `rolloverEpoch()`: `frozenNullifierRoots[currentEpoch] = activeNullifierRoot`, then `activeNullifierRoot = EMPTY_IMT_ROOT`, `activeLeafCount = 1` (reset to the genesis-leaf-only tree), `currentEpoch += 1`, emit `EpochRollover(uint64 epoch, bytes32 root)`.

Epoch cadence. The protocol does not impose an epoch duration; one epoch is whatever period elapses between two `rolloverEpoch()` calls. The PoC targets one rollover per month. Production deployments SHOULD pin a fixed cadence (e.g. one rollover every `N` blocks, or one per calendar period) so wallets and replicas can plan capacity. Coarse cadence directly bounds `k`, which sets both the per-spend on-chain accumulator hashing cost and the maximum chain-update work a wallet pays after an offline period.

On every `transfer` / `withdraw`: verify both proofs (spend + insertion), require their ordered `η_active_1..k` lists are identical, read each input note's `epoch_created` from the spend proof's public inputs, revert if `accumulator != expectedChainAccumulator(epoch_created)` for any input, revert if `pre_active_root != activeNullifierRoot` or `pre_leaf_count != activeLeafCount`, then set `activeNullifierRoot = post_active_root` and `activeLeafCount += k`. The insertion proof internally chains `k` sorted-low-leaf insertions (one per input nullifier) from `pre_active_root` to `post_active_root`, appending at indices `pre_leaf_count .. pre_leaf_count + k - 1`; a repeated η across two inputs of the same tx fails the second insertion because the low-leaf check would no longer be strict.

```solidity
function expectedChainAccumulator(uint64 epochCreated) public view returns (bytes32) {
    bytes32 acc = bytes32(0);
    for (uint64 e = epochCreated; e < currentEpoch; e++) {
        acc = poseidon2(acc, frozenNullifierRoots[e]);
    }
    return acc;
}
```

Active-epoch double-spend is caught by the insertion proof's sorted-low-leaf step: any prior occurrence of η in the active tree makes the strict `low_leaf.value < η < low_leaf.next_value` inequality unsatisfiable, so no separate uniqueness check is needed. On-chain gas per spend: `O(currentEpoch - epochCreated)` SLOADs and Poseidon hashes in `expectedChainAccumulator`, plus the verification cost of both proofs and the constant-size root/counter comparison and write; bounded by coarse epochs (monthly target).

---

## Off-Chain State-Replica Server

One server replicates public on-chain state and exposes a PIR endpoint. Hosted data (raw flattened Merkle nodes per [`tree-pir`](https://github.com/brech1/tree-pir), addressed as `(tree_id, node_offset)`):

| Tree | Construction | Source | Used for |
|---|---|---|---|
| Commitment tree | LeanIMT | `Deposit`, `Transfer` events | Membership witness of input notes (leaf-index known to wallet from its own minting event) |
| Active nullifier tree (current epoch) | Indexed Merkle tree | `Transfer`, `Withdraw` events since the last `EpochRollover` | Consumed by the insertion-proof prover (typically the relayer); the spender does not query it |
| Frozen nullifier tree (per past epoch `e`) | Indexed Merkle tree | `Transfer`, `Withdraw`, `EpochRollover` events | Sorted-low-leaf non-membership witness for the chain-update circuit; served in clear (phantom nullifiers have no on-chain footprint) |

The contract retains only roots (one live `activeNullifierRoot` plus one `frozenNullifierRoots[e]` per past epoch), so the server reconstructs every tree from event logs and offers them as a shared service.

Query model. The wallet makes two kinds of queries to the server per spend:

- Commitment membership (PIR'd). The wallet knows its own commitment's leaf-index from its minting event and issues one index-addressed PIR query for the membership path. The server learns nothing about which commitment is being spent.
- Phantom-epoch non-membership (in clear). A note's per-epoch nullifiers `η_e = poseidon(commitment, spending_key, e)` for `e` in `[epoch_created, currentEpoch - 1]` are phantoms: the note was not spent in those epochs, so these values never appear on-chain. With no on-chain footprint to correlate against, the wallet sends each phantom to the server in clear and receives the sorted-low-leaf non-membership witness. Correctness is re-checked in the chain-update circuit against the light-client root, so a malicious witness cannot produce a valid chain extension.

The wallet does not query the active nullifier tree. The current-epoch nullifier `η_{currentEpoch}` is consumed downstream by the relayer's insertion proof, not by the spender.

Serving modes for frozen epochs. Frozen-epoch data is public and fully reconstructible from event logs, so the server is a convenience rather than a trust root, and the wallet MAY obtain each phantom non-membership witness either way:

- Query (default): send the phantom `η_e` to the server and receive its sorted-low-leaf witness. Bandwidth is `O(1)` per epoch, but the server learns the phantom (the metadata leak documented in the Threat Model and Limitations).
- Static file: download the sealed leaf set for the frozen epoch (immutable, hence cacheable via a CDN or IPFS), then locate the low-leaf and reconstruct the path entirely client-side. This reveals nothing to the server but costs `O(epoch size)` bandwidth per frozen epoch.

The static-file mode suits short epochs or small deployments; at the Visa-scale monthly target a single epoch is hundreds of GB of leaf data, so neither mode removes the need for oblivious synchronization at scale (see Limitations).

The server is untrusted for correctness. Returned nodes are reassembled client-side into a root and compared against the light-client-verified on-chain root; the circuits re-check the same reconstructions.

Root-fetch scheduling. Wallets MUST issue `eth_getProof` for `commitment_root` and any newly-emitted `frozenNullifierRoots[e]` on a fixed schedule, independent of intent to spend: poll `commitment_root` every `T` blocks and pull `frozenNullifierRoots[e]` immediately on observing each `EpochRollover(e)` event. The RPC therefore sees a uniform stream of queries shared by every active wallet, and cannot link a fetch to an imminent spend. Privacy reduces to k-anonymity over the active user base; the only metadata that remains is "this client is a ShieldedPool user," which is already public for anyone who has ever deposited or withdrawn.

Light-client check (pseudocode). Reconciliation walks the two-level MPT from the consensus-verified header down to the contract's storage slot:

```
// Inputs: contract address C, storage slot s, expected value v.
header                       = LightClient.latest_finalized_header()  // verified vs consensus
{ accountProof, storageProof,
  storageHash, value }       = rpc.eth_getProof(C, [s], header.block_number)

// Level 1: header.state_root commits to all accounts.
//   Verify C's account leaf and extract its storageHash.
assert verify_mpt(
    root  = header.state_root,
    key   = keccak256(C),
    leaf  = rlp({nonce, balance, storageHash, codeHash}),
    proof = accountProof,
)

// Level 2: storageHash commits to all storage slots of C.
//   For mapping slot: slot = keccak256(abi.encode(mappingKey, baseSlot)).
assert verify_mpt(
    root  = storageHash,
    key   = keccak256(s),
    leaf  = rlp(value),
    proof = storageProof,
)

assert value == v
```

Run once per `commitment_root` consumed at spend time, and once per `frozenNullifierRoots[e]` consumed during chain extension.

Frozen nullifier trees are served in clear (no PIR), so no PIR preprocessing applies to them. The active nullifier tree is not PIR-served either: the spender never queries it, and the relayer builds insertion witnesses from its own replica. Only the commitment tree is PIR-served, and it mutates continuously (append-only); preprocessing amortization across those mutations is out of scope.

---

## Flows

The wallet maintains one `ChainProof` per owned note, updated either eagerly on each observed `EpochRollover` (one proof per rollover per held note) or lazily before spend (one proof per missed epoch, sequential). By spend time, `epoch_validated_through == currentEpoch`.

### Chain Maintenance (wallet-local; new)

1. Wallet observes `EpochRollover(e_frozen, root)` and verifies the root via the light client.
2. For each owned note with `ChainProof.epoch_validated_through == e_frozen`, the wallet computes the phantom `η_{e_frozen} = poseidon(commitment, spending_key, e_frozen)` and sends it to the server in clear; the server returns the sorted-low-leaf non-membership witness against the just-frozen tree (see Off-Chain State-Replica Server, query model).
3. Wallet runs the chain-update circuit, which recursively verifies the prior chain proof, reconstructs `frozenNullifierRoots[e_frozen]` from the server-returned siblings, checks `η_{e_frozen}` absent under the sorted-low-leaf pattern, folds it into the accumulator, and emits a new `ChainProof` with `epoch_validated_through = e_frozen + 1`.
4. Wallet stores the new chain proof and discards the previous one.

Catch-up: an offline wallet runs steps 2-3 sequentially per missed epoch. Work is bounded-memory and resumable.

### Note Genesis (sentinel chain proof)

On note creation (via `Deposit` or as a `Transfer` output), the owner generates an initial `ChainProof` with `epoch_validated_through = epoch_created`, `accumulator = 0`. The chain-update circuit handles this via its base-case branch (`epoch_validated_through == epoch_created`), which skips prior-proof verification.

### Private Transfer (extended)

1. Catch up each input note's `ChainProof` to `epoch_validated_through == currentEpoch` via Chain Maintenance (phantom-epoch witnesses fetched in clear). Notes created in the current epoch already satisfy this via their genesis proof.
2. PIR-fetch `log(N)` sibling nodes per input commitment, reconstruct the root, and assert equality with the light-client-verified `commitment_root`.
3. Run the spend circuit with per-input chain proofs, commitment-tree membership witnesses, spending key, and output note data (`epoch_created = currentEpoch`). The circuit emits per-input `(η_active_i, epoch_created_in_i, chain_accumulator_in_i)` publicly.
4. Send the spend proof and its public inputs to the relayer.
5. Relayer reads its replica of the active nullifier tree, builds the per-input sorted-low-leaf insertion witnesses, and produces the insertion proof with public inputs `(pre_active_root, post_active_root, pre_leaf_count, η_active_1..k)`.
6. Relayer submits both proofs and their public inputs to the contract.
7. Contract verifies both proofs, asserts their ordered `η_active_1..k` lists are identical, checks `accumulator_i == expectedChainAccumulator(epoch_created_i)` per input and `pre_active_root == activeNullifierRoot` and `pre_leaf_count == activeLeafCount`, sets `activeNullifierRoot = post_active_root` and `activeLeafCount += k`, inserts output commitments, emits `Transfer` carrying the per-input `η_active` values so replicas can rebuild the active indexed tree.

PIR is used only for the commitment read (step 2); phantom-epoch witnesses (step 1) are served in clear. The server is never trusted for roots: every returned node is re-checked in-circuit against the light-client root.

### Withdraw (extended)

Same diff as `Transfer` applied to a single input note.

### Epoch Rollover

The operator (PoC: contract owner) calls `rolloverEpoch()`. The contract reads the active-tree root, writes it to `frozenNullifierRoots[currentEpoch]`, increments `currentEpoch`, and emits `EpochRollover`. The state-replica server ingests the event and appends the frozen tree's nodes to its hosted data. Wallets run Chain Maintenance for their notes.

---

## Circuit Constraints (diff)

Two new circuits (chain-update, insertion) plus diffs to the parent Deposit / Transfer / Withdraw circuits.

### Deposit Circuit (diff)

- New public input: `current_epoch_at_deposit: u64`. The contract enforces `current_epoch_at_deposit == currentEpoch`.
- New constraint: `commitment == poseidon(token, amount, owner_pubkey, salt, epoch_created)` with `epoch_created == current_epoch_at_deposit`.

After deposit, the wallet generates the genesis chain proof via the chain-update circuit's base-case branch.

### Chain-Update Circuit (new)

Inner artifact, consumed recursively by other chain-update proofs and by the spend circuit. Used for both extension and genesis.

Kept separate from the spend circuit because (a) chain-update proofs are consumed only recursively and need not be zero-knowledge or EVM-verifiable, while spend proofs are both; (b) the two have different public-input shapes; (c) keeping the recursion-frequent artifact small reduces wallet proving time across the typical update sequence. An implementation MAY merge them into one circuit with a mode flag, at the cost of paying ZK and EVM-target overhead on every chain update.

Public inputs (the `ChainProof`):

- `commitment: Field`
- `epoch_created: u64`
- `epoch_validated_through: u64`
- `accumulator: Field`

Private inputs:

- `is_base_case: bool`. True only when `epoch_validated_through == epoch_created`.
- `prior_chain.{vk, proof, public_inputs}`: recursive witness; ignored when `is_base_case == true`.
- `frozen_root_next: Field`: equal to `frozenNullifierRoots[prior_chain.public_inputs.epoch_validated_through]`.
- `spending_key: Field`
- `token, amount, salt: Field`: the input note's remaining commitment preimage (`commitment` and `epoch_created` are already public inputs).
- `non_membership.{low_leaf, low_leaf_next_value, path, indices, leaf_index}`: sorted-low-leaf witness against `frozen_root_next`.

Constraints:

Let `e_prev = prior_chain.public_inputs.epoch_validated_through`.

1. Base-case branch (`is_base_case == true`):
   - `epoch_validated_through == epoch_created`
   - `accumulator == 0`
   - No recursive verify, no non-membership check.

2. Inductive branch (`is_base_case == false`):
   - `assert recursive_verify(prior_chain.vk, prior_chain.public_inputs, prior_chain.proof)`
   - `prior_chain.vk == FixedVK` (the chain-update circuit's own VK)
   - `prior_chain.public_inputs.commitment == commitment`
   - `prior_chain.public_inputs.epoch_created == epoch_created`
   - `epoch_validated_through == e_prev + 1` (advances by one rollover; see "Epoch Cadence" below for what one rollover represents)
   - `accumulator == poseidon2(prior_chain.public_inputs.accumulator, frozen_root_next)`
   - Key binding: `owner_pubkey == poseidon(spending_key)` and `commitment == poseidon(token, amount, owner_pubkey, salt, epoch_created)`. The public `commitment` thus pins `spending_key` to the note's real owner key, so the nullifier below is the one that would actually have been published if the note were spent in `e_prev`. Without this, a prover could supply a fabricated `spending_key`, derive a phantom η that is trivially absent, and pass non-membership while the real nullifier sits in the frozen tree.
   - `η = poseidon(commitment, spending_key, e_prev)`
   - Sorted-low-leaf check: `low_leaf.value < η < low_leaf_next_value`, and the supplied Merkle path with `low_leaf` at `leaf_index` reconstructs to `frozen_root_next`.

Branch soundness: `is_base_case` is private but constraint set #1 forces `epoch_validated_through == epoch_created` and `accumulator == 0`. A spender cannot fake the base case for a note with `epoch_created < currentEpoch` because the spend circuit enforces `chain.epoch_validated_through == currentEpoch` and the on-chain accumulator check binds to real frozen roots.

### Spend Circuit (Transfer / Withdraw, diff)

Outer artifact, verified on-chain. MUST be zero-knowledge. Produced by the wallet. Performs no active-tree work: it only proves commitment membership, chain-proof recursion, and nullifier derivation.

New public inputs:

- Per input note `i`: `nullifier_active_i: Field`, `epoch_created_in_i: u64`, `chain_accumulator_in_i: Field`.
- Global: `current_epoch: u64` (in addition to the parent's output commitments and `commitment_root`).

`nullifier_active_i` is public and emitted in the `Transfer` / `Withdraw` event so replicas can rebuild the active indexed tree from the event log. `commitment_in_i` is kept private (below) for unlinkability, matching the parent: only the nullifier becomes the public spend artifact, never the input commitment.

New private inputs:

- Per input note `i`: `commitment_in_i: Field`, proven a member of the commitment tree against `commitment_root`.
- Per input note `i`: `chain_proof_i.{vk, proof, public_inputs}`.

New constraints (per input note `i`):

1. `assert recursive_verify(chain_proof_i.vk, chain_proof_i.public_inputs, chain_proof_i.proof)`
2. `chain_proof_i.vk == FixedVK`
3. `chain_proof_i.public_inputs.commitment == commitment_in_i`
4. `chain_proof_i.public_inputs.epoch_created == epoch_created_in_i`
5. `chain_proof_i.public_inputs.accumulator == chain_accumulator_in_i`
6. `chain_proof_i.public_inputs.epoch_validated_through == current_epoch` (for a fresh note this holds via the base case).
7. `nullifier_active_i == poseidon(commitment_in_i, spending_key, current_epoch)` (replaces parent's `poseidon2(commitment, spending_key)`); the result is the public input of the same name and is emitted in the event.

New constraint (per output note `j`):

8. `commitment_out_j == poseidon(token_out_j, amount_out_j, owner_out_j, salt_out_j, current_epoch)` (outputs minted with `epoch_created == current_epoch`).

Input commitment reconstruction (changed from parent): each input note's commitment is reconstructed inside the circuit as `commitment_in_i == poseidon(token_in_i, amount_in_i, owner_pubkey, salt_in_i, epoch_created_in_i)`, where `owner_pubkey == poseidon(spending_key)` is the parent's inherited key binding (Transfer/Withdraw constraint 1) — the only change versus the parent is the added `epoch_created_in_i` field. The commitment-tree membership witness is verified against this reconstructed value; the membership-proof shape (Merkle path against `commitment_root`) is unchanged. Value preservation and token consistency are unchanged from the parent SPEC.

Contract-side public-input checks for this proof: `commitment_root` is validated against the contract's known commitment-tree root(s) exactly as in the parent (the PIR read path changes how the wallet fetches the path, not how the contract pins the root), `chain_accumulator_in_i == expectedChainAccumulator(epoch_created_in_i)` per input, and `current_epoch == self.currentEpoch`.

### Insertion Circuit (new)

Outer artifact, verified on-chain. Need not be zero-knowledge: all inputs are public state. Produced by the relayer (or any party running the state-replica, which already maintains the active-tree leaves).

Public inputs:

- `pre_active_root: Field`
- `post_active_root: Field`
- `pre_leaf_count: u64`
- Ordered list `nullifier_active_1..k: Field`, matching the spend proof's per-input emission order.

Private inputs, per insertion `i in 1..k`:

- `low_leaf: { value, next_value, next_index }`
- `low_leaf_index: u64`
- `low_leaf_path: Field[]`, the sibling path authenticating `low_leaf` at `low_leaf_index`.
- `new_leaf_path: Field[]`, the sibling path authenticating the (empty) slot at the append index.

Constraints: an insertion chain threading the root through all `k` nullifiers. Let `r_0 = pre_active_root`. For each input `i = 1..k`, with canonical append index `new_leaf_index = pre_leaf_count + (i - 1)`:

1. Predecessor membership and non-membership: `low_leaf` at `low_leaf_index` with `low_leaf_path` reconstructs to `r_{i-1}`, and `low_leaf.value < nullifier_active_i < low_leaf.next_value`.
2. Mutate predecessor: `low_leaf_updated = (value = low_leaf.value, next_value = nullifier_active_i, next_index = new_leaf_index)`. Recompute the intermediate root `r'` from `r_{i-1}` along `low_leaf_path`.
3. Empty-slot check: `new_leaf_path` proves the slot at `new_leaf_index` holds the empty leaf in `r'`. This prevents overwriting an existing nullifier leaf.
4. Write new leaf: `new_leaf = (value = nullifier_active_i, next_value = low_leaf.next_value, next_index = low_leaf.next_index)` at `new_leaf_index`. Recompute `r_i` from `r'` along `new_leaf_path`.

Final constraint: `r_k == post_active_root`.

Two leaves change per insertion (predecessor and new slot), so each step carries two paths and is applied in sequence: the predecessor mutation produces `r'`, and the new-leaf write is proven against `r'`, since the two positions may share internal nodes. Double-spend prevention follows from step 1: any prior occurrence of `nullifier_active_i` in the active tree (from a past spend, or an earlier input in the same tx) breaks the strict `low_leaf.value < nullifier_active_i < low_leaf.next_value` inequality and makes the proof unsatisfiable.

Contract-side public-input checks for this proof: `pre_active_root == self.activeNullifierRoot`, `pre_leaf_count == self.activeLeafCount`. On success: `self.activeNullifierRoot = post_active_root`, `self.activeLeafCount += k`.

### Cross-proof binding

The contract MUST assert the ordered `nullifier_active_1..k` list in the insertion proof's public inputs is identical, element-wise, to the ordered `nullifier_active_i` values emitted by the spend proof's per-input public inputs. Without this, a relayer could submit an insertion proof for a different nullifier list and corrupt the active tree's correspondence to actual spends. With it, the two proofs are glued through the public η values: the spend proof commits the spender to the η list (via the key-bound derivation), and the insertion proof commits the relayer to inserting exactly that list into the active tree.

---

## Security Model

### Threat Model (additions to parent)

| Adversary | Capabilities | Mitigations |
|---|---|---|
| Malicious PIR / state-replica server | Sees query traffic; MAY serve incorrect nodes | InsPIRe single-server malicious-server model for privacy; every returned node is re-checked against a light-client-verified root inside a circuit |
| Oblivious-sync server profiling a wallet | Receives phantom nullifiers `η_e` in clear; MAY profile a wallet's note ages and portfolio size, and across colluding servers link the same note across providers | Phantoms have no on-chain footprint, so the public spend stays unlinkable to these queries; the leak is per-wallet metadata to the serving party only. PoC accepts this; production SHOULD use oblivious nullifier derivation and synchronization (Bowe and Miers 2025/2031) so the service stays oblivious. See Limitations. |
| Public observer correlating note age | Reads each spend's public `epoch_created_in_i`, learning the creation epoch of every spent input | `epoch_created` is published so the contract can recompute `expectedChainAccumulator`; it reveals note age only (never amount or owner), but shrinks the anonymity set for inputs drawn from sparsely-populated epochs. PoC accepts this; the shared-accumulator / on-chain-Merkle-of-frozen-roots mitigation (see Limitations) lets the circuit prove the accumulator over a contiguous frozen-root suffix without publishing `epoch_created`, closing this leak. |
| Operator joining in-clear phantom queries with on-chain `epoch_created` | A party that both serves in-clear phantom queries and relays/observes the spend can join the two: the phantom batch reveals the note's `epoch_created` (its minimum) and links to the query session, and the on-chain spend republishes the same `epoch_created`. With session-to-identity linkage this can map a spend back to a KYC identity, even though the phantom `η_e` values never equal the on-chain nullifier | Requires one party (or colluders) in both roles AND default in-clear serving. Closed by either static-file serving (no in-clear phantom query) or separating the state-replica operator from the relayer; the shared-accumulator mitigation also removes public `epoch_created`, eliminating the join key. PoC documents this as a trust assumption; production SHOULD enforce role separation or oblivious sync |
| Untrusted RPC for root reads | MAY misreport `commitment_root` or `frozenNullifierRoots[e]` | Roots MUST be read through a light client verifying storage proofs against consensus |
| Malicious wallet attempting cross-epoch double-spend | Holds spending key; MAY spend the same note in two epochs, forge a chain against fabricated roots, build the chain under a fabricated spending key, or try to substitute a different `η_active` between the spend and insertion proofs | `epoch_created` bound into commitment; spend circuit enforces `chain.epoch_validated_through == current_epoch`; contract enforces `accumulator == expectedChainAccumulator(epoch_created)`; chain VK constrained to `FixedVK`; chain-update circuit binds `spending_key` to the public `commitment` via `owner_pubkey == poseidon(spending_key)`, so phantom non-membership cannot be proven under a fake key; the spend circuit inherits the parent's owner-key binding (`owner_pubkey == poseidon(spending_key)`), so a note yields exactly one `nullifier_active` per epoch (no multi-nullifier double-spend, and no spending a note whose key the prover lacks); the contract asserts the spend proof's emitted `η_active_1..k` list is identical to the insertion proof's input list, so a wallet cannot substitute a different η |
| Malicious or absent relayer for the insertion proof | MAY refuse to produce the insertion proof, or produce one whose root transition is invalid or whose η list disagrees with the spend proof | The insertion proof is verified on-chain so a wrong root or wrong η list cannot land. Refusal only delays the spend (liveness only). Mitigated by relayer competition or a permissionless prover market |
| Network observer | Sees IP, timing, size of PIR sessions | Out of scope; production SHOULD use Tor or batched windows |

The parent threat model (public observer, malicious relayer, compromised viewing key, malicious compliance authority) is unchanged.

### Guarantees (additions to parent)

| Property | Description |
|---|---|
| Query privacy (PIR'd reads) | The one PIR'd read is the commitment-membership lookup; the server learns nothing about the queried index beyond timing. Phantom-epoch non-membership is intentionally served in clear, so the server does learn those phantom nullifiers (see Threat Model, Limitations); this never links to the on-chain spend. |
| Witness correctness | A malicious server cannot induce a valid spend against an incorrect path, non-membership witness, or chain proof: reconstructions are re-checked in-circuit against light-client roots, and accumulators are re-checked on-chain. |
| Cross-epoch double-spend safety | A note can be spent in at most one epoch. Range `[epoch_created, current_epoch - 1]` is bound by the commitment and on-chain accumulator check; the current epoch is covered by the insertion proof's sorted-low-leaf step against `activeNullifierRoot`, which fails if η already appears in the active tree. The spend proof's η list and the insertion proof's η list are pinned equal on-chain, so a wallet cannot substitute. |
| Bounded active state (nullifier side) | On-chain state per epoch is one `bytes32` (`activeNullifierRoot`, overwritten on each spend, reset on rollover) plus one `bytes32` per past epoch (`frozenNullifierRoots[e]`). Per-leaf state of the active and frozen trees lives off-chain and is reconstructible from event logs, so on-chain storage does not grow per nullifier. This bound is nullifier-scoped: the commitment tree remains append-only and unbounded (parent-owned), and the PIR database and per-query cost grow with it. |
| Constant-cost spend circuit (when chain is current) | Spend-circuit verification cost is independent of note age once `epoch_validated_through == currentEpoch`: one recursive chain-proof verify per input plus nullifier derivation, with no per-input active-tree work. |
| Linear contract-side accumulator check | The on-chain check is not constant: `expectedChainAccumulator(epoch_created)` costs `O(currentEpoch - epoch_created)` SLOADs and Poseidon hashes, linear in the number of frozen epochs the note spans. Bounded in practice by coarse epochs (monthly target); see Limitations for the production mitigation (on-chain Merkle of frozen roots, or shared accumulator). |

### Limitations & Shortcuts (PoC Scope)

| Limitation | Impact | Production Mitigation |
|---|---|---|
| Chain catch-up cost on offline wallets | A wallet offline for `k` epochs pays `O(k)` sequential chain-update proofs and `O(k)` in-clear non-membership queries before spending | Tachyon-style shared accumulator |
| Per-spend `O(k)` on-chain accumulator hashing | `expectedChainAccumulator` costs `O(currentEpoch - epoch_created)` SLOADs and Poseidon hashes | On-chain Merkle of frozen roots, or shared accumulator |
| Wallet maintains a chain proof per held note | Per-note state plus incremental proofs at every rollover | Shared accumulator removes per-note state |
| Centralized epoch rollover | Owner-only `rolloverEpoch()` is a liveness single point | Decentralized trigger |
| Single state-replica server | Spend liveness depends on one replica; logs allow reconstruction so funds are safe | Multiple independent replicas |
| Active-root write contention (relayer-side) | The active tree is advanced through a single `activeNullifierRoot`; the relayer's insertion proof is built against the current root and must be regenerated if another spend lands first. The spender's spend proof is state-independent and does not need to be rebuilt. | A single designated sequencer per epoch removes contention by serializing spends, but trades it for a centralization, censorship, and liveness single point (and a spend-metadata honeypot); since only the insertion proof is state-dependent, this is a deployment choice, not a protocol requirement. Production: decentralized or rotating sequencing, or batched multi-spend insertion proofs under relayer competition. |
| Insertion-proof liveness | Spends require at least one relayer willing to produce the insertion proof. Funds are safe (the proof is verified on-chain so it cannot be forged), but spend liveness depends on relayer availability. | Multiple independent relayers or a permissionless prover market |
| Server-side metadata leak (in-clear phantom serving) | The state-replica server learns a wallet's phantom nullifiers, hence note ages and portfolio metadata (not its on-chain spends); colluding servers can link the same note across providers | Oblivious nullifier derivation and synchronization (Bowe and Miers 2025/2031, Project Tachyon), keeping the syncing service oblivious |
| On-chain note-age disclosure (public `epoch_created`) | Each spend publishes the creation epoch of its inputs so the contract can recompute the chain accumulator; reveals note age (not amount/owner) and reduces the anonymity set for sparse epochs | Shared accumulator / on-chain Merkle of frozen roots: the circuit proves the accumulator over a contiguous frozen-root suffix, so `epoch_created` need not be public |
| Recursive prover maturity | Required capabilities are not uniformly stable across systems | Pin a version; track upstream releases |
| No PIR over the encrypted note log | Note discovery requires trial decryption or operator-side filtering | FMD / OMR (future extension) |
| No post-quantum primitives | Note encryption uses ECDH/AEAD as in parent | Lattice KEM and signatures |

---

## Terminology

| Term | Definition |
|---|---|
| PIR | Private Information Retrieval. Client fetches row `i` from a server-held database without revealing `i`. |
| Silent preprocessing | PIR preprocessing model with all setup server-side; no client hint download. |
| Frozen epoch | Past epoch whose nullifier set has been committed to a single root on-chain; tree content hosted off-chain. |
| Indexed Merkle tree | Merkle tree whose leaves are sorted by value and carry `(next_value, next_index)` pointers to the next-larger leaf; supports both sorted-low-leaf non-membership and ordered insertion proofs. The active and frozen nullifier trees use this construction. |
| LeanIMT | Lean Incremental Merkle Tree (Semaphore); an append-only Merkle tree variant. The commitment tree uses this construction (membership only, no ordering needed). |
| Non-membership witness | Sorted-low-leaf Merkle witness proving absence from an indexed Merkle tree. |
| State-replica server | Off-chain service hosting flattened node arrays of the commitment tree and the active/frozen nullifier trees. Answers PIR queries for the commitment-path read, serves phantom (frozen-epoch) non-membership witnesses in clear, and (typically the same operator as the relayer) builds active-tree insertion witnesses for the insertion proof. |
| Phantom nullifier | A note's per-epoch nullifier `η_e` for an epoch in which the note was not spent; never emitted on-chain, so it can be revealed to the state-replica server without linking to any on-chain transaction. |
| Light client | Verifies Ethereum headers and storage proofs against consensus. |
| Chain proof | Per-note off-chain proof of non-spend from `epoch_created` through `epoch_validated_through - 1`. |
| IVC | Incrementally Verifiable Computation. Each invocation recursively verifies its predecessor; permits bounded-memory step-wise extension. |
| Base-case sentinel | Genesis chain proof with `epoch_validated_through == epoch_created` and `accumulator == 0`. |
| Chain accumulator | Running Poseidon hash binding a chain proof to the sequence of frozen roots; recomputable on-chain. |
| Insertion proof | Per-spend proof attesting that the active-tree root transition `(pre_active_root, post_active_root)` is a valid indexed-tree insertion of the public `η_active_1..k` list at canonical append indices starting from `pre_leaf_count`. Produced by the relayer; carries no spending-key data. |

---

## References

Normative and background:

- InsPIRe: Mahdavi, Patel, Seo, Yeo, "Communication-Efficient PIR with Server-side Preprocessing". IACR ePrint 2025/1352. <https://eprint.iacr.org/2025/1352>
- Bowe, Miers, "A Note on Notes: Towards Scalable Anonymous Payments via Evolving Nullifiers and Oblivious Synchronization". IACR ePrint 2025/2031. <https://eprint.iacr.org/2025/2031>
- tree-pir: <https://github.com/brech1/tree-pir>
- Helios light client: <https://github.com/a16z/helios>
- Polygon Miden, "Epoch-based nullifier database": <https://github.com/0xMiden/miden-vm/discussions/356>
- Aztec, "Global State Epochs": <https://forum.aztec.network/t/global-state-epochs/2704>
- A. Tomescu, "Notes on scaling nullifier sets": <https://alinush.github.io/nullifiers>
- Parent SPEC: [`../shielded-pool/SPEC.md`](../shielded-pool/SPEC.md)
- Parent REQUIREMENTS: [`../REQUIREMENTS.md`](../REQUIREMENTS.md)

Reference instantiation (non-normative):

- Noir standard library, "Recursion": <https://noir-lang.org/docs/noir/standard_library/recursion>
- Aztec `bb_proof_verification`: <https://github.com/AztecProtocol/aztec-packages/tree/master/barretenberg/noir/bb_proof_verification>
- noir-examples, "Recursion": <https://github.com/noir-lang/noir-examples/tree/master/recursion>

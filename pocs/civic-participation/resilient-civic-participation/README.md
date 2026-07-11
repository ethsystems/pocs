# Resilient Civic Participation

> **Status:** Draft (proof of concept)
> **Privacy Primitive:** Credentialed petition signing with forward-secure ratchet, blob-anchored batches, on-chain resolution SNARK.

## What this PoC demonstrates

A petition system where signers prove eligibility against an external [ResilientIdentity (RI)](../../private-identity/resilient-private-identity/) credential root, sign once per petition with cross-petition unlinkability, and produce an outcome verifiable from durable chain state after the dispute window closes. Key properties:

- **Per-petition forward secrecy.** Each signer maintains a Forward-Secure Ratchet Tree (FSRT) chain over `N = 2^24` slot values. After each finalised signing the slot's seed is overwritten in place; a post-signing device compromise reveals nothing about past signed slots beyond what the prior seed material had already produced.
- **Cross-petition unlinkability.** The signer SNARK exposes only `(petition_id, slot, class_tag, nullifier, identity_tag)`. The same RI leaf signs different petitions under distinct slot indices and distinct per-slot ratchet values; no on-chain linkability between two signings of the same signer beyond the predicate-match intersection bound.
- **Operator-free outcome verifiability.** After `close_at_block + dispute window`, anyone can reconstruct the leaf set `L` from blob bytes, recompute `(b, b_per_class)`, and re-verify the resolution SNARK. The organiser, RI issuer, relayers, and resolver can all go offline; the chain holds enough state to settle the outcome.

The protocol spec is in [SPEC.md](./SPEC.md). The repo-wide umbrella requirements live in [../REQUIREMENTS.md](../REQUIREMENTS.md).

## Layout

```
circuits/                   -- Noir workspace (nargo 1.0-beta.21, bb 5.0-nightly.20260324)
├── lib/                    -- shared: poseidon, IMT, FSRT, predicate, blob field-element binding, binary_merkle_root (vendored)
├── signer/                 -- inner SNARK; compiled with `noir-recursive`
├── batch/                  -- outer SNARK; recursively verifies BATCH_SIZE_MAX signer proofs via `bb_proof_verification` v5.0.0-nightly.20260324
└── resolution/             -- outer SNARK; tallies leaves under `running_root`

contracts/                  -- foundry project
├── src/PetitionRegistry.sol         -- on-chain state machine: register / publishBatch / dispute / resolve
├── src/interfaces/{IPetitionRegistry,IVerifier}.sol
├── src/mocks/{MockBatchVerifier,MockResolutionVerifier,MockERC20}.sol
├── src/verifiers/{Batch,Resolution}Verifier.sol  -- emitted by `scripts/generate-verifiers.sh`
└── script/Deploy.s.sol     -- forge deploy script

scripts/generate-verifiers.sh        -- nargo compile + bb write_vk + bb write_solidity_verifier

src/
├── lib.rs                  -- crate root, domain constants
├── types.rs                -- shared domain types
├── poseidon.rs             -- Poseidon1 helpers + sponge + domain separators
├── imt/                    -- depth-24 sorted-linked-list Indexed Merkle Tree
├── fsrt.rs                 -- FSRT chain expansion + caterpillar frontier
├── predicate.rs            -- postfix predicate grammar + canonical scalar encoding
├── blob.rs                 -- EIP-4844 blob payload encoder + batch_versioned_hash
├── ports/                  -- proof, imt, ri, blob, submission traits
├── adapters/
│   ├── bb_prover.rs        -- real BB shell-out (signer = noir-recursive, outer = evm)
│   ├── blob_4844.rs        -- real EIP-4844 blob carrier (c-kzg + alloy BlobTransactionSidecar)
│   ├── chain_registry.rs   -- alloy sol! bindings for on-chain PetitionRegistry
│   ├── in_memory_ri.rs     -- mock RI credential layer (lean_imt-backed)
│   ├── mock_proof.rs       -- sentinel-bytes proof backend for unit + off-chain integration tests
│   └── in_memory_blob.rs   -- mock blob carrier for unit tests
├── signer/                 -- enrollment + per-petition signing + state journaling
├── organizer/              -- petition draft assembly + structural validation
├── relayer/                -- batch aggregation + leaf ordering + IMT insertion witness
├── disputant/              -- builders for the three SPEC dispute predicates
├── resolver/               -- leaf-set reconstruction + outcome computation
└── registry/               -- off-chain shadow state machine for unit tests

tests/
├── common/mod.rs                          -- in-process harness (mock proofs, in-memory RI / blob)
├── duplicate_nullifier_across_batches_rejected.rs
├── anvil_harness.rs                       -- spawns anvil + forge script + parses addresses
└── golden_path.rs                   -- real anvil + real EIP-4844 blob tx + on-chain PetitionRegistry
```

## Build & run

Prerequisites: `nargo 1.0-beta.21+`, `bb 5.0-nightly.20260324+`, `foundry` (forge + anvil), `rust 2024 edition`.

```bash
# Compile circuits + emit Solidity verifiers from bb-generated VKs.
(cd circuits && nargo compile)
scripts/generate-verifiers.sh

# Compile contracts.
forge build

# Off-chain unit + integration tests (mock proofs, in-memory blob / RI).
cargo test

# Real anvil + EIP-4844 + on-chain PetitionRegistry. Uses MockProofBackend
# + Mock*Verifier on chain by default so a developer can iterate without
# paying real bb proving time. Set `USE_MOCK_VERIFIER=false` to opt in.
cargo test --test golden_path
```

The mock golden-path runs the full lifecycle in-process. The anvil golden-path spawns anvil with the cancun hardfork, deploys `PetitionRegistry` + the mock verifiers via `forge script`, publishes a real EIP-4844 blob transaction, and asserts `blobhash(0)` binding succeeds on chain.

## Cryptographic assumptions

- **UltraHonk SNARK** (Aztec Barretenberg) over BN254 KZG; recursive verification. The signer circuit is compiled with `bb --verifier_target noir-recursive` so the batch circuit can `verify_honk_proof_zk` it in-circuit (`bb_proof_verification` v5.0.0-nightly.20260324). Outer batch + resolution circuits emit EVM Honk verifiers via `bb write_solidity_verifier -t evm`.
- **BLS12-381 KZG (EIP-4844)** for blob payload commitments. `EIP4844BlobCarrier` calls `c-kzg::ethereum_kzg_settings()` for the canonical mainnet trusted setup, builds an alloy `BlobTransactionSidecar`, and the relayer submits a real EIP-4844 blob transaction; on-chain `PetitionRegistry.publishBatch` reads `blobhash(0)` and binds it into the batch SNARK's public inputs.
- **Forward-Secure Ratchet (Bellare-Yee 2003)** instantiated by the Poseidon1 sponge as a length-doubling PRG.
- **Caterpillar Merkle frontier (Szydlo)** for log-space Merkle traversal at depth 24.
- **Keccak-256** for `petition_id` derivation. The top byte is masked to keep the identifier under the BN254 scalar modulus (no silent reduction between the on-chain `bytes32` and the SNARK's `Fr` public input).

## Threat model summary

Adversary:
- Indefinite passive observation of L1 + the blob retention window + voluntary blob archives.
- Compelled key disclosure for Organiser / Relayer / Resolver / Disputant / archiver.
- Compelled key disclosure or device compromise for a signer (yielding `(identity_secret, attr_vector, RI Merkle path, s_curr, t, caterpillar, chain_root)`).
- Cross-petition correlation across every observable, including predicate-match intersections.
- Sybil enrolment of multiple RI identities.

Honest-party assumptions:
- Poseidon1 sponge security and UltraHonk soundness.
- EIP-4844 blob commitment binding.
- L1 censorship-resistant inclusion and finality.
- Permissionless Relayer entry such that signers can resubmit on Relayer-side censorship.
- Sybil resistance from RI.

Out of scope:
- Network-transport anonymity beyond what Tor or an equivalent provides.
- Real-time device compromise before the chain advances past `s_slot`.
- Forensic recovery of overwritten storage on commodity media without `TRIM`.

## Known limitations and shortcuts (PoC scope)

| Concern | Mitigation / Production Path |
|---------|------------------------------|
| `BATCH_SIZE_MAX = 6` in the PoC batch circuit (SPEC value: 100). The recursive verifier inflates the constraint count linearly in `BATCH_SIZE_MAX`; the PoC cap keeps `nargo compile` + `bb prove` tractable on a developer laptop. | Production rebuilds the batch circuit with `BATCH_SIZE_MAX = 100`. The recursion API and the Solidity verifier ABI stay unchanged. |
| `InMemoryRi` is an in-process `lean_imt`-backed Poseidon1 Merkle tree; root age is tracked by block number only. | The RI port maps directly onto the [resilient-private-identity](../../private-identity/resilient-private-identity/) PoC's on-chain `IdentityTree`. |
| `petition_id` is masked to fit in the BN254 scalar field (top byte zeroed) so the on-chain `bytes32` and the SNARK's `Fr` public input agree bit-for-bit. SPEC defines it as a full `keccak256` output. | Either keep the mask convention in production (loses 8 bits of identifier entropy: still 248 bits, far above any collision concern) or split the storage into a separate `Fr`-typed `snark_petition_id` derived from the full `keccak256`. |
| FSRT depth at runtime defaults to a SPEC-mandated `2^24`; the runtime API accepts an override (`chain_len`) so tests use a shallow tree. | The spec-mandated depth must be used in production. The eager-expansion design materializes all `v_i` in RAM during enrollment; production deployments retain only the caterpillar frontier and recompute `v_slot` on demand. |
| The `anvil` golden-path test deploys mock Honk verifiers (`Mock{Batch,Resolution}Verifier`) by default so iteration time stays in seconds. The real Honk verifiers emitted by `scripts/generate-verifiers.sh` accept the bb-generated proofs but require multi-minute prover time per batch on commodity hardware. | Real BB proving is wired through `BBProver` (see `src/adapters/bb_prover.rs`) and is opt-in via `USE_MOCK_VERIFIER=false` in the deploy script. |

## References

- [SPEC.md](./SPEC.md): full protocol specification.
- [Resilient Civic Participation use case](https://github.com/ethsystems/map/blob/master/use-cases/resilient-civic-participation.md) (ethsystems/map).
- [Civic Participation approach](https://github.com/ethsystems/map/blob/master/approaches/approach-civic-participation.md) (ethsystems/map).
- [ResilientIdentity SPEC](../../private-identity/resilient-private-identity/SPEC.md): the credential layer this PoC composes with.

# Shielded Pool Extension: PIR + Epoch Nullifiers

Extension of the [shielded-pool](../shielded-pool/) private-payments construction with:

- PIR over the wallet's pre-spend tree reads, closing the state-read privacy leak at the indexer/RPC layer.
- Epoch-based nullifiers with a per-note recursive chain proof (IVC), bounding the on-chain nullifier set without imposing linear per-spend work as notes age.

The note format, deposit, and attestation flows of the parent are preserved. The commitment is extended to bind `epoch_created` so the on-chain verifier can enforce that a spend's chain proof covers the note's full lifetime.

## Status

Implemented end-to-end as a research PoC: the extended circuits, the two-proof spend contract, the off-chain stack (state replica, bb prover, SimplePIR commitment-path read, light-client storage-proof verifier), and self-contained on-chain integration tests covering both spend flows — transfer (k=2 insertion) and withdraw (k=1 insertion). See "Implementation shortcuts" below for the deliberate spec-vs-impl divergences. The protocol is proof-system agnostic; see [SPEC.md](./SPEC.md) for the abstract requirements an implementation must meet. This folder is a self-contained PoC (no cross-PoC imports from `../shielded-pool/`); any source mirrored from the parent is duplicated locally per the repo's PoC-independence rule.

## Layout

```
shielded-pool-extension/
├── SPEC.md                 protocol specification (primary deliverable)
├── README.md               this file
├── Cargo.toml              wallet / off-chain Rust workspace
├── Nargo.toml              Noir circuit workspace
├── foundry.toml            Solidity build config
├── circuits/
│   ├── deposit/            extended deposit circuit
│   ├── transfer/           extended spend circuit (recursive chain-proof verify)
│   ├── withdraw/           extended spend circuit (recursive chain-proof verify)
│   └── chain_update/       new IVC chain-update circuit
├── contracts/
│   ├── src/                ShieldedPoolExt, interfaces, verifiers
│   ├── script/             deploy scripts
│   └── test/               forge tests
├── scripts/
│   └── generate-verifiers.sh
└── src/lib/                Rust wallet, PIR client, prover/channel adapters
```

## Prerequisites

- [Foundry](https://getfoundry.sh/introduction/installation)
- [Nargo](https://noir-lang.org/docs/getting_started/noir_installation) **1.0.0** — the chain-update recursion (`bb_proof_verification`) requires it; install with `noirup -v 1.0.0`
- [Barretenberg (`bb`)](https://barretenberg.aztec.network/docs/getting_started) **6.0.0** — install with `bbup -v 6.0.0`
- Rust toolchain (pinned via `rust-toolchain.toml`)

## Installation

```bash
cd pocs/private-payment/shielded-pool-extension
forge soldeer install
cp .env.example .env
```

## Build & Test

```bash
# Contracts
forge build
forge test

# Circuits
nargo compile --workspace
nargo test --workspace

# Wallet
cargo test --lib

# Regenerate Solidity verifiers after circuit changes
chmod +x scripts/generate-verifiers.sh
./scripts/generate-verifiers.sh
```

## Documents

- [SPEC.md](./SPEC.md) — protocol specification
- Parent SPEC: [`../shielded-pool/SPEC.md`](../shielded-pool/SPEC.md)
- Parent REQUIREMENTS: [`../REQUIREMENTS.md`](../REQUIREMENTS.md)

## Implementation shortcuts

[SPEC.md](./SPEC.md) describes the full protocol, including the parent's KYC attestation registry and flows (unchanged by this extension). Where this PoC's implementation deliberately diverges from the spec, it is noted here:

- **KYC attestation is not enforced in the deposit circuit.** This extension *composes with* the parent [shielded-pool](../shielded-pool/) rather than replacing it: it layers the PIR commitment-path read and epoch-nullifier machinery on top of the parent's flows. The deposit here proves commitment well-formedness and the new `epoch_created` binding, but does not re-verify KYC attestation membership — that check is orthogonal to the mechanisms this extension demonstrates and is fully enforced in the parent's deposit circuit.

- **No on-chain nullifier-uniqueness check (differs from the parent contract).** The parent rejected identical/spent nullifiers with an explicit mapping and `IdenticalNullifiers` guard. This extension keeps no on-chain nullifier set: active-epoch double-spend and in-tx duplicate η are caught inside the insertion proof's sorted-low-leaf step (SPEC "On-Chain State"), so the contract only pins the two proofs to one shared η list.

- **SimplePIR stands in for the SPEC's InsPIRe.** The SPEC specifies InsPIRe (single-server PIR with *silent* preprocessing). Its only Rust implementation (Google's `private-membership`) is an Ubuntu/AVX-512 benchmark CLI over synthetic databases, not a portable library, so the commitment-path read uses the published `simplepir` crate. SimplePIR gives the same index privacy (the server never learns the queried leaf) but is **not** silent — the client keeps a per-database hint from the offline `setup`. InsPIRe's hint-free profile is the documented production target.

- **The light-client check ships the verifier, not the light client.** `adapters/light_client.rs` verifies a contract storage slot against a state root via the SPEC's two-level MPT proof (`verify_account_storage`), behind the `RootVerifier` port. In production a Helios light client supplies the **consensus-verified** `state_root` (a `HeliosRootVerifier`); that isn't wired here because Helios needs a beacon chain the in-process `anvil` e2e lacks, so the test trusts an anvil block's `stateRoot`. Other root reads remain over plain RPC pending that wiring.

## Security disclaimer

Research prototype, not production-ready. Cryptographic assumptions are documented in [SPEC.md](./SPEC.md); implementation shortcuts are listed above.

# Plasma Private Payments

> **Status:** Complete
> **Privacy Primitive:** Confidential transfers via stateless ZK-rollup

## Overview

Demonstrates private institutional payments using [Intmax2](https://eprint.iacr.org/2025/021), a stateless ZK-rollup where transaction details don't appear on-chain. The PoC scaffolds the full Intmax2 service stack (block builder, validity prover, store vault, balance prover, withdrawal server) and runs an end-to-end flow: Alice deposits ETH, Bob deposits ETH, Alice transfers privately to Bob on L2, Bob withdraws to L1.

Privacy is achieved architecturally: the rollup contract stores only block commitments (Merkle roots of salted transaction hashes) and aggregated BLS signatures. Aggregators are stateless and never see transaction contents. Users maintain their own balance proofs client-side via recursive ZK proofs (Plonky2).

See [SPEC.md](./SPEC.md) for the full protocol specification.

## Cryptographic Assumptions

- **Primitives used:** BLS signature aggregation, Plonky2 recursive ZK proofs (FRI-based), Poseidon hash, sparse Merkle trees
- **Security assumptions:** Hardness of the discrete logarithm problem over BN254; collision resistance of Poseidon; binding property of the authenticated dictionary (sparse Merkle tree)
- **Trusted setup:** None. Plonky2 uses FRI (transparent, no trusted setup).

## Threat Model

What this protects against:

- Public observers cannot learn transaction amounts, recipients, or payment patterns (only block commitments and sender lists are on-chain)
- Aggregators cannot learn transaction contents (they receive only salted hashes)
- Recipients learn only their specific transaction, not the sender's balance or other transactions

What this does NOT protect against:

- Network-level timing correlation (IP/request timing to aggregator)
- Compromised spending key (enables unauthorized transfers)
- Compromised viewing key (reveals full transaction history, but not spending authority)

## Prerequisites

- [Nightly Rust](https://www.rust-lang.org/tools/install)
- [Docker](https://docs.docker.com/get-docker/) (for testcontainers: PostgreSQL + Redis)
- [Foundry](https://book.getfoundry.sh/getting-started/installation) (for Anvil local EVM)

## Building

```bash
cargo check
```

## Running

> Ensure that the docker engine / equivalent container runtime is running. See instructions [here](https://docs.docker.com/engine/daemon/troubleshoot/) to check.

```bash
cargo test --release -- --nocapture
```

`--release` is recommended for faster proof generation

## Known Limitations

- **Attestation registry not deployed:** The SPEC requires attestation-gated deposits (KYC verification via ZK proof of inclusion in an on-chain attestation tree). The current implementation does not deploy an AML permitter contract, but the mechanism is compatible and will work when integrated. See [AttestationRegistry](pocs/private-payment/shielded-pool/contracts/src/AttestationRegistry.sol) for a compatible implementation.
- **Single Anvil for L1+L2:** Deposit relay is simulated via a test Scroll Messenger contract rather than real cross-chain messaging.
- **Single block builder:** Only one block builder is registered; production would use multiple builders with stake and heartbeat monitoring.

## Upcoming work: PlasmaBlind

[PlasmaBlind](https://pse.dev/mastermap/ptr) is another approach of stateless plasma ZK-rollups using [folding schemes](https://github.com/lurk-lab/awesome-folding). It is under active R&D by PSE and has not been audited.

- **Research:** <https://pse.dev/mastermap/ptr>
- **Engineering:** <https://pse.dev/mastermap/pte>
- **Library:** PlasmaBlind uses [Sonobe](https://sonobe.pse.dev/), a modular folding schemes library.
- **Implementation:** https://github.com/winderica/plasma-blind

Folding-based (IVC based recursion) proving may offer efficiency advantages over traditional recursive SNARKs for the balance proof pipeline, making it a promising direction for future iterations of the stateless plasma approach.

## References

- [Intmax2: A ZK-rollup with Minimal Onchain Data and Computation Costs](https://eprint.iacr.org/2025/021)
- [EthSystems Map: Private Payments Use Case](https://github.com/ethsystems/map/blob/master/use-cases/private-payments.md)
- [EthSystems Map: Private Payments Approach](https://github.com/ethsystems/map/blob/master/approaches/approach-private-payments.md)
- [PlasmaBlind Research](https://pse.dev/mastermap/ptr)
- [PlasmaBlind Engineering](https://pse.dev/mastermap/pte)
- [Sonobe Folding Schemes Library](https://sonobe.pse.dev/)

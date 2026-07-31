# Private Payments

> **Status:** Complete
> **Privacy Primitive:** Confidential stablecoin transfers with regulatory compliance

## Overview

This PoC group demonstrates privacy-preserving institutional payment protocols. Institutions can deposit, transfer, and withdraw stablecoins without exposing amounts, counterparties, or transaction patterns to public observers, while maintaining auditability for regulators.

Two implementation approaches are provided, and the shielded pool approach has two research extensions building on its base construction:

| Approach           | Description                                      | Location                           |
| ------------------ | ------------------------------------------------ | ---------------------------------- |
| **Shielded Pool**  | On-chain UTXO pool with ZK proofs (Noir/Groth16) | [shielded-pool/](./shielded-pool/) |
| **Plasma (Intmax)** | Stateless ZK-rollup with off-chain transfers      | [plasma/](./plasma/)               |

| Shielded pool extension | Description | Location |
| ------------------------ | ------------ | -------- |
| **Extension: PIR + epoch nullifiers** | Adds PIR over pre-spend tree reads and epoch-based recursive nullifier chains | [shielded-pool-extension/](./shielded-pool-extension/) |
| **Extension: Compliance** | Adds attested-issuer velocity screening as an in-circuit policy, with a blocked-funds exit for lapsed or policy-blocked accounts | [shielded-pool-compliance/](./shielded-pool-compliance/) |

## Requirements

See [REQUIREMENTS.md](./REQUIREMENTS.md) for the shared requirements both approaches implement.

## Specifications

- [shielded-pool/SPEC.md](./shielded-pool/SPEC.md): Shielded pool protocol design
- [plasma/SPEC.md](./plasma/SPEC.md): Intmax2 plasma protocol design
- [shielded-pool-extension/SPEC.md](./shielded-pool-extension/SPEC.md): PIR + epoch nullifiers extension
- [shielded-pool-compliance/SPEC.md](./shielded-pool-compliance/SPEC.md): Compliance extension

## Comparison

| Aspect                | Shielded Pool                          | Plasma (Intmax)                              |
| --------------------- | -------------------------------------- | -------------------------------------------- |
| Deployment            | Ethereum L1                            | L2 rollup (posts roots to L1)                |
| State model           | UTXO (commitments, nullifiers)         | UTXO (client-side balance trees)             |
| Privacy mechanism     | ZK proofs per transaction              | ZK proofs per transaction                    |
| Proving system        | Groth16 via Noir/Barretenberg          | Plonky2 (recursive, transparent)             |
| Trusted setup         | Yes (circuit-specific)                 | None                                         |
| Operator required     | No, but compliance authority required  | Yes (block builder, validity prover)         |
| Gas cost per transfer | ~2.6M (user pays directly)             | Off-chain (operator posts batched roots)     |
| Proof generation      | Sub-second, client-side                | Multi-second, mix of client-side + server-side |
| Regulatory access     | Per-note viewing keys                  | Dual-key (viewing key for audits)            |
| Client requirements   | Wallet with local proving              | SDK with network calls to operator services  |

## Benchmarks

See [BENCHMARK.md](./BENCHMARK.md) for gas costs, proof generation latency, and an interpretation of the results.

## Quick Start

### Shielded Pool

```bash
cd shielded-pool

# Install Solidity dependencies
forge soldeer install

# Build and test contracts
forge build && forge test

# Build and test circuits
nargo compile --workspace && nargo test --workspace
```

See [shielded-pool/README.md](./shielded-pool/README.md) for E2E test instructions and deployment configuration.

### Plasma (Intmax)

```bash
cd plasma

# Build
cargo check

# Run integration test (requires Docker + Anvil)
cargo test --release -- --nocapture
```

See [plasma/README.md](./plasma/README.md) for prerequisites and known limitations.

## Known Limitations

See each approach's README for specific limitations:

- [shielded-pool/README.md](./shielded-pool/README.md)
- [plasma/README.md](./plasma/README.md)
- [shielded-pool-extension/README.md](./shielded-pool-extension/README.md)
- [shielded-pool-compliance/README.md](./shielded-pool-compliance/README.md)

## References

- [EthSystems Map: Private Payments Use Case](https://github.com/ethsystems/map/blob/master/use-cases/private-payments.md)
- [EthSystems Map: Private Payments Approach](https://github.com/ethsystems/map/blob/master/approaches/approach-private-payments.md)
- [Intmax2: A ZK-rollup with Minimal Onchain Data and Computation Costs](https://eprint.iacr.org/2025/021)

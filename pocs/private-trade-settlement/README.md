# Private Trade Settlement

> **Status:** Draft
> **Privacy Primitive:** Confidential atomic delivery-versus-payment (DvP) for tokenized securities

## Overview

This PoC demonstrates privacy-preserving atomic trade settlement between institutional counterparties. The goal is to enable tokenized asset swaps (e.g., bond tokens for stablecoins) where trade details—amounts, prices, and counterparty identities—remain confidential from public observers while maintaining regulatory auditability.

Implementation approaches:

| Approach     | Description                                      | Location               |
| ------------ | ------------------------------------------------ | ---------------------- |
| **TEE Swap** | Atomic DvP inside a Trusted Execution Environment | [tee_swap/](./tee_swap/) |

## Requirements

See [REQUIREMENTS.md](./REQUIREMENTS.md) for the shared requirements all approaches implement.

## Specifications

- [tee_swap/SPEC.md](./tee_swap/SPEC.md) — TEE-based atomic swap protocol design

## Known Limitations

See each approach's README for specific limitations:

- [tee_swap/README.md](./tee_swap/README.md)

## References

- [Private Trade Settlement Use Case (ethsystems/map)](https://github.com/ethsystems/map/blob/master/use-cases/private-trade-settlement.md)
- [Private Trade Settlement Approach (ethsystems/map)](https://github.com/ethsystems/map/blob/master/approaches/approach-private-trade-settlement.md)

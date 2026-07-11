# Private Identity

> **Status:** Complete
> **Privacy Primitive:** Anonymous credentials verifiable on Ethereum

## Overview

This set of PoCs explores privacy-preserving access control on Ethereum. The shared goal is to gate access to on-chain resources based on verified properties of the caller without exposing who the caller is, what credentials they hold, or which issuer credentialed them. Verifiers learn only a boolean result and a scope-bound nullifier that prevents replay within a given context.

Each approach tackles a different aspect of the problem space (issuer resilience, multi-source identity, selective disclosure, etc.) under the same set of shared requirements.

Implementation approaches:

| Approach                       | Description                                                                                | Location                                                     |
| ------------------------------ | ------------------------------------------------------------------------------------------ | ------------------------------------------------------------ |
| **Resilient Private Identity** | Anonymous credentials with issuer-independent verification via vOPRF and Merkle membership | [resilient-private-identity/](./resilient-private-identity/) |

## Requirements

See [REQUIREMENTS.md](./REQUIREMENTS.md) for the shared requirements all approaches implement.

## Specifications

- [resilient-private-identity/SPEC.md](./resilient-private-identity/SPEC.md) - Resilient Private Identity protocol design

## Known Limitations

See each approach's README for specific limitations:

- [resilient-private-identity/README.md](./resilient-private-identity/README.md)

## References

- [Private Identity Use Case (ethsystems/map)](https://github.com/ethsystems/map/blob/master/use-cases/private-identity.md)
- [Resilient Identity Continuity Use Case (ethsystems/map)](https://github.com/ethsystems/map/blob/master/use-cases/resilient-identity-continuity.md)
- [Private Identity Approach (ethsystems/map)](https://github.com/ethsystems/map/blob/master/approaches/approach-private-identity.md)

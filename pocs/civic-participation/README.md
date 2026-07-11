# Civic Participation

> **Status:** Draft
> **Privacy Primitive:** Privacy-preserving civic participation

## Overview

This PoC collects approaches for privacy-preserving civic participation: credentialed petitions, ballots, organising lists, and similar processes where eligibility must be checkable but signer identity, evidence of eligibility, and cross-process linkage must remain hidden.

Implementation approaches:

| Approach | Description | Location |
| -------- | ----------- | -------- |
| **Resilient Civic Participation** | Forward-secure ratcheting, blob-anchored signature batches, on-chain resolution SNARK | [resilient-civic-participation/](./resilient-civic-participation/) |

## Requirements

See [REQUIREMENTS.md](./REQUIREMENTS.md) for the shared requirements all approaches implement.

## Specifications

- [resilient-civic-participation/SPEC.md](./resilient-civic-participation/SPEC.md): Resilient Civic Participation protocol design

## Known Limitations

See each approach's README for specific limitations:

- [resilient-civic-participation/README.md](./resilient-civic-participation/README.md)

## References

- [Resilient Civic Participation Use Case (ethsystems/map)](https://github.com/ethsystems/map/blob/master/use-cases/resilient-civic-participation.md)
- [Civic Participation Approach (ethsystems/map)](https://github.com/ethsystems/map/blob/master/approaches/approach-civic-participation.md)

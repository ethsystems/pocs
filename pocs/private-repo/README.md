# Private Repo

> **Status:** Draft
> **Privacy Primitive:** Confidential collateralized intraday credit between banks, proven by each bank and settled on Ethereum

## Overview

This PoC group studies confidential secured lending between banks on Ethereum. A borrower locks collateral to a lender for a term. The lender's cash settles against that lock. Counterparties and amounts stay hidden from the public and from the sequencer that orders transactions.

The first approach, EEZ member, is a general way to connect an existing system to the Ethereum Economic Zone (EEZ): each operation becomes a proven leg under a pluggable rule, and repo is the first rule it implements.

What it aims to show:
- Members of an interbank network can settle on Ethereum without running a private chain. Each bank proves its own transactions. The sequencer orders them into batches. Ethereum verifies one proof per batch.
- The lender claims the collateral after a missed deadline without the borrower's secret.

What it doesn't show:
- The items [REQUIREMENTS.md](./REQUIREMENTS.md) puts out of scope, such as tri-party repo and collateral substitution.

| PoC | Description | Location |
| --- | --- | --- |
| **EEZ member** | Intraday credit lines between banks, in GBP and EUR settlement tokens against collateral notes. Each bank proves its own legs. The sequencer aggregates them into one proof per batch, which Ethereum verifies through the Ethereum Economic Zone (EEZ). | Planned |

## Requirements

See [REQUIREMENTS.md](./REQUIREMENTS.md) for the shared requirements.

## Specifications

- `eez-member/SPEC.md`: EEZ member protocol design (planned)

## Cryptographic Assumptions

TBD 

## Threat Model

TBD

## Known Limitations

TBD

## References

- [Private Repo Use Case (ethsystems/map)](https://github.com/ethsystems/map/blob/master/use-cases/private-repo.md)
- [Private Trade Settlement Approach (ethsystems/map)](https://github.com/ethsystems/map/blob/master/approaches/approach-private-trade-settlement.md)

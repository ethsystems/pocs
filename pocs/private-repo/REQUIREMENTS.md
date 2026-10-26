---
title: "Private Repo Requirements"
use_cases:
  - "https://github.com/ethsystems/map/blob/master/use-cases/private-repo.md"
approach: "https://github.com/ethsystems/map/blob/master/approaches/approach-private-trade-settlement.md"
---

# Private Repo Requirements

## 1. Core Problem

> From [Private Repo](https://github.com/ethsystems/map/blob/master/use-cases/private-repo.md): "Tokenized repurchase agreements where counterparties and transaction amounts must remain confidential."

Repo is short-term secured lending. On a public ledger, a repo shows a bank's funding dependencies and credit relationships. A competitor can use the dependencies to target the bank's funding sources. The credit relationships also show a perceived weakness for the competitor to exploit.

Visible funding costs let a competitor undercut the bank's pricing. From a visible rollover pattern, the competitor can front-run the bank's next funding need.

The use case names banks, clearing houses, prime brokers, money market funds, central banks and regulators as its actors.

## 2. Functional Requirements (MUST)

- **Opening**:
  - Opening exchanges the lender's cash for a lock on the borrower's collateral, held for the term of the repo.
  - An eligibility check runs on the collateral with its details hidden.
  - A haircut applies to the collateral's value.

- **Repayment**:
  - Repayment releases the collateral against the cash at the agreed rate.
  - After a missed repayment, the lender claims the collateral without the borrower's secret.
  - Settlement conditions and timeouts are deterministic, with a defined outcome for each failure.

- **Access Control**:
  - Participation composes with existing custody and KYC workflows.

## 3. Privacy Requirements (MUST)

- **Confidential Data**: counterparty identities, transaction amounts, collateral details, rates obtained, funding frequency and rollover patterns. The public, the sequencer and participants outside the trade cannot learn them from the data they receive. The sequencer is the party that orders transactions into batches. Each SPEC under `pocs/private-repo/` gives a table of what each party sees.

- **Public Data**: aggregate market statistics, general market rates and reference rates such as SOFR and repo indices.

- **Regulatory Oversight**:
  - Regulator access covers systemic risk monitoring, counterparty exposure aggregation, collateral sufficiency, rate surveillance and market manipulation monitoring.
  - A disclosure covers one jurisdiction for a set period.
  - Each disclosure grant is logged and revocable. Revocation stops later releases and leaves earlier ones disclosed.

- **Anonymity set**: each SPEC under `pocs/private-repo/` names who is in its anonymity set and what determines its size. The [Private Trade Settlement](https://github.com/ethsystems/map/blob/master/approaches/approach-private-trade-settlement.md) approach bounds that set by the number of institutional participants.

- **Public tokens**: each move between private holdings and public tokens appears in the SPEC with what it exposes.

## 4. Security Requirements (MUST)

- **Atomicity**: a failed opening or repayment reverts the cash leg together with the collateral leg.
- **Conservation**: each settlement conserves value in each asset class.
- **Double-spend protection**: cash and collateral can each be spent at most once.
- **Front-running**: funding needs stay hidden until settlement.
- **Censorship**: a participant censored by the sequencer can settle directly on chain. Its address is then linked to that settlement. A borrower censored by the sequencer can still repay by the deadline this way. The lender's claim opens only after such a repay has had time to settle.

## 5. Operational Requirements (MUST)

- **Finality**: settlement on the trade date, often intraday.
- **Pricing**: collateral is valued at a price no older than a set maximum age at settlement. Each SPEC names the price publisher and what fetching a price reveals.

## 6. Out of Scope (PoC)

- Tri-party repo.
- Netting and novation for clearing.
- Collateral substitution.
- Margin calls during the term.
- Title transfer and reuse of the collateral during the term. The PoC models a pledge: the collateral stays locked until repayment or claim.
- Close-out netting after a default. The lender claims the whole collateral, and the master agreement between the two parties settles any difference.
- Cross-network settlement. The cash leg and the collateral leg settle on one network.
- Network-level metadata. The sequencer can link a transaction to the connection it arrives on. A participant hides that by sending through a relay.

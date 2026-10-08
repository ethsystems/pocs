---
title: "Private Money Market Fund Requirements"
use_cases:
  - "https://github.com/ethsystems/map/blob/master/use-cases/private-money-market-funds.md"
approach: "https://github.com/ethsystems/map/blob/master/approaches/approach-private-money-market-funds.md"
---

# Private Money Market Fund Requirements

## 1. Core Problem

Tokenized money market fund (MMF) shares on Ethereum run as allowlist-gated tokens on a permissioned compliance rail (for example DS Protocol or ERC-3643). Holdings, subscriptions, redemptions and yield distributions are public. For institutional holders that reveals treasury positions, liquidity moves and yield strategies to competitors.

Confidentiality can't be added on top of that rail. The rail itself reads public state: the registry's wallet-to-investor-to-country mapping, a per-transfer investor lookup, and investor counters. Holder sets are also small and concentrated, so a large movement can identify its owner even when amounts are hidden.

> From [Private Money Market Funds](https://github.com/ethsystems/map/blob/master/use-cases/private-money-market-funds.md): institutions prefer MMFs over non-yield stablecoins for treasury management, but require privacy for position sizes and yield strategies.

This PoC group maps the trade-offs between unlinkability and interoperability across configurations; it doesn't enforce every property at once. The requirements below are of two kinds:
- **hard invariants**, which every configuration MUST keep (section 4)
- **properties evaluated per configuration**, with no fixed target: the PoC reports where each configuration lands, so configurations can be compared. These are privacy level, interoperability per party, cost and operational burden.

## 2. Functional Requirements (MUST)

Organized by lifecycle phase, for two fund profiles: a **fund paying yield as a monthly dividend mint**, and a **fund reinvesting income daily**. Both keep a **stable USD 1 NAV**, with shares as integers at 6 decimals. The yield mechanism is a configuration parameter.

### 2.1 Eligibility and onboarding

- The transfer agent, or its KYC provider, verifies eligibility off-chain (KYC and AML, investor qualification, jurisdiction) and attests the holder's key. The transfer agent maps keys to pseudonymous investor IDs off-chain.
- Holders prove eligibility in zero knowledge, against an attestation tree, without revealing which attestation is theirs. There's no public wallet-to-investor mapping.
- Attestations expire, so revocation takes effect as a lapse.
- One investor may hold several positions or wallets; it counts once.

### 2.2 Subscription (issuance into positions)

- Shares reach the investor's confidential position without the investor ever holding a public balance, so no individual public deposit followed by a shielding step reveals the subscription. Aggregate issuance by the transfer agent may be public. Opted-out holders receive public balances, as today.
- Settles atomically against an on-chain cash leg, or after the transfer agent confirms off-chain cash. A public cash leg reveals amount, timing and payer, so atomic settlement stays private only with a confidential cash leg; configurations with a public one are evaluated for that leak.
- Investor counters and jurisdiction caps are checked on every new investor.

### 2.3 Transfer

- Confidential transfers between eligible holders, where the fund allows peer-to-peer transfers. Amounts and counterparties are hidden.
- Eligibility and locks are enforced inside the circuit, so a non-compliant transfer has no valid proof. Caps are never exceeded (section 4.4).
- Transfer restrictions that depend on both parties, for example between jurisdictions or investor classes, are configuration-dependent; each configuration states whether it supports them.

### 2.4 Yield distribution

- The yield mode is configurable: a **periodic mint into each position** (cadence as a parameter, for example monthly or daily), or a **multiplier** over share-denominated positions.
- Per-position amounts are never public; the rounding direction and the treatment of the remainder are specified.
- Yield accrues to locked positions too.

### 2.5 Redemption

- The holder redeems against an on-chain cash leg atomically (shares burned, cash paid), or off-chain through the transfer agent. A public cash leg reveals amount, timing and payee, so atomic settlement stays private only with a confidential cash leg; configurations with a public one are evaluated for that leak.
- Where the regime applies liquidity fees, they're computed from aggregate flows.

### 2.6 Locks, freeze and seizure

- Positions support locks, each recording its reason and who may release or claim it. Freeze, seizure (forced transfer by the transfer agent under authority) and holding periods are all locks.

### 2.7 Public and confidential holdings

- Holders are confidential by default and may opt out. They can move between the two, and each crossing's leakage of amount and timing is evaluated.
- Integrators that need public balances (reserve holders, autonomous contracts) keep working unchanged on the public side.

## 3. Privacy Requirements (MUST)

### 3.1 Confidential data

Hidden from public observers and other holders:

- individual positions
- subscription and redemption amounts and timing
- accrued yield per position
- links between a holder's positions and wallets, within the confidential set

### 3.2 Public data

- NAV per share, as published by the fund
- total shares outstanding and other aggregates, which reveal no individual confidential flow: they change only in batches at the fund's cadence, with yield, or with crossings, which are public
- transaction existence, and the compliance configuration (rules, trusted issuers)
- positions of holders who opt out

### 3.3 Participation

Privacy by default. Holders that must stay public (for example reserve holders, or autonomous contracts that can't hold secrets) opt out. Public and confidential holdings coexist in one fund, and what each crossing between them leaks is evaluated.

### 3.4 Unlinkability target

The target is full unlinkability within the confidential set. The level reached is evaluated per configuration (section 1), because it depends on parameters a design doesn't fully control, such as the size of the set and how concentrated its holders are. Each configuration MUST describe its confidential set, meaning who is in it and what determines its size (for example, the attested owners of one fund), and what its design links, for example a signature checked outside the circuit (5.4). The linkability simulation reports linkability as a function of set size and holder concentration; whether a given level is acceptable is for the fund and its regulators to decide.

### 3.5 Personal data

None on-chain, even encrypted, since data-protection rules such as GDPR conflict with an immutable ledger. The register feed carries pseudonymous owner keys, which the transfer agent maps to investor IDs off-chain; personal data stays off-chain with the transfer agent.

### 3.6 Register and regulatory access

- **Transfer agent:** a standing register feed, enough to rebuild the register of record for any date (eligibility, holder counts, sanctions screening, tax), without holder cooperation. How much the feed carries beyond ownership is evaluated.
- **Regulators and auditors:** scoped, logged disclosure under a mandate, through the transfer agent's register, viewing keys or predicate proofs.
- **Holders:** predicate proofs over their own position (for example "value ≥ X"), and disclosure scoped to a named party.

### 3.7 Who sees what

| Data | Public | Transfer agent | Regulator | Custodian | Named party |
|---|---|---|---|---|---|
| Position size | — | ✓ | under mandate | own clients | if disclosed |
| Subscription and redemption amounts and timing | aggregate, at cadence | ✓ | under mandate | own clients | if disclosed |
| Accrued yield per position | only the fund's yield rate | ✓ | under mandate | own clients | if disclosed |
| Holder identity (personal data) | — | ✓ (off-chain) | under mandate | own clients | — |
| Wallet ↔ investor link | — | ✓ | under mandate | own clients | — |
| Eligibility and jurisdiction | "an eligible holder" only | ✓ | under mandate | own clients | predicate only |
| NAV and total shares | ✓ | ✓ | ✓ | ✓ | ✓ |
| Per-transaction supply change | — | ✓ | under mandate | — | — |
| Investor counts per category | — | ✓ | ✓ | — | — |

Notes on the table:
- Other holders see the same as the public, plus their own positions.
- A *named party* is anyone a holder chooses to disclose to, such as a lender, the holder's auditor or a trading venue. It learns only what the holder releases, through a scoped disclosure or a predicate proof.
- Per-transaction supply changes stay hidden only while total supply is published at cadence. A configuration that updates it on every issuance or redemption reveals each one's size.
- Investor counts are enforced (section 4.4) and not published by default. A fund may choose to publish them as aggregates at its cadence, at the cost of revealing membership changes in small funds.

## 4. Security Requirements (MUST)

Hard invariants: every configuration MUST keep these.

### 4.1 Conservation

Total shares outstanding equal public balances plus confidential positions, counting each share once, at every checkpoint. Shares appear only through issuance and disappear only through redemption. Where confidential positions are held through a pool that is itself a public holder (omnibus), the pool's balance is their backing, and conservation becomes solvency: confidential positions, valued at the multiplier, never exceed the pool's balance. Under the multiplier yield mode, conservation holds in internal units; the legal share count is internal units × the multiplier, and each multiplier update counts as that period's issuance.

### 4.2 Double-spend protection

Each nullifier is consumed at most once, and nullifiers don't link a holder's operations to each other.

### 4.3 Eligibility

No confidential position exists without a verified eligibility proof. Public holders stay registry-checked. Attestation expiry takes effect on the first operation after it, so revocation takes effect at the latest when the attestation expires. Each configuration states its maximum attestation lifetime, which bounds the revocation delay. Faster action against a specific holder uses a freeze (2.6).

### 4.4 Investor counters and jurisdiction caps

Counters and caps are never exceeded across public and confidential holders. A holder with several wallets counts once. Each configuration states where they're enforced. Counting an investor once needs state per investor; where that state is on-chain or in-circuit, it MUST NOT link the investor's wallets (3.1). Enforcement by the transfer agent at attestation keeps it off-chain.

### 4.5 Yield conservation

Per-position accrual plus the accounted rounding remainder equals the yield credited. The rounding direction is specified.

### 4.6 Register restorability

The register is rebuildable for any point in time from the feed plus the public ledger, without holder-side secrets. A correction leaves the superseded state restorable.

### 4.7 Locks

A locked position moves only through its release or claim path. Freeze and seizure are locks. Yield keeps accruing to locked positions.

### 4.8 Access control

Only the owner, or the transfer agent's claim path, can spend a position. The claim path implements freeze, seizure and a lock's claim party. Duties are separated: the transfer agent issues, burns and claims; holders transfer and redeem. Administrative actions are logged.

### 4.9 Cryptographic integrity

Every state transition is verified on-chain, and proofs use a zero-knowledge proving mode. A non-zero-knowledge mode commits to the witness and voids the confidentiality claims.

### 4.10 Register-feed binding

The register ciphertext is bound in-circuit to the committed values; otherwise the configuration states that completeness rests on a legal obligation.

## 5. Operational Requirements (MUST)

### 5.1 Register of record

A standing register feed to the transfer agent (section 3.6), and reconciliation of on-chain state against the transfer agent's register at a defined cadence, with divergences detected. Where the on-chain ledger is part of the official record of ownership, this is stated explicitly.

### 5.2 Compliance by regime

Compliance depends on the regime, not on the yield mechanism:

- registered MMFs (for example SEC Rule 2a-7, ESMA MMFR): liquidity fees, and gates under MMFR, computed from aggregate flows
- private funds: offering rules, such as investor eligibility and investor-count limits
- in both cases, portfolio rules (liquidity minimums, diversification) apply to the fund's assets, outside the pool

### 5.3 Interoperability

Compatible at the rules and configuration layer of DS Protocol and ERC-3643 (compliance configuration, claim topics, trusted issuers, admin roles), with adapters at the execution layer. Interop cost is reported per party: the issuer's token stack, redemption contracts, reserve holders, custodians.

### 5.4 Custody

EOA control is required. Multisigs (Safe), smart accounts and autonomous contracts are analysed; contracts can't hold note secrets, so they stay public or delegate. Positions are spendable with keys held in institutional custody (sign-only HSMs, MPC): the spend credential is a standard-curve signature over a transaction plan the circuit binds to, and no secret is exported into the prover. Nullifier and viewing keys may be software-held. Where the signature is checked is left open: in-circuit keeps spends unlinkable but non-native ECDSA is costly, and the PoC benchmarks that cost; outside the circuit is cheap, but the key links a holder's spends.

### 5.5 Key management

Custody of the register key (optionally threshold-held) and of regulator viewing keys where used, with rotation and logged access.

### 5.6 Settlement and cost

Settles on Ethereum Layer 1, with finality in minutes. Costs must be viable for daily distribution and redemption. Gas and proving time are reported per operation: subscription, redemption, transfer, yield distribution (per mint for a periodic mint, per step where a multiplier needs one), public ↔ confidential crossing, reconciliation checkpoint.

### 5.7 Migration evaluation

The PoC doesn't implement a migration; it evaluates what a deployed tokenized MMF would spend to transition: contract changes by owner, holder actions, whether reissuance is avoided (in-place upgrades must fit each stack's storage layout), and the cost of the cutover.

## 6. Out of Scope (PoC)

- Collateral and lending: locks support it, but the loan, cash leg and liquidation aren't built
- Anonymity sets shared across funds or with the cash leg: analysed on paper and in the linkability simulation
- Account-model (FHE) and TEE configurations: analysed on paper
- Cross-chain and Layer 2 deployments
- Floating-NAV funds (entry-NAV cohorts, price-per-share yield)
- Portfolio-side compliance (liquidity minimums, diversification), which applies outside the pool
- NAV computation and asset-side attestation: the fund's portfolio is reported by its administrator or custodian, as today, and the PoC proves the share side only
- Integration with real transfer-agent systems and fiat rails: the transfer agent's register is simulated
- Production integrations with specific HSM, MPC or Safe products (the credential model is designed for them, section 5.4)
- Production key management for the register key and regulator viewing keys
- Network-layer privacy (IP and timing metadata), and private information retrieval for indexer queries
- Legal opinions on regime acceptance, for example whether a multiplier update counts as reinvestment

---
title: "Private Trade Settlement Requirements"
use_cases: 
  - "https://github.com/ethsystems/map/blob/master/use-cases/private-trade-settlement.md"
approach: "https://github.com/ethsystems/map/blob/master/approaches/approach-private-trade-settlement.md"
---

# Private Trade Settlement Requirements

## 1. Core Problem

Secondary market trading of tokenized securities on public blockchains exposes trade prices, volumes, and counterparty relationships—revealing competitive intelligence and trading strategies to observers. The system must enable atomic delivery-versus-payment (DvP) where asset and payment legs settle simultaneously, eliminating counterparty risk while keeping trade details confidential.

## 2. Functional Requirements (MUST)

- **Trade Negotiation**:
  - Support RFQ (Request for Quote) flow between counterparties
  - Counterparties agree on asset, quantity, and price off-chain or via encrypted channels
  - Both parties commit to the trade terms before settlement

- **Atomic Settlement (DvP)**:
  - Asset leg (e.g., bond token transfer) and payment leg (e.g., stablecoin transfer) execute atomically
  - Either both legs settle or neither does—no partial execution
  - Settlement must be final and irreversible once completed

- **Asset Compatibility**:
  - Support tokenized securities (ERC-20 or equivalent)
  - Support stablecoins as the payment leg (USDC, EURC)

- **Access Control**:
  - Only KYC-verified entities can participate in trades
  - Eligibility checks before settlement execution
  - KYC verification SHOULD preserve participant privacy (e.g., not reveal identity on-chain)

## 3. Privacy Requirements (MUST)

- **Confidential Data** (hidden from public observers):
  - Trade amounts and prices
  - Counterparty identities (who is trading with whom)
  - Order book / RFQ details
  - Individual position sizes

- **Public Data** (visible on-chain):
  - Transaction existence (settlement occurred)
  - Asset type (which token was involved)
  - Compliance attestation (both parties are eligible)

- **Regulatory Oversight** (SHOULD):
  - Selective disclosure mechanism for regulators to inspect specific trade details
  - Audit trail for post-trade reporting (MiFID II, SEC Rule 606 equivalent)
  - Disclosure SHOULD NOT compromise privacy of uninvolved parties

## 4. Security Requirements (MUST)

- **Atomicity**: No partial settlement—both legs or neither
- **Double-spend Protection**: Prevent reuse of committed assets during settlement
- **Front-running Prevention**: Trade details must not leak before settlement
- **No Custodial Risk**: Settlement mechanism should minimize trust in intermediaries

## 5. Operational Requirements (MUST)

- **Finality**: Settlement finality within minutes
- **Cost**: Transaction costs viable for institutional trade volumes
- **Throughput**: Support concurrent independent trades
- **Key Management**: Institutional-grade key management with rotation support

## 6. Out of Scope (PoC)

- Central limit order book (CLOB) matching
- Margin trading or derivatives
- Fiat on/off ramps
- Netting and batch settlement
- Corporate actions (dividends, splits)

---
title: "Private Bond Requirements"
use_cases: 
  - "https://github.com/ethsystems/map/blob/master/use-cases/use-case-private-bonds.md"
approach: "https://github.com/ethsystems/map/blob/master/approaches/approach-private-bonds.md"
---

# Confidential Bond Protocol Requirements

## 1. Core Problem
Institutional bonds on public blockchains need confidential amounts and positions while maintaining regulatory compliance. Crucially, the system must support Atomic Delivery-versus-Payment (DvP) for secondary market trades to eliminate counterparty risk, while accommodating traditional off-chain settlement for primary issuance.

## 2. Functional Requirements (MUST)
- **Issuance (Primary Market)**:
  - Off-Chain Settlement: Investor onboarding and initial capital subscription occur via classical fiat rails (USD/EUR wire).
  - Minting: Issuer mints bond tokens to the investor's address after off-chain payment confirmation.
  - Attributes: Maturity date, ISIN/Asset ID, Coupon details.

- **Secondary Market (Trading)**:
  - Atomic DvP: Peer-to-peer transfers must be atomic swaps (Confidential Bond ↔ Stablecoin/Payment Token).
  - Matching: Support for an RFQ (Request for Quote) flow where the Issuer or a Relayer can act as the matcher.

- **Redemption**:
  - Bonds redeemable for par value upon maturity.
  - Burn mechanism to remove retired bonds from circulation.

- **Whitelist**:
  - Only KYC verified addresses can hold or trade.
  - Registry must validate eligibility before allowing any transfer/mint.

## 3. Privacy Requirements (MUST)
- Confidential Data: Bond amounts, account balances, and trade volumes must be hidden.
- Public Data:
  - Transaction existence (tx hash).
  - Participant identities (Addresses/Legal Entities) — Dual Identity Model.
  - Timestamps.
- Regulatory Oversight:
  - Viewing Keys: Capability to grant regulators read-only access to specific transaction details.
  - Audit Trail: System must maintain an encrypted, append-only log of all state changes for post-trade compliance.

## 4. Security & Standards (MUST)
- Double-spend Protection: Cryptographic enforcement preventing reuse of spent bond notes (Nullifiers).
- Access Control: Strict separation of duties (Issuer = Admin/Mint; Investor = Trade/View).

## 5. Performance & Ops (MUST)
- Finality: On-chain settlement finality within minutes.
- Cost Efficiency: Transaction costs must be viable for daily operations.
- Key Management: Support for key rotation to align with institutional retention policies.

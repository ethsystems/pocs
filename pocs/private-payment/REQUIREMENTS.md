---
title: "Private Payment Requirements"
use_cases: 
  - "https://github.com/ethsystems/map/blob/master/use-cases/private-payments.md"
approach: "https://github.com/ethsystems/map/blob/master/approaches/approach-private-payments.md"
---

# Confidential Payment Protocol Requirements

## 1. Core Problem

Institutional payment flows on public blockchains expose treasury operations, supplier relationships, and settlement patterns—revealing competitive intelligence to observers.

> From [Private Payments](https://github.com/ethsystems/map/blob/master/use-cases/private-payments.md): The system must enable confidential stablecoin transfers while maintaining regulatory compliance and supporting high-frequency institutional operations.

## 2. Functional Requirements (MUST)

Organized by payment lifecycle. All operations require prior identity verification.

- **Entry (Public → Private)**:
  - Convert public ERC-20 stablecoins (USDC, EURC) into private balances
  - System holds public tokens while user maintains private claim
  - Entry transaction should not reveal user's total private balance

- **Private Transfer**:
  - Transfer value between private balances
  - Prove ownership and sufficient balance without revealing amount
  - Hide sender and recipient identities from public observers
  - Support medium to high-frequency operations (multiple transfers per hour)

- **Exit (Private → Public)**:
  - Convert private balances back to public ERC-20 tokens
  - Only balance owner can initiate exit
  - System releases tokens only after valid ownership proof

- **Access Control**:
  - Only KYC-verified entities can participate in any operation
  - Identity verification occurs before first entry
  - System can revoke access for compromised or sanctioned entities

## 3. Privacy Requirements (MUST)

- **Confidential Data** (hidden from public observers):
  - Payment amounts
  - Counterparty identities
  - Transaction patterns and timing correlation
  - User's total private balance

- **Public Data** (visible on-chain):
  - Transaction existence (hash/anchor)
  - System aggregate statistics (total value locked)
  - Compliance attestation status (without PII)

- **Regulatory Oversight**:
  - Selective disclosure mechanism to grant regulators/auditors access to specific transaction details
  - Audit trail sufficient for AML/CFT monitoring
  - Sanctions screening of participants
  - Disclosure does not compromise privacy of uninvolved parties

## 4. Security Requirements (MUST)

- **Double-spend Protection**: Prevent reuse of private balances
- **Unauthorized Access Prevention**: Only balance owner can spend or exit
- **Cryptographic Integrity**: All proofs and state transitions must be verifiable
- **No Trusted Party Risk**: No single party can unilaterally steal or freeze user funds
- **Stablecoin Compatibility**: Must work with standard ERC-20 tokens without requiring issuer modifications

## 5. Operational Requirements (MUST)

- **Finality**: Near real-time settlement (minutes, not hours)
- **Cost**: Transaction costs must support high-frequency institutional operations (daily treasury flows)
- **Key Management**: Support for key rotation, backup, and recovery aligned with institutional security policies
- **Graceful Degradation**: No catastrophic fund loss on partial system failure

## 6. Out of Scope (PoC)

- Traditional payment rail integration (SWIFT, ISO 20022, ACH, SEPA)
- Consumer (B2C) payment flows
- Cross-chain bridging
- Fiat on/off ramps
- Issuer-level controls (freeze, blacklist, clawback of private balances)
- Private smart contract interactions

---
title: "DIY Validium Requirements"
use_cases: 
  - "https://github.com/ethsystems/map/blob/master/use-cases/private-payments.md"
approach: "https://github.com/ethsystems/map/blob/master/approaches/approach-private-payments.md"
---

# DIY Validium Requirements

## 1. Core Problem

Financial institutions need to transact on Ethereum while keeping balances and transaction details confidential from public observers, competitors, and unauthorized parties. They also need to prove compliance to regulators without revealing sensitive data.

> Goal: Demonstrate a minimal private payment system with three core operations: transfer, bridge, and disclosure.

## 2. Functional Requirements (MUST)

### Transfer (Private Payment)

- User can transfer value to another user privately
- Transfer proof demonstrates: sender owns an account in the current state, sender has sufficient balance, state transition is correct
- Contract updates state root atomically after proof verification
- Recipient's balance is updated off-chain by operator

### Bridge (Deposit + Withdrawal)

- User can deposit ERC20 tokens to receive private balance
- Deposits are gated by allowlist membership proof
- User can withdraw private balance to receive ERC20 tokens
- Withdrawal proof demonstrates: account ownership, sufficient balance, state transition
- Total private supply equals total escrowed tokens (conservation)

### Disclosure (Compliance)

- User can prove balance >= threshold to a specific auditor
- Disclosure proof is bound to a specific auditor via disclosure key
- Disclosure is read-only (no state mutation)
- Auditor learns only that balance satisfies the threshold

### Access Control

- Only operator can update state roots
- Anyone can submit valid proofs for verification
- Sequential root check prevents double-spending (each operation changes stateRoot, invalidating stale proofs)

## 3. Privacy Requirements (MUST)

### Confidential Data (hidden from public)

- Individual account balances
- Account ownership (which pubkey has what balance)
- Transfer amounts
- Sender/recipient relationship in transfers

### Public Data (visible on-chain)

- Merkle roots (allowlist root, accounts root)
- Proof validity (pass/fail)
- Total deposited/withdrawn amounts
- Contract events and timestamps

### Regulatory Oversight

- Disclosure proofs allow selective attestation to auditors
- Auditor learns balance >= threshold, nothing more

## 4. Security Requirements (MUST)

- **No Double-Spend**: Sequential root check prevents spending the same balance twice
- **No Forgery**: Cannot create valid proofs for accounts you don't own (requires secret key)
- **No Replay**: Proofs are bound to specific state roots
- **Balance Conservation**: Transfers cannot create or destroy value
- **Root Integrity**: Only valid state transitions can update the root

## 5. Operational Requirements (MUST)

- **Finality**: Proof verification is immediate (single transaction)
- **Cost**: Verification gas cost should be reasonable (<500k gas target)
- **Operator Model**: Centralized operator for PoC (trust assumption documented)
- **Key Management**: Users manage their own secret keys (no recovery mechanism)

## 6. Out of Scope (PoC)

- Decentralized sequencing (single operator only)
- Data availability guarantees (no DA committee or on-chain calldata)
- Key recovery or social recovery
- Transaction batching
- Multi-asset support
- Production security audit
- MEV protection

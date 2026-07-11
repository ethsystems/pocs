---
title: "{{poc_name}} Requirements"
use_cases: 
  - "[link to ethsystems/map use case]"
approach: "[link to ethsystems/map approach]"
---

# {{poc_name}} Requirements

## 1. Core Problem

Brief statement of what we're solving. Reference the use case and approach that motivated this PoC.

> From [use case name](link): "quote the key problem statement"

## 2. Functional Requirements (MUST)

What the system must do. Organize by workflow/lifecycle phase.

- **[Phase 1: e.g., Issuance]**:
  - Requirement 1
  - Requirement 2

- **[Phase 2: e.g., Trading]**:
  - Requirement 1
  - Requirement 2

- **[Phase 3: e.g., Redemption]**:
  - Requirement 1
  - Requirement 2

- **Access Control**:
  - Who can do what

## 3. Privacy Requirements (MUST)

What's confidential, what's public, who can see what.

- **Confidential Data** (hidden from public):
  - [e.g., amounts, balances, positions]

- **Public Data** (visible on-chain):
  - [e.g., transaction existence, timestamps, participant addresses]

- **Regulatory Oversight**:
  - [e.g., viewing keys, audit trails, disclosure mechanisms]

## 4. Security Requirements (MUST)

Protection mechanisms and constraints.

- **[Requirement 1]**: e.g., Double-spend protection via nullifiers
- **[Requirement 2]**: e.g., Replay protection
- **[Requirement 3]**: e.g., Access control separation

## 5. Operational Requirements (MUST)

Non-functional requirements for real-world use.

- **Finality**: [e.g., minutes, daily cycles]
- **Cost**: [e.g., viable for daily operations]
- **Key Management**: [e.g., rotation, recovery]
- **Integration**: [e.g., compatibility with existing systems]

## 6. Out of Scope (PoC)

What this PoC explicitly does NOT address. Important for setting expectations.

- [Item 1]
- [Item 2]

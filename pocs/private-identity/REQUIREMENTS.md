---
title: "Private Identity Requirements"
use_cases: 
  - "https://github.com/ethsystems/map/blob/master/use-cases/private-identity.md"
  - "https://github.com/ethsystems/map/blob/master/use-cases/resilient-identity-continuity.md"
approach: "https://github.com/ethsystems/map/blob/master/approaches/approach-private-identity.md"
---

# Private Identity Requirements

## 1. Core Problem

On-chain access control currently requires revealing identity. Addresses are linked to real-world entities, and every authorization check produces a public, correlatable record. Institutions need to gate access to on-chain resources based on verified properties of the caller without exposing who the caller is or what credentials they hold.

> From [Private Identity](https://github.com/ethsystems/map/blob/master/use-cases/private-identity.md): "Current methods expose addresses and create linkability. The framework requires hiding prover identities and inter-verifier links while allowing auditor access and enabling replay attack resilience."

## 2. Functional Requirements (MUST)

### Actors

| Role | Responsibility |
|------|----------------|
| **Issuer** | Issues credentials attesting to holder properties. Maintains credential validity state. |
| **Holder** | Possesses credentials. Generates proofs to gain access without revealing identity. |
| **Verifier** | Validates proofs on-chain or off-chain. Enforces access policy. |
| **Auditor** | Authorized party with scoped read access to credential and proof metadata via selective disclosure. |

### Lifecycle

- **Credential Issuance**:
  - Issuer attests to one or more properties of a Holder (membership, jurisdiction, accreditation status, etc.)
  - Credential binding prevents transfer: only the original Holder can use a credential
  - Issuance does not leak Holder identity to public observers

- **Proof Presentation (Gated Access)**:
  - Holder generates a proof demonstrating possession of a valid credential that satisfies an access policy
  - Proof supports two claim types:
    - **Binary membership**: "I hold a valid credential from Issuer X"
    - **Attribute predicates**: "My credential attests property P satisfies condition C" (e.g., age >= 18, jurisdiction in {US, EU})
  - Verifier checks the proof and grants or denies access; no other information is revealed
  - Proof generation is practical on consumer hardware

- **Credential Revocation**:
  - Issuer can revoke a credential when a Holder no longer meets requirements
  - Revoked credentials fail verification
  - Revocation is privacy-preserving: public observers cannot determine which Holder was revoked

- **Self-Revocation**:
  - Holder can unilaterally revoke their own credential without Issuer involvement
  - Self-revocation serves as an escape hatch: the Holder retains sovereign control over their credential lifecycle
  - A self-revoked credential fails verification identically to an Issuer-revoked credential

- **Selective Disclosure (Audit)**:
  - Holder or system grants an Auditor scoped access to specific credential attributes or proof metadata
  - Disclosure is granular: the Auditor sees only what is explicitly shared
  - Audit access does not compromise the privacy of uninvolved Holders

## 3. Privacy Requirements (MUST)

- **Confidential Data** (hidden from public observers):
  - Holder identity (which address or entity is authenticating)
  - Credential contents (specific attributes, claim values)
  - Issuer-Holder relationship (which Issuer credentialed which Holder)

- **Public Data** (visible on-chain):
  - Proof validity (pass/fail)
  - Access policy being satisfied (e.g., "requires credential of type X")
  - Scope-bound nullifier (prevents replay within a given scope)

- **Unlinkability**:
  - Presentations are not correlatable to the Holder's on-chain address
  - An observer cannot determine that two proofs at the same Verifier came from the same Holder, unless the same scope-bound nullifier is used intentionally

- **Regulatory Oversight**:
  - Selective disclosure mechanism grants Auditors read access to specific proof or credential details
  - Append-only audit trail records all verification events (proof hash, policy checked, timestamp, result)

## 4. Security Requirements (MUST)

- **Replay Protection**: Scope-bound nullifiers prevent reuse of a proof within a given context (one vote per election, one claim per airdrop). Different scopes yield different nullifiers from the same credential.
- **Credential Forgery Prevention**: Only the Issuer can produce valid credentials. Proofs are sound: a Holder cannot forge a proof for a credential they do not possess.
- **Binding**: Credentials are non-transferable. Only the Holder to whom a credential was issued can generate valid proofs from it.
- **Revocation Integrity**: Once revoked (by Issuer or by self-revocation), a credential does not produce valid proofs under any circumstances.
- **Verifier Integrity**: The Verifier cannot extract Holder identity or credential contents beyond the boolean result and any explicitly disclosed attributes.

## 5. Operational Requirements (MUST)

- **Verification Latency**: On-chain proof verification completes within a single transaction.
- **Cost**: Verification gas costs are practical for frequent access checks.
- **Credential Freshness**: Revocation state is checkable at proof verification time, or within a bounded staleness window.
- **Issuer Availability**: Proof generation and verification do not require the Issuer to be online. The Holder operates with locally held credentials.

## 6. Out of Scope (PoC)

- Multi-address ownership proofs (proving control of multiple EOAs)
- Key recovery and rotation

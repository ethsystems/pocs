---
title: "Civic Participation Requirements"
use_cases:
  - "https://github.com/ethsystems/map/blob/master/use-cases/resilient-civic-participation.md"
approach: "https://github.com/ethsystems/map/blob/master/approaches/approach-civic-participation.md"
---

# Civic Participation Requirements

This document captures the umbrella requirements shared by every approach under `pocs/civic-participation/`. It is intentionally approach-agnostic. Approach-specific design (cryptographic primitives, deployment targets, durability mechanisms) lives in each approach's `SPEC.md`.

## 1. Core Problem

Public civic processes (petitions, ballots, polls) need verifiable outcomes computed from privacy-preserving events cast under stated eligibility criteria. Existing platforms record Participant identity, eligibility evidence, and event content in operator-held storage; that storage becomes a compelled-disclosure surface, is inherited by successor regimes, and loses its outcome guarantee the moment the platform shuts down.

The umbrella admits multiple use cases that share this shape: any civic process where (a) eligibility is verifiable against a stated criterion, (b) Participant identity and the link from Participant to event must stay hidden, and (c) the outcome must be publicly verifiable.

## 2. Functional Requirements (MUST)

### Vocabulary

| Term | Meaning |
|------|---------|
| **Process** | A bounded civic activity (petition, ballot, poll) with declared public parameters. |
| **Participant** | A holder of credentials that satisfy the Process's eligibility criterion. |
| **Participation Event** | A submission by a Participant that contributes to the Process outcome (a signature, a vote, a ranked ballot). |
| **Eligibility Criterion** | A predicate over credential attributes that a Participant must satisfy to participate. |
| **Outcome Function** | A function declared at Process registration that maps the set of admitted Events to the Process's output. |

### Actors

| Role | Responsibility |
|------|----------------|
| **Organizer** | Registers the Process and declares its public parameters. |
| **Participant** | Holds an eligibility credential. Generates and submits Participation Events. |
| **Credential Issuer** | Issues credentials over which eligibility is defined. Sybil resistance lives here (see Section 6). |
| **Relayer / Aggregator** | Optional intermediary. Some approaches mediate submissions through one; others do not. |
| **Outcome Verifier** | Any party that re-derives the Process outcome from public record. No special privilege required. |

The party that computes and publishes the outcome ("whoever computes the outcome") is approach-specific. It may be the Organizer, a Relayer, an independent Resolver, or anyone with access to the public record.

### Process Registration

- Organizer publishes the Process's public parameters to durable public record: Eligibility Criterion, Outcome Function, opening time, closing time, eligibility-snapshot policy, and per-Participant Event-count bound.
- Public parameters are immutable after registration. Mutations are rejected by every approach.
- The eligibility-snapshot policy is Process-declared: either (a) frozen at registration against a pinned credential-root snapshot, or (b) resolved against the credential layer's state at Event submission time.
- The per-Participant Event-count bound is Process-declared. There is no umbrella default; every Process MUST specify the bound at registration.

### Participation

- A Participant generates a Participation Event that proves (a) eligibility under the pinned Eligibility Criterion, and (b) that their per-Participant Event-count bound has not been exceeded.
- Approaches MUST support these Event semantics: binary (cast / not-cast), single-choice from N declared options, and ranked or weighted choices over N declared options.
- An Event submitted after the Process closing time is not admitted into the Outcome computation.

### Outcome Computation

- The Outcome is the result of applying the Process-declared Outcome Function over the set of admitted, valid Events.
- The Outcome is published to durable public record.
- The Outcome is re-verifiable from durable public record according to the Process-declared durability target. The umbrella does not set a floor on that target.

## 3. Privacy Requirements (MUST)

### Confidential Data (hidden from any non-Participant observer)

- Participant identity (on-chain address, real-world identity).
- The evidence used to establish eligibility (credentials, attestations, supporting documents).
- Any credential attribute beyond what the Eligibility Criterion's boolean outcome reveals.
- Whether any specific eligible candidate-Participant did or did not cast an Event in this Process.

### Public Data

- The Process declaration (Eligibility Criterion, Outcome Function, opening and closing time, eligibility-snapshot policy, per-Participant Event-count bound).
- The final Outcome (output of the Outcome Function).

The umbrella does not require the count of admitted Events or per-class breakdowns to be public; a Process makes that choice through its Outcome Function.

### Unlinkability

- **Cross-Process Unlinkability**: An observer who archives every Process's public record indefinitely cannot link any two Events to a common Participant, beyond what the intersection of the Processes' Eligibility Criteria forces on the achievable anonymity set.
- **Within-Process Unlinkability**: Within a single Process, an observer cannot link two Events to a common Participant unless the Process's Event-count bound and Outcome Function explicitly admit per-Participant linkage (e.g., a weighted-vote semantics that needs per-Participant aggregation).

## 4. Security Requirements

### MUST

- **Event Integrity**: Every Event admitted into the Outcome computation comes from a Participant eligible under the Process's pinned Eligibility Criterion. An adversary cannot admit Events from ineligible Participants.
- **Per-Process Replay Prevention**: Within a single Process, a Participant cannot cast more than the Process-declared Event-count bound.
- **Outcome Soundness**: The published Outcome is the result of applying the Process-declared Outcome Function over the set of admitted, valid Events.
- **Compelled-Disclosure Resistance**: Subpoena, breach, or successor-regime inheritance of any Organizer, Relayer / Aggregator, or outcome-computer state yields only what is already public. Participant identity, eligibility evidence, and Participant-to-Event linkage are not recoverable from those roles' state alone.

### SHOULD

- **Anti-Coercion**: Processes deployed under coercion risk (hostile-employer organising, dissident contexts) should declare and use a coercion-resistant mechanism (override-style key change or equivalent). The umbrella does not mandate a specific construction.
- **Forward Secrecy under Device Seizure**: Material on a Participant's device that enabled past Events should be unrecoverable from any later snapshot of that device, under standard one-way PRG or equivalent assumptions.

## 5. Operational Requirements

### MUST

- **Issuer-Independent Participation**: After credential enrollment, a Participant can generate and submit Events without the Credential Issuer being online or cooperating.
- **Consumer-Hardware Proving**: Participant-side cryptography completes in practical time and memory on a consumer laptop or phone.

### SHOULD

- **Operator-Free Outcome Verifiability After Closure**: After a Process closes, its Outcome remains verifiable from durable public record alone, without continued cooperation from the Organizer, the Credential Issuer, any Relayer, or the outcome-computer, for the Process-declared durability target.

## 6. Out of Scope (PoC)

- **Sybil-resistance design**: Delegated to the credential layer. See [private-identity](../private-identity/) for one such layer.
- **Network-layer / transport-layer anonymity**: Tor, mixnets, and equivalent are assumed to be available; the umbrella does not design them.
- **Key recovery and multi-device participation under one credential**: A single device per credential per Process is the assumed deployment model.
- **Regulator audit / selective disclosure mechanisms**: Civic processes default to operator-free and audit-free. Approaches may add scoped disclosure but the umbrella does not require it.
- **Free-form deliberative or comment-style participation**: Event semantics are limited to binary, single-choice, and ranked / weighted. Open-text deliberation is a separate problem class.
- **Per-class / per-jurisdiction Outcome partitioning**: Approach-specific. Approaches that target use cases requiring per-class minima (ECI per-member-state, repo per-team) declare it in their own SPEC.

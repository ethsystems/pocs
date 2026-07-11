# CLAUDE.md

Project context and guidelines for working in this repository.

## Project Overview

This repository contains proofs of concept for EthSystems privacy primitives. The mission is to accelerate institutional Ethereum adoption by demonstrating how financial institutions can use Ethereum privately.

## Target Audience

Specs and documentation should be accessible to:

- **Executives / C-levels**: Need high-level understanding of what privacy guarantees are achieved and business implications
- **Financial institution engineers**: Need technical depth to evaluate and implement
- **Legal / Ops / Business**: Need to understand compliance implications, trust assumptions, and operational requirements

Write specs with layered depth: executive summary up front, technical details below. Avoid unexplained jargon—define terms or link to terminology section.

## Philosophy

The goal is **not** production-ready or fully-secure implementations. The primary deliverable is a detailed `SPEC.md` that thoroughly documents the protocol. Implementation shortcuts are acceptable as long as they are explicitly documented in the spec or README.

Prioritize:

1. Clear, complete specifications
2. Working demonstrations of the core concept
3. Documented limitations and shortcuts

## Security Disclaimer

**These implementations are proofs of concept for research and evaluation purposes only.**

- Do NOT use in production without thorough security audits
- Implementations may contain bugs, incomplete features, or cryptographic weaknesses
- No guarantees of correctness, security, or fitness for any purpose

## PoC Structure

Each PoC lives in `/pocs/[project-name]`. See `/pocs/_template/` for the standard structure.

Required files:

- `REQUIREMENTS.md` - Translates use case + approach into actionable requirements
- `SPEC.md` - Detailed protocol specification (the main deliverable)
- `README.md` with:
  - What privacy primitive this demonstrates
  - Cryptographic assumptions and threat model
  - Build and run instructions
  - Known limitations and shortcuts taken

A single `CHANGELOG.md` at the repository root tracks changes across all PoCs.

### Multi-Approach PoCs

When a use case can be solved with fundamentally different technical approaches (e.g., different cryptographic constructions or deployment targets), structure the PoC as follows:

```
pocs/[project-name]/
├── README.md           # Overview comparing approaches
├── REQUIREMENTS.md     # Shared requirements (approach-agnostic)
├── [approach-1]/
│   ├── README.md       # Approach-specific instructions
│   └── SPEC.md         # Approach-specific protocol design
└── [approach-2]/
    ├── README.md
    └── SPEC.md
```

This pattern is appropriate when:
- Approaches have different cryptographic assumptions
- Approaches target different deployment environments
- The same requirements can be satisfied with distinct constructions

The shared `REQUIREMENTS.md` captures what needs to be achieved; each approach's `SPEC.md` describes how.

## Methodology

Each PoC starts from an [ethsystems/map use case](https://github.com/ethsystems/map/tree/master/use-cases) and its corresponding [approach](https://github.com/ethsystems/map/tree/master/approaches). The workflow:

1. **Use Case (ethsystems/map):** Defines the business problem, actors, constraints, privacy needs
2. **Approach (ethsystems/map):** Recommends architecture, discusses trade-offs for different audiences
3. `REQUIREMENTS.md`: Translates use case + approach into concrete, actionable requirements for the PoC
4. `SPEC.md`: Designs the protocol that satisfies the requirements
5. **Implementation**: Code that demonstrates the spec

**REQUIREMENTS.md** is the bridge between ethsystems/map context and our technical spec. It extracts:

- Functional requirements by lifecycle phase (issuance, trading, redemption, etc.)
- Privacy requirements (what's confidential vs public, regulatory access)
- Security requirements (double-spend protection, access control)
- Operational requirements (finality, cost, key management)
- Out of scope items (explicit about what the PoC does NOT address)

## PoC Independence

Each PoC should be self-contained:

- Own build system and dependencies
- No cross-PoC imports or shared code (unless explicitly extracted to a shared library)
- Language/tooling choices independent of other PoCs

This ensures:

- Easy extraction if a PoC graduates to its own repo
- No cascading breakage across unrelated projects
- Clear ownership and maintenance boundaries

## CI/CD

General CI workflows live in `.github/workflows/` and validate repository-wide concerns like PoC structure. Since these are proofs of concept focused on specifications rather than production code, per-PoC test pipelines are not required.

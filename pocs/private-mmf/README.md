# Private Money Market Fund

> **Status:** In Progress
> **Privacy Primitive:** Confidential tokenized MMF shares with proven eligibility and a transfer-agent register

## Overview

This PoC group studies confidential shares for tokenized money market funds (MMFs) on Ethereum. Positions, flows and per-position yield are hidden from the public, holders prove eligibility in zero knowledge, and the transfer agent keeps a complete register. The group maps the trade-offs between unlinkability and interoperability with existing token stacks across configurations; it doesn't enforce every property at once.

What it aims to show:
- The share ledger stays consistent and compliant while positions are hidden. Conservation, eligibility, investor caps and locks are enforced in-circuit, and total shares stay publicly checkable at the fund's cadence.
- How much privacy holders actually get, as the share of confidential holders, holder concentration and event shaping vary.
- What each operation costs, and what moving a deployed tokenized MMF to this design would take.

What it doesn't show:
- The asset side. NAV computation and attestation of the fund's portfolio stay with the administrator or custodian; the PoC proves the share side only.
- Production readiness. The transfer agent's register is simulated, and fiat rails and custody products aren't integrated.
- The account-model (FHE), TEE and shared-pool configurations. These are analysed on paper, in the approach card.

| PoC | Description | Location |
| --- | --- | --- |
| **Shielded notes** | The configuration built end to end: notes, privacy by default, a single fund, with a simulated transfer agent. Builds on the attested shielded pool (2/SHIELDED-POOL, 3/ATTESTED-POOL) and its compliance extension. | [shielded-notes/](./shielded-notes/) |
| **Linkability simulation** | How linkable holders are as the share of confidential holders, holder concentration and event shaping (publication cadence, batching) vary, on an anonymized holder distribution. | Planned |

## Requirements

See [REQUIREMENTS.md](./REQUIREMENTS.md) for the shared requirements.

## Specifications

- [shielded-notes/SPEC.md](./shielded-notes/SPEC.md): shielded-notes protocol design

## Cryptographic Assumptions

Planned. The shielded-notes PoC inherits the base pool's primitives unless stated; [shielded-notes/SPEC.md](./shielded-notes/SPEC.md) will fix the instantiations.

| Primitive | Instantiation | Assumption |
|---|---|---|
| Algebraic hash | Poseidon over BN254, inherited | Collision and preimage resistance |
| Proving system | UltraHonk over BN254 (Noir, Barretenberg), zero-knowledge flavor | Knowledge soundness, and a correct verifying key in the deployed verifier. Universal KZG reference string, no circuit-specific setup. The non-ZK flavor commits to the witness, so the ZK flavor is required (REQUIREMENTS 4.9) |
| Commitment and attestation trees | LeanIMT, inherited | Collision resistance of the node hash, and honest attesters |
| Note encryption | ECDH, HKDF and an AEAD, inherited | Classical hardness only; no post-quantum path |
| Spend authorization | ECDSA over secp256k1 or P-256, signing a transaction plan (REQUIREMENTS 5.4) | Unforgeability. Verified in-circuit, it needs non-native field arithmetic |
| Register feed | Encryption to the transfer agent's register key, optionally threshold-held (REQUIREMENTS 5.5); scheme chosen in the spec | Confidentiality of the scheme. Completeness needs in-circuit binding, or rests on a legal obligation (REQUIREMENTS 4.10) |

Note ciphertexts and the register feed are harvest-now-decrypt-later targets.

## Threat Model

Who sees what is in [REQUIREMENTS.md](./REQUIREMENTS.md), section 3.7. This section states the trust assumptions and adversaries.

Trusted, as today:
- **Transfer agent:** issues shares only against settled subscriptions, keeps the register, and freezes or seizes under authority. It sees every position by design.
- **Attesters** (the transfer agent or its KYC provider): attest only eligible investors.
- **The fund:** publishes its NAV and reports its assets honestly.

Protected against:
- **Public observers**, including competitors and chain analysts. They learn no positions, flows or per-position yield, only aggregates at the fund's cadence, transaction existence and the positions of holders who opt out.
- **Other holders.** They see what the public sees, plus their own positions and the transfers they take part in.
- **Malicious holders.** They can't create shares, double-spend, or bypass eligibility, caps or locks: a non-compliant operation has no valid proof.

Not protected against:
- **Linkage in small, concentrated holder sets.** A large movement can identify its owner even with amounts hidden. The linkability simulation evaluates this.
- **Crossings and public cash legs.** Moving between public and confidential holdings, or settling against a public stablecoin, reveals amount and timing.
- **A dishonest transfer agent or attester.** It can mis-issue or mis-attest, as today. Conservation keeps total shares checkable, but not against the fund's assets.
- **An incomplete register feed**, where the ciphertext isn't bound in-circuit (REQUIREMENTS 4.10).
- **Key compromise.** A stolen spend key loses the position; leaked nullifier or viewing keys lose privacy, not shares.
- **Network-layer metadata** (IP, timing) and indexer queries.
- **Future quantum adversaries** against note and register ciphertexts.

## Known Limitations

- One configuration is built (shielded notes, single fund); the others are analysed on paper.
- The anonymity set is one fund's holders, which is small and concentrated.
- The transfer agent, its register and the cash leg are simulated; there are no fiat rails.
- Contract holders (multisigs, smart accounts, autonomous contracts) can't hold note secrets, so they stay public or delegate.
- Stable-NAV funds only; floating NAV is out of scope.
- The cost of verifying ECDSA in-circuit isn't known yet; the PoC benchmarks it.
- The base pool's implementation limitations apply until fixed; see [its README](../private-payment/shielded-pool-compliance/README.md#known-limitations-and-shortcuts).

## References

- Use case: [Private Money Market Funds](https://github.com/ethsystems/map/blob/master/use-cases/private-money-market-funds.md)
- Approach: [Private Money Market Funds](https://github.com/ethsystems/map/blob/master/approaches/approach-private-money-market-funds.md)
- Specs: [2/SHIELDED-POOL](https://specs.ethsystems.org/2/), [3/ATTESTED-POOL](https://specs.ethsystems.org/3/)
- Base implementation: [private-payment/shielded-pool-compliance](../private-payment/shielded-pool-compliance/)

## Security Disclaimer

**This is a proof of concept for research and evaluation purposes only.** Do not use it in production without thorough security audits. It may contain bugs, incomplete features or cryptographic weaknesses, and comes with no guarantees of correctness, security or fitness for any purpose.

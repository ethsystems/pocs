# Private Money Market Fund

> **Status:** In Progress
> **Privacy Primitive:** Confidential tokenized MMF shares with proven eligibility and a transfer-agent register

## Overview

This PoC group studies confidential shares for tokenized money market funds (MMFs) on Ethereum. Positions, flows and per-position yield are hidden from the public, holders prove eligibility in zero knowledge, and the transfer agent keeps a complete register. The group maps the trade-offs between unlinkability and interoperability with existing token stacks across configurations; it doesn't enforce every property at once.

What it aims to show:
- The share ledger stays consistent and compliant while positions are hidden. Conservation, eligibility and locks are enforced in-circuit, investor caps by the transfer agent when it attests owners, and total shares stay publicly checkable at the fund's cadence.
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

The shielded-notes PoC inherits the base pool's primitives unless stated; [shielded-notes/SPEC.md](./shielded-notes/SPEC.md) fixes the instantiations.

| Primitive | Instantiation | Assumption |
|---|---|---|
| Algebraic hash | Poseidon over BN254, inherited | Collision and preimage resistance |
| Proving system | UltraHonk over BN254 (Noir, Barretenberg), zero-knowledge flavor | Knowledge soundness, and a correct verifying key in the deployed verifier. Universal KZG reference string, no circuit-specific setup. The non-ZK flavor commits to the witness, so the ZK flavor is required (REQUIREMENTS 4.9) |
| Commitment and attestation trees | LeanIMT, inherited | Collision resistance of the node hash, and an honest attester (the transfer agent) |
| Recipient delivery | ECDH, HKDF and an AEAD, inherited | Classical hardness only; no post-quantum path |
| Spend authorization | ECDSA over secp256k1, signing a transaction plan (REQUIREMENTS 5.4) | Unforgeability. Verified in-circuit, it needs non-native field arithmetic |
| Register feed | ECDH over Grumpkin to the transfer agent's register key, with a Poseidon keystream, bound in-circuit (REQUIREMENTS 4.10) | Discrete logarithm on Grumpkin; Poseidon as a PRF. A threshold-held register key is a future extension (REQUIREMENTS 5.5) |

Note ciphertexts and the register feed are harvest-now-decrypt-later targets.

## Threat Model

Who sees what is in [REQUIREMENTS.md](./REQUIREMENTS.md), section 3.7. This section states the trust assumptions and adversaries.

Trusted, as today:
- **Transfer agent:** issues shares only against settled subscriptions, keeps the register, and freezes or seizes under authority. It sees every position by design.
- **Attester:** the transfer agent, the single attester in shielded notes: attests only eligible investors.
- **The fund:** publishes its NAV and reports its assets honestly.

Protected against:
- **Public observers**, including competitors and chain analysts. They learn no positions, flows or per-position yield, only aggregates at the fund's cadence, transaction existence and the positions of holders who opt out.
- **Other holders.** They see what the public sees, plus their own positions and the transfers they take part in.
- **Malicious holders.** They can't create shares, double-spend, or bypass eligibility, caps or locks: a non-compliant operation has no valid proof.

Not protected against:
- **Linkage in small, concentrated holder sets.** A large movement can identify its owner even with amounts hidden. The linkability simulation evaluates this.
- **Crossings and public cash legs.** Moving between public and confidential holdings, or settling against a public stablecoin, reveals amount and timing.
- **A dishonest transfer agent or attester.** It can mis-issue or mis-attest, as today. Conservation keeps total shares checkable, but not against the fund's assets.
- **An incomplete register feed** in configurations that don't bind the ciphertext in-circuit (REQUIREMENTS 4.10). Shielded notes binds it.
- **Key compromise.** A stolen spend key loses the position; leaked nullifier or viewing keys lose privacy, not shares.
- **Network-layer metadata** (IP, timing) and indexer queries.
- **Future quantum adversaries** against note and register ciphertexts.

## Known Limitations

- One configuration is built (shielded notes, single fund); the others are analysed on paper.
- The anonymity set is one fund's holders, which is small and concentrated.
- The transfer agent, its register and the cash leg are simulated; there are no fiat rails.
- Contract holders (multisigs, smart accounts, autonomous contracts) can't hold note secrets, so they stay public or delegate.
- Investor caps rest on the transfer agent's attestations, not on a proof. Proving the investor count in zero knowledge is a possible extension.
- The transfer agent is a single point of failure for liveness, and replacing it is an open process; see the spec's [Limitations](./shielded-notes/SPEC.md#limitations-and-shortcuts-poc-scope).
- Stable-NAV funds only; floating NAV is out of scope.
- Verifying the custody signature in-circuit costs about 42,500 gates, half of a deposit's circuit and a fifth of a transfer's; each operation costs about 3M gas, most of it proof verification. See the spec's [Measured Costs](./shielded-notes/SPEC.md#measured-costs).
- The implementation's limitations, including the one it keeps from the base pool's, are in [shielded-notes' README](./shielded-notes/README.md#limitations).

## References

- Use case: [Private Money Market Funds](https://github.com/ethsystems/map/blob/master/use-cases/private-money-market-funds.md)
- Approach: [Private Money Market Funds](https://github.com/ethsystems/map/blob/master/approaches/approach-private-money-market-funds.md)
- Specs: [2/SHIELDED-POOL](https://specs.ethsystems.org/2/), [3/ATTESTED-POOL](https://specs.ethsystems.org/3/)
- Base implementation: [private-payment/shielded-pool-compliance](../private-payment/shielded-pool-compliance/)

## Security Disclaimer

**This is a proof of concept for research and evaluation purposes only.** Do not use it in production without thorough security audits. It may contain bugs, incomplete features or cryptographic weaknesses, and comes with no guarantees of correctness, security or fitness for any purpose.

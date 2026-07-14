# EthSystems PoCs

Proof of concept implementations for [EthSystems](https://ethsystems.org).

> **Warning:** These are research prototypes, not production-ready code. Do not use in production without thorough security audits.

## Structure

```
pocs/
  [project-name]/       # Self-contained PoC
    REQUIREMENTS.md     # Actionable requirements from use case + approach
    SPEC.md             # Protocol specification (main deliverable)
    README.md           # Build/run instructions, limitations
    [approach-1]/       # For multi-approach PoCs
      SPEC.md
      README.md
    [approach-2]/
      ...
libs/
  [library-name]/       # Standalone libraries
docs/
  CONTRIBUTING.md       # PR guidelines
CHANGELOG.md            # Repository-wide change history
```

Each PoC is independent—own language and tooling. No shared dependencies between projects.

## PoCs

| Name | Privacy Primitive | Approaches | Status | Writeup |
|------|-------------------|------------|--------|---------|
| [private-payment](./pocs/private-payment/) | Confidential stablecoin transfers | Shielded Pool (Noir), Plasma (Intmax2), Resilient Disbursement Rails | Complete | [Shielded Pool](https://ethsystems.org/blog/building-private-transfers-on-ethereum-with-shielded-pools/), [Plasma](https://ethsystems.org/blog/building-private-transfers-on-ethereum-with-plasma/) |
| [private-bond](./pocs/private-bond/) | Confidential bond transfers | Custom UTXO (Noir), Privacy L2 (Aztec), FHE (Zama) | Complete | [Part 1 — Custom UTXO](https://ethsystems.org/blog/building-private-bonds-on-ethereum/), [Part 2 — Aztec](https://ethsystems.org/blog/building-private-bonds-on-ethereum-part-2/), [Part 3 — FHE](https://ethsystems.org/blog/building-private-bonds-on-ethereum-part-3/) |
| [private-trade-settlement](./pocs/private-trade-settlement/) | Confidential atomic DvP | TEE Swap | Complete | [Part 1](https://ethsystems.org/blog/private-crosschain-atomic-swaps-part-1-of-2/), [Part 2](https://ethsystems.org/blog/private-crosschain-atomic-swaps-part-2-of-2/) |
| [private-identity](./pocs/private-identity/) | Anonymous credentials | Resilient (vOPRF) | Complete | [Resilient Plural Identity](https://ethsystems.org/blog/resilient-plural-identity/) |
| [diy-validium](./pocs/diy-validium/) | Confidential institutional payments | Validium (RISC Zero) | Complete | [DIY Validium](https://ethsystems.org/blog/diy-validium-private-logic-on-public-rails/) |

## Libraries

| Name | Description |
|------|-------------|
| [binius-mayo](./libs/binius-mayo/) | Binius64 zk-circuit proving a MAYO-2 post-quantum signature verifies under a hidden public key |

## Contributing

See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for PR guidelines. Use [pocs/_template](pocs/_template) when adding new PoCs.

## License

File-level SPDX headers are authoritative. Code without a more specific file-level license is licensed under MIT OR Apache-2.0.
Documentation, specs, requirements, readmes, and writeups are licensed under CC0-1.0 unless otherwise stated.
Third-party dependencies retain their own licenses.

## See Also

- [ethsystems.org](https://ethsystems.org/) — Writeups and documentation
- [ethsystems/map](https://github.com/ethsystems/map) — Mapping of privacy primitives

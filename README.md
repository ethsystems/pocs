# IPTF PoCs

Proof of concept implementations for [IPTF](https://iptf.ethereum.org).

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
| [private-payment](./pocs/private-payment/) | Confidential stablecoin transfers | Shielded Pool (Noir), Plasma (Intmax2), Resilient Disbursement Rails | Complete | [Shielded Pool](https://iptf.ethereum.org/2026/02/19/building-private-transfers-on-ethereum/), [Plasma](https://iptf.ethereum.org/2026/02/26/private-stablecoins-with-plasma/) |
| [private-bond](./pocs/private-bond/) | Confidential bond transfers | Custom UTXO (Noir), Privacy L2 (Aztec), FHE (Zama) | Complete | [Part 1 — Custom UTXO](https://iptf.ethereum.org/2026/01/21/building-private-bonds-on-ethereum/), [Part 2 — Aztec](https://iptf.ethereum.org/2026/02/05/private-bonds-on-privacy-l2s/), [Part 3 — FHE](https://iptf.ethereum.org/2026/02/12/private-bonds-with-fhe/) |
| [private-trade-settlement](./pocs/private-trade-settlement/) | Confidential atomic DvP | TEE Swap | Complete | [Part 1](https://iptf.ethereum.org/2026/03/05/private-crosschain-atomic-swap-part-1/), [Part 2](https://iptf.ethereum.org/2026/03/18/private-crosschain-atomic-swap-part-2/) |
| [private-identity](./pocs/private-identity/) | Anonymous credentials | Resilient (vOPRF) | Complete | [Resilient Plural Identity](https://iptf.ethereum.org/2026/04/14/resilient-plural-identity/) |
| [diy-validium](./pocs/diy-validium/) | Confidential institutional payments | Validium (RISC Zero) | Complete | [DIY Validium](https://iptf.ethereum.org/2026/03/18/diy-validium/) |

## Libraries

| Name | Description |
|------|-------------|
| [binius-mayo](./libs/binius-mayo/) | Binius64 zk-circuit proving a MAYO-2 post-quantum signature verifies under a hidden public key |

## Contributing

See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for PR guidelines. Use [pocs/_template](pocs/_template) when adding new PoCs.

## License

Code in this repository is licensed under MIT OR Apache-2.0 unless a file states otherwise.
Documentation, specs, requirements, readmes, and writeups are licensed under CC0-1.0 unless otherwise stated.
Third-party dependencies retain their own licenses.

## See Also

- [iptf.ethereum.org](https://iptf.ethereum.org/) — Writeups and documentation
- [iptf-map](https://github.com/ethereum/iptf-map) — Mapping of privacy primitives

# {{poc_name}}

> **Status:** Draft | In Progress | Complete
> **Privacy Primitive:** [e.g., confidential transfers, private voting, anonymous credentials]

## Overview

Brief description of what this PoC demonstrates.

## Cryptographic Assumptions

- **Primitives used:** [e.g., Pedersen commitments, zk-SNARKs, ring signatures]
- **Security assumptions:** [e.g., discrete log hardness in the chosen group]
- **Trusted setup:** [Yes/No, and details if yes]

## Threat Model

What does this protect against:
- [ ] Public observers cannot learn X
- [ ] Validators cannot learn Y

What this does NOT protect against:
- Collusion between A and B
- Side-channel attacks
- etc.

## Prerequisites

- [Rust](https://www.rust-lang.org/tools/install)
{% if use_foundry %}- [Foundry](https://getfoundry.sh/introduction/installation)
{% endif %}{% if use_noir %}- [Nargo](https://noir-lang.org/docs/getting_started/noir_installation) 1.0.0
- [Barretenberg](https://barretenberg.aztec.network/docs/getting_started) `bb` 6.0.0. Generate Solidity verifiers with `bb write_solidity_verifier -t evm --optimized` (the ZK flavor, assembly verifier)
{% endif %}
{% if use_foundry %}## Installation

```bash
cd pocs/{{project-name}}
# Install Solidity dependencies
forge soldeer install
```

{% endif %}## Building

```bash
{% if use_noir %}nargo compile --workspace
{% endif %}{% if use_foundry %}forge build
{% endif %}cargo check
```

## Running

```bash
# How to run the PoC
```

## Tests

```bash
{% if use_noir %}nargo test --workspace
{% endif %}{% if use_foundry %}forge test
{% endif %}cargo test --lib
```

## Known Limitations

- Limitation 1
- Limitation 2

## References

- Link to paper/spec this implements
- Related work

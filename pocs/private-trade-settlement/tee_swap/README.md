# TEE Swap

> **Status:** Draft
> **Privacy Primitive:** Atomic cross-chain swaps of private UTXO notes via TEE-coordinated stealth address revelation

## Overview

This approach uses a Trusted Execution Environment (TEE) to coordinate atomic delivery-versus-payment (DvP) settlement of private UTXO notes across chains. Users lock notes to stealth addresses with time-locked dual spending conditions, and the TEE atomically reveals ephemeral keys that allow both parties to claim. Users never share spending keys — the TEE can censor but never steal.

See [SPEC.md](./SPEC.md) for the full protocol specification.

## Cryptographic Assumptions

- **Primitives used:** Stealth addresses (ECDH + elliptic curve arithmetic), hash-based commitments (domain-separated), ZK proofs (Noir circuits), time-locked spending conditions
- **Security assumptions:** Discrete log hardness (Grumpkin curve), TEE enclave integrity, hash function collision resistance
- **Trusted setup:** No cryptographic trusted setup; trust is placed in TEE hardware and attestation infrastructure

## Threat Model

What does this protect against:
- [x] Public observers cannot learn trade amounts, prices, or counterparty identities
- [x] Miners/validators cannot front-run trades (stealth address protection)
- [x] TEE compromise leads to censorship only, not fund theft
- [x] Users can always recover funds via timeout refund path

What this does NOT protect against:
- TEE hardware manufacturer can see plaintext inside enclave (privacy loss, not theft)
- TEE operator can censor by refusing to reveal (denial of service, not theft)
- Network-level traffic analysis (timing, message sizes)

## Prerequisites

- [Rust](https://www.rust-lang.org/tools/install)
- [Foundry](https://getfoundry.sh/introduction/installation)
- [Nargo](https://noir-lang.org/docs/getting_started/installation/) (Noir toolchain)
- [Barretenberg](https://barretenberg.aztec.network/docs/getting_started/)

## Prerequisite versions at the time of development

- rust: v1.90
- forge: v1.5.1 (Installed with foundry)
- nargo: v1.0.0
- bb: v6.0.0

> [!NOTE]
> if proof generation / verification fails for you, run `./scripts/generate-verifiers.sh` to regenerate the verifiers. this can happen when there is a mismatch in tooling versions for bb / nargo

## Installation

```bash
cd pocs/approach-private-trade-settlement/tee_swap
# Install Solidity dependencies
forge soldeer install
```

## Building

```bash
# Build Solidity contracts
forge build

# Check Rust TEE code
cargo check

# Build Noir circuits
cd circuits/transfer && nargo check && cd ../..
```

## Running

### Mock mode

```bash
cargo run --bin demo
```

### Full e2e demo with real proof generation + onchain verification + tee swap coordination (happy path)

```bash
cargo run --bin e2e
```

### Full e2e demo with real proof generation + onchain verification + tee swap coordination (tee crashes, refund path)

```bash
cargo run --bin e2e -- refund
```

> **note**: you may use `--release` to make the demos execute faster

### Testnet demo

Runs the full TEE swap protocol on live testnets (Sepolia + a Layer 2).

#### 1. Create a config file

Copy the example and fill in real values:

```bash
cp config.toml.example config.toml
```

The config has the following sections:

| Section | Purpose |
|---------|---------|
| `[sepolia]` | RPC URL and deployer key for Sepolia |
| `[layer2]` | RPC URL and deployer key for the L2 (e.g. Scroll Sepolia) |
| `[alice]` | Alice's private key, home chain (`"sepolia"` or `"layer2"`), and note amount |
| `[bob]` | Bob's private key, home chain (must differ from Alice's), and note amount |
| `[tee]` | TEE signer private key (only needed for local coordinator mode) |
| `[coordinator]` | Optional: external coordinator URL and TEE address |
| `[swap]` | Swap timeout (e.g. `"24h"`) |

> [!IMPORTANT]
> All deployer and party accounts must be funded with testnet ETH. Never use keys that hold mainnet funds.

#### 2. Pre-deployed contracts (optional)

If contracts are already deployed, set the addresses and deployment block to skip the forge deployment step:

```toml
[sepolia]
rpc_url = "https://rpc.sepolia.org"
deployer_private_key = "0x..."
deployment_block = 12345678
private_utxo_address = "0x..."
tee_lock_address = "0x..."
```

The same applies to the `[layer2]` section. When these fields are omitted, the binary deploys fresh contracts via `forge script`.

#### 3. Coordinator modes

**Local coordinator** (default): spawns an RA-TLS server locally. Requires `[tee]` private key:

```toml
[tee]
private_key = "0x..."
```

**External coordinator**: connects to a remote TEE coordinator. Omit the `[tee]` section and set:

```toml
[coordinator]
url = "https://tee.example.com"
tee_address = "0x..."  # required when deploying fresh contracts
```

#### 4. Run

```bash
cargo run --bin testnet -- --config config.toml
```

The binary executes a 12-step flow: deploy contracts, fund notes, lock notes, submit to TEE, and claim. Progress and transaction hashes are printed at each step.

> **note**: you may use `--release` to speed up proof generation

## Tests

```bash
forge test
cargo test --lib
```

## Known Limitations

- TEE enclave is simulated in software; no real hardware attestation
- Single TEE operator (no M-of-N redundancy)
- No actual encrypted channel between counterparties and enclave
- Simplified on-chain attestation verification (ECDSA signature check only)
- No KYC/whitelist enforcement or selective disclosure for regulators (can be layered at the UTXO contract level)
- No relayer infrastructure for UTXO contract interactions

## References

- [SPEC.md](./SPEC.md) — Full protocol specification
- [Intel SGX Explained (Costan & Devadas, 2016)](https://eprint.iacr.org/2016/086)
- [AWS Nitro Enclaves Documentation](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html)
- [Atomic DvP on Distributed Ledgers (BIS, 2020)](https://www.bis.org/publ/othp31.htm)

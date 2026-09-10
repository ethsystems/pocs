# Shielded Pool Private Payments

A proof-of-concept implementation of institutional stablecoin payments with transaction-level privacy while maintaining regulatory compliance. See [SPEC.md](./SPEC.md) for the full protocol specification.

## Prerequisites

- [Foundry](https://getfoundry.sh/introduction/installation)
- [Nargo](https://noir-lang.org/docs/getting_started/noir_installation) 
- [Barretenberg](https://barretenberg.aztec.network/docs/getting_started)

## Installation

```bash
cd pocs/private-payment/shielded-pool
# Install Solidity dependencies
forge soldeer install
```

## Environment Setup

```bash
# Copy the example environment file
cp .env.example .env
```

Edit `.env` and fill in the required values:

- `PRIVATE_KEY`: Your deployer private key
- `SEPOLIA_RPC_URL`: RPC endpoint for Sepolia testnet (if deploying to testnet)
- `VERIFIER_ADDRESS`: Set to `0x0000000000000000000000000000000000000000` for fresh deployment
- `ATTESTATION_REGISTRY_ADDRESS`: Set to `0x0000000000000000000000000000000000000000` for fresh deployment
- `ETHERSCAN_API_KEY`: For contract verification (optional)
- `DEPOSIT_VERIFIER_ADDRESS`: Set to `0x0000000000000000000000000000000000000000` for fresh deployment
- `TRANSFER_VERIFIER_ADDRESS`: Set to `0x0000000000000000000000000000000000000000` for fresh deployment
- `WITHDRAW_VERIFIER_ADDRESS`: Set to `0x0000000000000000000000000000000000000000` for fresh deployment

### Circuit Modifications

If you make changes to the circuits, you have to regenerate the solidity verifiers:

```bash
chmod +x scripts/generate-verifiers.sh
./scripts/generate-verifiers.sh
```

## Contracts

The Solidity contracts are located in `contracts/src/` and use the [forge-std Config pattern](https://getfoundry.sh/guides/scripting-with-config) for deployment configuration.

### Configuration

Deployment addresses are managed via `deployments.toml`. The file uses chain IDs as top-level keys with typed sub-tables:

```toml
[31337]                    # Chain ID (Anvil local)
endpoint_url = "http://localhost:8545"

[31337.bool]
use_mock_verifier = "${USE_MOCK_VERIFIER}"

[31337.address]
verifier_address = "0x..."
attestation_registry_address = "0x..."
shielded_pool_address = "0x..."
...
```

### Deployment

**Local deployment (Anvil) with mock verifiers:**

- Ensure that the `USE_MOCK_VERIFIER` in your .env is set to `true`

```bash
# Start local node in a separate terminal
anvil

# Deploy contracts
source .env
forge script contracts/script/Deploy.s.sol --rpc-url http://localhost:8545 --broadcast --private-key "${PRIVATE_KEY}"
```

**Local deployment (Anvil) with Barretenberg generated verifiers:**

- Ensure that the `USE_MOCK_VERIFIER` in your .env is set to `false`

```bash
# Start local node in a separate terminal
anvil

# Deploy contracts
source .env
forge script contracts/script/DeployVerifiers.s.sol --rpc-url http://localhost:8545 --broadcast --private-key "${PRIVATE_KEY}"
forge script contracts/script/Deploy.s.sol --rpc-url http://localhost:8545 --broadcast --private-key "${PRIVATE_KEY}"
```

### Redeployment

To redeploy contracts to a network where they were previously deployed, remove the existing address entries from `deployments.toml`:

```toml
[31337.address]
# Delete these lines to allow redeployment:
# verifier_address = "0x..."
# attestation_registry_address = "0x..."
# shielded_pool_address = "0x..."
```

Then run the deploy script again. The script will deploy new contracts and update `deployments.toml` with the new addresses.

### Build & Test


#### Contracts

```bash
# Build contracts
forge build

# Run tests
forge test
```

#### Circuits

```bash
# Build Circuits
nargo compile --workspace

# Run tests
nargo test --workspace
```

Includes the [ungated deposit fixture](tests/core_deposit/README.md), which covers a statement the gated deposit circuit does not.

#### Wallet

```bash
# Run unit tests 
cargo test --lib
```

#### E2E 

The E2E test executes the following flow:

1. Alice deposits 1000 tokens
2. Bob deposits 500 tokens
3. Alice transfers 700 to Bob (keeping 300 as change)
4. Bob withdraws 700 

This test uses the BBProver, and generated on-chain verifiers.

- Ensure that the `USE_MOCK_VERIFIER` in your .env is set to `false`

```bash
# Start local node in a separate terminal
anvil

# Deploy contracts
source .env
forge script contracts/script/DeployVerifiers.s.sol --rpc-url http://localhost:8545 --broadcast --private-key "${PRIVATE_KEY}"
forge script contracts/script/Deploy.s.sol --rpc-url http://localhost:8545 --broadcast --private-key "${PRIVATE_KEY}"
cargo test --test integration -- --nocapture
```

## Further development

The PoC is set up to be quite modular, so to iterate on it, you can do the following quite easily - 

1. Use a different proving backend: swap out the [bb_prover.rs](src/lib/adapters/bb_prover.rs) adapter
2. Use a secure channel i.e Mixnet / SWIFT for institutions: swap out the [channel.rs](src/lib/adapters/channel.rs) adapter
3. Use a different smart contract language: swap out the [contracts](contracts)

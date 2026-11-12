#!/bin/bash
# Generate the Solidity verifier from the Noir circuit
# Requires: nargo 1.0.0, bb 6.0.0 (override binary with BB=/path/to/bb)
# The wallet proves with the same pair (wallet/src/prover.rs). Rerun this script
# whenever the circuit or either version changes, and commit the result.
set -e

NARGO_VERSION="1.0.0"
BB_VERSION="6.0.0"
BB="${BB:-bb}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CIRCUIT_DIR="$PROJECT_ROOT/circuits"
OUTPUT_FILE="$PROJECT_ROOT/contracts/src/Verifier.sol"
# Real proof of circuits/Fixture.toml for test/RealVerifier.t.sol; a new verifier invalidates it
FIXTURE_FILE="$PROJECT_ROOT/contracts/test/fixtures/transfer_proof.json"

# A verifier from a different toolchain won't match the wallet's proofs
FOUND_NARGO="$(nargo --version | head -1 | awk '{print $4}')"
if [ "$FOUND_NARGO" != "$NARGO_VERSION" ]; then
    echo "ERROR: nargo $NARGO_VERSION required, found $FOUND_NARGO (run: noirup -v $NARGO_VERSION)"
    exit 1
fi
FOUND_BB="$("$BB" --version)"
if [ "$FOUND_BB" != "$BB_VERSION" ]; then
    echo "ERROR: bb $BB_VERSION required, found $FOUND_BB (run: bbup -v $BB_VERSION)"
    exit 1
fi

echo "=== Generating Solidity Verifier ==="
echo "Circuit directory: $CIRCUIT_DIR"
echo "Output file: $OUTPUT_FILE"
echo ""

cd "$CIRCUIT_DIR"

# 1. Compile the circuit (nargo compile, unlike nargo check, never writes Prover.toml)
echo "  [1/4] Compiling circuit..."
nargo compile

# 2. Generate verification key for the EVM target (keccak, ZK), matching the wallet's bb prove
echo "  [2/4] Generating verification key..."
"$BB" write_vk -b ./target/circuits.json -o ./target -t evm

# 3. Generate Solidity verifier (contract HonkVerifier, as imported by PrivateBond.sol).
#    --optimized is the assembly verifier for the same ZK flavor (-t evm); it accepts the same proofs.
echo "  [3/4] Generating Solidity verifier..."
"$BB" write_solidity_verifier -k ./target/vk -o "$OUTPUT_FILE" -t evm --optimized

# 4. Prove the committed Fixture.toml with the wallet's bb prove flags and write the test fixture.
#    The wallet overwrites Prover.toml before each proof, so the fixture keeps its own witness file.
echo "  [4/4] Writing real-proof fixture..."
nargo execute --prover-name Fixture
"$BB" prove -b ./target/circuits.json -w ./target/circuits.gz -o ./target -t evm
"$BB" verify -k ./target/vk -p ./target/proof -i ./target/public_inputs -t evm
mkdir -p "$(dirname "$FIXTURE_FILE")"
{
    echo "{"
    echo "  \"proof\": \"0x$(xxd -p ./target/proof | tr -d '\n')\","
    echo "  \"publicInputs\": ["
    xxd -p -c 32 ./target/public_inputs | sed 's/.*/    "0x&"/' | sed '$!s/$/,/'
    echo "  ]"
    echo "}"
} > "$FIXTURE_FILE"

echo ""
echo "=== Verifier generated: $OUTPUT_FILE ==="
echo "=== Fixture written: $FIXTURE_FILE ==="

#!/bin/bash
# Generate Solidity verifiers from Noir circuits
# Requires: nargo 1.0.0, bb 6.0.0 (barretenberg CLI)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CIRCUITS_DIR="$PROJECT_ROOT/circuits"
VERIFIERS_DIR="$PROJECT_ROOT/contracts/src/verifiers"

# Create verifiers directory if it doesn't exist
mkdir -p "$VERIFIERS_DIR"

CIRCUITS=("transfer")

echo "=== Generating Solidity Verifiers ==="
echo "Circuits directory: $CIRCUITS_DIR"
echo "Output directory: $VERIFIERS_DIR"
echo ""

for circuit in "${CIRCUITS[@]}"; do
    CIRCUIT_DIR="$CIRCUITS_DIR/$circuit"

    if [ ! -d "$CIRCUIT_DIR" ]; then
        echo "ERROR: Circuit directory not found: $CIRCUIT_DIR"
        exit 1
    fi

    echo "Processing $circuit circuit..."
    cd "$CIRCUIT_DIR"

    # 1. Compile the circuit (nargo check writes no ../../target/${circuit}.json)
    echo "  [1/3] Compiling circuit..."
    nargo compile

    # 2. Generate verification key for the EVM target (keccak, ZK), matching BBProver's bb prove
    echo "  [2/3] Generating verification key..."
    bb write_vk -b "../../target/${circuit}.json" -o ./target -t evm

    # 3. Generate Solidity verifier
    # Capitalize first letter for contract name
    CONTRACT_NAME="$(echo ${circuit:0:1} | tr '[:lower:]' '[:upper:]')${circuit:1}Verifier"
    OUTPUT_FILE="$VERIFIERS_DIR/${CONTRACT_NAME}.sol"

    # --optimized is the assembly verifier for the same ZK flavor (-t evm); it accepts the same proofs
    echo "  [3/3] Generating Solidity verifier: $CONTRACT_NAME"
    bb write_solidity_verifier -k ./target/vk -o "$OUTPUT_FILE" -t evm --optimized

    echo "  Done: $OUTPUT_FILE"
    echo ""
done

echo "=== All verifiers generated successfully ==="
echo ""
echo "Generated files:"
for circuit in "${CIRCUITS[@]}"; do
    CONTRACT_NAME="$(echo ${circuit:0:1} | tr '[:lower:]' '[:upper:]')${circuit:1}Verifier"
    echo "  - $VERIFIERS_DIR/${CONTRACT_NAME}.sol"
done

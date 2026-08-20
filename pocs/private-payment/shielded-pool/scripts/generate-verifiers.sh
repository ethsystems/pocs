#!/bin/bash
# Generate Solidity verifiers from Noir circuits
# Requires: nargo, bb (barretenberg CLI >= 5.0; override binary with BB=/path/to/bb)
set -e

BB="${BB:-bb}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CIRCUITS_DIR="$PROJECT_ROOT/circuits"
VERIFIERS_DIR="$PROJECT_ROOT/contracts/src/verifiers"

# Create verifiers directory if it doesn't exist
mkdir -p "$VERIFIERS_DIR"

CIRCUITS=("deposit" "transfer" "withdraw")

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

    # 1. Check/compile the circuit
    echo "  [1/4] Compiling circuit..."
    nargo check

    # 2. Execute to generate witness artifact
    echo "  [2/4] Executing circuit..."
    nargo execute witness

    # 3. Generate verification key for the EVM target (keccak, ZK)
    echo "  [3/4] Generating verification key..."
    "$BB" write_vk -b "../../target/${circuit}.json" -o ./target -t evm

    # 4. Generate Solidity verifier
    # Capitalize first letter for contract name
    CONTRACT_NAME="$(echo ${circuit:0:1} | tr '[:lower:]' '[:upper:]')${circuit:1}Verifier"
    OUTPUT_FILE="$VERIFIERS_DIR/${CONTRACT_NAME}.sol"

    echo "  [4/4] Generating Solidity verifier: $CONTRACT_NAME"
    "$BB" write_solidity_verifier -k ./target/vk -o "$OUTPUT_FILE"

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

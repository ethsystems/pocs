#!/usr/bin/env bash
# Generate Solidity verifiers from Noir circuits.
# Requires: nargo, bb (barretenberg CLI)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CIRCUITS_DIR="$PROJECT_ROOT/circuits"
VERIFIERS_DIR="$PROJECT_ROOT/contracts/src/verifiers"

mkdir -p "$VERIFIERS_DIR"

CIRCUITS=("claim" "withdraw")

echo "=== Generating Solidity Verifiers ==="
echo "Circuits directory: $CIRCUITS_DIR"
echo "Output directory: $VERIFIERS_DIR"
echo ""

for circuit in "${CIRCUITS[@]}"; do
    CIRCUIT_DIR="$CIRCUITS_DIR/$circuit"
    PACKAGE_NAME="rdr_${circuit}"

    if [ ! -d "$CIRCUIT_DIR" ]; then
        echo "ERROR: Circuit directory not found: $CIRCUIT_DIR"
        exit 1
    fi

    echo "Processing $circuit circuit..."
    cd "$CIRCUIT_DIR"

    echo "  [1/3] Compiling circuit..."
    nargo compile

    echo "  [2/3] Generating verification key..."
    bb write_vk -b "$PROJECT_ROOT/target/${PACKAGE_NAME}.json" -o ./target -t evm

    CONTRACT_NAME=""
    IFS='_' read -ra PARTS <<< "$circuit"
    for part in "${PARTS[@]}"; do
        CONTRACT_NAME+="$(echo "${part:0:1}" | tr '[:lower:]' '[:upper:]')${part:1}"
    done
    CONTRACT_NAME+="Verifier"
    OUTPUT_FILE="$VERIFIERS_DIR/${CONTRACT_NAME}.sol"

    echo "  [3/3] Generating Solidity verifier: $CONTRACT_NAME"
    # --optimized is the assembly verifier for the same ZK flavor as -t evm.
    bb write_solidity_verifier -k ./target/vk -o "$OUTPUT_FILE" -t evm --optimized

    echo "  Done: $OUTPUT_FILE"
    echo ""

    cd "$PROJECT_ROOT"
done

echo "=== All verifiers generated successfully ==="
echo ""
echo "Generated files:"
for circuit in "${CIRCUITS[@]}"; do
    CONTRACT_NAME=""
    IFS='_' read -ra PARTS <<< "$circuit"
    for part in "${PARTS[@]}"; do
        CONTRACT_NAME+="$(echo "${part:0:1}" | tr '[:lower:]' '[:upper:]')${part:1}"
    done
    CONTRACT_NAME+="Verifier"
    echo "  - $VERIFIERS_DIR/${CONTRACT_NAME}.sol"
done

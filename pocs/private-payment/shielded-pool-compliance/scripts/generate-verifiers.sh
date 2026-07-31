#!/usr/bin/env bash
# Generate Solidity verifiers from Noir circuits.
# Requires: nargo, bb (barretenberg CLI)
#
# Always -t evm, never -t evm-no-zk. `evm` is the keccak oracle with the ZK
# flavor; the SPEC requires the ZK flavor for every confidentiality claim,
# since the non-ZK flavor commits to the witness.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CIRCUITS_DIR="$PROJECT_ROOT/circuits"
VERIFIERS_DIR="$PROJECT_ROOT/contracts/src/verifiers"

mkdir -p "$VERIFIERS_DIR"

CIRCUITS=("deposit" "transfer" "withdraw" "withdraw_ungated")

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
done

echo "Compiling workspace..."
cd "$CIRCUITS_DIR"
nargo compile --workspace
cd "$PROJECT_ROOT"
echo ""

for circuit in "${CIRCUITS[@]}"; do
    CIRCUIT_DIR="$CIRCUITS_DIR/$circuit"
    PACKAGE_NAME="spc_${circuit}"

    echo "Processing $circuit circuit..."
    cd "$CIRCUIT_DIR"

    # bb prove -t evm requires bb write_vk -t evm to have run first; skipping
    # write_vk produces a cryptic failure whose message varies by bb version.
    echo "  [1/2] Generating verification key..."
    bb write_vk -b "$CIRCUITS_DIR/target/${PACKAGE_NAME}.json" -o ./target -t evm

    CONTRACT_NAME=""
    IFS='_' read -ra PARTS <<< "$circuit"
    for part in "${PARTS[@]}"; do
        CONTRACT_NAME+="$(echo "${part:0:1}" | tr '[:lower:]' '[:upper:]')${part:1}"
    done
    CONTRACT_NAME+="Verifier"
    OUTPUT_FILE="$VERIFIERS_DIR/${CONTRACT_NAME}.sol"

    echo "  [2/2] Generating Solidity verifier: $CONTRACT_NAME"
    bb write_solidity_verifier -k ./target/vk -o "$OUTPUT_FILE" -t evm

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

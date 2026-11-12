#!/usr/bin/env bash
# Generate Solidity verifiers from Noir circuits.
# Requires: nargo, bb (barretenberg CLI)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CIRCUITS_DIR="$PROJECT_ROOT/circuits"
VERIFIERS_DIR="$PROJECT_ROOT/contracts/src/verifiers"

mkdir -p "$VERIFIERS_DIR"

echo "=== Generating Solidity Verifiers ==="
echo "Circuits directory: $CIRCUITS_DIR"
echo "Output directory: $VERIFIERS_DIR"
echo ""

# Inner (signer) circuit: target noir-recursive so the batch
# circuit can recursively verify the signer proofs in-circuit. No
# Solidity verifier is generated for signer since it is never verified
# on chain directly.
echo "Processing signer circuit (inner, recursive target)..."
cd "$CIRCUITS_DIR/signer"
nargo compile
bb write_vk -b "$CIRCUITS_DIR/target/rcp_signer.json" -o ./target -t noir-recursive
echo "  signer VK (recursive) written to circuits/signer/target/vk"
cd "$PROJECT_ROOT"
echo ""

# Outer circuits: target evm (Keccak oracle, ZK flavor), to generate Solidity
# verifier contracts; `--optimized` is the assembly verifier for that same ZK
# flavor. They are deployed by Deploy.s.sol.
for circuit in "batch" "resolution"; do
    CIRCUIT_DIR="$CIRCUITS_DIR/$circuit"
    PACKAGE_NAME="rcp_${circuit}"
    echo "Processing $circuit circuit (outer, EVM target)..."
    cd "$CIRCUIT_DIR"
    nargo compile
    bb write_vk -b "$CIRCUITS_DIR/target/${PACKAGE_NAME}.json" -o ./target -t evm

    CONTRACT_NAME="$(echo "${circuit:0:1}" | tr '[:lower:]' '[:upper:]')${circuit:1}Verifier"
    OUTPUT_FILE="$VERIFIERS_DIR/${CONTRACT_NAME}.sol"
    bb write_solidity_verifier -k ./target/vk -o "$OUTPUT_FILE" -t evm --optimized
    echo "  $CONTRACT_NAME -> $OUTPUT_FILE"
    cd "$PROJECT_ROOT"
    echo ""
done

echo "=== All verifiers generated successfully ==="
echo ""
echo "Generated files:"
for circuit in "batch" "resolution"; do
    CONTRACT_NAME="$(echo "${circuit:0:1}" | tr '[:lower:]' '[:upper:]')${circuit:1}Verifier"
    echo "  - $VERIFIERS_DIR/${CONTRACT_NAME}.sol"
done

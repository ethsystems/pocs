#!/bin/bash
# Generate Solidity verifiers from the EVM-targeted Noir circuits.
#
# Five circuits are verified on-chain: deposit, the two spend circuits (transfer,
# withdraw), and the relayer insertion proof at both leaf counts — `insertion`
# (k=2, a 2-in transfer) and `insertion_withdraw` (k=1, a 1-in withdraw), two thin
# instantiations of the shared `insertion_core` logic. The chain-update circuit is
# consumed recursively off-chain (no Solidity verifier).
#
# VK generation needs only the compiled circuit, not a witness, so there is no
# Prover.toml / `nargo execute` step. Each verifier is emitted as bb's default
# `HonkVerifier`; forge disambiguates the same-named contracts by file path, and
# `ShieldedPoolExt` takes verifier *addresses*, so the contract names need not be
# unique.
#
# Always -t evm (keccak, ZK). `--optimized` selects the assembly verifier for
# that same ZK flavor: same proof, less gas.
#
# Requires nargo 1.0.0 + bb 6.0.0 on PATH (see README).
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGET_DIR="$PROJECT_ROOT/target"
VERIFIERS_DIR="$PROJECT_ROOT/contracts/src/verifiers"

mkdir -p "$VERIFIERS_DIR"

CIRCUITS=("deposit" "transfer" "withdraw" "insertion" "insertion_withdraw")

echo "=== Generating Solidity Verifiers ==="
echo "Output directory: $VERIFIERS_DIR"
echo ""

echo "Compiling circuits..."
(cd "$PROJECT_ROOT" && nargo compile --workspace)
echo ""

for circuit in "${CIRCUITS[@]}"; do
    echo "Processing $circuit circuit..."

    VK_DIR="$TARGET_DIR/vk_${circuit}"
    rm -rf "$VK_DIR"

    echo "  [1/2] Generating verification key (-t evm: keccak, ZK)..."
    bb write_vk -b "$TARGET_DIR/${circuit}.json" -o "$VK_DIR" -t evm

    # Default: capitalize the package name (deposit -> DepositVerifier). The k=1
    # insertion circuit maps to the contract's `withdrawInsertionVerifier` slot.
    case "$circuit" in
    insertion_withdraw) CONTRACT_NAME="WithdrawInsertionVerifier" ;;
    *) CONTRACT_NAME="$(echo ${circuit:0:1} | tr '[:lower:]' '[:upper:]')${circuit:1}Verifier" ;;
    esac
    OUTPUT_FILE="$VERIFIERS_DIR/${CONTRACT_NAME}.sol"

    echo "  [2/2] Generating Solidity verifier: $OUTPUT_FILE"
    bb write_solidity_verifier -k "$VK_DIR/vk" -o "$OUTPUT_FILE" -t evm --optimized

    echo "  Done: $OUTPUT_FILE"
    echo ""
done

echo "=== All verifiers generated successfully ==="

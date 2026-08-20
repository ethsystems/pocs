// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Test} from "forge-std/src/Test.sol";
import {HonkVerifier, Errors, P} from "../src/verifiers/WithdrawVerifier.sol";

/// @title Nullifier field-modulus aliasing — proof-of-concept / regression test
/// @notice Audit finding: `shieldedpool-missing-field-modulus-range-check` (Critical).
///
/// The pool stores a nullifier as a raw bytes32 key, while the ZK verifier reads the
/// same public input modulo the BN254 scalar field `P`. For a real nullifier `N`, the
/// distinct raw values `N`, `N+P`, `N+2P`, ... all reduce to `N`. If the verifier accepted
/// an out-of-range encoding, a participant could spend one note under several distinct
/// raw keys (double-spend / in-pool minting).
///
/// This test pins down whether the generated verifier rejects the `N+P` encoding. The
/// current Barretenberg codegen (bb 5.x, `-t evm`) emits, on the verify() path, in
/// generateEtaChallenge:
///     require(uint256(publicInputs[i]) < P, Errors.ValueGeFieldOrder());
/// which reverts before the sumcheck. This test is a regression guard: if a future
/// verifier regeneration (or a swapped verifier via ShieldedPool.setVerifier) drops that
/// check, `test_nullifierPlusP_isRejected` fails and flags the reopened hole.
///
/// Fixtures are a real withdraw proof over the committed circuits/withdraw/Prover.toml.
/// Regenerate after any circuit/toolchain change with:
///   nargo execute witness --package withdraw
///   bb prove -b target/withdraw.json -w target/witness.gz --write_vk -t evm \
///     -o contracts/test/fixtures/withdraw    # keep proof + public_inputs
///
/// Public input order (circuits/withdraw/src/main.nr): [0]=nullifier, [1]=token,
/// [2]=amount, [3]=recipient, [4]=commitment_root.
contract WithdrawVerifierAliasingTest is Test {
    HonkVerifier internal verifier;
    bytes internal proof;
    bytes32[] internal publicInputs;

    uint256 internal constant NULLIFIER_INDEX = 0;

    function setUp() public {
        verifier = new HonkVerifier();
        proof = vm.readFileBinary("contracts/test/fixtures/withdraw/proof");

        bytes memory raw = vm.readFileBinary("contracts/test/fixtures/withdraw/public_inputs");
        require(raw.length % 32 == 0, "malformed public_inputs fixture");
        uint256 n = raw.length / 32;
        publicInputs = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            bytes32 word;
            // solhint-disable-next-line no-inline-assembly
            assembly {
                word := mload(add(add(raw, 0x20), mul(i, 0x20)))
            }
            publicInputs[i] = word;
        }
    }

    /// Baseline: the honest proof with the canonical nullifier N (< P) verifies.
    function test_canonicalNullifier_verifies() public view {
        assertTrue(uint256(publicInputs[NULLIFIER_INDEX]) < P, "fixture nullifier must be canonical");
        assertTrue(verifier.verify(proof, publicInputs), "honest proof should verify");
    }

    /// PoC: the aliased encoding N+P (same field element, different raw bytes) is rejected
    /// by the verifier's range check. Without this check the pool would accept it as a
    /// second, distinct nullifier key for the same note.
    function test_nullifierPlusP_isRejected() public {
        uint256 n = uint256(publicInputs[NULLIFIER_INDEX]);
        // N < P and P < 2^254, so N + P does not overflow uint256.
        publicInputs[NULLIFIER_INDEX] = bytes32(n + P);
        assertEq((n + P) % P, n, "N+P must reduce to N (aliasing precondition)");

        vm.expectRevert(Errors.ValueGeFieldOrder.selector);
        verifier.verify(proof, publicInputs);
    }
}

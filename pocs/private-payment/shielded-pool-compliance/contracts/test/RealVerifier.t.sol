// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/src/Test.sol";
import {HonkVerifier} from "../src/verifiers/DepositVerifier.sol";

/// @title RealVerifierTest
/// @notice Verifies a real UltraHonk proof against the real generated verifier. Every
///         other test in this suite runs against accepting mocks, so this is the only
///         place the proving and verifying halves of the PoC meet.
/// @dev The fixture is written by `cargo run --release --example wallet_prove_check`
///      from a witness the `Wallet` actor built, not a hand-assembled one.
///      Regenerating the verifiers changes the VK and invalidates it.
contract RealVerifierTest is Test {
    HonkVerifier public verifier;
    bytes public proof;
    bytes32[] public publicInputs;

    function setUp() public {
        verifier = new HonkVerifier();

        string memory json = vm.readFile("contracts/test/fixtures/deposit_proof.json");
        proof = vm.parseJsonBytes(json, ".proof");
        publicInputs = vm.parseJsonBytes32Array(json, ".publicInputs");
    }

    function test_RealDepositProofVerifies() public view {
        assertTrue(verifier.verify(proof, publicInputs), "real deposit proof must verify");
    }

    /// @dev Without this the passing test above proves only that the verifier accepts,
    ///      not that it discriminates.
    function test_TamperedProofDoesNotVerify() public view {
        bytes memory tampered = proof;
        tampered[tampered.length - 1] = bytes1(uint8(tampered[tampered.length - 1]) ^ 0x01);

        try verifier.verify(tampered, publicInputs) returns (bool ok) {
            assertFalse(ok, "tampered proof must not verify");
        } catch {}
    }

    function test_TamperedPublicInputDoesNotVerify() public view {
        bytes32[] memory tampered = publicInputs;
        tampered[0] = bytes32(uint256(tampered[0]) + 1);

        try verifier.verify(proof, tampered) returns (bool ok) {
            assertFalse(ok, "proof must not verify against a different public input");
        } catch {}
    }
}

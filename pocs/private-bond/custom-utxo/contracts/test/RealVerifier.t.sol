// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {PrivateBond, BondPublicInputs} from "../src/PrivateBond.sol";
import {HonkVerifier} from "../src/Verifier.sol";

/// @title RealVerifierTest
/// @notice Runs a real proof of `circuits/Fixture.toml` through the real HonkVerifier and
///         PrivateBond. Every other test runs against a mock verifier, so this is the only
///         place the circuit, the generated verifier and the contract's input order meet.
/// @dev `scripts/generate-verifiers.sh` writes the fixture with the wallet's `bb prove`
///      flags. Regenerating the verifier changes the VK and invalidates the fixture, so the
///      script rewrites both.
contract RealVerifierTest is Test {
    HonkVerifier public verifier;
    PrivateBond public privateBond;
    bytes public proof;
    bytes32[] public publicInputs;

    // The optimized verifier reverts with this selector but declares no error type to import
    bytes4 constant SUMCHECK_FAILED = bytes4(keccak256("SumcheckFailed()"));

    // The only leaf of the tree Fixture.toml proves against: the real note in input 0. Input 1
    // is wallet padding (zero value, fresh salt), which the circuit does not look up in the tree.
    bytes32 constant LEAF_0 = 0x1b581e24c1c9b2e04edd33bf1cf87dc2626a40cf3089b8cb8636db30f5610b89;

    function setUp() public {
        verifier = new HonkVerifier();
        privateBond = new PrivateBond(keccak256("US0378331005"), address(verifier), address(this));

        string memory json = vm.readFile("test/fixtures/transfer_proof.json");
        proof = vm.parseJsonBytes(json, ".proof");
        publicInputs = vm.parseJsonBytes32Array(json, ".publicInputs");

        // buildMerkleRoot only matches the circuit's height-3, zero-padded root when the
        // tree holds exactly 8 leaves, so mint LEAF_0 and seven empty leaves
        bytes32[] memory leaves = new bytes32[](8);
        leaves[0] = LEAF_0;
        privateBond.mintBatch(leaves);
    }

    function _transfer(bytes32 maturityDate) internal {
        privateBond.transfer(
            proof,
            publicInputs[BondPublicInputs.ROOT],
            [publicInputs[BondPublicInputs.NULLIFIER_0], publicInputs[BondPublicInputs.NULLIFIER_1]],
            [publicInputs[BondPublicInputs.COMMITMENT_0], publicInputs[BondPublicInputs.COMMITMENT_1]],
            maturityDate
        );
    }

    function test_RealTransferProofVerifies() public view {
        assertEq(publicInputs.length, BondPublicInputs.LENGTH);
        assertTrue(verifier.verify(proof, publicInputs), "real transfer proof must verify");
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
        tampered[BondPublicInputs.ROOT] = bytes32(uint256(tampered[BondPublicInputs.ROOT]) + 1);

        try verifier.verify(proof, tampered) returns (bool ok) {
            assertFalse(ok, "proof must not verify against a different public input");
        } catch {}
    }

    function test_ContractRootMatchesProofRoot() public view {
        assertEq(privateBond.buildMerkleRoot(), publicInputs[BondPublicInputs.ROOT]);
    }

    function test_TransferAcceptsRealProof() public {
        _transfer(publicInputs[BondPublicInputs.INPUT_MATURITY_DATE]);

        assertTrue(privateBond.nullifiers(publicInputs[BondPublicInputs.NULLIFIER_0]));
        assertTrue(privateBond.nullifiers(publicInputs[BondPublicInputs.NULLIFIER_1]));
        assertEq(privateBond.commitments(8), publicInputs[BondPublicInputs.COMMITMENT_0]);
        assertEq(privateBond.commitments(9), publicInputs[BondPublicInputs.COMMITMENT_1]);
    }

    // The maturity date is bound by the proof: the verifier rejects it, not a contract check
    function test_TransferRejectsWrongMaturityDate() public {
        bytes32 wrongDate = bytes32(uint256(publicInputs[BondPublicInputs.INPUT_MATURITY_DATE]) + 1);

        vm.expectRevert(SUMCHECK_FAILED);
        _transfer(wrongDate);
    }

    // burn sets the redeem flag to 1, so a transfer proof (outputs carry value) cannot redeem
    function test_BurnRejectsTransferProof() public {
        vm.warp(uint256(publicInputs[BondPublicInputs.INPUT_MATURITY_DATE]));

        vm.expectRevert(SUMCHECK_FAILED);
        privateBond.burn(
            proof,
            publicInputs[BondPublicInputs.ROOT],
            [publicInputs[BondPublicInputs.NULLIFIER_0], publicInputs[BondPublicInputs.NULLIFIER_1]],
            [publicInputs[BondPublicInputs.COMMITMENT_0], publicInputs[BondPublicInputs.COMMITMENT_1]],
            publicInputs[BondPublicInputs.INPUT_MATURITY_DATE]
        );
    }
}

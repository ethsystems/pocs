// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/src/Test.sol";
import {BindingMockVerifier} from "../src/mocks/BindingMockVerifier.sol";

contract BindingMockVerifierTest is Test {
    /// @dev The Rust `MockProver`'s proof for the withdraw circuit over the
    ///      public inputs 1 to 10 (`mock_prover.rs`,
    ///      `a_mock_proof_matches_the_binding_verifier`).
    bytes32 constant RUST_PROOF = 0x26e0c7ad3a714fd2d4f1a046f2ac4ca65a023f715edf4090c0cf2501c6f0c3e5;

    function _inputs() internal pure returns (bytes32[] memory inputs) {
        inputs = new bytes32[](10);
        for (uint256 i = 0; i < 10; i++) {
            inputs[i] = bytes32(i + 1);
        }
    }

    function testAcceptsTheRustProverProof() public {
        BindingMockVerifier withdraw = new BindingMockVerifier(2);
        assertTrue(withdraw.verify(abi.encodePacked(RUST_PROOF), _inputs()));
    }

    function testRefusesOtherInputsCircuitsAndLengths() public {
        BindingMockVerifier withdraw = new BindingMockVerifier(2);
        bytes32[] memory changed = _inputs();
        changed[9] = bytes32(uint256(11));
        assertFalse(withdraw.verify(abi.encodePacked(RUST_PROOF), changed));
        assertFalse(new BindingMockVerifier(1).verify(abi.encodePacked(RUST_PROOF), _inputs()));
        assertFalse(withdraw.verify(abi.encodePacked(RUST_PROOF, bytes1(0)), _inputs()));
        assertFalse(withdraw.verify("", _inputs()));
    }
}

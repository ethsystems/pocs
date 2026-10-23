// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IUltraVerifier} from "../interfaces/IUltraVerifier.sol";

/// @title BindingMockVerifier
/// @notice Stands in for one circuit's verifier in local runs with mock proofs.
///         It accepts only a mock proof made for exactly the public inputs the
///         pool assembled: keccak256 of a domain tag, the circuit and those
///         inputs, which the Rust `MockProver` computes from the witness. A
///         layout that differs between Rust and the pool, or a value the pool
///         fills in from its state that the witness did not use, fails under
///         mocks as it would against the generated verifier. The circuit's own
///         rules are not checked.
contract BindingMockVerifier is IUltraVerifier {
    /// @notice The circuit, with the Rust prover's tags: 0 deposit, 1 transfer,
    ///         2 withdraw.
    uint8 public immutable CIRCUIT;

    constructor(uint8 circuit) {
        CIRCUIT = circuit;
    }

    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view override returns (bool) {
        return proof.length == 32
            && bytes32(proof) == keccak256(abi.encodePacked("shielded-notes mock proof", CIRCUIT, publicInputs));
    }
}

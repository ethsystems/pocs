// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IVerifier
/// @notice Pool-facing composite abstraction over the three gated circuit
///         verifiers, so ShieldedPool holds a single verifier address per policy
///         version. The ungated withdraw path is routed separately.
interface IVerifier {
    /// @notice `publicInputs` in `DepositPublicInputs` order
    function verifyDeposit(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);

    /// @notice `publicInputs` in `TransferPublicInputs` order
    function verifyTransfer(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);

    /// @notice `publicInputs` in `WithdrawPublicInputs` order
    function verifyWithdraw(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);
}

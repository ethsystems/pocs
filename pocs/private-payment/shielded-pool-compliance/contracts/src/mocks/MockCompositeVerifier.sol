// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IVerifier} from "../interfaces/IVerifier.sol";

/// @title MockCompositeVerifier
/// @notice Configurable stand-in for `CompositeVerifier`, one result flag per
///         gated path, so a pool test can force either outcome per operation.
contract MockCompositeVerifier is IVerifier {
    bool public depositResult = true;
    bool public transferResult = true;
    bool public withdrawResult = true;

    function setDepositResult(bool newResult) external {
        depositResult = newResult;
    }

    function setTransferResult(bool newResult) external {
        transferResult = newResult;
    }

    function setWithdrawResult(bool newResult) external {
        withdrawResult = newResult;
    }

    function verifyDeposit(bytes calldata, bytes32[] calldata) external view override returns (bool) {
        return depositResult;
    }

    function verifyTransfer(bytes calldata, bytes32[] calldata) external view override returns (bool) {
        return transferResult;
    }

    function verifyWithdraw(bytes calldata, bytes32[] calldata) external view override returns (bool) {
        return withdrawResult;
    }
}

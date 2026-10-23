// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IVerifier} from "./interfaces/IVerifier.sol";
import {IUltraVerifier} from "./interfaces/IUltraVerifier.sol";

/// @title CompositeVerifier
/// @notice Routes the three circuit verification calls to their own
///         `bb`-generated verifiers. Its three slots are immutable, so changing
///         any circuit is a new deployment routed through `ShieldedPool.setVerifier`.
contract CompositeVerifier is IVerifier {
    IUltraVerifier public immutable DEPOSIT_VERIFIER;
    IUltraVerifier public immutable TRANSFER_VERIFIER;
    IUltraVerifier public immutable WITHDRAW_VERIFIER;

    error ZeroAddress();
    error NoCode();

    /// @dev A slot without code would fail every proof of its circuit, or, if
    ///      code were later placed at that address, route to whatever it is.
    constructor(address depositVerifier_, address transferVerifier_, address withdrawVerifier_) {
        if (depositVerifier_ == address(0) || transferVerifier_ == address(0) || withdrawVerifier_ == address(0)) {
            revert ZeroAddress();
        }
        if (
            depositVerifier_.code.length == 0 || transferVerifier_.code.length == 0
                || withdrawVerifier_.code.length == 0
        ) revert NoCode();
        DEPOSIT_VERIFIER = IUltraVerifier(depositVerifier_);
        TRANSFER_VERIFIER = IUltraVerifier(transferVerifier_);
        WITHDRAW_VERIFIER = IUltraVerifier(withdrawVerifier_);
    }

    function verifyDeposit(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool) {
        return DEPOSIT_VERIFIER.verify(proof, publicInputs);
    }

    function verifyTransfer(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool) {
        return TRANSFER_VERIFIER.verify(proof, publicInputs);
    }

    function verifyWithdraw(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool) {
        return WITHDRAW_VERIFIER.verify(proof, publicInputs);
    }
}

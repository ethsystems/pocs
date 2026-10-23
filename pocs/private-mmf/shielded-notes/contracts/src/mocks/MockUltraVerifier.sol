// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IUltraVerifier} from "../interfaces/IUltraVerifier.sol";

/// @title MockUltraVerifier
/// @notice Configurable stand-in for one `bb`-generated circuit verifier.
///         Defaults to accepting.
contract MockUltraVerifier is IUltraVerifier {
    bool public result = true;

    function setResult(bool newResult) external {
        result = newResult;
    }

    function verify(bytes calldata, bytes32[] calldata) external view override returns (bool) {
        return result;
    }
}

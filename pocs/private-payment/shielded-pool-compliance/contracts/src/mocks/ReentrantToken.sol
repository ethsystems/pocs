// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC20} from "@openzeppelin-contracts/token/ERC20/ERC20.sol";

/// @title ReentrantToken
/// @notice ERC20 with a transfer hook that re-enters a configured target once
///         per armed transfer. Exists to prove a pool that inserts commitments
///         and emits before its token transfer cannot have a reentrant call
///         interleave a leaf ahead of the outer call's event: with the correct
///         order plus `nonReentrant`, the nested call below MUST fail, and this
///         contract records that outcome instead of reverting on it, so the
///         outer transaction can complete and a test can inspect both sides.
contract ReentrantToken is ERC20 {
    address public target;
    bytes public reentrantCalldata;
    bool public armed;

    bool public reentrancyAttempted;
    bool public reentrancySucceeded;

    constructor(string memory name_, string memory symbol_) ERC20(name_, symbol_) {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    /// @param target_ contract to call back into during the next transfer
    /// @param data the calldata to re-enter with
    /// @param armed_ whether the next transfer triggers the callback
    function setReentrancy(address target_, bytes calldata data, bool armed_) external {
        target = target_;
        reentrantCalldata = data;
        armed = armed_;
        reentrancyAttempted = false;
        reentrancySucceeded = false;
    }

    function _update(address from, address to, uint256 value) internal override {
        super._update(from, to, value);

        if (armed && target != address(0)) {
            armed = false;
            reentrancyAttempted = true;
            (bool ok,) = target.call(reentrantCalldata);
            reentrancySucceeded = ok;
        }
    }
}

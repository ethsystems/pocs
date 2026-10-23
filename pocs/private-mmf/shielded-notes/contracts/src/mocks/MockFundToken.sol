// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC20} from "@openzeppelin-contracts/token/ERC20/ERC20.sol";

/// @title MockFundToken
/// @notice A minimal permissioned fund share token standing in for the issuer's
///         token: an allowlist, a per-holder balance limit, issuer mint and burn,
///         a forced transfer (an administrative power), and a daily reinvestment
///         that mints yield to holders as new shares. 6 decimals, USD 1 NAV.
/// @dev SPEC, Public Token Requirements: the pool is registered as a holder
///      (allowlisted), exempt from the balance limit, and, when `adminExempt`,
///      exempt from the administrative powers modelled here, forced transfer
///      and burn. Leaving the pool out of `adminExempt` models the policy
///      fallback, where such a power can halt the pool. Ordinary transfers need
///      both sides allowlisted; administrative ones do not.
contract MockFundToken is ERC20 {
    address public immutable issuer;
    uint256 public maxBalance;

    mapping(address => bool) public allowlisted;
    mapping(address => bool) public limitExempt;
    mapping(address => bool) public adminExempt;

    /// @dev Set during a forced transfer, which moves shares from a holder
    ///      whatever its standing.
    bool private _adminTransfer;

    error NotIssuer();
    error NotAllowlisted(address holder);
    error BalanceLimitExceeded(address holder);
    error AdminExempt(address holder);

    modifier onlyIssuer() {
        if (msg.sender != issuer) revert NotIssuer();
        _;
    }

    constructor(string memory name_, string memory symbol_, address issuer_, uint256 maxBalance_)
        ERC20(name_, symbol_)
    {
        issuer = issuer_;
        maxBalance = maxBalance_;
    }

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    function setAllowlisted(address holder, bool value) external onlyIssuer {
        allowlisted[holder] = value;
    }

    function setLimitExempt(address holder, bool value) external onlyIssuer {
        limitExempt[holder] = value;
    }

    function setAdminExempt(address holder, bool value) external onlyIssuer {
        adminExempt[holder] = value;
    }

    function setMaxBalance(uint256 value) external onlyIssuer {
        maxBalance = value;
    }

    /// @notice Public-side issuance against settled cash.
    function mint(address to, uint256 amount) external onlyIssuer {
        _mint(to, amount);
    }

    /// @notice Public-side redemption: the agent burns the shares it withdrew.
    ///         Also an administrative power, so an exempt holder cannot be burnt.
    function burn(address from, uint256 amount) external onlyIssuer {
        if (adminExempt[from]) revert AdminExempt(from);
        _burn(from, amount);
    }

    /// @notice An administrative power. Used on the pool, it lowers the
    ///         multiplier for every note and halts the pool.
    function forceTransfer(address from, address to, uint256 amount) external onlyIssuer {
        if (adminExempt[from]) revert AdminExempt(from);
        _adminTransfer = true;
        _transfer(from, to, amount);
        _adminTransfer = false;
    }

    /// @notice Daily reinvestment: mints each holder's yield as new shares, at
    ///         `rateWad` (1e18 = 100%) of its balance. The pool is one holder, so
    ///         its balance grows and the next deposit or withdrawal reads a
    ///         higher multiplier.
    function reinvest(address[] calldata holders, uint256 rateWad) external onlyIssuer {
        for (uint256 i = 0; i < holders.length; i++) {
            _mint(holders[i], balanceOf(holders[i]) * rateWad / 1e18);
        }
    }

    function _update(address from, address to, uint256 value) internal override {
        super._update(from, to, value);
        if (to == address(0)) return;
        if (from != address(0) && !_adminTransfer && !allowlisted[from]) revert NotAllowlisted(from);
        if (!allowlisted[to]) revert NotAllowlisted(to);
        if (!limitExempt[to] && balanceOf(to) > maxBalance) revert BalanceLimitExceeded(to);
    }
}

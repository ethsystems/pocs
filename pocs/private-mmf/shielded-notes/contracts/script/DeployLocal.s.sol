// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {console} from "forge-std/src/Script.sol";
import {DeployBase} from "./DeployBase.s.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {MockFundToken} from "../src/mocks/MockFundToken.sol";
import {BindingMockVerifier} from "../src/mocks/BindingMockVerifier.sol";

/// @title DeployLocal
/// @notice The local stack for the tests, on the local chain only: the mock
///         fund token, with the broadcaster as its issuer, the pool as `Deploy`
///         builds it, and the pool registered on the token as an allowlisted
///         holder exempt from the balance limit and, unless `pool_admin_exempt`
///         is false, from forced transfers. `use_mock_verifier` swaps the three
///         circuit verifiers for `BindingMockVerifier`s; the composite verifier
///         in front of them is real either way, so its routing is exercised in
///         both modes.
contract DeployLocal is DeployBase {
    function run() public {
        require(block.chainid == 31337, "DeployLocal deploys mocks, so only to the local chain");
        _loadConfig("./deployments.toml", false);

        bool useMockVerifier = config.get("use_mock_verifier").toBool();
        Verifiers memory reused;
        if (!useMockVerifier) reused = _checkedReusedVerifiers();

        vm.startBroadcast();

        MockFundToken token =
            new MockFundToken("Mock Fund Shares", "mMMF", msg.sender, config.get("max_balance").toUint256());
        console.log("MockFundToken:", address(token));

        Verifiers memory v = useMockVerifier ? _mockVerifiers() : _generatedVerifiers(reused);
        ShieldedPool pool = _deployPool(address(token), v);

        token.setAllowlisted(address(pool), true);
        token.setLimitExempt(address(pool), true);
        token.setAdminExempt(address(pool), config.get("pool_admin_exempt").toBool());

        vm.stopBroadcast();

        console.log("");
        console.log("=== Deployment Summary ===");
        console.log("Chain ID:", block.chainid);
        console.log("Mock verifiers:", useMockVerifier);
    }

    /// @dev Mocks that accept only the Rust mock prover's proof for the inputs
    ///      the pool assembles.
    function _mockVerifiers() internal returns (Verifiers memory v) {
        v.deposit = address(new BindingMockVerifier(0));
        v.transfer = address(new BindingMockVerifier(1));
        v.withdraw = address(new BindingMockVerifier(2));
    }
}

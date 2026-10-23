// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {console} from "forge-std/src/Script.sol";
import {DeployBase} from "./DeployBase.s.sol";

/// @title Deploy
/// @notice Deploys a pool for the fund's existing token (`token` in
///         `deployments.toml`): the registry, the three generated circuit
///         verifiers, or ones a `DeployVerifiers` run deployed once their code
///         checks out, the composite verifier and the pool. It deploys no mock:
///         a mock verifier accepts proofs anyone can make, and the mock token
///         is not the fund's. The token's issuer then registers the pool as
///         the SPEC requires (Public Token Requirements), and the transfer
///         agent seeds it before attesting any investor.
contract Deploy is DeployBase {
    function run() public {
        _loadConfig("./deployments.toml", false);

        address token = config.get("token").toAddress();
        require(token.code.length > 0, "the fund token has no code");
        Verifiers memory reused = _checkedReusedVerifiers();

        vm.startBroadcast();
        _deployPool(token, _generatedVerifiers(reused));
        vm.stopBroadcast();

        console.log("");
        console.log("=== Deployment Summary ===");
        console.log("Chain ID:", block.chainid);
        console.log("Token:", token);
        console.log("Next: the issuer allowlists the pool and exempts it from the balance limit and forced transfers;");
        console.log("then the transfer agent seeds the pool, before attesting any investor.");
    }
}

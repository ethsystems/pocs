// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/src/Script.sol";
import {Config} from "forge-std/src/Config.sol";
import {AttestationRegistry} from "../src/AttestationRegistry.sol";
import {CompositeVerifier} from "../src/CompositeVerifier.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {MockERC20} from "../src/mocks/MockERC20.sol";
import {MockUltraVerifier} from "../src/mocks/MockUltraVerifier.sol";
import {HonkVerifier as DepositHonkVerifier} from "../src/verifiers/DepositVerifier.sol";
import {HonkVerifier as TransferHonkVerifier} from "../src/verifiers/TransferVerifier.sol";
import {HonkVerifier as WithdrawHonkVerifier} from "../src/verifiers/WithdrawVerifier.sol";
import {HonkVerifier as WithdrawUngatedHonkVerifier} from "../src/verifiers/WithdrawUngatedVerifier.sol";

/// @title Deploy
/// @notice Deploys the full stack. `use_mock_verifier` swaps the four circuit
///         verifiers for accepting mocks; the `CompositeVerifier` in front of them
///         is real either way, so its routing is exercised in both modes.
/// @dev The `console.log` labels below are parsed by the Rust integration harness.
///      They are an interface: do not reword them.
contract Deploy is Script, Config {
    /// @dev Verifier addresses resolved before the pool is constructed. Grouped to
    ///      keep `run` under the stack slot limit.
    struct Verifiers {
        address deposit;
        address transfer;
        address withdraw;
        address withdrawUngated;
    }

    function run() public {
        _loadConfig("./deployments.toml", true);

        bool useMockVerifier = config.get("use_mock_verifier").toBool();

        vm.startBroadcast();

        MockERC20 token = new MockERC20("Mock USDC", "mUSDC", 6);
        console.log("MockERC20:", address(token));

        AttestationRegistry registry = new AttestationRegistry(
            config.get("epoch_seconds").toUint256(),
            config.get("max_attestation_epochs").toUint256(),
            config.get("min_cohort_size").toUint256(),
            config.get("governance").toAddress(),
            config.get("timelock_controller").toAddress(),
            config.get("overlap_epochs").toUint256()
        );
        console.log("AttestationRegistry:", address(registry));

        Verifiers memory v = _resolveVerifiers(useMockVerifier);

        CompositeVerifier composite = new CompositeVerifier(v.deposit, v.transfer, v.withdraw);
        console.log("CompositeVerifier:", address(composite));

        ShieldedPool pool = new ShieldedPool(_poolParams(address(token), address(registry), address(composite), v));
        console.log("ShieldedPool:", address(pool));

        vm.stopBroadcast();

        config.set("mock_token_address", address(token));
        config.set("attestation_registry_address", address(registry));
        config.set("composite_verifier_address", address(composite));
        config.set("deposit_verifier_address", v.deposit);
        config.set("transfer_verifier_address", v.transfer);
        config.set("withdraw_verifier_address", v.withdraw);
        config.set("withdraw_ungated_verifier_address", v.withdrawUngated);
        config.set("shielded_pool_address", address(pool));

        console.log("");
        console.log("=== Deployment Summary ===");
        console.log("Chain ID:", block.chainid);
        console.log("Mock verifiers:", useMockVerifier);
    }

    /// @dev Reuses a configured verifier when it is nonzero, so a prior
    ///      `DeployVerifiers` run is not repeated. Mock mode always deploys fresh,
    ///      since a configured address is a real verifier.
    function _resolveVerifiers(bool useMockVerifier) internal returns (Verifiers memory v) {
        if (useMockVerifier) {
            v.deposit = address(new MockUltraVerifier());
            v.transfer = address(new MockUltraVerifier());
            v.withdraw = address(new MockUltraVerifier());
            v.withdrawUngated = address(new MockUltraVerifier());
        } else {
            v.deposit = config.get("deposit_verifier_address").toAddress();
            if (v.deposit == address(0)) v.deposit = address(new DepositHonkVerifier());

            v.transfer = config.get("transfer_verifier_address").toAddress();
            if (v.transfer == address(0)) v.transfer = address(new TransferHonkVerifier());

            v.withdraw = config.get("withdraw_verifier_address").toAddress();
            if (v.withdraw == address(0)) v.withdraw = address(new WithdrawHonkVerifier());

            v.withdrawUngated = config.get("withdraw_ungated_verifier_address").toAddress();
            if (v.withdrawUngated == address(0)) v.withdrawUngated = address(new WithdrawUngatedHonkVerifier());
        }

        console.log("DepositVerifier:", v.deposit);
        console.log("TransferVerifier:", v.transfer);
        console.log("WithdrawVerifier:", v.withdraw);
        console.log("WithdrawUngatedVerifier:", v.withdrawUngated);
    }

    function _poolParams(address token, address registry, address composite, Verifiers memory v)
        internal
        view
        returns (ShieldedPool.ConstructorParams memory)
    {
        return ShieldedPool.ConstructorParams({
            token: token,
            attestationRegistry: registry,
            initialVerifier: composite,
            initialPolicySourceHash: config.get("initial_policy_source_hash").toBytes32(),
            ungatedWithdrawVerifier: v.withdrawUngated,
            blockedFundsAccount: config.get("blocked_funds_account").toAddress(),
            singleTxThreshold: config.get("single_tx_threshold").toUint256(),
            epochSeconds: config.get("epoch_seconds").toUint256(),
            timelockDelaySeconds: config.get("timelock_delay_seconds").toUint256(),
            maxPauseEpochs: config.get("max_pause_epochs").toUint256(),
            maxBlockedExitPauseEpochs: config.get("max_blocked_exit_pause_epochs").toUint256(),
            pauseBudgetEpochs: config.get("pause_budget_epochs").toUint256(),
            pauseWindowEpochs: config.get("pause_window_epochs").toUint256(),
            timelockController: config.get("timelock_controller").toAddress(),
            guardian: config.get("guardian").toAddress(),
            curator: config.get("curator").toAddress(),
            committee: config.get("committee").toAddress()
        });
    }
}

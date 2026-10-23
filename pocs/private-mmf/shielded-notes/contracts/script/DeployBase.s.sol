// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/src/Script.sol";
import {Config} from "forge-std/src/Config.sol";
import {AttestationRegistry} from "../src/AttestationRegistry.sol";
import {CompositeVerifier} from "../src/CompositeVerifier.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {HonkVerifier as DepositHonkVerifier} from "../src/verifiers/DepositVerifier.sol";
import {HonkVerifier as TransferHonkVerifier} from "../src/verifiers/TransferVerifier.sol";
import {HonkVerifier as WithdrawHonkVerifier} from "../src/verifiers/WithdrawVerifier.sol";

/// @title DeployBase
/// @notice What `Deploy` and `DeployLocal` share: the registry, the composite
///         verifier in front of three circuit verifiers, and the pool, with
///         the parameters in `deployments.toml`. The config is read only:
///         nothing is written back, so its placeholders always come from the
///         environment. The deployed addresses are printed, and forge records
///         them under `contracts/broadcast/`.
/// @dev The `console.log` labels are parsed by the Rust integration harness.
///      They are an interface: do not reword them.
abstract contract DeployBase is Script, Config {
    struct Verifiers {
        address deposit;
        address transfer;
        address withdraw;
    }

    /// @dev The registry, the composite verifier in front of `v`, and the pool
    ///      for `token`.
    function _deployPool(address token, Verifiers memory v) internal returns (ShieldedPool pool) {
        AttestationRegistry registry = new AttestationRegistry(
            config.get("epoch_seconds").toUint256(),
            config.get("max_attestation_epochs").toUint256(),
            config.get("overlap_epochs").toUint256(),
            config.get("min_batch_size").toUint256(),
            config.get("transfer_agent").toAddress(),
            config.get("timelock_controller").toAddress()
        );
        console.log("AttestationRegistry:", address(registry));

        console.log("DepositVerifier:", v.deposit);
        console.log("TransferVerifier:", v.transfer);
        console.log("WithdrawVerifier:", v.withdraw);
        CompositeVerifier composite = new CompositeVerifier(v.deposit, v.transfer, v.withdraw);
        console.log("CompositeVerifier:", address(composite));

        pool = new ShieldedPool(_poolParams(token, address(registry), address(composite)));
        console.log("ShieldedPool:", address(pool));
    }

    /// @dev The configured verifier addresses, from a prior `DeployVerifiers`
    ///      run, each checked against a fresh build of its generated verifier.
    ///      Called before the broadcast, so the builds exist in the simulation
    ///      only. The constructors take no arguments, so the code is fixed: a
    ///      mock, or anything else, at a configured address reverts.
    function _checkedReusedVerifiers() internal returns (Verifiers memory r) {
        r.deposit = config.get("deposit_verifier_address").toAddress();
        if (r.deposit != address(0)) _requireSameCode(r.deposit, address(new DepositHonkVerifier()));

        r.transfer = config.get("transfer_verifier_address").toAddress();
        if (r.transfer != address(0)) _requireSameCode(r.transfer, address(new TransferHonkVerifier()));

        r.withdraw = config.get("withdraw_verifier_address").toAddress();
        if (r.withdraw != address(0)) _requireSameCode(r.withdraw, address(new WithdrawHonkVerifier()));
    }

    function _requireSameCode(address reused, address fresh) internal view {
        require(reused.codehash == fresh.codehash, "a reused verifier is not the generated one");
    }

    /// @dev The generated verifiers, each reused if `reused` names one.
    function _generatedVerifiers(Verifiers memory reused) internal returns (Verifiers memory v) {
        v.deposit = reused.deposit != address(0) ? reused.deposit : address(new DepositHonkVerifier());
        v.transfer = reused.transfer != address(0) ? reused.transfer : address(new TransferHonkVerifier());
        v.withdraw = reused.withdraw != address(0) ? reused.withdraw : address(new WithdrawHonkVerifier());
    }

    function _poolParams(address token, address registry, address composite)
        internal
        view
        returns (ShieldedPool.ConstructorParams memory)
    {
        return ShieldedPool.ConstructorParams({
            token: token,
            attestationRegistry: registry,
            verifier: composite,
            claimKeyHash: config.get("claim_key_hash").toBytes32(),
            transferAgent: config.get("transfer_agent").toAddress(),
            registerKeyX: config.get("register_key_x").toUint256(),
            registerKeyY: config.get("register_key_y").toUint256(),
            epochSeconds: config.get("epoch_seconds").toUint256(),
            maxPauseEpochs: config.get("max_pause_epochs").toUint256(),
            pauseBudgetEpochs: config.get("pause_budget_epochs").toUint256(),
            pauseWindowEpochs: config.get("pause_window_epochs").toUint256(),
            timelockController: config.get("timelock_controller").toAddress(),
            guardian: config.get("guardian").toAddress()
        });
    }
}

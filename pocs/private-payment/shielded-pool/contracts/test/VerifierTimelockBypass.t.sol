// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/src/Test.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {AttestationRegistry} from "../src/AttestationRegistry.sol";
import {IVerifier} from "../src/interfaces/IVerifier.sol";
import {MockERC20} from "../src/mocks/MockERC20.sol";

/// Rejects every proof. Stands in for the audited circuit verifier that holders
/// check when they see VerifierProposed.
contract RejectAllVerifier is IVerifier {
    function verifyDeposit(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        return false;
    }

    function verifyTransfer(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        return false;
    }

    function verifyWithdraw(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        return false;
    }
}

/// Accepts every proof. The attack payload: an owner who installs this can
/// withdraw against notes that were never deposited.
contract AcceptAllVerifier is IVerifier {
    function verifyDeposit(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        return true;
    }

    function verifyTransfer(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        return true;
    }

    function verifyWithdraw(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        return true;
    }
}

/// Regression tests for the two timelock bypasses from the PR 24 review.
/// Before the code hash pin, the proposal recorded only an address, so the
/// code holders checked during the delay was not necessarily the code that ran
/// after applyVerifier. Both attacks below drained the pool at d97ee6a.
contract VerifierTimelockBypassTest is Test {
    ShieldedPool public pool;
    AttestationRegistry public registry;
    RejectAllVerifier public honest;
    MockERC20 public token;

    address public attacker = address(0xBAD);
    uint256 constant POOL_BALANCE = 1000e6;

    function setUp() public {
        registry = new AttestationRegistry();
        honest = new RejectAllVerifier();
        pool = new ShieldedPool(address(honest), address(registry));
        token = new MockERC20("USD Coin", "USDC", 6);
        pool.addSupportedToken(address(token));
        // Depositors' funds. Minted directly so the honest verifier can stay
        // reject-all; how the funds got in does not matter to the attack.
        token.mint(address(pool), POOL_BALANCE);
    }

    /// Attack (a): the proposed address is an EIP-7702 delegating account.
    /// During the delay it delegates to an audited verifier, so holders check
    /// it and stay. Before applyVerifier the owner re-points the delegation at
    /// an accept-all verifier. The address is unchanged; the account code (and
    /// codehash) are not. vm.etch models the delegation re-point: under
    /// EIP-7702 the account's code is the designator 0xef0100 || target, so
    /// changing the target changes the code at the same address.
    function test_codeSwapAtProposedAddressIsRejected() public {
        RejectAllVerifier proposed = new RejectAllVerifier();
        pool.proposeVerifier(address(proposed));

        vm.warp(pool.verifierApplyTime());

        // Owner swaps the code behind the proposed address after the delay ran.
        AcceptAllVerifier payload = new AcceptAllVerifier();
        vm.etch(address(proposed), address(payload).code);

        vm.expectRevert(ShieldedPool.VerifierCodeChanged.selector);
        pool.applyVerifier();

        // The honest verifier is still installed and a garbage withdrawal fails.
        assertEq(address(pool.verifier()), address(honest));
        bytes32 root = pool.commitmentRoot();
        vm.expectRevert(ShieldedPool.InvalidProof.selector);
        pool.withdraw("", bytes32(uint256(100)), address(token), POOL_BALANCE, attacker, root);
        assertEq(token.balanceOf(address(pool)), POOL_BALANCE);
    }

    /// Attack (b): the proposed address is an empty CREATE2 address. Holders
    /// have no code to check during the whole delay. After the delay the owner
    /// deploys an accept-all verifier there and applies in the same breath.
    function test_emptyCreate2AddressIsRejected() public {
        bytes32 salt = keccak256("attack");
        address predicted =
            vm.computeCreate2Address(salt, keccak256(type(AcceptAllVerifier).creationCode), address(this));
        assertEq(predicted.code.length, 0);

        vm.expectRevert(ShieldedPool.VerifierHasNoCode.selector);
        pool.proposeVerifier(predicted);

        assertEq(pool.pendingVerifier(), address(0));
        assertEq(token.balanceOf(address(pool)), POOL_BALANCE);
    }
}

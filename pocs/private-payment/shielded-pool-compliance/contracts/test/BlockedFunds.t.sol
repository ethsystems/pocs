// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/src/Test.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {AttestationRegistry} from "../src/AttestationRegistry.sol";
import {MockERC20} from "../src/mocks/MockERC20.sol";
import {MockCompositeVerifier} from "../src/mocks/MockCompositeVerifier.sol";
import {MockUltraVerifier} from "../src/mocks/MockUltraVerifier.sol";

contract BlockedFundsTest is Test {
    ShieldedPool public pool;
    AttestationRegistry public registry;
    MockERC20 public token;
    MockCompositeVerifier public verifier;
    MockUltraVerifier public ungatedVerifier;

    uint256 constant EPOCH_SECONDS = 86400;

    address public timelockController = address(0x71);
    address public guardian = address(0x62);
    address public curator = address(0x63);
    address public committee = address(0x64);
    address public blockedFundsAccount = address(0x65);
    address public alice = address(0xA11CE);

    bytes32 public initialPolicySourceHash = bytes32(uint256(0xABCDEF));

    function setUp() public {
        vm.warp(1000 * EPOCH_SECONDS);

        token = new MockERC20("Test Token", "TT", 6);
        registry = new AttestationRegistry(EPOCH_SECONDS, 7, 1, address(this), address(this), 2);
        verifier = new MockCompositeVerifier();
        ungatedVerifier = new MockUltraVerifier();

        pool = new ShieldedPool(
            ShieldedPool.ConstructorParams({
                token: address(token),
                attestationRegistry: address(registry),
                initialVerifier: address(verifier),
                initialPolicySourceHash: initialPolicySourceHash,
                ungatedWithdrawVerifier: address(ungatedVerifier),
                blockedFundsAccount: blockedFundsAccount,
                singleTxThreshold: 10_000_000_000,
                epochSeconds: EPOCH_SECONDS,
                timelockDelaySeconds: 172_800,
                maxPauseEpochs: 14,
                maxBlockedExitPauseEpochs: 7,
                pauseBudgetEpochs: 30,
                pauseWindowEpochs: 90,
                timelockController: timelockController,
                guardian: guardian,
                curator: curator,
                committee: committee
            })
        );

        token.mint(address(pool), 1_000_000_000_000);
    }

    function _baseWithdrawBlocked(bytes32 nullifier, uint256 amount)
        internal
        view
        returns (ShieldedPool.WithdrawBlockedParams memory)
    {
        return ShieldedPool.WithdrawBlockedParams({
            proof: "",
            nullifier: nullifier,
            token: uint256(uint160(address(token))),
            amount: amount,
            recipient: alice,
            commitmentRoot: pool.commitmentRoot()
        });
    }

    // ========== withdrawBlocked ==========

    function testWithdrawBlockedCreditsBalance() public {
        ShieldedPool.WithdrawBlockedParams memory p = _baseWithdrawBlocked(bytes32(uint256(1)), 500);
        vm.prank(alice);
        pool.withdrawBlocked(p);

        assertEq(pool.blockedBalance(bytes32(uint256(1))), 500);
        assertTrue(pool.nullifiers(bytes32(uint256(1))));
    }

    function testWithdrawBlockedRevertsWrongToken() public {
        ungatedVerifier.setResult(false);
        ShieldedPool.WithdrawBlockedParams memory p = _baseWithdrawBlocked(bytes32(uint256(2)), 500);
        p.token = uint256(uint160(address(0xdead)));
        vm.expectRevert(ShieldedPool.WrongToken.selector);
        vm.prank(alice);
        pool.withdrawBlocked(p);
    }

    function testWithdrawBlockedRevertsZeroAmount() public {
        ungatedVerifier.setResult(false);
        ShieldedPool.WithdrawBlockedParams memory p = _baseWithdrawBlocked(bytes32(uint256(3)), 0);
        vm.expectRevert(ShieldedPool.ZeroAmount.selector);
        vm.prank(alice);
        pool.withdrawBlocked(p);
    }

    function testWithdrawBlockedRevertsNullifierSpent() public {
        ShieldedPool.WithdrawBlockedParams memory first = _baseWithdrawBlocked(bytes32(uint256(4)), 500);
        vm.prank(alice);
        pool.withdrawBlocked(first);

        ungatedVerifier.setResult(false);
        ShieldedPool.WithdrawBlockedParams memory p = _baseWithdrawBlocked(bytes32(uint256(4)), 500);
        vm.expectRevert(ShieldedPool.NullifierSpent.selector);
        vm.prank(alice);
        pool.withdrawBlocked(p);
    }

    function testWithdrawBlockedRevertsUnknownCommitmentRoot() public {
        ungatedVerifier.setResult(false);
        ShieldedPool.WithdrawBlockedParams memory p = _baseWithdrawBlocked(bytes32(uint256(5)), 500);
        p.commitmentRoot = bytes32(uint256(0xdead));
        vm.expectRevert(ShieldedPool.UnknownRoot.selector);
        vm.prank(alice);
        pool.withdrawBlocked(p);
    }

    function testWithdrawBlockedRevertsInvalidProof() public {
        ungatedVerifier.setResult(false);
        ShieldedPool.WithdrawBlockedParams memory p = _baseWithdrawBlocked(bytes32(uint256(6)), 500);
        vm.expectRevert(ShieldedPool.InvalidProof.selector);
        vm.prank(alice);
        pool.withdrawBlocked(p);
    }

    function testWithdrawBlockedAppliesNoEpochOrAttestationChecks() public {
        // deliberately stale-looking epoch: withdrawBlocked runs the ungated
        // circuit and applies none of the epoch, attestation, velocity, or
        // policy checks the gated paths require.
        ShieldedPool.WithdrawBlockedParams memory p = _baseWithdrawBlocked(bytes32(uint256(7)), 500);
        vm.warp(block.timestamp + 100 * EPOCH_SECONDS);
        vm.prank(alice);
        pool.withdrawBlocked(p);
        assertEq(pool.blockedBalance(bytes32(uint256(7))), 500);
    }

    // ========== claimBlocked ==========

    function testClaimBlockedTransfersToBlockedFundsAccount() public {
        ShieldedPool.WithdrawBlockedParams memory p = _baseWithdrawBlocked(bytes32(uint256(11)), 500);
        vm.prank(alice);
        pool.withdrawBlocked(p);

        uint256 before = token.balanceOf(blockedFundsAccount);
        vm.prank(blockedFundsAccount);
        pool.claimBlocked(bytes32(uint256(11)));

        assertEq(token.balanceOf(blockedFundsAccount), before + 500);
    }

    function testClaimBlockedZeroesBalanceBeforeTransferring() public {
        ShieldedPool.WithdrawBlockedParams memory p = _baseWithdrawBlocked(bytes32(uint256(12)), 500);
        vm.prank(alice);
        pool.withdrawBlocked(p);

        vm.prank(blockedFundsAccount);
        pool.claimBlocked(bytes32(uint256(12)));

        assertEq(pool.blockedBalance(bytes32(uint256(12))), 0);

        // a second claim on the same nullifier moves nothing further
        uint256 before = token.balanceOf(blockedFundsAccount);
        vm.prank(blockedFundsAccount);
        pool.claimBlocked(bytes32(uint256(12)));
        assertEq(token.balanceOf(blockedFundsAccount), before);
    }

    function testClaimBlockedRevertsForAnyOtherCaller() public {
        ShieldedPool.WithdrawBlockedParams memory p = _baseWithdrawBlocked(bytes32(uint256(13)), 500);
        vm.prank(alice);
        pool.withdrawBlocked(p);

        vm.expectRevert(ShieldedPool.NotBlockedFundsAccount.selector);
        vm.prank(alice);
        pool.claimBlocked(bytes32(uint256(13)));
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/src/Test.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {AttestationRegistry} from "../src/AttestationRegistry.sol";
import {MockERC20} from "../src/mocks/MockERC20.sol";
import {MockCompositeVerifier} from "../src/mocks/MockCompositeVerifier.sol";
import {MockUltraVerifier} from "../src/mocks/MockUltraVerifier.sol";
import {IAccessControl} from "@openzeppelin-contracts/access/IAccessControl.sol";

contract GovernanceTest is Test {
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
    address public rando = address(0x99);

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
    }

    // ========== setPolicy / cancelPolicy access ==========

    function testSetPolicyRevertsFromRando() public {
        uint256 activationEpoch = pool.currentEpoch() + 3;
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, rando, bytes32(0))
        );
        vm.prank(rando);
        pool.setPolicy(address(0x1234), bytes32(uint256(1)), activationEpoch, "ipfs://x", bytes32(uint256(2)));
    }

    function testSetPolicyRevertsFromGuardian() public {
        uint256 activationEpoch = pool.currentEpoch() + 3;
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, guardian, bytes32(0))
        );
        vm.prank(guardian);
        pool.setPolicy(address(0x1234), bytes32(uint256(1)), activationEpoch, "ipfs://x", bytes32(uint256(2)));
    }

    function testSetPolicyAllowedFromTimelock() public {
        address newVerifier = address(new MockCompositeVerifier());
        uint256 activationEpoch = pool.currentEpoch() + 3;
        vm.prank(timelockController);
        pool.setPolicy(newVerifier, bytes32(uint256(1)), activationEpoch, "ipfs://x", bytes32(uint256(2)));
        assertEq(pool.pendingVerifier(), newVerifier);
    }

    function testSetPolicyRevertsZeroVerifier() public {
        uint256 activationEpoch = pool.currentEpoch() + 3;
        vm.expectRevert(ShieldedPool.ZeroAddress.selector);
        vm.prank(timelockController);
        pool.setPolicy(address(0), bytes32(uint256(1)), activationEpoch, "ipfs://x", bytes32(uint256(2)));
    }

    function testSetPolicyRevertsActivationNotFuture() public {
        address newVerifier = address(new MockCompositeVerifier());
        uint256 activationEpoch = pool.currentEpoch();
        vm.expectRevert(ShieldedPool.ActivationNotFuture.selector);
        vm.prank(timelockController);
        pool.setPolicy(newVerifier, bytes32(uint256(1)), activationEpoch, "ipfs://x", bytes32(uint256(2)));
    }

    function testSetPolicyRevertsBelowTimelockFloor() public {
        address newVerifier = address(new MockCompositeVerifier());
        uint256 activationEpoch = pool.currentEpoch() + 2;
        vm.expectRevert(ShieldedPool.ActivationTooSoon.selector);
        vm.prank(timelockController);
        pool.setPolicy(newVerifier, bytes32(uint256(1)), activationEpoch, "ipfs://x", bytes32(uint256(2)));
    }

    function testSetPolicyAcceptsAtTimelockFloor() public {
        address newVerifier = address(new MockCompositeVerifier());
        uint256 activationEpoch = pool.currentEpoch() + 3;
        vm.prank(timelockController);
        pool.setPolicy(newVerifier, bytes32(uint256(1)), activationEpoch, "ipfs://x", bytes32(uint256(2)));
        assertEq(pool.pendingVerifier(), newVerifier);
    }

    function testSetPolicyRevertsNonContractVerifier() public {
        uint256 activationEpoch = pool.currentEpoch() + 3;
        vm.expectRevert(ShieldedPool.ZeroAddress.selector);
        vm.prank(timelockController);
        pool.setPolicy(address(0x1234), bytes32(uint256(1)), activationEpoch, "ipfs://x", bytes32(uint256(2)));
    }

    function testSetPolicyStillWorksWhilePaused() public {
        uint256 pauseUntil = pool.currentEpoch() + 5;
        vm.prank(guardian);
        pool.pause(pauseUntil, false);

        address newVerifier = address(new MockCompositeVerifier());
        uint256 activationEpoch = pool.currentEpoch() + 3;
        vm.prank(timelockController);
        pool.setPolicy(newVerifier, bytes32(uint256(1)), activationEpoch, "ipfs://x", bytes32(uint256(2)));

        assertEq(pool.pendingVerifier(), newVerifier);
    }

    function testCancelPolicyRevertsFromRando() public {
        vm.expectRevert(ShieldedPool.NotGuardianOrAdmin.selector);
        vm.prank(rando);
        pool.cancelPolicy();
    }

    function testCancelPolicyClearsPending() public {
        address newVerifier = address(new MockCompositeVerifier());
        uint256 activationEpoch = pool.currentEpoch() + 3;
        vm.prank(timelockController);
        pool.setPolicy(newVerifier, bytes32(uint256(1)), activationEpoch, "ipfs://x", bytes32(uint256(2)));

        vm.prank(guardian);
        pool.cancelPolicy();

        assertEq(pool.pendingVerifier(), address(0));
        assertEq(pool.policyActivationEpoch(), type(uint256).max);
    }

    function testCancelPolicyPromotesElapsedPendingBeforeCancelling() public {
        address newVerifier = address(new MockCompositeVerifier());
        uint256 activationEpoch = pool.currentEpoch() + 3;
        vm.prank(timelockController);
        pool.setPolicy(newVerifier, bytes32(uint256(0x9999)), activationEpoch, "ipfs://x", bytes32(uint256(2)));

        vm.warp(activationEpoch * EPOCH_SECONDS);

        vm.prank(guardian);
        pool.cancelPolicy();

        // the elapsed pending pair is promoted before cancellation, so the
        // already-active policy is untouched.
        assertEq(pool.activeVerifier(), newVerifier);
        assertEq(pool.activePolicySourceHash(), bytes32(uint256(0x9999)));
        assertEq(pool.pendingVerifier(), address(0));
        assertEq(pool.policyActivationEpoch(), type(uint256).max);
    }

    // ========== Activation timing ==========

    function testPolicyActivatesOnlyAtActivationEpoch() public {
        address newVerifier = address(new MockCompositeVerifier());
        uint256 activationEpoch = pool.currentEpoch() + 3;
        vm.prank(timelockController);
        pool.setPolicy(newVerifier, bytes32(uint256(0x9999)), activationEpoch, "ipfs://x", bytes32(uint256(2)));

        // one epoch before activation: still the outgoing policy
        vm.warp((activationEpoch - 1) * EPOCH_SECONDS);
        (address v, bytes32 h) = pool.effectivePolicy();
        assertEq(v, address(verifier));
        assertEq(h, initialPolicySourceHash);

        // at the activation epoch: the incoming policy, even before any pool call
        vm.warp(activationEpoch * EPOCH_SECONDS);
        (v, h) = pool.effectivePolicy();
        assertEq(v, newVerifier);
        assertEq(h, bytes32(uint256(0x9999)));
    }

    function testEffectivePolicyReportsIncomingBetweenActivationAndFirstCall() public {
        address newVerifier = address(new MockCompositeVerifier());
        uint256 activationEpoch = pool.currentEpoch() + 3;
        vm.prank(timelockController);
        pool.setPolicy(newVerifier, bytes32(uint256(0xCAFE)), activationEpoch, "ipfs://x", bytes32(uint256(2)));

        vm.warp(activationEpoch * EPOCH_SECONDS);

        // storage still names the outgoing policy...
        assertEq(pool.activeVerifier(), address(verifier));
        // ...but the view already reports the incoming one.
        (address v, bytes32 h) = pool.effectivePolicy();
        assertEq(v, newVerifier);
        assertEq(h, bytes32(uint256(0xCAFE)));
    }

    function testSetPolicyPromotesElapsedPendingBeforeQueuingNew() public {
        address firstVerifier = address(new MockCompositeVerifier());
        address secondVerifier = address(new MockCompositeVerifier());

        uint256 firstActivation = pool.currentEpoch() + 3;
        vm.prank(timelockController);
        pool.setPolicy(firstVerifier, bytes32(uint256(0x1111)), firstActivation, "ipfs://a", bytes32(uint256(1)));

        vm.warp(firstActivation * EPOCH_SECONDS);

        uint256 secondActivation = pool.currentEpoch() + 3;
        vm.prank(timelockController);
        pool.setPolicy(secondVerifier, bytes32(uint256(0x2222)), secondActivation, "ipfs://b", bytes32(uint256(2)));

        // the first pair was promoted to active before the second was queued
        assertEq(pool.activeVerifier(), firstVerifier);
        assertEq(pool.activePolicySourceHash(), bytes32(uint256(0x1111)));
        assertEq(pool.pendingVerifier(), secondVerifier);
    }

    // ========== Other governance setters ==========

    function testSetUngatedWithdrawVerifierOnlyAdmin() public {
        address newVerifier = address(new MockUltraVerifier());

        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, guardian, bytes32(0))
        );
        vm.prank(guardian);
        pool.setUngatedWithdrawVerifier(newVerifier);

        vm.prank(timelockController);
        pool.setUngatedWithdrawVerifier(newVerifier);
        assertEq(pool.ungatedWithdrawVerifier(), newVerifier);
    }

    function testSetUngatedWithdrawVerifierRevertsNonContract() public {
        vm.expectRevert(ShieldedPool.ZeroAddress.selector);
        vm.prank(timelockController);
        pool.setUngatedWithdrawVerifier(address(0x1234));
    }

    function testSetSingleTxThresholdOnlyCurator() public {
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, rando, pool.CURATOR_ROLE())
        );
        vm.prank(rando);
        pool.setSingleTxThreshold(1);

        vm.prank(curator);
        pool.setSingleTxThreshold(777);
        assertEq(pool.singleTxThreshold(), 777);
    }

    function testSetBlockedDestinationOnlyCurator() public {
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, rando, pool.CURATOR_ROLE())
        );
        vm.prank(rando);
        pool.setBlockedDestination(address(0xBAD), true);

        vm.prank(curator);
        pool.setBlockedDestination(address(0xBAD), true);
        assertTrue(pool.blockedDestination(address(0xBAD)));
    }

    function testRecordGrantOnlyCommittee() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, rando, pool.COMMITTEE_ROLE()
            )
        );
        vm.prank(rando);
        pool.recordGrant(bytes32(uint256(1)));

        vm.prank(committee);
        pool.recordGrant(bytes32(uint256(1)));
        assertTrue(pool.auditGrant(bytes32(uint256(1))));
    }

    // ========== Constructor validation ==========

    function _constructorParamsWithCeilings(uint256 maxPauseEpochs, uint256 maxBlockedExitPauseEpochs)
        internal
        view
        returns (ShieldedPool.ConstructorParams memory)
    {
        return ShieldedPool.ConstructorParams({
            token: address(token),
            attestationRegistry: address(registry),
            initialVerifier: address(verifier),
            initialPolicySourceHash: initialPolicySourceHash,
            ungatedWithdrawVerifier: address(ungatedVerifier),
            blockedFundsAccount: blockedFundsAccount,
            singleTxThreshold: 10_000_000_000,
            epochSeconds: EPOCH_SECONDS,
            timelockDelaySeconds: 172_800,
            maxPauseEpochs: maxPauseEpochs,
            maxBlockedExitPauseEpochs: maxBlockedExitPauseEpochs,
            pauseBudgetEpochs: 30,
            pauseWindowEpochs: 90,
            timelockController: timelockController,
            guardian: guardian,
            curator: curator,
            committee: committee
        });
    }

    function testConstructorRevertsWhenBlockedExitCeilingEqualsGatedCeiling() public {
        vm.expectRevert(ShieldedPool.BlockedExitCeilingNotShorter.selector);
        new ShieldedPool(_constructorParamsWithCeilings(14, 14));
    }

    function testConstructorRevertsWhenBlockedExitCeilingExceedsGatedCeiling() public {
        vm.expectRevert(ShieldedPool.BlockedExitCeilingNotShorter.selector);
        new ShieldedPool(_constructorParamsWithCeilings(14, 15));
    }

    function testConstructorAcceptsStrictlyShorterBlockedExitCeiling() public {
        ShieldedPool p = new ShieldedPool(_constructorParamsWithCeilings(14, 13));
        assertEq(p.MAX_BLOCKED_EXIT_PAUSE_EPOCHS(), 13);
    }

    function testSetCommitteeIncrementsVersion() public {
        assertEq(pool.committeeVersion(), 0);
        vm.prank(timelockController);
        pool.setCommittee(bytes32(uint256(0xAAA)));
        assertEq(pool.committeeVersion(), 1);
    }
}

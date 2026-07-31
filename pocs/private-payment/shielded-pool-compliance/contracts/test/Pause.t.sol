// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/src/Test.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {PublicInputs} from "../src/PublicInputs.sol";
import {AttestationRegistry} from "../src/AttestationRegistry.sol";
import {MockERC20} from "../src/mocks/MockERC20.sol";
import {MockCompositeVerifier} from "../src/mocks/MockCompositeVerifier.sol";
import {MockUltraVerifier} from "../src/mocks/MockUltraVerifier.sol";
import {IAccessControl} from "@openzeppelin-contracts/access/IAccessControl.sol";

contract PauseTest is Test {
    ShieldedPool public pool;
    AttestationRegistry public registry;
    MockERC20 public token;
    MockCompositeVerifier public verifier;
    MockUltraVerifier public ungatedVerifier;

    uint256 constant EPOCH_SECONDS = 86400;
    uint256 constant MAX_PAUSE_EPOCHS = 14;
    uint256 constant MAX_BLOCKED_EXIT_PAUSE_EPOCHS = 7;
    uint256 constant PAUSE_BUDGET_EPOCHS = 30;
    uint256 constant PAUSE_WINDOW_EPOCHS = 90;
    uint256 constant TIMELOCK_DELAY_SECONDS = 172_800;

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
                timelockDelaySeconds: TIMELOCK_DELAY_SECONDS,
                maxPauseEpochs: MAX_PAUSE_EPOCHS,
                maxBlockedExitPauseEpochs: MAX_BLOCKED_EXIT_PAUSE_EPOCHS,
                pauseBudgetEpochs: PAUSE_BUDGET_EPOCHS,
                pauseWindowEpochs: PAUSE_WINDOW_EPOCHS,
                timelockController: timelockController,
                guardian: guardian,
                curator: curator,
                committee: committee
            })
        );

        token.mint(alice, 1_000_000_000_000);
        vm.prank(alice);
        token.approve(address(pool), type(uint256).max);
    }

    function _baseDeposit() internal view returns (ShieldedPool.DepositParams memory) {
        ShieldedPool.DepositParams memory p = ShieldedPool.DepositParams({
            proof: "",
            commitment: bytes32(uint256(1)),
            token: uint256(uint160(address(token))),
            amount: 500,
            attestationRoot: registry.attestationRoot(),
            velocityNullifier: bytes32(uint256(2)),
            complianceCommitmentOut: bytes32(uint256(3)),
            epoch: pool.currentEpoch(),
            epochSeconds: EPOCH_SECONDS,
            policySourceHash: pool.activePolicySourceHash(),
            commitmentRoot: pool.commitmentRoot(),
            attesterRevocationRoot: registry.attesterRevocationRoot(),
            minAcceptedGeneration: registry.minAcceptedGeneration(),
            payloadCommitment: bytes32(0),
            encryptedNotes: ""
        });
        p.payloadCommitment = bytes32(uint256(keccak256(p.encryptedNotes)) % PublicInputs.BN254_MODULUS);
        return p;
    }

    function _baseWithdrawBlocked() internal view returns (ShieldedPool.WithdrawBlockedParams memory) {
        return ShieldedPool.WithdrawBlockedParams({
            proof: "",
            nullifier: bytes32(uint256(31)),
            token: uint256(uint160(address(token))),
            amount: 500,
            recipient: alice,
            commitmentRoot: pool.commitmentRoot()
        });
    }

    // ========== Gated pause ==========

    function testGatedPauseBlocksDeposit() public {
        uint256 epoch = pool.currentEpoch();
        vm.prank(guardian);
        pool.pause(epoch + 5, false);

        ShieldedPool.DepositParams memory p = _baseDeposit();
        vm.expectRevert(ShieldedPool.ContractPaused.selector);
        vm.prank(alice);
        pool.deposit(p);
    }

    function testDepositSucceedsAfterPauseLifts() public {
        uint256 epoch = pool.currentEpoch();
        vm.prank(guardian);
        pool.pause(epoch + 2, false);

        vm.warp((epoch + 2) * EPOCH_SECONDS);

        ShieldedPool.DepositParams memory p = _baseDeposit();
        vm.prank(alice);
        pool.deposit(p);
        assertTrue(pool.nullifiers(bytes32(uint256(2))));
    }

    // ========== Blocked-exit pause ==========

    function testBlockedExitPauseBlocksWithdrawBlocked() public {
        uint256 epoch = pool.currentEpoch();
        vm.prank(guardian);
        pool.pause(epoch + 3, true);

        ShieldedPool.WithdrawBlockedParams memory p = _baseWithdrawBlocked();
        vm.expectRevert(ShieldedPool.ContractPaused.selector);
        vm.prank(alice);
        pool.withdrawBlocked(p);
    }

    function testBlockedExitPauseDoesNotBlockDeposit() public {
        uint256 epoch = pool.currentEpoch();
        vm.prank(guardian);
        pool.pause(epoch + 3, true);

        ShieldedPool.DepositParams memory p = _baseDeposit();
        vm.prank(alice);
        pool.deposit(p);
        assertTrue(pool.nullifiers(bytes32(uint256(2))));
    }

    // ========== Ceilings ==========

    function testPauseRevertsAboveGatedCeiling() public {
        uint256 epoch = pool.currentEpoch();
        vm.expectRevert(ShieldedPool.PauseCeilingExceeded.selector);
        vm.prank(guardian);
        pool.pause(epoch + MAX_PAUSE_EPOCHS + 1, false);
    }

    function testPauseRevertsAboveBlockedExitCeiling() public {
        uint256 epoch = pool.currentEpoch();
        vm.expectRevert(ShieldedPool.PauseCeilingExceeded.selector);
        vm.prank(guardian);
        pool.pause(epoch + MAX_BLOCKED_EXIT_PAUSE_EPOCHS + 1, true);
    }

    function testPauseOnlyGuardian() public {
        uint256 epoch = pool.currentEpoch();
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, alice, pool.GUARDIAN_ROLE()
            )
        );
        vm.prank(alice);
        pool.pause(epoch + 1, false);
    }

    // ========== Budget and rearm ==========

    function testGuardianBudgetExceededDisarms() public {
        uint256 epoch = pool.currentEpoch();

        vm.prank(guardian);
        pool.pause(epoch + MAX_PAUSE_EPOCHS, false); // spends 14

        vm.prank(guardian);
        pool.pause(epoch + MAX_PAUSE_EPOCHS, false); // spends 14 more, total 28

        // a further 3-epoch request would bring cumulative spend to 31 > 30
        vm.expectRevert(ShieldedPool.PauseBudgetExceeded.selector);
        vm.prank(guardian);
        pool.pause(epoch + 3, false);

        // exactly exhausting the remaining budget (2 epochs) disarms the guardian
        vm.prank(guardian);
        pool.pause(epoch + 2, false);
        assertFalse(pool.guardianArmed());

        vm.expectRevert(ShieldedPool.GuardianNotArmed.selector);
        vm.prank(guardian);
        pool.pause(epoch + 1, false);
    }

    function testRearmGuardianOnlyAdmin() public {
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, guardian, bytes32(0))
        );
        vm.prank(guardian);
        pool.rearmGuardian();
    }

    function testRearmGuardianRestoresBudget() public {
        uint256 epoch = pool.currentEpoch();
        vm.prank(guardian);
        pool.pause(epoch + MAX_PAUSE_EPOCHS, false);
        vm.prank(guardian);
        pool.pause(epoch + MAX_PAUSE_EPOCHS, false);
        vm.prank(guardian);
        pool.pause(epoch + 2, false); // exhausts the 30-epoch budget, disarms

        vm.prank(timelockController);
        pool.rearmGuardian();

        assertTrue(pool.guardianArmed());
        assertEq(pool.pauseBudgetSpent(), 0);

        vm.prank(guardian);
        pool.pause(epoch + 5, false); // succeeds again post-rearm
        assertEq(pool.pausedUntilEpoch(), epoch + 5);
    }

    // ========== setBlockedFundsAccount lock ==========

    function testSetBlockedFundsAccountRevertsWhilePaused() public {
        uint256 epoch = pool.currentEpoch();
        vm.prank(guardian);
        pool.pause(epoch + 5, false);

        vm.expectRevert(ShieldedPool.BlockedFundsAccountLocked.selector);
        vm.prank(timelockController);
        pool.setBlockedFundsAccount(address(0x9999));
    }

    function testSetBlockedFundsAccountRevertsDuringTimelockDelayAfterLift() public {
        uint256 epoch = pool.currentEpoch();
        vm.prank(guardian);
        pool.pause(epoch + 2, false);

        vm.warp((epoch + 2) * EPOCH_SECONDS);

        vm.expectRevert(ShieldedPool.BlockedFundsAccountLocked.selector);
        vm.prank(timelockController);
        pool.setBlockedFundsAccount(address(0x9999));
    }

    function testSetBlockedFundsAccountSucceedsAfterDelayElapses() public {
        uint256 epoch = pool.currentEpoch();
        vm.prank(guardian);
        pool.pause(epoch + 2, false);

        vm.warp((epoch + 2) * EPOCH_SECONDS + TIMELOCK_DELAY_SECONDS);

        vm.prank(timelockController);
        pool.setBlockedFundsAccount(address(0x9999));
        assertEq(pool.blockedFundsAccount(), address(0x9999));
    }

    function testSetBlockedFundsAccountSucceedsWithNoPriorPause() public {
        vm.prank(timelockController);
        pool.setBlockedFundsAccount(address(0x9999));
        assertEq(pool.blockedFundsAccount(), address(0x9999));
    }
}

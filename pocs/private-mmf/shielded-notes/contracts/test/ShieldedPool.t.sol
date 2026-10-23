// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ShieldedPool} from "../src/ShieldedPool.sol";
import {AttestationRegistry} from "../src/AttestationRegistry.sol";
import {PublicInputs, DepositPublicInputs} from "../src/PublicInputs.sol";
import {MockFundToken} from "../src/mocks/MockFundToken.sol";
import {PoolTestBase} from "./PoolTestBase.sol";
import {IVerifier} from "../src/interfaces/IVerifier.sol";
import {MockCompositeVerifier} from "../src/mocks/MockCompositeVerifier.sol";
import {CompositeVerifier} from "../src/CompositeVerifier.sol";
import {MockUltraVerifier} from "../src/mocks/MockUltraVerifier.sol";
import {IAccessControl} from "@openzeppelin-contracts/access/IAccessControl.sol";

contract ShieldedPoolTest is PoolTestBase {
    uint256 internal constant P = PublicInputs.BN254_MODULUS;

    // ========== Deposit ==========

    function testDepositPullsSharesAndCreditsUnits() public {
        uint256 before = token.balanceOf(alice);
        bytes32 commitment = _deposit(alice, 1_000_000);

        assertEq(token.balanceOf(address(pool)), SEED_UNITS + 1_000_000, "m = 1 pulls one share per unit");
        assertEq(token.balanceOf(alice), before - 1_000_000);
        assertEq(pool.totalUnits(), SEED_UNITS + 1_000_000);
        assertEq(pool.getCommitmentCount(), 2, "the seed's, then alice's");
        assertTrue(pool.isKnownRoot(pool.commitmentRoot()));
        assertEq(pool.lastMultiplier(), S);
        commitment;
    }

    function testDepositFillsPublicInputsFromState() public {
        ShieldedPool.DepositParams memory p = _depositParams(_leaf(), 777);
        vm.expectCall(
            address(verifier), abi.encodeCall(IVerifier.verifyDeposit, (p.proof, _expectedDepositInputs(p, alice)))
        );
        vm.prank(alice);
        pool.deposit(p);
    }

    /// @dev An empty pool takes its first deposit from the transfer agent only,
    ///      so no holder can be alone in it, donate, and leave m inflated.
    function testAnEmptyPoolTakesItsFirstDepositFromTheAgent() public {
        ShieldedPool empty = new ShieldedPool(_params());
        token.setAllowlisted(address(empty), true);
        token.setLimitExempt(address(empty), true);
        vm.prank(alice);
        token.approve(address(empty), type(uint256).max);
        vm.prank(agent);
        token.approve(address(empty), type(uint256).max);

        ShieldedPool.DepositParams memory p = _depositParams(_leaf(), 1000);
        vm.prank(alice);
        vm.expectRevert(ShieldedPool.EmptyPool.selector);
        empty.deposit(p);

        ShieldedPool.DepositParams memory seed = _depositParams(_leaf(), 1);
        vm.prank(agent);
        empty.deposit(seed);
        vm.prank(alice);
        empty.deposit(p);
        assertEq(empty.totalUnits(), 1001);
    }

    function testDepositRevertsOnZeroUnits() public {
        ShieldedPool.DepositParams memory p = _depositParams(_leaf(), 0);
        vm.prank(alice);
        vm.expectRevert(ShieldedPool.ZeroUnits.selector);
        pool.deposit(p);
    }

    function testDepositRevertsOnWrongEpoch() public {
        ShieldedPool.DepositParams memory p = _depositParams(_leaf(), 1);
        p.epoch = pool.currentEpoch() - 1;
        vm.prank(alice);
        vm.expectRevert(ShieldedPool.WrongEpoch.selector);
        pool.deposit(p);
    }

    function testDepositRevertsOnFeedPointOffTheCurve() public {
        ShieldedPool.DepositParams memory p = _depositParams(_leaf(), 1);
        p.feedR = [uint256(11), uint256(12)];
        vm.prank(alice);
        vm.expectRevert(ShieldedPool.InvalidFeedPoint.selector);
        pool.deposit(p);
    }

    function testDepositRevertsOnFeedPointAtInfinity() public {
        // R = (0, 0) encodes the point at infinity, where the feed key is public.
        ShieldedPool.DepositParams memory p = _depositParams(_leaf(), 1);
        p.feedR = [uint256(0), uint256(0)];
        vm.prank(alice);
        vm.expectRevert(ShieldedPool.InvalidFeedPoint.selector);
        pool.deposit(p);
    }

    function testDepositFromAHolderNoLongerAllowlistedFails() public {
        token.setAllowlisted(alice, false);
        ShieldedPool.DepositParams memory p = _depositParams(_leaf(), 1);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(MockFundToken.NotAllowlisted.selector, alice));
        pool.deposit(p);
    }

    function testDepositRevertsOnUnknownAttestationRoot() public {
        ShieldedPool.DepositParams memory p = _depositParams(_leaf(), 1);
        p.attestationRoot = bytes32(uint256(0xdead));
        vm.prank(alice);
        vm.expectRevert(ShieldedPool.UnknownRoot.selector);
        pool.deposit(p);
    }

    function testDepositRevertsOnInvalidProof() public {
        verifier.setDepositResult(false);
        ShieldedPool.DepositParams memory p = _depositParams(_leaf(), 1);
        vm.prank(alice);
        vm.expectRevert(ShieldedPool.InvalidProof.selector);
        pool.deposit(p);
    }

    function testDepositRevertsOnNonCanonicalCommitment() public {
        ShieldedPool.DepositParams memory p = _depositParams(bytes32(P), 1);
        vm.prank(alice);
        vm.expectRevert(PublicInputs.NonCanonicalInput.selector);
        pool.deposit(p);
    }

    function testDepositRevertsOnNonCanonicalFeedElement() public {
        ShieldedPool.DepositParams memory p = _depositParams(_leaf(), 1);
        p.feedCt[3] = P + 24;
        vm.prank(alice);
        vm.expectRevert(PublicInputs.NonCanonicalInput.selector);
        pool.deposit(p);
    }

    function testDepositRevertsWhenCallerCannotPay() public {
        ShieldedPool.DepositParams memory p = _depositParams(_leaf(), 1);
        vm.prank(bob);
        vm.expectRevert();
        pool.deposit(p);
    }

    // ========== Transfer ==========

    function testTransferMarksNullifiersAndInsertsBothOutputs() public {
        _deposit(alice, 1000);
        bytes32 n0 = _leaf();
        bytes32 n1 = _leaf();
        ShieldedPool.TransferParams memory p = _transferParams(n0, n1, _leaf(), _leaf());
        pool.transfer(p);

        assertTrue(pool.nullifiers(n0));
        assertTrue(pool.nullifiers(n1));
        assertEq(pool.getCommitmentCount(), 4, "the seed, the deposit and both outputs");
        assertEq(pool.totalUnits(), SEED_UNITS + 1000, "a transfer moves no units in or out");
    }

    function testTransferFillsPublicInputsFromState() public {
        _deposit(alice, 1000);
        ShieldedPool.TransferParams memory p = _transferParams(_leaf(), _leaf(), _leaf(), _leaf());
        vm.expectCall(
            address(verifier), abi.encodeCall(IVerifier.verifyTransfer, (p.proof, _expectedTransferInputs(p)))
        );
        pool.transfer(p);
    }

    function testTransferRevertsOnDuplicateNullifier() public {
        _deposit(alice, 1000);
        bytes32 n = _leaf();
        ShieldedPool.TransferParams memory p = _transferParams(n, n, _leaf(), _leaf());
        vm.expectRevert(ShieldedPool.DuplicateNullifier.selector);
        pool.transfer(p);
    }

    function testTransferRevertsOnFeedPointOffTheCurve() public {
        _deposit(alice, 1000);
        ShieldedPool.TransferParams memory p = _transferParams(_leaf(), _leaf(), _leaf(), _leaf());
        p.feedR = [uint256(11), uint256(12)];
        vm.expectRevert(ShieldedPool.InvalidFeedPoint.selector);
        pool.transfer(p);
    }

    function testTransferRevertsOnSpentNullifier() public {
        _deposit(alice, 1000);
        bytes32 n0 = _leaf();
        pool.transfer(_transferParams(n0, _leaf(), _leaf(), _leaf()));
        ShieldedPool.TransferParams memory p = _transferParams(n0, _leaf(), _leaf(), _leaf());
        vm.expectRevert(ShieldedPool.NullifierSpent.selector);
        pool.transfer(p);
    }

    /// @dev The pool's spent check is the only double-spend guard for a
    ///      transfer's second input: the circuit sees no global state.
    function testTransferRevertsOnSpentSecondNullifier() public {
        _deposit(alice, 1000);
        bytes32 n1 = _leaf();
        pool.transfer(_transferParams(_leaf(), n1, _leaf(), _leaf()));
        ShieldedPool.TransferParams memory p = _transferParams(_leaf(), n1, _leaf(), _leaf());
        vm.expectRevert(ShieldedPool.NullifierSpent.selector);
        pool.transfer(p);
    }

    function testTransferRevertsOnUnknownCommitmentRoot() public {
        _deposit(alice, 1000);
        ShieldedPool.TransferParams memory p = _transferParams(_leaf(), _leaf(), _leaf(), _leaf());
        p.commitmentRoot = bytes32(uint256(0xbad));
        vm.expectRevert(ShieldedPool.UnknownRoot.selector);
        pool.transfer(p);
    }

    function testTransferAcceptsARootInTheWindow() public {
        _deposit(alice, 1000);
        bytes32 oldRoot = pool.commitmentRoot();
        _deposit(alice, 1000);
        ShieldedPool.TransferParams memory p = _transferParams(_leaf(), _leaf(), _leaf(), _leaf());
        p.commitmentRoot = oldRoot;
        pool.transfer(p);
    }

    function testRootLeavesTheWindowAfterMaxHistoricalRoots() public {
        _deposit(alice, 1000);
        bytes32 oldRoot = pool.commitmentRoot();
        // 300 transfers exceed one test's gas limit; the eviction, not the gas, is under test.
        vm.pauseGasMetering();
        for (uint256 i = 0; i < pool.MAX_HISTORICAL_ROOTS(); i++) {
            pool.transfer(_transferParams(_leaf(), _leaf(), _leaf(), _leaf()));
        }
        assertFalse(pool.isKnownRoot(oldRoot));
    }

    function testTransferRevertsOnUnknownAttestationRoot() public {
        _deposit(alice, 1000);
        ShieldedPool.TransferParams memory p = _transferParams(_leaf(), _leaf(), _leaf(), _leaf());
        p.attestationRoot = bytes32(uint256(0xbad));
        vm.expectRevert(ShieldedPool.UnknownRoot.selector);
        pool.transfer(p);
    }

    function testTransferRevertsOnInvalidProof() public {
        _deposit(alice, 1000);
        verifier.setTransferResult(false);
        ShieldedPool.TransferParams memory p = _transferParams(_leaf(), _leaf(), _leaf(), _leaf());
        vm.expectRevert(ShieldedPool.InvalidProof.selector);
        pool.transfer(p);
    }

    function testTransferRevertsOnNonCanonicalNullifier() public {
        _deposit(alice, 1000);
        ShieldedPool.TransferParams memory p = _transferParams(bytes32(P + 1), _leaf(), _leaf(), _leaf());
        vm.expectRevert(PublicInputs.NonCanonicalInput.selector);
        pool.transfer(p);
    }

    /// @dev The proof verifies for whatever epoch it was built with; only the
    ///      pool ties it to now. A future epoch would release holding periods
    ///      early, a past one revive lapsed attestations and expired plans.
    function testTransferRevertsOnWrongEpoch() public {
        _deposit(alice, 1000);
        ShieldedPool.TransferParams memory p = _transferParams(_leaf(), _leaf(), _leaf(), _leaf());
        p.epoch = pool.currentEpoch() + 1;
        vm.expectRevert(ShieldedPool.WrongEpoch.selector);
        pool.transfer(p);
    }

    // ========== Withdraw ==========

    function testWithdrawPaysSharesAndDebitsUnits() public {
        _deposit(alice, 1000);
        bytes32 nullifier = _withdraw(400, bob);

        assertEq(token.balanceOf(bob), 400);
        assertEq(pool.totalUnits(), SEED_UNITS + 600);
        assertTrue(pool.nullifiers(nullifier));
        assertEq(pool.getCommitmentCount(), 2, "a withdrawal inserts nothing");
    }

    function testWithdrawFillsPublicInputsFromState() public {
        _deposit(alice, 1000);
        ShieldedPool.WithdrawParams memory p = _withdrawParams(_leaf(), 400, bob);
        vm.expectCall(
            address(verifier), abi.encodeCall(IVerifier.verifyWithdraw, (p.proof, _expectedWithdrawInputs(p)))
        );
        pool.withdraw(p);
    }

    function testWithdrawRevertsOnZeroUnits() public {
        _deposit(alice, 1000);
        ShieldedPool.WithdrawParams memory p = _withdrawParams(_leaf(), 0, bob);
        vm.expectRevert(ShieldedPool.ZeroUnits.selector);
        pool.withdraw(p);
    }

    function testWithdrawRevertsOnZeroRecipient() public {
        _deposit(alice, 1000);
        ShieldedPool.WithdrawParams memory p = _withdrawParams(_leaf(), 1, address(0));
        vm.expectRevert(ShieldedPool.ZeroAddress.selector);
        pool.withdraw(p);
    }

    function testWithdrawRevertsOnSpentNullifier() public {
        _deposit(alice, 1000);
        bytes32 nullifier = _withdraw(400, bob);
        ShieldedPool.WithdrawParams memory p = _withdrawParams(nullifier, 400, bob);
        vm.expectRevert(ShieldedPool.NullifierSpent.selector);
        pool.withdraw(p);
    }

    /// @dev The proof verifies against whatever root it was built with; only the
    ///      pool ties it to a tree it knows. Without the check, a made-up tree
    ///      could withdraw any shares.
    function testWithdrawRevertsOnUnknownCommitmentRoot() public {
        _deposit(alice, 1000);
        ShieldedPool.WithdrawParams memory p = _withdrawParams(_leaf(), 400, bob);
        p.commitmentRoot = bytes32(uint256(0xbad));
        vm.expectRevert(ShieldedPool.UnknownRoot.selector);
        pool.withdraw(p);
    }

    function testWithdrawRevertsOnUnknownAttestationRoot() public {
        _deposit(alice, 1000);
        ShieldedPool.WithdrawParams memory p = _withdrawParams(_leaf(), 400, bob);
        p.attestationRoot = bytes32(uint256(0xbad));
        vm.expectRevert(ShieldedPool.UnknownRoot.selector);
        pool.withdraw(p);
    }

    function testWithdrawRevertsOnWrongEpoch() public {
        _deposit(alice, 1000);
        ShieldedPool.WithdrawParams memory p = _withdrawParams(_leaf(), 400, bob);
        p.epoch = pool.currentEpoch() + 1;
        vm.expectRevert(ShieldedPool.WrongEpoch.selector);
        pool.withdraw(p);
    }

    function testWithdrawRevertsOnNonCanonicalNullifier() public {
        _deposit(alice, 1000);
        ShieldedPool.WithdrawParams memory p = _withdrawParams(bytes32(P + 1), 400, bob);
        vm.expectRevert(PublicInputs.NonCanonicalInput.selector);
        pool.withdraw(p);
    }

    function testWithdrawRevertsOnInvalidProof() public {
        _deposit(alice, 1000);
        verifier.setWithdrawResult(false);
        ShieldedPool.WithdrawParams memory p = _withdrawParams(_leaf(), 400, bob);
        vm.expectRevert(ShieldedPool.InvalidProof.selector);
        pool.withdraw(p);
    }

    function testWithdrawToANonAllowlistedAddressFailsOnTheToken() public {
        _deposit(alice, 1000);
        address stranger = address(0x5713);
        ShieldedPool.WithdrawParams memory p = _withdrawParams(_leaf(), 400, stranger);
        vm.expectRevert(abi.encodeWithSelector(MockFundToken.NotAllowlisted.selector, stranger));
        pool.withdraw(p);
    }

    // ========== Transfer agent ==========

    function testCheckpointEmitsTotals() public {
        _deposit(alice, 1000 - SEED_UNITS);
        _reinvest(0.5e18);
        vm.expectEmit(address(pool));
        emit ShieldedPool.Checkpoint(pool.currentEpoch(), 1500, 1000, 1.5e18, bytes32(uint256(0xabc)));
        vm.prank(agent);
        pool.checkpoint(bytes32(uint256(0xabc)), 1000);
    }

    /// @dev A deposit between the agent's snapshot and its checkpoint would pair
    ///      the register hash with other totals.
    function testCheckpointRevertsWhenUnitsMovedSinceTheSnapshot() public {
        _deposit(alice, 1000);
        uint256 snapshot = pool.totalUnits();
        _deposit(alice, 7);
        vm.prank(agent);
        vm.expectRevert(ShieldedPool.UnitsChanged.selector);
        pool.checkpoint(bytes32(0), snapshot);
    }

    function testAgentCallsRejectOthers() public {
        vm.expectRevert(ShieldedPool.NotTransferAgent.selector);
        pool.checkpoint(bytes32(0), 0);
        vm.expectRevert(ShieldedPool.NotTransferAgent.selector);
        pool.recordGrant(bytes32(0));
        vm.expectRevert(ShieldedPool.NotTransferAgent.selector);
        pool.setRegisterKey(GX, GY, 1);
    }

    function testRecordGrantEmits() public {
        vm.expectEmit(address(pool));
        emit ShieldedPool.GrantRecorded(bytes32(uint256(0x5c0)));
        vm.prank(agent);
        pool.recordGrant(bytes32(uint256(0x5c0)));
    }

    function testSetRegisterKeyRotatesAndFeedsNewProofs() public {
        uint256 negY = P - GY;
        vm.prank(agent);
        pool.setRegisterKey(GX, negY, 1);
        assertEq(pool.registerKeyY(), negY);
        assertEq(pool.registerKeyVersion(), 1);

        ShieldedPool.DepositParams memory p = _depositParams(_leaf(), 1);
        bytes32[] memory expected = _expectedDepositInputs(p, alice);
        assertEq(uint256(expected[DepositPublicInputs.REGISTER_KEY_Y]), negY);
        vm.expectCall(address(verifier), abi.encodeCall(IVerifier.verifyDeposit, (p.proof, expected)));
        vm.prank(alice);
        pool.deposit(p);
    }

    function testSetRegisterKeyRequiresNextVersion() public {
        vm.prank(agent);
        vm.expectRevert(ShieldedPool.WrongRegisterKeyVersion.selector);
        pool.setRegisterKey(GX, GY, 2);
    }

    function testSetRegisterKeyRejectsPointOffTheCurve() public {
        vm.prank(agent);
        vm.expectRevert(ShieldedPool.InvalidRegisterKey.selector);
        pool.setRegisterKey(GX, GY + 1, 1);
    }

    /// @dev A coordinate at or above the field modulus would be accepted as the
    ///      same point, then fail every deposit's and transfer's canonical check.
    function testSetRegisterKeyRejectsANonCanonicalKey() public {
        vm.prank(agent);
        vm.expectRevert(ShieldedPool.InvalidRegisterKey.selector);
        pool.setRegisterKey(GX + P, GY, 1);
    }

    // ========== Governance ==========

    function testGovernanceSettersRejectOthers() public {
        bytes memory missingAdmin = abi.encodeWithSelector(
            IAccessControl.AccessControlUnauthorizedAccount.selector, address(this), pool.DEFAULT_ADMIN_ROLE()
        );
        vm.expectRevert(missingAdmin);
        pool.setVerifier(address(verifier));
        vm.expectRevert(missingAdmin);
        pool.setClaimKeyHash(bytes32(uint256(1)));
        vm.expectRevert(missingAdmin);
        pool.setTransferAgent(bob);
    }

    function testSetVerifierRequiresAContract() public {
        vm.prank(timelock);
        vm.expectRevert(ShieldedPool.ZeroAddress.selector);
        pool.setVerifier(address(0x1234));

        MockCompositeVerifier next = new MockCompositeVerifier();
        vm.prank(timelock);
        pool.setVerifier(address(next));
        assertEq(address(pool.verifier()), address(next));
    }

    function testCompositeVerifierRequiresCodeInEverySlot() public {
        address v = address(new MockUltraVerifier());
        vm.expectRevert(CompositeVerifier.NoCode.selector);
        new CompositeVerifier(v, address(0x1234), v);
        new CompositeVerifier(v, v, v);
    }

    /// @dev Every pool test uses the mock composite verifier, so this is the
    ///      one check that each circuit's call reaches its own verifier.
    function testCompositeVerifierRoutesEachCircuit() public {
        CompositeVerifier c = new CompositeVerifier(
            address(new InputCountVerifier(22)),
            address(new InputCountVerifier(32)),
            address(new InputCountVerifier(10))
        );
        assertTrue(c.verifyDeposit("", new bytes32[](22)));
        assertTrue(c.verifyTransfer("", new bytes32[](32)));
        assertTrue(c.verifyWithdraw("", new bytes32[](10)));
        assertFalse(c.verifyDeposit("", new bytes32[](10)));
    }

    function testSetClaimKeyHashRejectsNonCanonical() public {
        vm.prank(timelock);
        vm.expectRevert(ShieldedPool.NonCanonicalClaimKeyHash.selector);
        pool.setClaimKeyHash(bytes32(P));
    }

    function testReplacingTheTransferAgentMovesItsPowers() public {
        vm.prank(timelock);
        pool.setTransferAgent(bob);

        vm.prank(agent);
        vm.expectRevert(ShieldedPool.NotTransferAgent.selector);
        pool.checkpoint(bytes32(0), SEED_UNITS);
        vm.prank(bob);
        pool.checkpoint(bytes32(0), SEED_UNITS);
    }

    function testSetTransferAgentRejectsZero() public {
        vm.prank(timelock);
        vm.expectRevert(ShieldedPool.ZeroAddress.selector);
        pool.setTransferAgent(address(0));
    }

    function testConstructorRejectsInvalidRegisterKey() public {
        ShieldedPool.ConstructorParams memory p = _params();
        p.registerKeyY = GY + 1;
        vm.expectRevert(ShieldedPool.InvalidRegisterKey.selector);
        new ShieldedPool(p);
    }

    function testConstructorRejectsNonCanonicalClaimKeyHash() public {
        ShieldedPool.ConstructorParams memory p = _params();
        p.claimKeyHash = bytes32(P);
        vm.expectRevert(ShieldedPool.NonCanonicalClaimKeyHash.selector);
        new ShieldedPool(p);
    }

    function testConstructorRejectsEpochMismatchWithRegistry() public {
        ShieldedPool.ConstructorParams memory p = _params();
        p.attestationRegistry = address(new AttestationRegistry(3600, 30, 3, 1, agent, timelock));
        vm.expectRevert(ShieldedPool.WrongEpochSeconds.selector);
        new ShieldedPool(p);
    }

    /// @dev The circuits hard-code a day. With week-long epochs, the circuit's
    ///      `(epoch + 1) * 86400` bound would lag real time sevenfold, and
    ///      expired attestations would verify.
    function testConstructorRejectsANonDailyEpoch() public {
        ShieldedPool.ConstructorParams memory p = _params();
        p.epochSeconds = 7 * EPOCH_SECONDS;
        p.attestationRegistry = address(new AttestationRegistry(7 * EPOCH_SECONDS, 30, 3, 1, agent, timelock));
        vm.expectRevert(ShieldedPool.WrongEpochSeconds.selector);
        new ShieldedPool(p);
    }

    function testConstructorRejectsInconsistentPauseParameters() public {
        ShieldedPool.ConstructorParams memory p = _params();
        p.maxPauseEpochs = 0;
        vm.expectRevert(ShieldedPool.InvalidPauseParams.selector);
        new ShieldedPool(p);

        p = _params();
        p.maxPauseEpochs = p.pauseBudgetEpochs + 1;
        vm.expectRevert(ShieldedPool.InvalidPauseParams.selector);
        new ShieldedPool(p);

        p = _params();
        p.pauseWindowEpochs = p.pauseBudgetEpochs;
        vm.expectRevert(ShieldedPool.InvalidPauseParams.selector);
        new ShieldedPool(p);
    }

    // ========== Pause ==========

    function testPauseStopsEveryOperationUntilItLifts() public {
        _deposit(alice, 1000);
        uint256 epoch = pool.currentEpoch();
        vm.prank(guardian);
        pool.pause(epoch + 2);

        ShieldedPool.DepositParams memory d = _depositParams(_leaf(), 1);
        vm.prank(alice);
        vm.expectRevert(ShieldedPool.ContractPaused.selector);
        pool.deposit(d);

        ShieldedPool.TransferParams memory t = _transferParams(_leaf(), _leaf(), _leaf(), _leaf());
        vm.expectRevert(ShieldedPool.ContractPaused.selector);
        pool.transfer(t);

        ShieldedPool.WithdrawParams memory w = _withdrawParams(_leaf(), 1, bob);
        vm.expectRevert(ShieldedPool.ContractPaused.selector);
        pool.withdraw(w);

        vm.warp((epoch + 2) * EPOCH_SECONDS);
        _deposit(alice, 1);
    }

    function testPauseRespectsCeilingAndBudget() public {
        uint256 epoch = pool.currentEpoch();
        vm.startPrank(guardian);
        vm.expectRevert(ShieldedPool.PauseCeilingExceeded.selector);
        pool.pause(epoch + 15);

        pool.pause(epoch + 14);
        pool.pause(epoch + 14);
        vm.expectRevert(ShieldedPool.PauseBudgetExceeded.selector);
        pool.pause(epoch + 3);
        pool.pause(epoch + 2);
        assertFalse(pool.guardianArmed(), "an exhausted budget disarms the guardian");
        vm.expectRevert(ShieldedPool.GuardianNotArmed.selector);
        pool.pause(epoch + 1);
        vm.stopPrank();

        vm.expectEmit(address(pool));
        emit ShieldedPool.GuardianRearmed();
        vm.prank(timelock);
        pool.rearmGuardian();
        assertTrue(pool.guardianArmed());
    }

    function testThePauseBudgetResetsWithEachWindow() public {
        uint256 epoch = pool.currentEpoch();
        vm.startPrank(guardian);
        pool.pause(epoch + 14);
        pool.pause(epoch + 14);
        vm.expectRevert(ShieldedPool.PauseBudgetExceeded.selector);
        pool.pause(epoch + 3);

        uint256 next = pool.pauseWindowStart() + pool.PAUSE_WINDOW_EPOCHS();
        vm.warp(next * EPOCH_SECONDS);
        pool.pause(next + 3);
        vm.stopPrank();
        assertEq(pool.pauseBudgetSpent(), 3, "a new window, a new budget");
    }

    /// @dev Rearming restores the whole budget, not only the flag: a guardian
    ///      rearmed with the budget still spent could not pause until the next
    ///      window.
    function testRearmingRestoresTheWholeBudget() public {
        uint256 epoch = pool.currentEpoch();
        vm.startPrank(guardian);
        pool.pause(epoch + 14);
        pool.pause(epoch + 14);
        pool.pause(epoch + 2);
        vm.stopPrank();
        assertFalse(pool.guardianArmed());
        vm.prank(timelock);
        pool.rearmGuardian();
        vm.prank(guardian);
        pool.pause(epoch + 14);
        assertEq(pool.pauseBudgetSpent(), 14, "a rearmed guardian has its whole budget");
    }

    function testPauseOnlyGuardian() public {
        uint256 untilEpoch = pool.currentEpoch() + 1;
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, address(this), pool.GUARDIAN_ROLE()
            )
        );
        pool.pause(untilEpoch);
    }

    /// @dev Rearming restores the whole pause budget, so a guardian that could
    ///      rearm itself could keep the pool paused for good.
    function testRearmOnlyGovernance() public {
        bytes32 admin = pool.DEFAULT_ADMIN_ROLE();
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, guardian, admin)
        );
        vm.prank(guardian);
        pool.rearmGuardian();
    }
}

/// @notice A verifier that accepts exactly one public-input count, so a call
///         routed to the wrong circuit's verifier fails.
contract InputCountVerifier {
    uint256 public immutable expected;

    constructor(uint256 n) {
        expected = n;
    }

    function verify(bytes calldata, bytes32[] calldata publicInputs) external view returns (bool) {
        return publicInputs.length == expected;
    }
}

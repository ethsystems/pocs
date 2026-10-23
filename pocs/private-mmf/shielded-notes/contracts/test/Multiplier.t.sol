// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/src/Test.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {MockFundToken} from "../src/mocks/MockFundToken.sol";
import {AttestationRegistry} from "../src/AttestationRegistry.sol";
import {PoolTestBase, GRUMPKIN_GX, GRUMPKIN_GY} from "./PoolTestBase.sol";
import {IAccessControl} from "@openzeppelin-contracts/access/IAccessControl.sol";

/// @notice SPEC, Multiplier Rules: m = floor(B * S / U); deposits pull
///         ceil(u * m / S); withdrawals pay floor(u * m / S); m never falls
///         across deposits and withdrawals; a fall reverts both, and a
///         checkpoint that finds it halts the pool until governance clears it.
contract MultiplierTest is PoolTestBase {
    function testInitialMultiplierIsS() public view {
        assertEq(pool.multiplier(), S);
        assertEq(pool.lastMultiplier(), S);
    }

    function testReinvestmentRaisesTheMultiplier() public {
        _deposit(alice, 1_000_000 - SEED_UNITS);
        _reinvest(0.0001e18);
        assertEq(pool.multiplier(), 1.0001e18);
        // No transaction touches the notes: lastMultiplier moves only on the
        // next deposit, withdrawal or checkpoint.
        assertEq(pool.lastMultiplier(), S);
        _deposit(alice, 1);
        assertGe(pool.lastMultiplier(), 1.0001e18);
    }

    /// @dev The worked example from the review: at m = 1.5 share-wei per unit,
    ///      one unit in costs 2 and one unit out pays 1.
    function testRoundingFavoursThePool() public {
        _deposit(alice, 2 - SEED_UNITS);
        _reinvest(0.5e18);
        assertEq(pool.multiplier(), 1.5e18);

        uint256 aliceBefore = token.balanceOf(alice);
        _deposit(alice, 1);
        assertEq(aliceBefore - token.balanceOf(alice), 2, "deposit rounds up");

        uint256 bobBefore = token.balanceOf(bob);
        _withdraw(1, bob);
        assertEq(token.balanceOf(bob) - bobBefore, 1, "withdrawal rounds down");
        assertGe(pool.multiplier(), 1.5e18);
    }

    function testForcedTransferOutRevertsDepositsAndWithdrawalsButNotTransfers() public {
        _deposit(alice, 1_000_000);
        token.setAdminExempt(address(pool), false);
        token.forceTransfer(address(pool), bob, 1);

        ShieldedPool.DepositParams memory d = _depositParams(_leaf(), 10);
        vm.prank(alice);
        vm.expectRevert(ShieldedPool.MultiplierDecreased.selector);
        pool.deposit(d);

        ShieldedPool.WithdrawParams memory w = _withdrawParams(_leaf(), 10, bob);
        vm.expectRevert(ShieldedPool.MultiplierDecreased.selector);
        pool.withdraw(w);

        // Transfers, and so claims, still work: they move no shares.
        pool.transfer(_transferParams(_leaf(), _leaf(), _leaf(), _leaf()));
    }

    function testReturningTheMissingSharesLetsDepositsAndWithdrawalsResume() public {
        _deposit(alice, 1_000_000);
        token.setAdminExempt(address(pool), false);
        token.forceTransfer(address(pool), bob, 1);

        token.mint(address(pool), 1);
        _deposit(alice, 10);
        _withdraw(10, bob);
    }

    function testAWithdrawalRecordsTheMultiplier() public {
        _deposit(alice, 1_000_000);
        _reinvest(0.01e18);
        _withdraw(1_000, bob);
        assertEq(pool.lastMultiplier(), pool.multiplier());
        assertGe(pool.lastMultiplier(), 1.01e18);
    }

    /// @dev With no units left m is undefined; the check after the token call
    ///      must not compare the stale value it then returns. The seed leaves
    ///      first, so the withdrawal after the yield empties the pool.
    function testTheLastWithdrawalSucceedsAfterYield() public {
        _deposit(alice, 999);
        _withdraw(SEED_UNITS, agent);
        _reinvest(1e18);
        assertEq(pool.multiplier(), 2e18);
        uint256 bobBefore = token.balanceOf(bob);
        _withdraw(999, bob);
        assertEq(pool.totalUnits(), 0);
        assertEq(token.balanceOf(bob) - bobBefore, 1_998);
    }

    /// @dev An emptied pool keeps its `lastMultiplier`: the agent comes back in
    ///      at that price, not at S, so emptying the pool never resets m.
    function testAnEmptiedPoolReadmitsTheAgentAtTheLastMultiplier() public {
        _deposit(alice, 999);
        _reinvest(1e18);
        _withdraw(999, bob);
        _withdraw(SEED_UNITS, agent);
        assertEq(pool.totalUnits(), 0);
        assertEq(pool.lastMultiplier(), 2e18);
        uint256 before = token.balanceOf(agent);
        _deposit(agent, 10);
        assertEq(before - token.balanceOf(agent), 20, "pays ceil(10 * lastMultiplier / S)");
    }

    function testExemptPoolRejectsForcedTransfer() public {
        _deposit(alice, 1_000_000);
        vm.expectRevert(abi.encodeWithSelector(MockFundToken.AdminExempt.selector, address(pool)));
        token.forceTransfer(address(pool), bob, 1);
    }

    function testExemptPoolCannotBeBurnt() public {
        _deposit(alice, 1_000_000);
        vm.expectRevert(abi.encodeWithSelector(MockFundToken.AdminExempt.selector, address(pool)));
        token.burn(address(pool), 1);
    }

    // ========== The halt ==========

    function _forceOut(uint256 shares) internal {
        token.setAdminExempt(address(pool), false);
        token.forceTransfer(address(pool), bob, shares);
    }

    function _checkpoint() internal {
        uint256 units = pool.totalUnits();
        vm.prank(agent);
        pool.checkpoint(bytes32(0), units);
    }

    function testCheckpointRecordsTheMultiplier() public {
        _deposit(alice, 1_000_000 - SEED_UNITS);
        _reinvest(0.01e18);
        _checkpoint();
        assertEq(pool.lastMultiplier(), 1.01e18);
        assertFalse(pool.halted());
    }

    /// @dev Before the latch, later yield lifted the halt by itself, so holders
    ///      absorbed the loss without the shares being returned.
    function testHaltSetAtACheckpointSurvivesLaterYield() public {
        _deposit(alice, 1_000_000);
        _forceOut(1);

        vm.expectEmit(address(pool));
        emit ShieldedPool.Halted(pool.multiplier(), S);
        _checkpoint();
        assertTrue(pool.halted());

        _reinvest(0.01e18);
        assertGt(pool.multiplier(), pool.lastMultiplier(), "yield more than covers the loss");

        ShieldedPool.DepositParams memory d = _depositParams(_leaf(), 10);
        vm.prank(alice);
        vm.expectRevert(ShieldedPool.PoolHalted.selector);
        pool.deposit(d);

        ShieldedPool.WithdrawParams memory w = _withdrawParams(_leaf(), 10, bob);
        vm.expectRevert(ShieldedPool.PoolHalted.selector);
        pool.withdraw(w);

        // Transfers, and so claims, still work: they move no shares.
        pool.transfer(_transferParams(_leaf(), _leaf(), _leaf(), _leaf()));
    }

    function testGovernanceClearsTheHaltOnceTheSharesAreReturned() public {
        _deposit(alice, 1_000_000);
        _forceOut(1);
        _checkpoint();

        token.mint(address(pool), 1);
        vm.expectEmit(address(pool));
        emit ShieldedPool.HaltCleared(S);
        vm.prank(timelock);
        pool.clearHalt();

        assertFalse(pool.halted());
        assertEq(pool.lastMultiplier(), S);
        _deposit(alice, 10);
        _withdraw(10, bob);
    }

    /// @dev clearHalt is scheduled days before it runs. Shares that are only
    ///      partly back, a second loss during the delay, or a total loss keep
    ///      the pool halted, rather than spreading the loss over every note.
    function testClearingTheHaltRequiresTheSharesBack() public {
        _deposit(alice, 1_000_000);
        _forceOut(1_000);
        _checkpoint();

        token.mint(address(pool), 500);
        vm.prank(timelock);
        vm.expectRevert(ShieldedPool.MultiplierNotRestored.selector);
        pool.clearHalt();

        token.mint(address(pool), 500);
        _forceOut(1);
        vm.prank(timelock);
        vm.expectRevert(ShieldedPool.MultiplierNotRestored.selector);
        pool.clearHalt();

        token.mint(address(pool), 1);
        vm.prank(timelock);
        pool.clearHalt();
        assertFalse(pool.halted());
    }

    function testATotalLossCannotBeCleared() public {
        _deposit(alice, 1_000_000);
        _forceOut(token.balanceOf(address(pool)));
        _checkpoint();
        vm.prank(timelock);
        vm.expectRevert(ShieldedPool.MultiplierNotRestored.selector);
        pool.clearHalt();
    }

    /// @dev Yield that arrives while the pool is halted counts: a checkpoint
    ///      records it, and clearing records the multiplier it finds.
    function testTheHaltKeepsTrackOfYield() public {
        _deposit(alice, 1_000_000);
        _forceOut(1);
        _checkpoint();

        token.mint(address(pool), 1);
        _reinvest(0.01e18);
        _checkpoint();
        assertTrue(pool.halted());
        assertEq(pool.lastMultiplier(), pool.multiplier(), "a checkpoint while halted records the recovery");

        _reinvest(0.01e18);
        vm.prank(timelock);
        pool.clearHalt();
        assertEq(pool.lastMultiplier(), pool.multiplier(), "clearing records the multiplier");
        assertGt(pool.lastMultiplier(), 1.02e18);
    }

    function testOnlyGovernanceClearsAHalt() public {
        _deposit(alice, 1_000_000);
        vm.prank(timelock);
        vm.expectRevert(ShieldedPool.NotHalted.selector);
        pool.clearHalt();

        _forceOut(1);
        _checkpoint();
        bytes32 admin = pool.DEFAULT_ADMIN_ROLE();
        vm.prank(agent);
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, agent, admin));
        pool.clearHalt();
    }

    /// @dev The SPEC's stated gap: an outflow smaller than the yield since the
    ///      last checkpoint leaves m above lastMultiplier, so nothing halts and
    ///      every note bears the loss. The transfer agent detects it off-chain.
    function testALossSmallerThanTheYieldSinceTheLastCheckpointPasses() public {
        _deposit(alice, 1_000_000 - SEED_UNITS);
        _reinvest(0.0001e18);
        _forceOut(50);
        _checkpoint();
        assertFalse(pool.halted());
        assertEq(pool.lastMultiplier(), 1.00005e18);
    }

    function testFuzzRoundTripNeverLowersTheMultiplier(uint64 first, uint64 units, uint256 rate) public {
        first = uint64(bound(first, 1, 1e12));
        units = uint64(bound(units, 1, 1e12));
        rate = bound(rate, 0, 1e18);

        _deposit(alice, first);
        _reinvest(rate);
        uint256 m0 = pool.multiplier();

        _deposit(alice, units);
        assertGe(pool.multiplier(), m0, "deposit lowered m");
        uint256 m1 = pool.multiplier();

        _withdraw(units, bob);
        assertGe(pool.multiplier(), m1, "withdrawal lowered m");

        // Solvency as an act: the last note can still be withdrawn.
        _withdraw(first, bob);
        assertEq(pool.totalUnits(), SEED_UNITS, "only the seed is left");
    }
}

/// @notice Drives random deposits, withdrawals and reinvestments against the
///         pool, tracking the notes it holds.
contract MultiplierHandler is Test {
    ShieldedPool public pool;
    MockFundToken public token;
    AttestationRegistry public registry;

    uint64[] public notes;
    uint256 public highestLastMultiplier;
    bool public multiplierFell;
    uint256 internal nextLeaf = 1_000_000;

    constructor(ShieldedPool pool_, MockFundToken token_, AttestationRegistry registry_) {
        pool = pool_;
        token = token_;
        registry = registry_;
        highestLastMultiplier = pool.lastMultiplier();
    }

    function deposit(uint64 units) external {
        units = uint64(bound(units, 1, 1e12));
        ShieldedPool.DepositParams memory p;
        p.commitment = bytes32(nextLeaf++);
        p.units = units;
        p.attestationRoot = registry.attestationRoot();
        p.epoch = pool.currentEpoch();
        p.feedR = [GRUMPKIN_GX, GRUMPKIN_GY];
        pool.deposit(p);
        notes.push(units);
        _track();
    }

    function withdraw(uint256 index) external {
        if (notes.length == 0) return;
        _withdraw(bound(index, 0, notes.length - 1));
    }

    /// @dev Withdraws every note still held, for the end of a run.
    function withdrawAll() external {
        while (notes.length > 0) {
            _withdraw(0);
        }
    }

    /// @dev The transfer agent's daily checkpoint. With no outflow here, it
    ///      never halts the pool.
    function checkpoint() external {
        uint256 units = pool.totalUnits();
        vm.prank(pool.transferAgent());
        pool.checkpoint(bytes32(0), units);
        _track();
    }

    function _withdraw(uint256 index) internal {
        uint64 units = notes[index];
        notes[index] = notes[notes.length - 1];
        notes.pop();

        ShieldedPool.WithdrawParams memory p;
        p.nullifier = bytes32(nextLeaf++);
        p.units = units;
        p.recipient = address(this);
        p.commitmentRoot = pool.commitmentRoot();
        p.attestationRoot = registry.attestationRoot();
        p.epoch = pool.currentEpoch();
        pool.withdraw(p);
        _track();
    }

    /// @dev Yield of up to 0.1% a day, as the issuer's daily reinvestment.
    function reinvest(uint256 rate) external {
        rate = bound(rate, 0, 0.001e18);
        address[] memory holders = new address[](1);
        holders[0] = address(pool);
        vm.prank(token.issuer());
        token.reinvest(holders, rate);
    }

    function outstandingUnits() external view returns (uint256 total) {
        for (uint256 i = 0; i < notes.length; i++) {
            total += notes[i];
        }
    }

    function _track() internal {
        uint256 m = pool.lastMultiplier();
        if (m < highestLastMultiplier) multiplierFell = true;
        highestLastMultiplier = m;
    }
}

/// forge-config: default.invariant.runs = 64
/// forge-config: default.invariant.depth = 40
/// forge-config: default.invariant.fail-on-revert = true
contract MultiplierInvariantTest is PoolTestBase {
    MultiplierHandler internal handler;

    function setUp() public override {
        super.setUp();
        handler = new MultiplierHandler(pool, token, registry);
        token.setAllowlisted(address(handler), true);
        // The handler receives every withdrawal, so it would hit the per-holder limit.
        token.setLimitExempt(address(handler), true);
        token.mint(address(handler), 1e15);
        vm.prank(address(handler));
        token.approve(address(pool), type(uint256).max);
        targetContract(address(handler));
    }

    function invariantMultiplierNeverFalls() public view {
        assertFalse(handler.multiplierFell());
        assertGe(pool.multiplier(), pool.lastMultiplier());
    }

    function invariantNeverHalts() public view {
        // The handler has no outflow, so no checkpoint finds m fallen.
        assertFalse(pool.halted());
    }

    /// @dev Solvency as an act rather than an inequality: at the end of every
    ///      run, every note the handler holds is withdrawn, none may revert, and
    ///      the pool keeps whatever rounding left.
    function afterInvariant() public {
        handler.withdrawAll();
        assertEq(pool.totalUnits(), SEED_UNITS, "only the seed is left");
    }

    function invariantUnitsMatchTheNotes() public view {
        assertEq(pool.totalUnits(), handler.outstandingUnits() + SEED_UNITS);
    }
}

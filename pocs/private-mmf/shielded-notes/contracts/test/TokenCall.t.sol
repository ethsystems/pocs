// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC20} from "@openzeppelin-contracts/token/ERC20/ERC20.sol";
import {Vm} from "forge-std/src/Vm.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {PoolTestBase} from "./PoolTestBase.sol";

/// @notice A share token whose transfer hook runs inside the pool's own token
///         call, as a token with hooks, or an upgradeable one, could. Armed to
///         skim, it moves shares out of the pool during that call; armed to
///         probe, it records what the pool has already written by then.
contract HookedToken is ERC20 {
    address public pool;
    address public sink;
    uint256 public skim;

    bool public probing;
    bytes32 public probedNullifier;
    uint256 public seenCommitments;
    uint256 public seenUnits;
    bool public seenSpent;

    constructor() ERC20("Hooked Fund Shares", "hMMF") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function armSkim(address pool_, address sink_, uint256 skim_) external {
        pool = pool_;
        sink = sink_;
        skim = skim_;
    }

    function armProbe(address pool_, bytes32 nullifier) external {
        pool = pool_;
        probing = true;
        probedNullifier = nullifier;
    }

    function _update(address from, address to, uint256 value) internal override {
        super._update(from, to, value);
        if (pool == address(0) || (from != pool && to != pool)) return;
        if (skim != 0) {
            uint256 amount = skim;
            skim = 0;
            _transfer(pool, sink, amount);
        }
        if (probing) {
            probing = false;
            ShieldedPool p = ShieldedPool(pool);
            seenCommitments = p.getCommitmentCount();
            seenUnits = p.totalUnits();
            seenSpent = p.nullifiers(probedNullifier);
        }
    }
}

/// @notice SPEC, Per-Operation Checks and Multiplier Rules: the pool records a
///         deposit's or withdrawal's notes and emits its event before the token
///         call, and the token must move exactly the shares asked for. A token
///         that also moves shares out of the pool during that call would lower
///         m inside the pool's own operation, where the check before the call
///         cannot see it; the check after it reverts the operation, outflow
///         included (council 2, C24).
contract TokenCallTest is PoolTestBase {
    HookedToken internal hooked;
    ShieldedPool internal hpool;
    address internal issuer = address(0x155);

    function setUp() public override {
        super.setUp();
        hooked = new HookedToken();
        ShieldedPool.ConstructorParams memory p = _params();
        p.token = address(hooked);
        hpool = new ShieldedPool(p);
        hooked.mint(alice, 1e13);
        vm.prank(alice);
        hooked.approve(address(hpool), type(uint256).max);

        // The agent seeds the pool, as at deployment.
        hooked.mint(agent, 1e13);
        vm.prank(agent);
        hooked.approve(address(hpool), type(uint256).max);
        ShieldedPool.DepositParams memory seed = _depositParams(_leaf(), SEED_UNITS);
        vm.prank(agent);
        hpool.deposit(seed);
    }

    function _hdeposit(uint64 units) internal {
        ShieldedPool.DepositParams memory d = _depositParams(_leaf(), units);
        vm.prank(alice);
        hpool.deposit(d);
    }

    function _hwithdrawParams(uint64 units, address to) internal returns (ShieldedPool.WithdrawParams memory w) {
        w = _withdrawParams(_leaf(), units, to);
        w.commitmentRoot = hpool.commitmentRoot();
    }

    function testAnOutflowInsideADepositReverts() public {
        _hdeposit(1_000_000);
        hooked.armSkim(address(hpool), issuer, 100_000);

        ShieldedPool.DepositParams memory d = _depositParams(_leaf(), 1_000);
        vm.prank(alice);
        vm.expectRevert(ShieldedPool.MultiplierDecreased.selector);
        hpool.deposit(d);

        assertEq(hooked.balanceOf(issuer), 0, "the revert undid the outflow");
        assertEq(hpool.lastMultiplier(), S);
        assertEq(hpool.totalUnits(), SEED_UNITS + 1_000_000);
    }

    /// @dev With yield since the last operation, m sits above lastMultiplier,
    ///      so an outflow smaller than that yield keeps m above lastMultiplier
    ///      too. Only the comparison with the m the call started from sees it.
    function testAnOutflowUnderTheYieldInsideADepositReverts() public {
        _hdeposit(1_000_000);
        hooked.mint(address(hpool), 10_000);
        hooked.armSkim(address(hpool), issuer, 100);

        ShieldedPool.DepositParams memory d = _depositParams(_leaf(), 1_000);
        vm.prank(alice);
        vm.expectRevert(ShieldedPool.MultiplierDecreased.selector);
        hpool.deposit(d);
    }

    function testAnOutflowInsideAWithdrawalReverts() public {
        _hdeposit(1_000_000);
        hooked.armSkim(address(hpool), issuer, 100_000);

        ShieldedPool.WithdrawParams memory w = _hwithdrawParams(10_000, bob);
        vm.expectRevert(ShieldedPool.MultiplierDecreased.selector);
        hpool.withdraw(w);

        assertEq(hooked.balanceOf(issuer), 0, "the revert undid the outflow");
        assertEq(hooked.balanceOf(bob), 0);
        assertEq(hpool.lastMultiplier(), S);
    }

    /// @dev Inside the token call, the deposit's commitment is already in the
    ///      tree and its units counted; the withdrawal's nullifier is already
    ///      marked and its units debited.
    function testTheNotesAreRecordedBeforeTheTokenCall() public {
        _hdeposit(1_000);
        hooked.armProbe(address(hpool), bytes32(0));
        _hdeposit(500);
        assertEq(hooked.seenCommitments(), 3, "the seed's, the first deposit's and this one's");
        assertEq(hooked.seenUnits(), SEED_UNITS + 1_500);

        ShieldedPool.WithdrawParams memory w = _hwithdrawParams(500, bob);
        hooked.armProbe(address(hpool), w.nullifier);
        hpool.withdraw(w);
        assertTrue(hooked.seenSpent());
        assertEq(hooked.seenUnits(), SEED_UNITS + 1_000);
    }

    /// @dev The pool's event precedes the token's `Transfer` in the logs.
    function testThePoolEmitsBeforeTheTokenMovesShares() public {
        vm.recordLogs();
        _deposit(alice, 1_000);
        _assertPoolEventFirst(ShieldedPool.Deposit.selector);

        vm.recordLogs();
        _withdraw(400, bob);
        _assertPoolEventFirst(ShieldedPool.Withdraw.selector);
    }

    function _assertPoolEventFirst(bytes32 poolEvent) internal {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 tokenTransfer = keccak256("Transfer(address,address,uint256)");
        uint256 poolAt = type(uint256).max;
        uint256 tokenAt = type(uint256).max;
        for (uint256 i = 0; i < logs.length; i++) {
            if (poolAt == type(uint256).max && logs[i].emitter == address(pool) && logs[i].topics[0] == poolEvent) {
                poolAt = i;
            }
            if (tokenAt == type(uint256).max && logs[i].emitter == address(token) && logs[i].topics[0] == tokenTransfer)
            {
                tokenAt = i;
            }
        }
        assertLt(tokenAt, logs.length, "the token moved shares");
        assertLt(poolAt, tokenAt, "the pool's event comes first");
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, Vm} from "forge-std/src/Test.sol";
import {ReentrancyGuard} from "@openzeppelin-contracts/utils/ReentrancyGuard.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {AttestationRegistry} from "../src/AttestationRegistry.sol";
import {MockVerifier} from "../src/mocks/MockCompositeVerifier.sol";
import {MockERC20} from "../src/mocks/MockERC20.sol";

/// @dev ERC-20 with a transfer hook that reenters the pool from inside transferFrom/transfer,
/// standing in for ERC-777 / ERC-1363 style tokens (spec §4.6: all entry points non-reentrant).
contract ReenteringToken is MockERC20 {
    ShieldedPool public pool;
    uint8 public mode; // 0 = none, 1 = reenter deposit, 2 = reenter withdraw
    bool public reentered;
    bytes public reentryRevert;

    constructor() MockERC20("Hook", "HOOK", 18) {}

    function setPool(ShieldedPool _pool) external {
        pool = _pool;
    }

    function setMode(uint8 _mode) external {
        mode = _mode;
    }

    function _update(address from, address to, uint256 value) internal override {
        super._update(from, to, value);
        if (mode != 0 && !reentered) {
            reentered = true;
            if (mode == 1) {
                try pool.deposit("", bytes32(uint256(99)), address(this), 1, address(this), "") {}
                catch (bytes memory reason) {
                    reentryRevert = reason;
                }
            } else {
                try pool.withdraw("", bytes32(uint256(99)), address(this), 1, address(this), pool.commitmentRoot()) {}
                catch (bytes memory reason) {
                    reentryRevert = reason;
                }
            }
        }
    }
}

contract ShieldedPoolReentrancyTest is Test {
    ShieldedPool pool;
    ReenteringToken token;
    address user = address(0x1);

    function setUp() public {
        AttestationRegistry registry = new AttestationRegistry();
        MockVerifier verifier = new MockVerifier();
        pool = new ShieldedPool(address(verifier), address(registry));
        token = new ReenteringToken();
        token.setPool(pool);
        pool.addSupportedToken(address(token));
        token.mint(user, 1_000e18);
        token.mint(address(pool), 1_000e18);
        vm.prank(user);
        token.approve(address(pool), type(uint256).max);
    }

    function test_depositReentrancyIsRejected() public {
        token.setMode(1);
        vm.prank(user);
        pool.deposit("", bytes32(uint256(1)), address(token), 100, user, "note");

        assertTrue(token.reentered(), "hook did not fire");
        assertEq(
            token.reentryRevert(),
            abi.encodeWithSelector(ReentrancyGuard.ReentrancyGuardReentrantCall.selector),
            "inner deposit must revert with ReentrancyGuardReentrantCall"
        );
        // Only the outer deposit landed
        assertEq(pool.getCommitmentCount(), 1);
    }

    function test_withdrawReentrancyIsRejected() public {
        token.setMode(2);
        pool.withdraw("", bytes32(uint256(7)), address(token), 100, address(0xBEEF), pool.commitmentRoot());

        assertTrue(token.reentered(), "hook did not fire");
        assertEq(
            token.reentryRevert(),
            abi.encodeWithSelector(ReentrancyGuard.ReentrancyGuardReentrantCall.selector),
            "inner withdraw must revert with ReentrancyGuardReentrantCall"
        );
        assertTrue(pool.nullifiers(bytes32(uint256(7))));
        assertFalse(pool.nullifiers(bytes32(uint256(99))));
    }

    /// @dev The Deposit event must be logged before the token pull (spec §4.6).
    function test_depositEventPrecedesTokenTransfer() public {
        vm.recordLogs();
        vm.prank(user);
        pool.deposit("", bytes32(uint256(1)), address(token), 100, user, "note");

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 depositSig = keccak256("Deposit(bytes32,address,uint256,bytes)");
        bytes32 transferSig = keccak256("Transfer(address,address,uint256)");
        uint256 depositIdx = type(uint256).max;
        uint256 transferIdx = type(uint256).max;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter == address(pool) && logs[i].topics[0] == depositSig && depositIdx == type(uint256).max) {
                depositIdx = i;
            }
            if (logs[i].emitter == address(token) && logs[i].topics[0] == transferSig && transferIdx == type(uint256).max) {
                transferIdx = i;
            }
        }
        assertTrue(depositIdx != type(uint256).max, "no Deposit event");
        assertTrue(transferIdx != type(uint256).max, "no ERC20 Transfer event");
        assertLt(depositIdx, transferIdx, "Deposit must be emitted before the token transfer");
    }
}

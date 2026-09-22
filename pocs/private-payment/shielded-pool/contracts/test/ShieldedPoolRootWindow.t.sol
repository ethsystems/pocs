// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/src/Test.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {AttestationRegistry} from "../src/AttestationRegistry.sol";
import {MockVerifier} from "../src/mocks/MockCompositeVerifier.sol";
import {MockERC20} from "../src/mocks/MockERC20.sol";
import {LeanIMT, LeanIMTData} from "@zk-kit/packages/lean-imt/contracts/LeanIMT.sol";

/// @notice 2/SHIELDED-POOL section 4.4: the root after the final insertion of each operation
/// enters the window; intermediate roots do not. The window holds 100 roots.
contract ShieldedPoolRootWindowTest is Test {
    using LeanIMT for LeanIMTData;

    ShieldedPool public pool;
    MockERC20 public token;
    address public user = address(0x1);

    // Replays the pool's insertions to compute roots the pool never exposes
    LeanIMTData internal _shadow;

    uint256 constant DEPOSIT_AMOUNT = 1000e6;

    function setUp() public {
        pool = new ShieldedPool(address(new MockVerifier()), address(new AttestationRegistry()));
        token = new MockERC20("USD Coin", "USDC", 6);
        pool.addSupportedToken(address(token));
        token.mint(user, DEPOSIT_AMOUNT);
        vm.prank(user);
        token.approve(address(pool), type(uint256).max);
    }

    function _deposit(uint256 commitment) internal {
        vm.prank(user);
        pool.deposit("", bytes32(commitment), address(token), DEPOSIT_AMOUNT, user, "");
        _shadow.insert(commitment);
    }

    /// @dev Transfer number `i` spends two fresh nullifiers and mints two fresh commitments
    function _transfer(uint256 i) internal returns (bytes32 intermediateRoot) {
        uint256 out0 = 1000 + 2 * i;
        uint256 out1 = 1001 + 2 * i;
        bytes32[2] memory nullifiers_ = [bytes32(5000 + 2 * i), bytes32(5001 + 2 * i)];
        bytes32[2] memory commitments_ = [bytes32(out0), bytes32(out1)];
        pool.transfer("", nullifiers_, commitments_, pool.commitmentRoot(), "");

        _shadow.insert(out0);
        intermediateRoot = bytes32(_shadow.root());
        _shadow.insert(out1);
        assertEq(bytes32(_shadow.root()), pool.commitmentRoot(), "shadow tree diverged");
    }

    function testTransferIntermediateRootNotKnown() public {
        _deposit(1);
        bytes32 before = pool.commitmentRoot();

        bytes32 intermediate = _transfer(0);

        assertFalse(pool.isKnownRoot(intermediate), "intermediate root accepted");
        assertTrue(pool.isKnownRoot(before), "prior operation root lost");
        assertTrue(pool.isKnownRoot(pool.commitmentRoot()), "current root lost");
    }

    function testCurrentRootEntersWindowAtOnce() public {
        _deposit(1);
        assertTrue(pool.validRoots(pool.commitmentRoot()));
    }

    function testWindowRetainsRootThrough99Operations() public {
        _deposit(1);
        bytes32 depositRoot = pool.commitmentRoot();

        // 100 transfers exceed the default test gas limit; gas is not under test here
        vm.pauseGasMetering();
        for (uint256 i = 0; i < 99; i++) {
            _transfer(i);
        }
        assertTrue(pool.isKnownRoot(depositRoot), "evicted before 100 roots");

        _transfer(99);
        assertFalse(pool.isKnownRoot(depositRoot), "kept past 100 roots");
    }
}

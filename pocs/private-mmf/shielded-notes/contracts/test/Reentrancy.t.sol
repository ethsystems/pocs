// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/src/Test.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {AttestationRegistry} from "../src/AttestationRegistry.sol";
import {ReentrantToken} from "../src/mocks/ReentrantToken.sol";
import {MockCompositeVerifier} from "../src/mocks/MockCompositeVerifier.sol";
import {LeanIMT, LeanIMTData} from "@zk-kit/packages/lean-imt/contracts/LeanIMT.sol";
import {GRUMPKIN_GX, GRUMPKIN_GY} from "./PoolTestBase.sol";
import {ReentrancyGuard} from "@openzeppelin-contracts/utils/ReentrancyGuard.sol";

/// @notice `ReentrantToken` re-enters the pool from inside the outer call's
///         token transfer. Since the value-moving entry points are
///         `nonReentrant`, the nested call MUST fail and the outer call's leaves
///         MUST be exactly the ones the outer proof committed to. The nested
///         caller is the token contract, funded and approved, so its call can
///         fail only on the guard, and each test checks it did. The guard stops
///         it whatever the order inside the pool; `TokenCallTest` checks that
///         order, insert and emit before the token call.
contract ReentrancyTest is Test {
    using LeanIMT for LeanIMTData;

    ShieldedPool public pool;
    AttestationRegistry public registry;
    ReentrantToken public token;
    MockCompositeVerifier public verifier;

    uint256 constant EPOCH_SECONDS = 86400;
    uint256 constant GX = 1;
    uint256 constant GY = 17631683881184975370165255887551781615748388533673675138860;

    address public alice = address(0xA11CE);
    address public agent = address(0xA6E7);

    /// @dev The transfer agent's seed, deposited in `setUp` as at deployment.
    bytes32 constant SEED = bytes32(uint256(0x5eed));

    LeanIMTData private _scratchTree;

    function setUp() public {
        vm.warp(1000 * EPOCH_SECONDS);

        token = new ReentrantToken("Reentrant Token", "RT");
        registry = new AttestationRegistry(EPOCH_SECONDS, 30, 3, 1, agent, address(0x71));
        verifier = new MockCompositeVerifier();

        pool = new ShieldedPool(
            ShieldedPool.ConstructorParams({
                token: address(token),
                attestationRegistry: address(registry),
                verifier: address(verifier),
                claimKeyHash: bytes32(uint256(0xc1a1)),
                transferAgent: agent,
                registerKeyX: GX,
                registerKeyY: GY,
                epochSeconds: EPOCH_SECONDS,
                maxPauseEpochs: 14,
                pauseBudgetEpochs: 30,
                pauseWindowEpochs: 90,
                timelockController: address(0x71),
                guardian: address(0x62)
            })
        );

        bytes32[] memory owners = new bytes32[](1);
        owners[0] = bytes32(uint256(0x0e1));
        uint64 expiresAt = uint64((pool.currentEpoch() + 30) * EPOCH_SECONDS);
        vm.prank(agent);
        registry.addAttestations(owners, expiresAt, 0);

        token.mint(alice, 1_000_000_000_000);
        vm.prank(alice);
        token.approve(address(pool), type(uint256).max);

        token.mint(agent, 1);
        vm.prank(agent);
        token.approve(address(pool), type(uint256).max);
        ShieldedPool.DepositParams memory seed = _deposit(SEED, 1);
        vm.prank(agent);
        pool.deposit(seed);

        token.mint(address(token), 1_000_000_000_000);
        token.selfApprove(address(pool), type(uint256).max);
    }

    function _assertStoppedByTheGuard() internal view {
        assertTrue(token.reentrancyAttempted());
        assertFalse(token.reentrancySucceeded());
        assertEq(
            bytes4(token.reentrantRevertData()), ReentrancyGuard.ReentrancyGuardReentrantCall.selector, "not the guard"
        );
    }

    function _deposit(bytes32 commitment, uint64 units) internal view returns (ShieldedPool.DepositParams memory p) {
        p.commitment = commitment;
        p.units = units;
        p.attestationRoot = registry.attestationRoot();
        p.epoch = pool.currentEpoch();
        p.feedR = [GRUMPKIN_GX, GRUMPKIN_GY];
    }

    function testDepositTransferHookCannotReenterPool() public {
        ShieldedPool.DepositParams memory nested = _deposit(bytes32(uint256(101)), 10);
        token.setReentrancy(address(pool), abi.encodeWithSelector(pool.deposit.selector, nested), true);

        ShieldedPool.DepositParams memory p = _deposit(bytes32(uint256(1)), 500);
        vm.prank(alice);
        pool.deposit(p);

        _assertStoppedByTheGuard();
    }

    function testWithdrawTransferHookCannotReenterPool() public {
        ShieldedPool.DepositParams memory first = _deposit(bytes32(uint256(1)), 500);
        vm.prank(alice);
        pool.deposit(first);

        ShieldedPool.DepositParams memory nested = _deposit(bytes32(uint256(101)), 10);
        token.setReentrancy(address(pool), abi.encodeWithSelector(pool.deposit.selector, nested), true);

        ShieldedPool.WithdrawParams memory w;
        w.nullifier = bytes32(uint256(0x5e));
        w.units = 500;
        w.recipient = alice;
        w.commitmentRoot = pool.commitmentRoot();
        w.attestationRoot = registry.attestationRoot();
        w.epoch = pool.currentEpoch();
        pool.withdraw(w);

        _assertStoppedByTheGuard();
        assertEq(pool.getCommitmentCount(), 2, "the seed and the first deposit");
        assertEq(pool.totalUnits(), 1, "the seed");
    }

    function testDepositTransferHookCannotInterleaveLeavesAheadOfEvent() public {
        // A second deposit armed as the reentrant call. Were it to get past the
        // guard, its leaf would land inside the outer call and the tree would
        // diverge from the outer proof's.
        ShieldedPool.DepositParams memory nested = _deposit(bytes32(uint256(101)), 10);
        token.setReentrancy(address(pool), abi.encodeWithSelector(pool.deposit.selector, nested), true);

        ShieldedPool.DepositParams memory p = _deposit(bytes32(uint256(1)), 500);
        vm.prank(alice);
        pool.deposit(p);

        _assertStoppedByTheGuard();

        assertEq(pool.getCommitmentCount(), 2, "the seed and the outer deposit");
        _scratchTree.insert(uint256(SEED));
        _scratchTree.insert(1);
        assertEq(pool.commitmentRoot(), bytes32(_scratchTree.root()));
        assertEq(pool.totalUnits(), 501);
    }
}

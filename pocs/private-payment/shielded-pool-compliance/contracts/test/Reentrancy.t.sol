// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/src/Test.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {PublicInputs} from "../src/PublicInputs.sol";
import {AttestationRegistry} from "../src/AttestationRegistry.sol";
import {ReentrantToken} from "../src/mocks/ReentrantToken.sol";
import {MockCompositeVerifier} from "../src/mocks/MockCompositeVerifier.sol";
import {MockUltraVerifier} from "../src/mocks/MockUltraVerifier.sol";
import {LeanIMT, LeanIMTData} from "@zk-kit/packages/lean-imt/contracts/LeanIMT.sol";

/// @notice `ReentrantToken` re-enters the pool from inside the outer call's
///         token transfer. Since every entry point inserts its commitments
///         and emits its event before that transfer (step 7 and 8 before step
///         9), and every entry point is `nonReentrant`, the nested call MUST
///         fail and the outer call's leaves MUST be exactly the ones the
///         outer proof committed to, in the outer's own order.
contract ReentrancyTest is Test {
    using LeanIMT for LeanIMTData;

    ShieldedPool public pool;
    AttestationRegistry public registry;
    ReentrantToken public token;
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

    LeanIMTData private _scratchTree;

    function setUp() public {
        vm.warp(1000 * EPOCH_SECONDS);

        token = new ReentrantToken("Reentrant Token", "RT");
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

        token.mint(alice, 1_000_000_000_000);
        vm.prank(alice);
        token.approve(address(pool), type(uint256).max);
    }

    function _baseDeposit(bytes32 commitment, bytes32 velocityNullifier, bytes32 complianceOut, uint256 amount)
        internal
        view
        returns (ShieldedPool.DepositParams memory)
    {
        ShieldedPool.DepositParams memory p = ShieldedPool.DepositParams({
            proof: "",
            commitment: commitment,
            token: uint256(uint160(address(token))),
            amount: amount,
            attestationRoot: registry.attestationRoot(),
            velocityNullifier: velocityNullifier,
            complianceCommitmentOut: complianceOut,
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

    function testDepositTransferHookCannotReenterPool() public {
        // Arm the token to call back into `claimBlocked` (any `nonReentrant`
        // entry point) mid-transfer.
        bytes memory reentrantCall = abi.encodeWithSelector(pool.claimBlocked.selector, bytes32(uint256(999)));
        token.setReentrancy(address(pool), reentrantCall, true);

        bytes32 commitment = bytes32(uint256(1));
        bytes32 velocityNullifier = bytes32(uint256(2));
        bytes32 complianceOut = bytes32(uint256(3));
        ShieldedPool.DepositParams memory p = _baseDeposit(commitment, velocityNullifier, complianceOut, 500);

        vm.prank(alice);
        pool.deposit(p);

        assertTrue(token.reentrancyAttempted());
        assertFalse(token.reentrancySucceeded());
    }

    function testDepositTransferHookCannotInterleaveLeavesAheadOfEvent() public {
        // A second, independent deposit's leaves, armed as the reentrant call.
        // If the pool's own ordering (insert + emit, then transfer) were
        // violated, this nested deposit's leaves would land inside the outer
        // call and the tree would diverge from the expected two-leaf root.
        bytes32 nestedCommitment = bytes32(uint256(101));
        bytes32 nestedVelocity = bytes32(uint256(102));
        bytes32 nestedCompliance = bytes32(uint256(103));
        ShieldedPool.DepositParams memory nested = _baseDeposit(nestedCommitment, nestedVelocity, nestedCompliance, 10);
        bytes memory reentrantCall = abi.encodeWithSelector(pool.deposit.selector, nested);
        token.setReentrancy(address(pool), reentrantCall, true);

        bytes32 commitment = bytes32(uint256(1));
        bytes32 velocityNullifier = bytes32(uint256(2));
        bytes32 complianceOut = bytes32(uint256(3));
        ShieldedPool.DepositParams memory p = _baseDeposit(commitment, velocityNullifier, complianceOut, 500);

        vm.prank(alice);
        pool.deposit(p);

        assertTrue(token.reentrancyAttempted());
        assertFalse(token.reentrancySucceeded());

        // Exactly the outer call's two leaves, in the outer's own order.
        assertEq(pool.getCommitmentCount(), 2);
        _scratchTree.insert(uint256(commitment));
        _scratchTree.insert(uint256(complianceOut));
        assertEq(pool.commitmentRoot(), bytes32(_scratchTree.root()));

        // The nested deposit's own nullifier never got marked.
        assertFalse(pool.nullifiers(nestedVelocity));
    }
}

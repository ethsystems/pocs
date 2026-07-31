// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/src/Test.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {PublicInputs} from "../src/PublicInputs.sol";
import {AttestationRegistry} from "../src/AttestationRegistry.sol";
import {MockERC20} from "../src/mocks/MockERC20.sol";
import {MockCompositeVerifier} from "../src/mocks/MockCompositeVerifier.sol";
import {MockUltraVerifier} from "../src/mocks/MockUltraVerifier.sol";

/// @notice `PublicInputs.requireCanonical` MUST reject `x + p` for every
///         field-typed input on all four entry points, before any other
///         predicate or proof verification runs.
contract CanonicalizationTest is Test {
    ShieldedPool public pool;
    AttestationRegistry public registry;
    MockERC20 public token;
    MockCompositeVerifier public verifier;
    MockUltraVerifier public ungatedVerifier;

    uint256 constant EPOCH_SECONDS = 86400;
    uint256 constant BN254_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

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

        token.mint(alice, 1_000_000_000_000);
        vm.prank(alice);
        token.approve(address(pool), type(uint256).max);
    }

    function _aboveModulus(uint256 base) internal pure returns (bytes32) {
        return bytes32(base + BN254_MODULUS);
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
        p.payloadCommitment = bytes32(uint256(keccak256(p.encryptedNotes)) % BN254_MODULUS);
        return p;
    }

    function _baseTransfer() internal view returns (ShieldedPool.TransferParams memory) {
        ShieldedPool.TransferParams memory p = ShieldedPool.TransferParams({
            proof: "",
            nullifier0: bytes32(uint256(11)),
            nullifier1: bytes32(uint256(12)),
            commitmentOut0: bytes32(uint256(13)),
            commitmentOut1: bytes32(uint256(14)),
            commitmentRoot: pool.commitmentRoot(),
            velocityNullifier: bytes32(uint256(15)),
            complianceCommitmentOut: bytes32(uint256(16)),
            epoch: pool.currentEpoch(),
            epochSeconds: EPOCH_SECONDS,
            policySourceHash: pool.activePolicySourceHash(),
            attestationRoot: registry.attestationRoot(),
            attesterRevocationRoot: registry.attesterRevocationRoot(),
            minAcceptedGeneration: registry.minAcceptedGeneration(),
            payloadCommitment: bytes32(0),
            encryptedNotes: ""
        });
        p.payloadCommitment = bytes32(uint256(keccak256(p.encryptedNotes)) % BN254_MODULUS);
        return p;
    }

    function _baseWithdraw() internal view returns (ShieldedPool.WithdrawParams memory) {
        ShieldedPool.WithdrawParams memory p = ShieldedPool.WithdrawParams({
            proof: "",
            nullifier: bytes32(uint256(21)),
            token: uint256(uint160(address(token))),
            amount: 500,
            recipient: alice,
            commitmentRoot: pool.commitmentRoot(),
            velocityNullifier: bytes32(uint256(22)),
            complianceCommitmentOut: bytes32(uint256(23)),
            epoch: pool.currentEpoch(),
            epochSeconds: EPOCH_SECONDS,
            policySourceHash: pool.activePolicySourceHash(),
            attestationRoot: registry.attestationRoot(),
            attesterRevocationRoot: registry.attesterRevocationRoot(),
            minAcceptedGeneration: registry.minAcceptedGeneration(),
            payloadCommitment: bytes32(0),
            encryptedNotes: ""
        });
        p.payloadCommitment = bytes32(uint256(keccak256(p.encryptedNotes)) % BN254_MODULUS);
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

    // ========== Deposit ==========

    function testDepositRejectsNonCanonicalCommitment() public {
        ShieldedPool.DepositParams memory p = _baseDeposit();
        p.commitment = _aboveModulus(1);
        vm.expectRevert(PublicInputs.NonCanonicalInput.selector);
        vm.prank(alice);
        pool.deposit(p);
    }

    function testDepositRejectsNonCanonicalAttestationRoot() public {
        ShieldedPool.DepositParams memory p = _baseDeposit();
        p.attestationRoot = _aboveModulus(0);
        vm.expectRevert(PublicInputs.NonCanonicalInput.selector);
        vm.prank(alice);
        pool.deposit(p);
    }

    function testDepositRejectsNonCanonicalVelocityNullifier() public {
        ShieldedPool.DepositParams memory p = _baseDeposit();
        p.velocityNullifier = _aboveModulus(2);
        vm.expectRevert(PublicInputs.NonCanonicalInput.selector);
        vm.prank(alice);
        pool.deposit(p);
    }

    function testDepositRejectsNonCanonicalComplianceCommitmentOut() public {
        ShieldedPool.DepositParams memory p = _baseDeposit();
        p.complianceCommitmentOut = _aboveModulus(3);
        vm.expectRevert(PublicInputs.NonCanonicalInput.selector);
        vm.prank(alice);
        pool.deposit(p);
    }

    function testDepositRejectsNonCanonicalPolicySourceHash() public {
        ShieldedPool.DepositParams memory p = _baseDeposit();
        p.policySourceHash = _aboveModulus(0);
        vm.expectRevert(PublicInputs.NonCanonicalInput.selector);
        vm.prank(alice);
        pool.deposit(p);
    }

    function testDepositRejectsNonCanonicalCommitmentRoot() public {
        ShieldedPool.DepositParams memory p = _baseDeposit();
        p.commitmentRoot = _aboveModulus(0);
        vm.expectRevert(PublicInputs.NonCanonicalInput.selector);
        vm.prank(alice);
        pool.deposit(p);
    }

    function testDepositRejectsNonCanonicalAttesterRevocationRoot() public {
        ShieldedPool.DepositParams memory p = _baseDeposit();
        p.attesterRevocationRoot = _aboveModulus(0);
        vm.expectRevert(PublicInputs.NonCanonicalInput.selector);
        vm.prank(alice);
        pool.deposit(p);
    }

    function testDepositRejectsNonCanonicalPayloadCommitment() public {
        ShieldedPool.DepositParams memory p = _baseDeposit();
        p.payloadCommitment = _aboveModulus(0);
        vm.expectRevert(PublicInputs.NonCanonicalInput.selector);
        vm.prank(alice);
        pool.deposit(p);
    }

    // ========== Transfer ==========

    function testTransferRejectsNonCanonicalNullifier0() public {
        ShieldedPool.TransferParams memory p = _baseTransfer();
        p.nullifier0 = _aboveModulus(11);
        vm.expectRevert(PublicInputs.NonCanonicalInput.selector);
        vm.prank(alice);
        pool.transfer(p);
    }

    function testTransferRejectsNonCanonicalNullifier1() public {
        ShieldedPool.TransferParams memory p = _baseTransfer();
        p.nullifier1 = _aboveModulus(12);
        vm.expectRevert(PublicInputs.NonCanonicalInput.selector);
        vm.prank(alice);
        pool.transfer(p);
    }

    function testTransferRejectsNonCanonicalCommitmentOut0() public {
        ShieldedPool.TransferParams memory p = _baseTransfer();
        p.commitmentOut0 = _aboveModulus(13);
        vm.expectRevert(PublicInputs.NonCanonicalInput.selector);
        vm.prank(alice);
        pool.transfer(p);
    }

    function testTransferRejectsNonCanonicalCommitmentOut1() public {
        ShieldedPool.TransferParams memory p = _baseTransfer();
        p.commitmentOut1 = _aboveModulus(14);
        vm.expectRevert(PublicInputs.NonCanonicalInput.selector);
        vm.prank(alice);
        pool.transfer(p);
    }

    function testTransferRejectsNonCanonicalCommitmentRoot() public {
        ShieldedPool.TransferParams memory p = _baseTransfer();
        p.commitmentRoot = _aboveModulus(0);
        vm.expectRevert(PublicInputs.NonCanonicalInput.selector);
        vm.prank(alice);
        pool.transfer(p);
    }

    function testTransferRejectsNonCanonicalVelocityNullifier() public {
        ShieldedPool.TransferParams memory p = _baseTransfer();
        p.velocityNullifier = _aboveModulus(15);
        vm.expectRevert(PublicInputs.NonCanonicalInput.selector);
        vm.prank(alice);
        pool.transfer(p);
    }

    function testTransferRejectsNonCanonicalComplianceCommitmentOut() public {
        ShieldedPool.TransferParams memory p = _baseTransfer();
        p.complianceCommitmentOut = _aboveModulus(16);
        vm.expectRevert(PublicInputs.NonCanonicalInput.selector);
        vm.prank(alice);
        pool.transfer(p);
    }

    function testTransferRejectsNonCanonicalAttestationRoot() public {
        ShieldedPool.TransferParams memory p = _baseTransfer();
        p.attestationRoot = _aboveModulus(0);
        vm.expectRevert(PublicInputs.NonCanonicalInput.selector);
        vm.prank(alice);
        pool.transfer(p);
    }

    function testTransferRejectsNonCanonicalPayloadCommitment() public {
        ShieldedPool.TransferParams memory p = _baseTransfer();
        p.payloadCommitment = _aboveModulus(0);
        vm.expectRevert(PublicInputs.NonCanonicalInput.selector);
        vm.prank(alice);
        pool.transfer(p);
    }

    // ========== Withdraw (gated) ==========

    function testWithdrawRejectsNonCanonicalNullifier() public {
        ShieldedPool.WithdrawParams memory p = _baseWithdraw();
        p.nullifier = _aboveModulus(21);
        vm.expectRevert(PublicInputs.NonCanonicalInput.selector);
        vm.prank(alice);
        pool.withdraw(p);
    }

    function testWithdrawRejectsNonCanonicalCommitmentRoot() public {
        ShieldedPool.WithdrawParams memory p = _baseWithdraw();
        p.commitmentRoot = _aboveModulus(0);
        vm.expectRevert(PublicInputs.NonCanonicalInput.selector);
        vm.prank(alice);
        pool.withdraw(p);
    }

    function testWithdrawRejectsNonCanonicalVelocityNullifier() public {
        ShieldedPool.WithdrawParams memory p = _baseWithdraw();
        p.velocityNullifier = _aboveModulus(22);
        vm.expectRevert(PublicInputs.NonCanonicalInput.selector);
        vm.prank(alice);
        pool.withdraw(p);
    }

    function testWithdrawRejectsNonCanonicalComplianceCommitmentOut() public {
        ShieldedPool.WithdrawParams memory p = _baseWithdraw();
        p.complianceCommitmentOut = _aboveModulus(23);
        vm.expectRevert(PublicInputs.NonCanonicalInput.selector);
        vm.prank(alice);
        pool.withdraw(p);
    }

    function testWithdrawRejectsNonCanonicalAttesterRevocationRoot() public {
        ShieldedPool.WithdrawParams memory p = _baseWithdraw();
        p.attesterRevocationRoot = _aboveModulus(0);
        vm.expectRevert(PublicInputs.NonCanonicalInput.selector);
        vm.prank(alice);
        pool.withdraw(p);
    }

    function testWithdrawRejectsNonCanonicalPayloadCommitment() public {
        ShieldedPool.WithdrawParams memory p = _baseWithdraw();
        p.payloadCommitment = _aboveModulus(0);
        vm.expectRevert(PublicInputs.NonCanonicalInput.selector);
        vm.prank(alice);
        pool.withdraw(p);
    }

    // ========== WithdrawBlocked (ungated) ==========

    function testWithdrawBlockedRejectsNonCanonicalNullifier() public {
        ShieldedPool.WithdrawBlockedParams memory p = _baseWithdrawBlocked();
        p.nullifier = _aboveModulus(31);
        vm.expectRevert(PublicInputs.NonCanonicalInput.selector);
        vm.prank(alice);
        pool.withdrawBlocked(p);
    }

    function testWithdrawBlockedRejectsNonCanonicalCommitmentRoot() public {
        ShieldedPool.WithdrawBlockedParams memory p = _baseWithdrawBlocked();
        p.commitmentRoot = _aboveModulus(0);
        vm.expectRevert(PublicInputs.NonCanonicalInput.selector);
        vm.prank(alice);
        pool.withdrawBlocked(p);
    }
}

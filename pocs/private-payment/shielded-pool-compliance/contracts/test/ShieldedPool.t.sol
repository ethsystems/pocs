// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/src/Test.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {PublicInputs} from "../src/PublicInputs.sol";
import {AttestationRegistry} from "../src/AttestationRegistry.sol";
import {MockERC20} from "../src/mocks/MockERC20.sol";
import {MockCompositeVerifier} from "../src/mocks/MockCompositeVerifier.sol";
import {MockUltraVerifier} from "../src/mocks/MockUltraVerifier.sol";
import {LeanIMT, LeanIMTData} from "@zk-kit/packages/lean-imt/contracts/LeanIMT.sol";

contract ShieldedPoolTest is Test {
    using LeanIMT for LeanIMTData;

    ShieldedPool public pool;
    AttestationRegistry public registry;
    MockERC20 public token;
    MockCompositeVerifier public verifier;
    MockUltraVerifier public ungatedVerifier;

    uint256 constant EPOCH_SECONDS = 86400;
    uint256 constant MAX_ATTESTATION_EPOCHS = 7;
    uint256 constant MIN_COHORT_SIZE = 1;
    uint256 constant SINGLE_TX_THRESHOLD = 10_000_000_000;
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
        registry = new AttestationRegistry(
            EPOCH_SECONDS, MAX_ATTESTATION_EPOCHS, MIN_COHORT_SIZE, address(this), address(this), 2
        );
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
                singleTxThreshold: SINGLE_TX_THRESHOLD,
                epochSeconds: EPOCH_SECONDS,
                timelockDelaySeconds: TIMELOCK_DELAY_SECONDS,
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
            encryptedNotes: "notes"
        });
        p.payloadCommitment = bytes32(uint256(keccak256(p.encryptedNotes)) % PublicInputs.BN254_MODULUS);
        return p;
    }

    function _baseTransfer(
        bytes32 nullifier0,
        bytes32 nullifier1,
        bytes32 commitmentOut0,
        bytes32 commitmentOut1,
        bytes32 velocityNullifier,
        bytes32 complianceOut
    ) internal view returns (ShieldedPool.TransferParams memory) {
        ShieldedPool.TransferParams memory p = ShieldedPool.TransferParams({
            proof: "",
            nullifier0: nullifier0,
            nullifier1: nullifier1,
            commitmentOut0: commitmentOut0,
            commitmentOut1: commitmentOut1,
            commitmentRoot: pool.commitmentRoot(),
            velocityNullifier: velocityNullifier,
            complianceCommitmentOut: complianceOut,
            epoch: pool.currentEpoch(),
            epochSeconds: EPOCH_SECONDS,
            policySourceHash: pool.activePolicySourceHash(),
            attestationRoot: registry.attestationRoot(),
            attesterRevocationRoot: registry.attesterRevocationRoot(),
            minAcceptedGeneration: registry.minAcceptedGeneration(),
            payloadCommitment: bytes32(0),
            encryptedNotes: "notes"
        });
        p.payloadCommitment = bytes32(uint256(keccak256(p.encryptedNotes)) % PublicInputs.BN254_MODULUS);
        return p;
    }

    function _baseWithdraw(
        bytes32 nullifier,
        bytes32 velocityNullifier,
        bytes32 complianceOut,
        uint256 amount,
        address recipient
    ) internal view returns (ShieldedPool.WithdrawParams memory) {
        ShieldedPool.WithdrawParams memory p = ShieldedPool.WithdrawParams({
            proof: "",
            nullifier: nullifier,
            token: uint256(uint160(address(token))),
            amount: amount,
            recipient: recipient,
            commitmentRoot: pool.commitmentRoot(),
            velocityNullifier: velocityNullifier,
            complianceCommitmentOut: complianceOut,
            epoch: pool.currentEpoch(),
            epochSeconds: EPOCH_SECONDS,
            policySourceHash: pool.activePolicySourceHash(),
            attestationRoot: registry.attestationRoot(),
            attesterRevocationRoot: registry.attesterRevocationRoot(),
            minAcceptedGeneration: registry.minAcceptedGeneration(),
            payloadCommitment: bytes32(0),
            encryptedNotes: "notes"
        });
        p.payloadCommitment = bytes32(uint256(keccak256(p.encryptedNotes)) % PublicInputs.BN254_MODULUS);
        return p;
    }

    // ========== Deposit ==========

    function testDepositHappyPath() public {
        uint256 balanceBefore = token.balanceOf(address(pool));
        ShieldedPool.DepositParams memory p =
            _baseDeposit(bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)), 500);

        vm.prank(alice);
        pool.deposit(p);

        assertEq(token.balanceOf(address(pool)), balanceBefore + 500);
        assertTrue(pool.nullifiers(bytes32(uint256(2))));
        assertEq(pool.getCommitmentCount(), 2);
    }

    LeanIMTData private _scratchTree;

    function testDepositInsertionOrderIsValueThenCompliance() public {
        bytes32 commitment = bytes32(uint256(11));
        bytes32 complianceOut = bytes32(uint256(12));
        ShieldedPool.DepositParams memory p = _baseDeposit(commitment, bytes32(uint256(13)), complianceOut, 500);

        vm.prank(alice);
        pool.deposit(p);

        _scratchTree.insert(uint256(commitment));
        _scratchTree.insert(uint256(complianceOut));

        assertEq(pool.commitmentRoot(), bytes32(_scratchTree.root()));
    }

    function testDepositRevertsWrongToken() public {
        verifier.setDepositResult(false);
        ShieldedPool.DepositParams memory p =
            _baseDeposit(bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)), 500);
        p.token = uint256(uint160(address(0xdead)));
        vm.expectRevert(ShieldedPool.WrongToken.selector);
        vm.prank(alice);
        pool.deposit(p);
    }

    function testDepositRevertsZeroAmount() public {
        verifier.setDepositResult(false);
        ShieldedPool.DepositParams memory p =
            _baseDeposit(bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)), 0);
        vm.expectRevert(ShieldedPool.ZeroAmount.selector);
        vm.prank(alice);
        pool.deposit(p);
    }

    function testDepositRevertsWrongEpoch() public {
        verifier.setDepositResult(false);
        ShieldedPool.DepositParams memory p =
            _baseDeposit(bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)), 500);
        p.epoch = pool.currentEpoch() + 1;
        vm.expectRevert(ShieldedPool.WrongEpoch.selector);
        vm.prank(alice);
        pool.deposit(p);
    }

    function testDepositRevertsWrongEpochSeconds() public {
        verifier.setDepositResult(false);
        ShieldedPool.DepositParams memory p =
            _baseDeposit(bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)), 500);
        p.epochSeconds = EPOCH_SECONDS + 1;
        vm.expectRevert(ShieldedPool.WrongEpochSeconds.selector);
        vm.prank(alice);
        pool.deposit(p);
    }

    function testDepositRevertsWrongPolicySourceHash() public {
        verifier.setDepositResult(false);
        ShieldedPool.DepositParams memory p =
            _baseDeposit(bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)), 500);
        p.policySourceHash = bytes32(uint256(0xdead));
        vm.expectRevert(ShieldedPool.WrongPolicySourceHash.selector);
        vm.prank(alice);
        pool.deposit(p);
    }

    function testDepositRevertsVelocityNullifierSpent() public {
        ShieldedPool.DepositParams memory first =
            _baseDeposit(bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)), 500);
        vm.prank(alice);
        pool.deposit(first);

        verifier.setDepositResult(false);
        ShieldedPool.DepositParams memory p =
            _baseDeposit(bytes32(uint256(4)), bytes32(uint256(2)), bytes32(uint256(5)), 500);
        vm.expectRevert(ShieldedPool.NullifierSpent.selector);
        vm.prank(alice);
        pool.deposit(p);
    }

    function testDepositRevertsUnknownCommitmentRoot() public {
        verifier.setDepositResult(false);
        ShieldedPool.DepositParams memory p =
            _baseDeposit(bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)), 500);
        p.commitmentRoot = bytes32(uint256(0xdead));
        vm.expectRevert(ShieldedPool.UnknownRoot.selector);
        vm.prank(alice);
        pool.deposit(p);
    }

    function testDepositRevertsUnknownAttestationRoot() public {
        verifier.setDepositResult(false);
        ShieldedPool.DepositParams memory p =
            _baseDeposit(bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)), 500);
        p.attestationRoot = bytes32(uint256(0xdead));
        vm.expectRevert(ShieldedPool.UnknownRoot.selector);
        vm.prank(alice);
        pool.deposit(p);
    }

    function testDepositRevertsWrongAttesterRevocationRoot() public {
        verifier.setDepositResult(false);
        ShieldedPool.DepositParams memory p =
            _baseDeposit(bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)), 500);
        p.attesterRevocationRoot = bytes32(uint256(0xdead));
        vm.expectRevert(ShieldedPool.WrongAttesterRevocationRoot.selector);
        vm.prank(alice);
        pool.deposit(p);
    }

    function testDepositRevertsWrongGeneration() public {
        verifier.setDepositResult(false);
        ShieldedPool.DepositParams memory p =
            _baseDeposit(bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)), 500);
        p.minAcceptedGeneration = 99;
        vm.expectRevert(ShieldedPool.WrongGeneration.selector);
        vm.prank(alice);
        pool.deposit(p);
    }

    function testDepositRevertsInvalidProof() public {
        verifier.setDepositResult(false);
        ShieldedPool.DepositParams memory p =
            _baseDeposit(bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)), 500);
        vm.expectRevert(ShieldedPool.InvalidProof.selector);
        vm.prank(alice);
        pool.deposit(p);
    }

    function testDepositRevertsPayloadMismatch() public {
        verifier.setDepositResult(false);
        ShieldedPool.DepositParams memory p =
            _baseDeposit(bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)), 500);
        p.encryptedNotes = "swapped";
        vm.expectRevert(ShieldedPool.PayloadMismatch.selector);
        vm.prank(alice);
        pool.deposit(p);
    }

    function testDepositEmitsSizeFlagAboveThreshold() public {
        ShieldedPool.DepositParams memory p =
            _baseDeposit(bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)), SINGLE_TX_THRESHOLD + 1);

        vm.expectEmit(true, false, false, true, address(pool));
        emit ShieldedPool.SizeFlag(bytes32(uint256(2)), pool.OP_DEPOSIT(), SINGLE_TX_THRESHOLD + 1);
        vm.prank(alice);
        pool.deposit(p);
    }

    // ========== Transfer ==========

    function testTransferHappyPathAndInsertionOrder() public {
        bytes32 out0 = bytes32(uint256(21));
        bytes32 out1 = bytes32(uint256(22));
        bytes32 complianceOut = bytes32(uint256(23));
        ShieldedPool.TransferParams memory p =
            _baseTransfer(bytes32(uint256(24)), bytes32(uint256(25)), out0, out1, bytes32(uint256(26)), complianceOut);

        vm.prank(alice);
        pool.transfer(p);

        assertTrue(pool.nullifiers(bytes32(uint256(24))));
        assertTrue(pool.nullifiers(bytes32(uint256(25))));
        assertTrue(pool.nullifiers(bytes32(uint256(26))));

        LeanIMTData storage expected = _scratchTree;
        expected.insert(uint256(out0));
        expected.insert(uint256(out1));
        expected.insert(uint256(complianceOut));

        assertEq(pool.commitmentRoot(), bytes32(expected.root()));
    }

    function testTransferRevertsWrongEpoch() public {
        verifier.setTransferResult(false);
        ShieldedPool.TransferParams memory p = _baseTransfer(
            bytes32(uint256(31)),
            bytes32(uint256(32)),
            bytes32(uint256(33)),
            bytes32(uint256(34)),
            bytes32(uint256(35)),
            bytes32(uint256(36))
        );
        p.epoch = pool.currentEpoch() + 1;
        vm.expectRevert(ShieldedPool.WrongEpoch.selector);
        vm.prank(alice);
        pool.transfer(p);
    }

    function testTransferRevertsDuplicateNullifiers() public {
        verifier.setTransferResult(false);
        ShieldedPool.TransferParams memory p = _baseTransfer(
            bytes32(uint256(41)),
            bytes32(uint256(41)),
            bytes32(uint256(43)),
            bytes32(uint256(44)),
            bytes32(uint256(45)),
            bytes32(uint256(46))
        );
        vm.expectRevert(ShieldedPool.DuplicateNullifier.selector);
        vm.prank(alice);
        pool.transfer(p);
    }

    function testTransferRevertsNullifierSpent() public {
        ShieldedPool.TransferParams memory first = _baseTransfer(
            bytes32(uint256(51)),
            bytes32(uint256(52)),
            bytes32(uint256(53)),
            bytes32(uint256(54)),
            bytes32(uint256(55)),
            bytes32(uint256(56))
        );
        vm.prank(alice);
        pool.transfer(first);

        verifier.setTransferResult(false);
        ShieldedPool.TransferParams memory p = _baseTransfer(
            bytes32(uint256(51)),
            bytes32(uint256(62)),
            bytes32(uint256(63)),
            bytes32(uint256(64)),
            bytes32(uint256(65)),
            bytes32(uint256(66))
        );
        vm.expectRevert(ShieldedPool.NullifierSpent.selector);
        vm.prank(alice);
        pool.transfer(p);
    }

    function testTransferRevertsUnknownCommitmentRoot() public {
        verifier.setTransferResult(false);
        ShieldedPool.TransferParams memory p = _baseTransfer(
            bytes32(uint256(71)),
            bytes32(uint256(72)),
            bytes32(uint256(73)),
            bytes32(uint256(74)),
            bytes32(uint256(75)),
            bytes32(uint256(76))
        );
        p.commitmentRoot = bytes32(uint256(0xdead));
        vm.expectRevert(ShieldedPool.UnknownRoot.selector);
        vm.prank(alice);
        pool.transfer(p);
    }

    function testTransferRevertsInvalidProof() public {
        verifier.setTransferResult(false);
        ShieldedPool.TransferParams memory p = _baseTransfer(
            bytes32(uint256(81)),
            bytes32(uint256(82)),
            bytes32(uint256(83)),
            bytes32(uint256(84)),
            bytes32(uint256(85)),
            bytes32(uint256(86))
        );
        vm.expectRevert(ShieldedPool.InvalidProof.selector);
        vm.prank(alice);
        pool.transfer(p);
    }

    function testTransferRevertsPayloadMismatch() public {
        verifier.setTransferResult(false);
        ShieldedPool.TransferParams memory p = _baseTransfer(
            bytes32(uint256(181)),
            bytes32(uint256(182)),
            bytes32(uint256(183)),
            bytes32(uint256(184)),
            bytes32(uint256(185)),
            bytes32(uint256(186))
        );
        p.encryptedNotes = "swapped";
        vm.expectRevert(ShieldedPool.PayloadMismatch.selector);
        vm.prank(alice);
        pool.transfer(p);
    }

    // ========== Withdraw (gated) ==========

    function testWithdrawHappyPathAndInsertionOrder() public {
        token.mint(address(pool), 10_000);
        bytes32 complianceOut = bytes32(uint256(93));
        ShieldedPool.WithdrawParams memory p =
            _baseWithdraw(bytes32(uint256(91)), bytes32(uint256(92)), complianceOut, 500, alice);

        vm.prank(alice);
        pool.withdraw(p);

        LeanIMTData storage expected = _scratchTree;
        expected.insert(uint256(complianceOut));
        assertEq(pool.commitmentRoot(), bytes32(expected.root()));
    }

    function testWithdrawTransfersToRecipient() public {
        token.mint(address(pool), 10_000);
        uint256 before = token.balanceOf(alice);
        ShieldedPool.WithdrawParams memory p =
            _baseWithdraw(bytes32(uint256(101)), bytes32(uint256(102)), bytes32(uint256(103)), 500, alice);

        vm.prank(alice);
        pool.withdraw(p);

        assertEq(token.balanceOf(alice), before + 500);
    }

    function testWithdrawRevertsWrongToken() public {
        verifier.setWithdrawResult(false);
        ShieldedPool.WithdrawParams memory p =
            _baseWithdraw(bytes32(uint256(111)), bytes32(uint256(112)), bytes32(uint256(113)), 500, alice);
        p.token = uint256(uint160(address(0xdead)));
        vm.expectRevert(ShieldedPool.WrongToken.selector);
        vm.prank(alice);
        pool.withdraw(p);
    }

    function testWithdrawRevertsZeroAmount() public {
        verifier.setWithdrawResult(false);
        ShieldedPool.WithdrawParams memory p =
            _baseWithdraw(bytes32(uint256(121)), bytes32(uint256(122)), bytes32(uint256(123)), 0, alice);
        vm.expectRevert(ShieldedPool.ZeroAmount.selector);
        vm.prank(alice);
        pool.withdraw(p);
    }

    function testWithdrawRevertsZeroRecipient() public {
        verifier.setWithdrawResult(false);
        ShieldedPool.WithdrawParams memory p =
            _baseWithdraw(bytes32(uint256(131)), bytes32(uint256(132)), bytes32(uint256(133)), 500, address(0));
        vm.expectRevert(ShieldedPool.ZeroAddress.selector);
        vm.prank(alice);
        pool.withdraw(p);
    }

    function testWithdrawRevertsDuplicateNullifiers() public {
        verifier.setWithdrawResult(false);
        ShieldedPool.WithdrawParams memory p =
            _baseWithdraw(bytes32(uint256(141)), bytes32(uint256(141)), bytes32(uint256(143)), 500, alice);
        vm.expectRevert(ShieldedPool.DuplicateNullifier.selector);
        vm.prank(alice);
        pool.withdraw(p);
    }

    function testWithdrawRevertsBlockedDestination() public {
        vm.prank(curator);
        pool.setBlockedDestination(alice, true);

        verifier.setWithdrawResult(false);
        ShieldedPool.WithdrawParams memory p =
            _baseWithdraw(bytes32(uint256(151)), bytes32(uint256(152)), bytes32(uint256(153)), 500, alice);
        vm.expectRevert(ShieldedPool.BlockedDestination.selector);
        vm.prank(alice);
        pool.withdraw(p);
    }

    function testWithdrawRevertsPayloadMismatch() public {
        token.mint(address(pool), 10_000);
        verifier.setWithdrawResult(false);
        ShieldedPool.WithdrawParams memory p =
            _baseWithdraw(bytes32(uint256(191)), bytes32(uint256(192)), bytes32(uint256(193)), 500, alice);
        p.encryptedNotes = "swapped";
        vm.expectRevert(ShieldedPool.PayloadMismatch.selector);
        vm.prank(alice);
        pool.withdraw(p);
    }

    function testWithdrawEmitsSizeFlagAboveThreshold() public {
        token.mint(address(pool), SINGLE_TX_THRESHOLD * 2);
        ShieldedPool.WithdrawParams memory p = _baseWithdraw(
            bytes32(uint256(161)), bytes32(uint256(162)), bytes32(uint256(163)), SINGLE_TX_THRESHOLD + 1, alice
        );

        vm.expectEmit(true, false, false, true, address(pool));
        emit ShieldedPool.SizeFlag(bytes32(uint256(162)), pool.OP_WITHDRAW(), SINGLE_TX_THRESHOLD + 1);
        vm.prank(alice);
        pool.withdraw(p);
    }
}

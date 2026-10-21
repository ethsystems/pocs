// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/src/Test.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {AttestationRegistry} from "../src/AttestationRegistry.sol";
import {MockVerifier} from "../src/mocks/MockCompositeVerifier.sol";
import {MockERC20} from "../src/mocks/MockERC20.sol";

contract ShieldedPoolTest is Test {
    ShieldedPool public pool;
    AttestationRegistry public registry;
    MockVerifier public verifier;
    MockERC20 public token;

    address public owner;
    address public user;
    address public recipient;

    // Use smaller commitment values that fit in BN254 scalar field
    bytes32 constant COMMITMENT_0 = bytes32(uint256(1));
    bytes32 constant COMMITMENT_1 = bytes32(uint256(2));
    bytes32 constant COMMITMENT_2 = bytes32(uint256(3));
    bytes32 constant COMMITMENT_3 = bytes32(uint256(4));
    bytes32 constant NULLIFIER_0 = bytes32(uint256(100));
    bytes32 constant NULLIFIER_1 = bytes32(uint256(101));

    uint256 constant DEPOSIT_AMOUNT = 1000e6; // 1000 USDC

    event Deposit(bytes32 indexed commitment, address indexed token, uint256 amount, bytes encryptedNote);
    event Transfer(
        bytes32 indexed nullifier1,
        bytes32 indexed nullifier2,
        bytes32 commitment1,
        bytes32 commitment2,
        bytes encryptedNotes
    );
    event Withdraw(bytes32 indexed nullifier, address indexed recipient, address indexed token, uint256 amount);
    event TokenAdded(address indexed token);
    event TokenRemoved(address indexed token);
    event VerifierProposed(address indexed newVerifier, uint256 applyTime, bytes32 codeHash);
    event VerifierCancelled(address indexed cancelledVerifier);
    event VerifierUpdated(address indexed oldVerifier, address indexed newVerifier);

    function setUp() public {
        owner = address(this);
        user = address(0x1);
        recipient = address(0x2);

        // Deploy contracts
        registry = new AttestationRegistry();
        verifier = new MockVerifier();
        pool = new ShieldedPool(address(verifier), address(registry));

        // Deploy and setup mock token
        token = new MockERC20("USD Coin", "USDC", 6);
        pool.addSupportedToken(address(token));

        // Mint tokens to user
        token.mint(user, DEPOSIT_AMOUNT * 10);

        // Approve pool to spend user's tokens
        vm.prank(user);
        token.approve(address(pool), type(uint256).max);
    }

    // ========== Token Management Tests ==========

    function testAddSupportedToken() public {
        MockERC20 newToken = new MockERC20("Test", "TST", 18);

        vm.expectEmit(true, false, false, false);
        emit TokenAdded(address(newToken));

        pool.addSupportedToken(address(newToken));
        assertTrue(pool.supportedTokens(address(newToken)));
    }

    function testAddSupportedTokenRevertsIfAlreadySupported() public {
        vm.expectRevert(ShieldedPool.TokenAlreadySupported.selector);
        pool.addSupportedToken(address(token));
    }

    function testAddSupportedTokenRevertsIfZeroAddress() public {
        vm.expectRevert(ShieldedPool.ZeroAddress.selector);
        pool.addSupportedToken(address(0));
    }

    function testAddSupportedTokenOnlyOwner() public {
        vm.prank(user);
        vm.expectRevert(ShieldedPool.OnlyOwner.selector);
        pool.addSupportedToken(address(0x123));
    }

    function testRemoveSupportedToken() public {
        vm.expectEmit(true, false, false, false);
        emit TokenRemoved(address(token));

        pool.removeSupportedToken(address(token));
        assertFalse(pool.supportedTokens(address(token)));
    }

    function testRemoveSupportedTokenRevertsIfNotSupported() public {
        vm.expectRevert(ShieldedPool.TokenNotSupported.selector);
        pool.removeSupportedToken(address(0x123));
    }

    function testRemoveSupportedTokenOnlyOwner() public {
        vm.prank(user);
        vm.expectRevert(ShieldedPool.OnlyOwner.selector);
        pool.removeSupportedToken(address(token));
    }

    // ========== Deposit Tests ==========

    function testDeposit() public {
        bytes memory proof = "";
        bytes memory encryptedNote = "encrypted_data";

        vm.prank(user);
        vm.expectEmit(true, true, false, true);
        emit Deposit(COMMITMENT_0, address(token), DEPOSIT_AMOUNT, encryptedNote);

        pool.deposit(proof, COMMITMENT_0, address(token), DEPOSIT_AMOUNT, user, encryptedNote);

        assertEq(pool.getCommitmentCount(), 1);
        assertTrue(pool.commitmentRoot() != bytes32(0));
        assertEq(token.balanceOf(address(pool)), DEPOSIT_AMOUNT);
    }

    function testDepositRevertsUnsupportedToken() public {
        MockERC20 unsupportedToken = new MockERC20("Unsupported", "UNS", 18);

        vm.prank(user);
        vm.expectRevert(ShieldedPool.UnsupportedToken.selector);
        pool.deposit("", COMMITMENT_0, address(unsupportedToken), DEPOSIT_AMOUNT, user, "");
    }

    function testDepositRevertsZeroAmount() public {
        vm.prank(user);
        vm.expectRevert(ShieldedPool.ZeroAmount.selector);
        pool.deposit("", COMMITMENT_0, address(token), 0, user, "");
    }

    function testDepositRevertsInvalidProof() public {
        verifier.setDepositResult(false);

        vm.prank(user);
        vm.expectRevert(ShieldedPool.InvalidProof.selector);
        pool.deposit("", COMMITMENT_0, address(token), DEPOSIT_AMOUNT, user, "");
    }

    function testDepositUpdatesRoot() public {
        vm.prank(user);
        pool.deposit("", COMMITMENT_0, address(token), DEPOSIT_AMOUNT, user, "");
        bytes32 root1 = pool.commitmentRoot();

        vm.prank(user);
        pool.deposit("", COMMITMENT_1, address(token), DEPOSIT_AMOUNT, user, "");
        bytes32 root2 = pool.commitmentRoot();

        assertTrue(root1 != root2);
        assertTrue(pool.isKnownRoot(root1)); // Historical root is preserved
    }

    // ========== Transfer Tests ==========

    function testTransfer() public {
        // First deposit to get a valid root
        vm.prank(user);
        pool.deposit("", COMMITMENT_0, address(token), DEPOSIT_AMOUNT, user, "");
        bytes32 root = pool.commitmentRoot();

        bytes memory proof = "";
        bytes memory encryptedNotes = "encrypted_data";
        bytes32[2] memory nullifiers_ = [NULLIFIER_0, NULLIFIER_1];
        bytes32[2] memory commitments_ = [COMMITMENT_2, COMMITMENT_3];

        vm.expectEmit(true, true, false, true);
        emit Transfer(NULLIFIER_0, NULLIFIER_1, COMMITMENT_2, COMMITMENT_3, encryptedNotes);

        pool.transfer(proof, nullifiers_, commitments_, root, encryptedNotes);

        assertTrue(pool.nullifiers(NULLIFIER_0));
        assertTrue(pool.nullifiers(NULLIFIER_1));
        assertEq(pool.getCommitmentCount(), 3); // 1 deposit + 2 from transfer
    }

    function testTransferRevertsInvalidRoot() public {
        bytes32[2] memory nullifiers_ = [NULLIFIER_0, NULLIFIER_1];
        bytes32[2] memory commitments_ = [COMMITMENT_2, COMMITMENT_3];

        vm.expectRevert(ShieldedPool.InvalidRoot.selector);
        pool.transfer("", nullifiers_, commitments_, bytes32(uint256(999)), "");
    }

    function testTransferRevertsNullifierAlreadySpent() public {
        vm.prank(user);
        pool.deposit("", COMMITMENT_0, address(token), DEPOSIT_AMOUNT, user, "");
        bytes32 root = pool.commitmentRoot();

        bytes32[2] memory nullifiers_ = [NULLIFIER_0, NULLIFIER_1];
        bytes32[2] memory commitments_ = [COMMITMENT_2, COMMITMENT_3];

        // First transfer succeeds
        pool.transfer("", nullifiers_, commitments_, root, "");

        // Get new root after first transfer
        bytes32 newRoot = pool.commitmentRoot();

        // Second transfer with same nullifier fails
        bytes32[2] memory newCommitments = [bytes32(uint256(5)), bytes32(uint256(6))];
        vm.expectRevert(ShieldedPool.NullifierAlreadySpent.selector);
        pool.transfer("", nullifiers_, newCommitments, newRoot, "");
    }

    function testTransferRevertsIdenticalNullifiers() public {
        vm.prank(user);
        pool.deposit("", COMMITMENT_0, address(token), DEPOSIT_AMOUNT, user, "");
        bytes32 root = pool.commitmentRoot();

        bytes32[2] memory nullifiers_ = [NULLIFIER_1, NULLIFIER_1]; // Same nullifier
        bytes32[2] memory commitments_ = [COMMITMENT_2, COMMITMENT_3];

        vm.expectRevert(ShieldedPool.IdenticalNullifiers.selector);
        pool.transfer("", nullifiers_, commitments_, root, "");
    }

    function testTransferRevertsInvalidProof() public {
        vm.prank(user);
        pool.deposit("", COMMITMENT_0, address(token), DEPOSIT_AMOUNT, user, "");
        bytes32 root = pool.commitmentRoot();

        verifier.setTransferResult(false);

        bytes32[2] memory nullifiers_ = [NULLIFIER_0, NULLIFIER_1];
        bytes32[2] memory commitments_ = [COMMITMENT_2, COMMITMENT_3];

        vm.expectRevert(ShieldedPool.InvalidProof.selector);
        pool.transfer("", nullifiers_, commitments_, root, "");
    }

    function testTransferWithHistoricalRoot() public {
        vm.prank(user);
        pool.deposit("", COMMITMENT_0, address(token), DEPOSIT_AMOUNT, user, "");
        bytes32 historicalRoot = pool.commitmentRoot();

        // Make another deposit to change the root
        vm.prank(user);
        pool.deposit("", COMMITMENT_1, address(token), DEPOSIT_AMOUNT, user, "");

        // Transfer using the historical root should work
        bytes32[2] memory nullifiers_ = [NULLIFIER_0, NULLIFIER_1];
        bytes32[2] memory commitments_ = [COMMITMENT_2, COMMITMENT_3];

        pool.transfer("", nullifiers_, commitments_, historicalRoot, "");

        assertTrue(pool.nullifiers(NULLIFIER_1));
    }

    // ========== Withdraw Tests ==========

    function testWithdraw() public {
        // First deposit to have funds in pool
        vm.prank(user);
        pool.deposit("", COMMITMENT_0, address(token), DEPOSIT_AMOUNT, user, "");
        bytes32 root = pool.commitmentRoot();

        uint256 recipientBalanceBefore = token.balanceOf(recipient);

        vm.expectEmit(true, true, true, true);
        emit Withdraw(NULLIFIER_1, recipient, address(token), DEPOSIT_AMOUNT);

        pool.withdraw("", NULLIFIER_1, address(token), DEPOSIT_AMOUNT, recipient, root);

        assertTrue(pool.nullifiers(NULLIFIER_1));
        assertEq(token.balanceOf(recipient), recipientBalanceBefore + DEPOSIT_AMOUNT);
        assertEq(token.balanceOf(address(pool)), 0);
    }

    function testWithdrawRevertsInvalidRoot() public {
        vm.expectRevert(ShieldedPool.InvalidRoot.selector);
        pool.withdraw("", NULLIFIER_1, address(token), DEPOSIT_AMOUNT, recipient, bytes32(uint256(999)));
    }

    function testWithdrawRevertsNullifierAlreadySpent() public {
        vm.prank(user);
        pool.deposit("", COMMITMENT_0, address(token), DEPOSIT_AMOUNT * 2, user, "");
        bytes32 root = pool.commitmentRoot();

        // First withdraw succeeds
        pool.withdraw("", NULLIFIER_1, address(token), DEPOSIT_AMOUNT, recipient, root);

        // Second withdraw with same nullifier fails
        vm.expectRevert(ShieldedPool.NullifierAlreadySpent.selector);
        pool.withdraw("", NULLIFIER_1, address(token), DEPOSIT_AMOUNT, recipient, root);
    }

    // Removing a token must not block withdrawals of existing notes (2/SHIELDED-POOL 4.4)
    function testWithdrawRemovedTokenSucceeds() public {
        vm.prank(user);
        pool.deposit("", COMMITMENT_0, address(token), DEPOSIT_AMOUNT, user, "");
        bytes32 root = pool.commitmentRoot();

        pool.removeSupportedToken(address(token));

        vm.expectEmit(true, true, true, true);
        emit Withdraw(NULLIFIER_1, recipient, address(token), DEPOSIT_AMOUNT);
        pool.withdraw("", NULLIFIER_1, address(token), DEPOSIT_AMOUNT, recipient, root);

        assertTrue(pool.nullifiers(NULLIFIER_1));
        assertEq(token.balanceOf(recipient), DEPOSIT_AMOUNT);
        assertEq(token.balanceOf(address(pool)), 0);
    }

    function testDepositRemovedTokenReverts() public {
        vm.prank(user);
        pool.deposit("", COMMITMENT_0, address(token), DEPOSIT_AMOUNT, user, "");

        pool.removeSupportedToken(address(token));

        vm.prank(user);
        vm.expectRevert(ShieldedPool.UnsupportedToken.selector);
        pool.deposit("", COMMITMENT_1, address(token), DEPOSIT_AMOUNT, user, "");
    }

    function testTransferRemovedTokenSucceeds() public {
        vm.prank(user);
        pool.deposit("", COMMITMENT_0, address(token), DEPOSIT_AMOUNT, user, "");
        bytes32 root = pool.commitmentRoot();

        pool.removeSupportedToken(address(token));

        bytes32[2] memory nullifiers_ = [NULLIFIER_0, NULLIFIER_1];
        bytes32[2] memory commitments_ = [COMMITMENT_2, COMMITMENT_3];
        pool.transfer("", nullifiers_, commitments_, root, "");

        assertTrue(pool.nullifiers(NULLIFIER_0));
        assertEq(pool.getCommitmentCount(), 3);
    }

    function testWithdrawRevertsZeroAmount() public {
        vm.prank(user);
        pool.deposit("", COMMITMENT_0, address(token), DEPOSIT_AMOUNT, user, "");
        bytes32 root = pool.commitmentRoot();

        vm.expectRevert(ShieldedPool.ZeroAmount.selector);
        pool.withdraw("", NULLIFIER_1, address(token), 0, recipient, root);
    }

    function testWithdrawRevertsZeroRecipient() public {
        vm.prank(user);
        pool.deposit("", COMMITMENT_0, address(token), DEPOSIT_AMOUNT, user, "");
        bytes32 root = pool.commitmentRoot();

        vm.expectRevert(ShieldedPool.ZeroAddress.selector);
        pool.withdraw("", NULLIFIER_1, address(token), DEPOSIT_AMOUNT, address(0), root);
    }

    function testWithdrawRevertsInvalidProof() public {
        vm.prank(user);
        pool.deposit("", COMMITMENT_0, address(token), DEPOSIT_AMOUNT, user, "");
        bytes32 root = pool.commitmentRoot();

        verifier.setWithdrawResult(false);

        vm.expectRevert(ShieldedPool.InvalidProof.selector);
        pool.withdraw("", NULLIFIER_1, address(token), DEPOSIT_AMOUNT, recipient, root);
    }

    // ========== Historical Roots Tests ==========

    function testIsKnownRoot() public {
        assertFalse(pool.isKnownRoot(bytes32(uint256(999))));

        vm.prank(user);
        pool.deposit("", COMMITMENT_0, address(token), DEPOSIT_AMOUNT, user, "");
        bytes32 root1 = pool.commitmentRoot();

        assertTrue(pool.isKnownRoot(root1));

        vm.prank(user);
        pool.deposit("", COMMITMENT_1, address(token), DEPOSIT_AMOUNT, user, "");
        bytes32 root2 = pool.commitmentRoot();

        assertTrue(pool.isKnownRoot(root1)); // Historical root still valid
        assertTrue(pool.isKnownRoot(root2)); // Current root valid
    }

    function testValidRootsMapping() public {
        vm.prank(user);
        pool.deposit("", COMMITMENT_0, address(token), DEPOSIT_AMOUNT, user, "");
        bytes32 root1 = pool.commitmentRoot();
        assertTrue(pool.validRoots(root1)); // Recorded after the operation's final insert

        vm.prank(user);
        pool.deposit("", COMMITMENT_1, address(token), DEPOSIT_AMOUNT, user, "");

        assertTrue(pool.validRoots(root1)); // Still in the window
    }

    // ========== Ownership Tests ==========

    function testTransferOwnership() public {
        address newOwner = address(0x999);
        pool.transferOwnership(newOwner);
        assertEq(pool.owner(), newOwner);
    }

    function testTransferOwnershipOnlyOwner() public {
        vm.prank(user);
        vm.expectRevert(ShieldedPool.OnlyOwner.selector);
        pool.transferOwnership(user);
    }

    function testTransferOwnershipRevertsZeroAddress() public {
        vm.expectRevert(ShieldedPool.ZeroAddress.selector);
        pool.transferOwnership(address(0));
    }

    // ========== Verifier/Registry Update Tests ==========

    function testProposeVerifier() public {
        MockVerifier newVerifier = new MockVerifier();
        uint256 applyTime = block.timestamp + pool.VERIFIER_DELAY();

        vm.expectEmit(true, false, false, true);
        emit VerifierProposed(address(newVerifier), applyTime, address(newVerifier).codehash);
        pool.proposeVerifier(address(newVerifier));

        assertEq(pool.pendingVerifier(), address(newVerifier));
        assertEq(pool.verifierApplyTime(), applyTime);
        assertEq(pool.pendingVerifierCodeHash(), address(newVerifier).codehash);
        assertEq(address(pool.verifier()), address(verifier)); // Not installed yet
    }

    function testVerifierDelayIsTwoDays() public view {
        assertEq(pool.VERIFIER_DELAY(), 2 days);
    }

    function testApplyVerifierRevertsBeforeDelay() public {
        MockVerifier newVerifier = new MockVerifier();
        pool.proposeVerifier(address(newVerifier));

        vm.expectRevert(ShieldedPool.VerifierDelayNotElapsed.selector);
        pool.applyVerifier();

        vm.warp(pool.verifierApplyTime() - 1);
        vm.expectRevert(ShieldedPool.VerifierDelayNotElapsed.selector);
        pool.applyVerifier();

        assertEq(address(pool.verifier()), address(verifier));
    }

    function testApplyVerifierAfterDelay() public {
        MockVerifier newVerifier = new MockVerifier();
        pool.proposeVerifier(address(newVerifier));
        vm.warp(pool.verifierApplyTime());

        vm.expectEmit(true, true, false, false);
        emit VerifierUpdated(address(verifier), address(newVerifier));
        pool.applyVerifier();

        assertEq(address(pool.verifier()), address(newVerifier));
        assertEq(pool.pendingVerifier(), address(0));
        assertEq(pool.verifierApplyTime(), 0);
        assertEq(pool.pendingVerifierCodeHash(), bytes32(0));
    }

    function testApplyVerifierRevertsWithoutProposal() public {
        vm.expectRevert(ShieldedPool.NoPendingVerifier.selector);
        pool.applyVerifier();
    }

    function testApplyVerifierCannotRunTwice() public {
        pool.proposeVerifier(address(new MockVerifier()));
        vm.warp(pool.verifierApplyTime());
        pool.applyVerifier();

        vm.expectRevert(ShieldedPool.NoPendingVerifier.selector);
        pool.applyVerifier();
    }

    function testReproposeRestartsDelay() public {
        pool.proposeVerifier(address(new MockVerifier()));
        vm.warp(block.timestamp + 1 days);

        MockVerifier second = new MockVerifier();
        pool.proposeVerifier(address(second));
        assertEq(pool.pendingVerifier(), address(second));
        assertEq(pool.verifierApplyTime(), block.timestamp + 2 days);

        // The first proposal's apply time has passed, the second's has not
        vm.warp(block.timestamp + 1 days);
        vm.expectRevert(ShieldedPool.VerifierDelayNotElapsed.selector);
        pool.applyVerifier();

        vm.warp(block.timestamp + 1 days);
        pool.applyVerifier();
        assertEq(address(pool.verifier()), address(second));
    }

    function testCancelVerifier() public {
        MockVerifier newVerifier = new MockVerifier();
        pool.proposeVerifier(address(newVerifier));

        vm.expectEmit(true, false, false, false);
        emit VerifierCancelled(address(newVerifier));
        pool.cancelVerifier();

        assertEq(pool.pendingVerifier(), address(0));
        assertEq(pool.verifierApplyTime(), 0);
        assertEq(pool.pendingVerifierCodeHash(), bytes32(0));

        vm.warp(block.timestamp + 2 days);
        vm.expectRevert(ShieldedPool.NoPendingVerifier.selector);
        pool.applyVerifier();
        assertEq(address(pool.verifier()), address(verifier));
    }

    function testCancelVerifierRevertsWithoutProposal() public {
        vm.expectRevert(ShieldedPool.NoPendingVerifier.selector);
        pool.cancelVerifier();
    }

    function testProposeVerifierOnlyOwner() public {
        vm.prank(user);
        vm.expectRevert(ShieldedPool.OnlyOwner.selector);
        pool.proposeVerifier(address(0x123));
    }

    function testApplyVerifierOnlyOwner() public {
        pool.proposeVerifier(address(new MockVerifier()));
        vm.warp(pool.verifierApplyTime());

        vm.prank(user);
        vm.expectRevert(ShieldedPool.OnlyOwner.selector);
        pool.applyVerifier();
    }

    function testCancelVerifierOnlyOwner() public {
        pool.proposeVerifier(address(new MockVerifier()));

        vm.prank(user);
        vm.expectRevert(ShieldedPool.OnlyOwner.selector);
        pool.cancelVerifier();
    }

    // A pending proposal survives an ownership change with its original apply time:
    // the new owner can apply it once mature, but not earlier, and the old owner loses control
    function testPendingVerifierSurvivesOwnershipTransfer() public {
        MockVerifier newVerifier = new MockVerifier();
        pool.proposeVerifier(address(newVerifier));
        uint256 applyTime = pool.verifierApplyTime();

        address newOwner = address(0x999);
        pool.transferOwnership(newOwner);
        assertEq(pool.verifierApplyTime(), applyTime);

        vm.expectRevert(ShieldedPool.OnlyOwner.selector);
        pool.applyVerifier();

        vm.warp(applyTime - 1);
        vm.prank(newOwner);
        vm.expectRevert(ShieldedPool.VerifierDelayNotElapsed.selector);
        pool.applyVerifier();

        vm.warp(applyTime);
        vm.prank(newOwner);
        pool.applyVerifier();
        assertEq(address(pool.verifier()), address(newVerifier));
    }

    function testProposeVerifierRevertsZeroAddress() public {
        vm.expectRevert(ShieldedPool.ZeroAddress.selector);
        pool.proposeVerifier(address(0));
    }

    function testVerifierApplyWindowIsOneDay() public view {
        assertEq(pool.VERIFIER_APPLY_WINDOW(), 1 days);
    }

    function testApplyVerifierSucceedsAtWindowBoundary() public {
        MockVerifier newVerifier = new MockVerifier();
        pool.proposeVerifier(address(newVerifier));
        vm.warp(pool.verifierApplyTime() + pool.VERIFIER_APPLY_WINDOW());

        pool.applyVerifier();
        assertEq(address(pool.verifier()), address(newVerifier));
    }

    function testApplyVerifierRevertsAfterLapse() public {
        MockVerifier newVerifier = new MockVerifier();
        pool.proposeVerifier(address(newVerifier));
        vm.warp(pool.verifierApplyTime() + pool.VERIFIER_APPLY_WINDOW() + 1);

        vm.expectRevert(ShieldedPool.VerifierProposalLapsed.selector);
        pool.applyVerifier();

        assertEq(address(pool.verifier()), address(verifier));
        assertEq(pool.pendingVerifier(), address(newVerifier)); // Still pending; cancel or re-propose
    }

    function testCancelVerifierAfterLapse() public {
        MockVerifier newVerifier = new MockVerifier();
        pool.proposeVerifier(address(newVerifier));
        vm.warp(pool.verifierApplyTime() + pool.VERIFIER_APPLY_WINDOW() + 1);

        pool.cancelVerifier();
        assertEq(pool.pendingVerifier(), address(0));
        assertEq(pool.verifierApplyTime(), 0);
        assertEq(pool.pendingVerifierCodeHash(), bytes32(0));
    }

    function testReproposeAfterLapseRestartsDelay() public {
        pool.proposeVerifier(address(new MockVerifier()));
        vm.warp(pool.verifierApplyTime() + pool.VERIFIER_APPLY_WINDOW() + 1);

        MockVerifier second = new MockVerifier();
        pool.proposeVerifier(address(second));
        assertEq(pool.pendingVerifier(), address(second));
        assertEq(pool.verifierApplyTime(), block.timestamp + 2 days);

        vm.warp(pool.verifierApplyTime());
        pool.applyVerifier();
        assertEq(address(pool.verifier()), address(second));
    }

    function testProposeVerifierRevertsIfNoCode() public {
        vm.expectRevert(ShieldedPool.VerifierHasNoCode.selector);
        pool.proposeVerifier(address(0x123));
    }

    function testApplyVerifierRevertsIfCodeChanged() public {
        MockVerifier newVerifier = new MockVerifier();
        pool.proposeVerifier(address(newVerifier));
        vm.warp(pool.verifierApplyTime());

        vm.etch(address(newVerifier), hex"00");
        vm.expectRevert(ShieldedPool.VerifierCodeChanged.selector);
        pool.applyVerifier();

        assertEq(address(pool.verifier()), address(verifier));
    }

    function testSetAttestationRegistry() public {
        AttestationRegistry newRegistry = new AttestationRegistry();
        pool.setAttestationRegistry(address(newRegistry));
        assertEq(address(pool.attestationRegistry()), address(newRegistry));
    }

    function testSetAttestationRegistryOnlyOwner() public {
        vm.prank(user);
        vm.expectRevert(ShieldedPool.OnlyOwner.selector);
        pool.setAttestationRegistry(address(0x123));
    }

    function testSetAttestationRegistryRevertsZeroAddress() public {
        vm.expectRevert(ShieldedPool.ZeroAddress.selector);
        pool.setAttestationRegistry(address(0));
    }

    // ========== Constructor Tests ==========

    function testConstructorRevertsZeroVerifier() public {
        vm.expectRevert(ShieldedPool.ZeroAddress.selector);
        new ShieldedPool(address(0), address(registry));
    }

    function testConstructorRevertsZeroRegistry() public {
        vm.expectRevert(ShieldedPool.ZeroAddress.selector);
        new ShieldedPool(address(verifier), address(0));
    }
}

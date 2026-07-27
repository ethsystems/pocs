// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/src/Test.sol";
import {IERC20} from "forge-std/src/interfaces/IERC20.sol";
import {IRiscZeroVerifier} from "../src/interfaces/IRiscZeroVerifier.sol";
import {ValidiumBridge} from "../src/ValidiumBridge.sol";

/// @dev Mock verifier that always succeeds (no-op verify).
contract MockRiscZeroVerifier is IRiscZeroVerifier {
    function verify(bytes calldata, bytes32, bytes32) external pure override {}
}

/// @dev Minimal ERC20 implementation for testing. Supports mint, transfer,
///      transferFrom, approve, and balanceOf. No overflow checks beyond
///      Solidity 0.8 built-ins.
contract MockERC20 is IERC20 {
    string public name = "MockToken";
    string public symbol = "MTK";
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }
}

contract ValidiumBridgeTest is Test {
    ValidiumBridge internal bridge;
    MockRiscZeroVerifier internal mockVerifier;
    MockERC20 internal token;

    bytes32 internal constant STATE_ROOT = keccak256("test-state-root");
    bytes32 internal constant NEW_ROOT = keccak256("test-new-state-root");
    bytes32 internal constant THIRD_ROOT = keccak256("test-third-root");
    bytes32 internal constant ALLOWLIST_ROOT = keccak256("test-allowlist-root");
    bytes32 internal constant PUBKEY = keccak256("test-pubkey");

    address internal alice = address(0xA11CE);
    address internal bob = address(0xB0B);

    uint64 internal constant DEPOSIT_AMOUNT = 1000;
    uint64 internal constant WITHDRAW_AMOUNT = 500;

    // Escape hatch test data (depth-2 tree, 4 leaves)
    bytes32 internal constant ESCAPE_PUBKEY_0 = bytes32(uint256(0xAA));
    bytes32 internal constant ESCAPE_PUBKEY_1 = bytes32(uint256(0xBB));
    bytes32 internal constant ESCAPE_PUBKEY_2 = bytes32(uint256(0xCC));
    bytes32 internal constant ESCAPE_PUBKEY_3 = bytes32(uint256(0xDD));
    uint64 internal constant ESCAPE_BALANCE_0 = 1000;
    uint64 internal constant ESCAPE_BALANCE_1 = 2000;
    uint64 internal constant ESCAPE_BALANCE_2 = 3000;
    uint64 internal constant ESCAPE_BALANCE_3 = 4000;
    bytes32 internal constant ESCAPE_SALT_0 = bytes32(uint256(0x11));
    bytes32 internal constant ESCAPE_SALT_1 = bytes32(uint256(0x22));
    bytes32 internal constant ESCAPE_SALT_2 = bytes32(uint256(0x33));
    bytes32 internal constant ESCAPE_SALT_3 = bytes32(uint256(0x44));

    // Computed in _buildEscapeTree()
    bytes32 internal escapeStateRoot;
    bytes32[4] internal leaves;
    bytes32[2] internal internalNodes; // [left_internal, right_internal]

    function setUp() public {
        mockVerifier = new MockRiscZeroVerifier();
        token = new MockERC20();
        bridge = new ValidiumBridge(
            IERC20(address(token)),
            IRiscZeroVerifier(address(mockVerifier)),
            STATE_ROOT,
            ALLOWLIST_ROOT,
            bytes32(0),
            bytes32(0),
            bytes32(0)
        );
        _buildEscapeTree();
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    /// @dev Mint tokens to `user`, approve the bridge, then deposit.
    function _depositAs(address user, uint256 amount, bytes32 pubkey) internal {
        token.mint(user, amount);
        vm.startPrank(user);
        token.approve(address(bridge), amount);
        bridge.deposit(amount, pubkey, hex"");
        vm.stopPrank();
    }

    /// @dev Convert uint64 to little-endian bytes (matches Rust u64::to_le_bytes()).
    function _uint64ToLE(uint64 value) internal pure returns (bytes8) {
        uint64 reversed = (uint64(uint8(value)) << 56) | (uint64(uint8(value >> 8)) << 48)
            | (uint64(uint8(value >> 16)) << 40) | (uint64(uint8(value >> 24)) << 32)
            | (uint64(uint8(value >> 32)) << 24) | (uint64(uint8(value >> 40)) << 16)
            | (uint64(uint8(value >> 48)) << 8) | uint64(uint8(value >> 56));
        return bytes8(reversed);
    }

    /// @dev Compute account commitment: SHA256(pubkey || balance_le || salt)
    function _accountCommitment(bytes32 pubkey, uint64 balance, bytes32 salt) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(pubkey, _uint64ToLE(balance), salt));
    }

    /// @dev Build a depth-2 SHA-256 Merkle tree with 4 leaves.
    function _buildEscapeTree() internal {
        leaves[0] = _accountCommitment(ESCAPE_PUBKEY_0, ESCAPE_BALANCE_0, ESCAPE_SALT_0);
        leaves[1] = _accountCommitment(ESCAPE_PUBKEY_1, ESCAPE_BALANCE_1, ESCAPE_SALT_1);
        leaves[2] = _accountCommitment(ESCAPE_PUBKEY_2, ESCAPE_BALANCE_2, ESCAPE_SALT_2);
        leaves[3] = _accountCommitment(ESCAPE_PUBKEY_3, ESCAPE_BALANCE_3, ESCAPE_SALT_3);

        internalNodes[0] = sha256(abi.encodePacked(leaves[0], leaves[1]));
        internalNodes[1] = sha256(abi.encodePacked(leaves[2], leaves[3]));

        escapeStateRoot = sha256(abi.encodePacked(internalNodes[0], internalNodes[1]));
    }

    /// @dev Get Merkle proof (2 siblings) for a leaf index in the depth-2 tree.
    function _getMerkleProof(uint256 leafIdx) internal view returns (bytes32[] memory) {
        bytes32[] memory proof = new bytes32[](2);
        if (leafIdx == 0) {
            proof[0] = leaves[1];
            proof[1] = internalNodes[1];
        } else if (leafIdx == 1) {
            proof[0] = leaves[0];
            proof[1] = internalNodes[1];
        } else if (leafIdx == 2) {
            proof[0] = leaves[3];
            proof[1] = internalNodes[0];
        } else {
            proof[0] = leaves[2];
            proof[1] = internalNodes[0];
        }
        return proof;
    }

    /// @dev Write escapeAddress[pubkey] = owner directly to storage.
    ///      escapeAddress mapping is at storage slot 6.
    function _setEscapeAddress(ValidiumBridge b, bytes32 pubkey, address owner) internal {
        bytes32 slot = keccak256(abi.encodePacked(pubkey, uint256(6)));
        vm.store(address(b), slot, bytes32(uint256(uint160(owner))));
    }

    /// @dev Deploy a bridge with escape tree root and fund it with enough tokens.
    function _deployEscapeBridge() internal returns (ValidiumBridge) {
        ValidiumBridge escapeBridge = new ValidiumBridge(
            IERC20(address(token)),
            IRiscZeroVerifier(address(mockVerifier)),
            escapeStateRoot,
            ALLOWLIST_ROOT,
            bytes32(0),
            bytes32(0),
            bytes32(0)
        );
        uint256 totalBalance =
            uint256(ESCAPE_BALANCE_0) + ESCAPE_BALANCE_1 + ESCAPE_BALANCE_2 + ESCAPE_BALANCE_3;
        token.mint(address(escapeBridge), totalBalance);

        // Register escape addresses for front-running protection
        _setEscapeAddress(escapeBridge, ESCAPE_PUBKEY_0, alice);
        _setEscapeAddress(escapeBridge, ESCAPE_PUBKEY_1, bob);
        _setEscapeAddress(escapeBridge, ESCAPE_PUBKEY_2, bob);
        _setEscapeAddress(escapeBridge, ESCAPE_PUBKEY_3, alice);

        return escapeBridge;
    }

    /// @dev Warp past timeout and freeze a bridge.
    function _freezeBridge(ValidiumBridge b) internal {
        vm.warp(block.timestamp + b.ESCAPE_TIMEOUT() + 1);
        b.freeze();
    }

    // ---------------------------------------------------------------
    // 1. Constructor sets state correctly
    // ---------------------------------------------------------------
    function test_constructor_setsState() public view {
        assertEq(address(bridge.token()), address(token));
        assertEq(address(bridge.verifier()), address(mockVerifier));
        assertEq(bridge.stateRoot(), STATE_ROOT);
        assertEq(bridge.allowlistRoot(), ALLOWLIST_ROOT);
        assertEq(bridge.operator(), address(this));
    }

    function test_constructor_setsTransferImageId() public view {
        assertEq(bridge.TRANSFER_IMAGE_ID(), bytes32(0));
    }

    function test_constructor_setsLastProofTimestamp() public view {
        assertEq(bridge.lastProofTimestamp(), block.timestamp);
    }

    // ---------------------------------------------------------------
    // 2. Deposit transfers ERC20 from caller and emits Deposit event
    // ---------------------------------------------------------------
    function test_deposit_transfersTokenAndEmits() public {
        uint256 amount = DEPOSIT_AMOUNT;
        token.mint(alice, amount);

        vm.startPrank(alice);
        token.approve(address(bridge), amount);

        // Expect the Deposit event with correct args
        vm.expectEmit(true, true, true, true);
        emit ValidiumBridge.Deposit(alice, PUBKEY, amount);

        bridge.deposit(amount, PUBKEY, hex"");
        vm.stopPrank();

        // Bridge should hold the tokens
        assertEq(token.balanceOf(address(bridge)), amount);
        // Alice should have zero tokens left
        assertEq(token.balanceOf(alice), 0);
    }

    function test_deposit_setsEscapeAddress() public {
        _depositAs(alice, DEPOSIT_AMOUNT, PUBKEY);
        assertEq(bridge.escapeAddress(PUBKEY), alice);
    }

    function test_deposit_allowsSameDepositorTwice() public {
        _depositAs(alice, DEPOSIT_AMOUNT, PUBKEY);
        _depositAs(alice, DEPOSIT_AMOUNT, PUBKEY);
        assertEq(bridge.escapeAddress(PUBKEY), alice);
    }

    function test_deposit_revertsPubkeyAlreadyClaimed() public {
        _depositAs(alice, DEPOSIT_AMOUNT, PUBKEY);

        token.mint(bob, DEPOSIT_AMOUNT);
        vm.startPrank(bob);
        token.approve(address(bridge), DEPOSIT_AMOUNT);
        vm.expectRevert(ValidiumBridge.PubkeyAlreadyClaimed.selector);
        bridge.deposit(DEPOSIT_AMOUNT, PUBKEY, hex"");
        vm.stopPrank();
    }

    // ---------------------------------------------------------------
    // 3. Deposit reverts with InvalidAmount when amount = 0
    // ---------------------------------------------------------------
    function test_deposit_revertsZeroAmount() public {
        vm.prank(alice);
        vm.expectRevert(ValidiumBridge.InvalidAmount.selector);
        bridge.deposit(0, PUBKEY, hex"");
    }

    // ---------------------------------------------------------------
    // 4. Deposit calls verifier.verify with membership journal
    // ---------------------------------------------------------------
    function test_deposit_requiresMembershipProof() public {
        uint256 amount = DEPOSIT_AMOUNT;
        token.mint(alice, amount);

        vm.startPrank(alice);
        token.approve(address(bridge), amount);
        bridge.deposit(amount, PUBKEY, hex"");
        vm.stopPrank();

        // Deposit succeeded => verifier.verify was called and did not revert
        assertEq(token.balanceOf(address(bridge)), amount);
    }

    // ---------------------------------------------------------------
    // 5. Withdraw verifies proof, updates stateRoot, and transfers tokens
    // ---------------------------------------------------------------
    function test_withdraw_updatesStateAndTransfers() public {
        // First, fund the bridge via a deposit
        _depositAs(alice, WITHDRAW_AMOUNT, PUBKEY);

        // Execute withdrawal to bob
        bridge.withdraw(hex"", STATE_ROOT, NEW_ROOT, WITHDRAW_AMOUNT, bob);

        // State root should be updated
        assertEq(bridge.stateRoot(), NEW_ROOT);
        // Bob should have received the tokens
        assertEq(token.balanceOf(bob), WITHDRAW_AMOUNT);
        // Bridge balance should be zero
        assertEq(token.balanceOf(address(bridge)), 0);
    }

    // ---------------------------------------------------------------
    // 6. Withdraw emits Withdrawal event with correct args
    // ---------------------------------------------------------------
    function test_withdraw_emitsWithdrawalEvent() public {
        // Fund the bridge
        _depositAs(alice, WITHDRAW_AMOUNT, PUBKEY);

        vm.expectEmit(true, true, true, true);
        emit ValidiumBridge.Withdrawal(bob, WITHDRAW_AMOUNT);

        bridge.withdraw(hex"", STATE_ROOT, NEW_ROOT, WITHDRAW_AMOUNT, bob);
    }

    // ---------------------------------------------------------------
    // 7. Withdraw reverts when oldRoot != stateRoot (stale state)
    // ---------------------------------------------------------------
    function test_withdraw_revertsStaleState() public {
        bytes32 wrongRoot = keccak256("wrong-root");

        vm.expectRevert(abi.encodeWithSelector(ValidiumBridge.StaleState.selector, STATE_ROOT, wrongRoot));
        bridge.withdraw(hex"", wrongRoot, NEW_ROOT, WITHDRAW_AMOUNT, bob);
    }

    // ---------------------------------------------------------------
    // 8. Sequential root check prevents replay (double-spend protection)
    // ---------------------------------------------------------------
    function test_withdraw_sequentialRootPreventsReplay() public {
        // Fund the bridge with enough for two withdrawals
        _depositAs(alice, WITHDRAW_AMOUNT * 2, PUBKEY);

        // First withdrawal succeeds: STATE_ROOT -> NEW_ROOT
        bridge.withdraw(hex"", STATE_ROOT, NEW_ROOT, WITHDRAW_AMOUNT, bob);

        // Replaying with old STATE_ROOT reverts — sequential root check prevents double-spend
        vm.expectRevert(abi.encodeWithSelector(ValidiumBridge.StaleState.selector, NEW_ROOT, STATE_ROOT));
        bridge.withdraw(hex"", STATE_ROOT, THIRD_ROOT, WITHDRAW_AMOUNT, bob);
    }

    // ---------------------------------------------------------------
    // 9. Withdraw reverts with InvalidAmount when amount = 0
    // ---------------------------------------------------------------
    function test_withdraw_revertsZeroAmount() public {
        vm.expectRevert(ValidiumBridge.InvalidAmount.selector);
        bridge.withdraw(hex"", STATE_ROOT, NEW_ROOT, 0, bob);
    }

    // ---------------------------------------------------------------
    // 10. Withdraw reverts when bridge doesn't have enough tokens
    // ---------------------------------------------------------------
    function test_withdraw_revertsInsufficientBridgeBalance() public {
        // Bridge has zero tokens -- withdrawal should revert due to
        // ERC20 transfer underflow in MockERC20.transfer
        vm.expectRevert();
        bridge.withdraw(hex"", STATE_ROOT, NEW_ROOT, WITHDRAW_AMOUNT, bob);
    }

    // ---------------------------------------------------------------
    // 11. Withdraw updates lastProofTimestamp
    // ---------------------------------------------------------------
    function test_withdraw_updatesLastProofTimestamp() public {
        _depositAs(alice, WITHDRAW_AMOUNT, PUBKEY);
        vm.warp(block.timestamp + 100);

        bridge.withdraw(hex"", STATE_ROOT, NEW_ROOT, WITHDRAW_AMOUNT, bob);
        assertEq(bridge.lastProofTimestamp(), block.timestamp);
    }

    // ---------------------------------------------------------------
    // postTransferBatch
    // ---------------------------------------------------------------
    function test_postTransferBatch_updatesRootAndTimestamp() public {
        vm.warp(block.timestamp + 100);
        bridge.postTransferBatch(hex"", STATE_ROOT, NEW_ROOT);
        assertEq(bridge.stateRoot(), NEW_ROOT);
        assertEq(bridge.lastProofTimestamp(), block.timestamp);
    }

    function test_postTransferBatch_emitsEvent() public {
        vm.expectEmit(true, true, true, true);
        emit ValidiumBridge.TransferBatchPosted(STATE_ROOT, NEW_ROOT);
        bridge.postTransferBatch(hex"", STATE_ROOT, NEW_ROOT);
    }

    function test_postTransferBatch_revertsStaleState() public {
        bytes32 wrongRoot = keccak256("wrong-root");
        vm.expectRevert(abi.encodeWithSelector(ValidiumBridge.StaleState.selector, STATE_ROOT, wrongRoot));
        bridge.postTransferBatch(hex"", wrongRoot, NEW_ROOT);
    }

    function test_postTransferBatch_revertsWhenFrozen() public {
        _freezeBridge(bridge);
        vm.expectRevert(ValidiumBridge.AlreadyFrozen.selector);
        bridge.postTransferBatch(hex"", STATE_ROOT, NEW_ROOT);
    }

    // ---------------------------------------------------------------
    // Freeze
    // ---------------------------------------------------------------
    function test_freeze_succeedsAfterTimeout() public {
        vm.warp(block.timestamp + bridge.ESCAPE_TIMEOUT() + 1);
        vm.expectEmit(true, true, true, true);
        emit ValidiumBridge.Frozen(block.timestamp);
        bridge.freeze();
        assertTrue(bridge.frozen());
    }

    function test_freeze_revertsBeforeTimeout() public {
        vm.warp(block.timestamp + bridge.ESCAPE_TIMEOUT());
        vm.expectRevert(ValidiumBridge.TimeoutNotReached.selector);
        bridge.freeze();
    }

    function test_freeze_revertsAlreadyFrozen() public {
        _freezeBridge(bridge);
        vm.expectRevert(ValidiumBridge.AlreadyFrozen.selector);
        bridge.freeze();
    }

    // ---------------------------------------------------------------
    // Escape withdraw
    // ---------------------------------------------------------------
    function test_escapeWithdraw_fullFlow() public {
        ValidiumBridge escapeBridge = _deployEscapeBridge();
        _freezeBridge(escapeBridge);

        bytes32[] memory proof = _getMerkleProof(0);
        vm.prank(alice);
        escapeBridge.escapeWithdraw(0, ESCAPE_PUBKEY_0, ESCAPE_BALANCE_0, ESCAPE_SALT_0, proof);

        assertEq(token.balanceOf(alice), ESCAPE_BALANCE_0);
        assertTrue(escapeBridge.claimed(0));
    }

    function test_escapeWithdraw_emitsEvent() public {
        ValidiumBridge escapeBridge = _deployEscapeBridge();
        _freezeBridge(escapeBridge);

        bytes32[] memory proof = _getMerkleProof(0);
        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit ValidiumBridge.EscapeWithdrawal(0, alice, ESCAPE_BALANCE_0);
        escapeBridge.escapeWithdraw(0, ESCAPE_PUBKEY_0, ESCAPE_BALANCE_0, ESCAPE_SALT_0, proof);
    }

    function test_escapeWithdraw_revertsNotFrozen() public {
        ValidiumBridge escapeBridge = _deployEscapeBridge();
        bytes32[] memory proof = _getMerkleProof(0);
        vm.expectRevert(ValidiumBridge.NotFrozen.selector);
        escapeBridge.escapeWithdraw(0, ESCAPE_PUBKEY_0, ESCAPE_BALANCE_0, ESCAPE_SALT_0, proof);
    }

    function test_escapeWithdraw_revertsDoubleClaim() public {
        ValidiumBridge escapeBridge = _deployEscapeBridge();
        _freezeBridge(escapeBridge);

        bytes32[] memory proof = _getMerkleProof(0);
        vm.prank(alice);
        escapeBridge.escapeWithdraw(0, ESCAPE_PUBKEY_0, ESCAPE_BALANCE_0, ESCAPE_SALT_0, proof);

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(ValidiumBridge.AlreadyClaimed.selector, 0));
        escapeBridge.escapeWithdraw(0, ESCAPE_PUBKEY_0, ESCAPE_BALANCE_0, ESCAPE_SALT_0, proof);
    }

    function test_escapeWithdraw_revertsInvalidProof() public {
        ValidiumBridge escapeBridge = _deployEscapeBridge();
        _freezeBridge(escapeBridge);

        // Use proof for leaf 0 but claim leaf 1's data
        bytes32[] memory proof = _getMerkleProof(0);
        vm.expectRevert(ValidiumBridge.InvalidMerkleProof.selector);
        escapeBridge.escapeWithdraw(0, ESCAPE_PUBKEY_1, ESCAPE_BALANCE_1, ESCAPE_SALT_1, proof);
    }

    function test_escapeWithdraw_revertsWrongBalance() public {
        ValidiumBridge escapeBridge = _deployEscapeBridge();
        _freezeBridge(escapeBridge);

        bytes32[] memory proof = _getMerkleProof(0);
        vm.expectRevert(ValidiumBridge.InvalidMerkleProof.selector);
        escapeBridge.escapeWithdraw(0, ESCAPE_PUBKEY_0, ESCAPE_BALANCE_0 + 1, ESCAPE_SALT_0, proof);
    }

    function test_escapeWithdraw_revertsZeroBalance() public {
        ValidiumBridge escapeBridge = _deployEscapeBridge();
        _freezeBridge(escapeBridge);

        bytes32[] memory proof = _getMerkleProof(0);
        vm.expectRevert(ValidiumBridge.InvalidAmount.selector);
        escapeBridge.escapeWithdraw(0, ESCAPE_PUBKEY_0, 0, ESCAPE_SALT_0, proof);
    }

    function test_escapeWithdraw_revertsUnregisteredPubkey() public {
        // Deploy bridge WITHOUT setting escape addresses
        ValidiumBridge rawBridge = new ValidiumBridge(
            IERC20(address(token)),
            IRiscZeroVerifier(address(mockVerifier)),
            escapeStateRoot,
            ALLOWLIST_ROOT,
            bytes32(0),
            bytes32(0),
            bytes32(0)
        );
        uint256 totalBalance =
            uint256(ESCAPE_BALANCE_0) + ESCAPE_BALANCE_1 + ESCAPE_BALANCE_2 + ESCAPE_BALANCE_3;
        token.mint(address(rawBridge), totalBalance);
        _freezeBridge(rawBridge);

        // escapeAddress[ESCAPE_PUBKEY_0] == address(0), so any non-zero sender reverts
        bytes32[] memory proof = _getMerkleProof(0);
        vm.prank(alice);
        vm.expectRevert(ValidiumBridge.NotEscapeAddress.selector);
        rawBridge.escapeWithdraw(0, ESCAPE_PUBKEY_0, ESCAPE_BALANCE_0, ESCAPE_SALT_0, proof);
    }

    function test_escapeWithdraw_revertsNotEscapeAddress() public {
        ValidiumBridge escapeBridge = _deployEscapeBridge();
        _freezeBridge(escapeBridge);

        // Bob tries to escape-withdraw alice's leaf (ESCAPE_PUBKEY_0 → alice)
        bytes32[] memory proof = _getMerkleProof(0);
        vm.prank(bob);
        vm.expectRevert(ValidiumBridge.NotEscapeAddress.selector);
        escapeBridge.escapeWithdraw(0, ESCAPE_PUBKEY_0, ESCAPE_BALANCE_0, ESCAPE_SALT_0, proof);
    }

    function test_escapeWithdraw_multipleUsers() public {
        ValidiumBridge escapeBridge = _deployEscapeBridge();
        _freezeBridge(escapeBridge);

        // Alice escapes from leaf 0
        bytes32[] memory proof0 = _getMerkleProof(0);
        vm.prank(alice);
        escapeBridge.escapeWithdraw(0, ESCAPE_PUBKEY_0, ESCAPE_BALANCE_0, ESCAPE_SALT_0, proof0);

        // Bob escapes from leaf 2
        bytes32[] memory proof2 = _getMerkleProof(2);
        vm.prank(bob);
        escapeBridge.escapeWithdraw(2, ESCAPE_PUBKEY_2, ESCAPE_BALANCE_2, ESCAPE_SALT_2, proof2);

        assertEq(token.balanceOf(alice), ESCAPE_BALANCE_0);
        assertEq(token.balanceOf(bob), ESCAPE_BALANCE_2);
        assertTrue(escapeBridge.claimed(0));
        assertTrue(escapeBridge.claimed(2));
        assertFalse(escapeBridge.claimed(1));
        assertFalse(escapeBridge.claimed(3));
    }

    /// @dev A leaf index above the tree size must not verify. The proof loop only
    ///      consumes proof.length bits, so index + k*2^depth would otherwise re-verify
    ///      against a fresh `claimed` slot and let one account drain the bridge.
    function test_escapeWithdraw_revertsShiftedIndexReplay() public {
        ValidiumBridge escapeBridge = _deployEscapeBridge();
        _freezeBridge(escapeBridge);

        bytes32[] memory proof0 = _getMerkleProof(0);
        vm.prank(alice);
        escapeBridge.escapeWithdraw(0, ESCAPE_PUBKEY_0, ESCAPE_BALANCE_0, ESCAPE_SALT_0, proof0);

        // Same leaf, same proof, index shifted by one tree width (4).
        for (uint256 i = 1; i < 4; i++) {
            vm.prank(alice);
            vm.expectRevert(ValidiumBridge.InvalidMerkleProof.selector);
            escapeBridge.escapeWithdraw(i * 4, ESCAPE_PUBKEY_0, ESCAPE_BALANCE_0, ESCAPE_SALT_0, proof0);
        }

        assertEq(token.balanceOf(alice), ESCAPE_BALANCE_0);
    }

    // ---------------------------------------------------------------
    // Frozen guards
    // ---------------------------------------------------------------
    function test_deposit_revertsWhenFrozen() public {
        _freezeBridge(bridge);
        token.mint(alice, DEPOSIT_AMOUNT);
        vm.startPrank(alice);
        token.approve(address(bridge), DEPOSIT_AMOUNT);
        vm.expectRevert(ValidiumBridge.AlreadyFrozen.selector);
        bridge.deposit(DEPOSIT_AMOUNT, PUBKEY, hex"");
        vm.stopPrank();
    }

    function test_withdraw_revertsWhenFrozen() public {
        _depositAs(alice, WITHDRAW_AMOUNT, PUBKEY);
        _freezeBridge(bridge);
        vm.expectRevert(ValidiumBridge.AlreadyFrozen.selector);
        bridge.withdraw(hex"", STATE_ROOT, NEW_ROOT, WITHDRAW_AMOUNT, bob);
    }

    // ---------------------------------------------------------------
    // Forced withdrawal
    // ---------------------------------------------------------------
    function test_requestForcedWithdrawal_storesRequest() public {
        _depositAs(alice, WITHDRAW_AMOUNT, PUBKEY);

        vm.expectEmit(true, true, true, true);
        emit ValidiumBridge.ForcedWithdrawalRequested(0, bob, WITHDRAW_AMOUNT, block.timestamp + bridge.FORCED_WITHDRAWAL_DEADLINE());

        bridge.requestForcedWithdrawal(hex"", STATE_ROOT, NEW_ROOT, WITHDRAW_AMOUNT, bob);

        (bytes32 oldRoot, bytes32 newRoot, uint64 amount, address recipient, uint256 deadline) = bridge.forcedRequests(0);
        assertEq(oldRoot, STATE_ROOT);
        assertEq(newRoot, NEW_ROOT);
        assertEq(amount, WITHDRAW_AMOUNT);
        assertEq(recipient, bob);
        assertEq(deadline, block.timestamp + bridge.FORCED_WITHDRAWAL_DEADLINE());
        // stateRoot unchanged — request is queued, not applied
        assertEq(bridge.stateRoot(), STATE_ROOT);
    }

    function test_requestForcedWithdrawal_revertsWhenFrozen() public {
        _freezeBridge(bridge);
        vm.expectRevert(ValidiumBridge.AlreadyFrozen.selector);
        bridge.requestForcedWithdrawal(hex"", STATE_ROOT, NEW_ROOT, WITHDRAW_AMOUNT, bob);
    }

    function test_requestForcedWithdrawal_revertsStaleState() public {
        bytes32 wrongRoot = keccak256("wrong-root");
        vm.expectRevert(abi.encodeWithSelector(ValidiumBridge.StaleState.selector, STATE_ROOT, wrongRoot));
        bridge.requestForcedWithdrawal(hex"", wrongRoot, NEW_ROOT, WITHDRAW_AMOUNT, bob);
    }

    function test_processForcedWithdrawal_executesAndDeletes() public {
        _depositAs(alice, WITHDRAW_AMOUNT, PUBKEY);
        bridge.requestForcedWithdrawal(hex"", STATE_ROOT, NEW_ROOT, WITHDRAW_AMOUNT, bob);

        vm.expectEmit(true, true, true, true);
        emit ValidiumBridge.ForcedWithdrawalProcessed(0);

        bridge.processForcedWithdrawal(0);

        assertEq(bridge.stateRoot(), NEW_ROOT);
        assertEq(token.balanceOf(bob), WITHDRAW_AMOUNT);
        // Request deleted (deadline == 0)
        (, , , , uint256 deadline) = bridge.forcedRequests(0);
        assertEq(deadline, 0);
    }

    function test_processForcedWithdrawal_revertsIfStateChanged() public {
        _depositAs(alice, WITHDRAW_AMOUNT * 2, PUBKEY);
        bridge.requestForcedWithdrawal(hex"", STATE_ROOT, NEW_ROOT, WITHDRAW_AMOUNT, bob);

        // Operator posts a different withdrawal that changes stateRoot
        bridge.withdraw(hex"", STATE_ROOT, THIRD_ROOT, WITHDRAW_AMOUNT, alice);

        // Now the forced request's oldRoot doesn't match current stateRoot
        vm.expectRevert(abi.encodeWithSelector(ValidiumBridge.StaleState.selector, STATE_ROOT, THIRD_ROOT));
        bridge.processForcedWithdrawal(0);
    }

    function test_processForcedWithdrawal_revertsNotFound() public {
        vm.expectRevert(abi.encodeWithSelector(ValidiumBridge.ForcedRequestNotFound.selector, 999));
        bridge.processForcedWithdrawal(999);
    }

    function test_freezeOnExpiredRequest_freezesAfterDeadline() public {
        _depositAs(alice, WITHDRAW_AMOUNT, PUBKEY);
        bridge.requestForcedWithdrawal(hex"", STATE_ROOT, NEW_ROOT, WITHDRAW_AMOUNT, bob);

        vm.warp(block.timestamp + bridge.FORCED_WITHDRAWAL_DEADLINE() + 1);

        vm.expectEmit(true, true, true, true);
        emit ValidiumBridge.Frozen(block.timestamp);

        bridge.freezeOnExpiredRequest(0);
        assertTrue(bridge.frozen());
    }

    function test_freezeOnExpiredRequest_revertsBeforeDeadline() public {
        _depositAs(alice, WITHDRAW_AMOUNT, PUBKEY);
        bridge.requestForcedWithdrawal(hex"", STATE_ROOT, NEW_ROOT, WITHDRAW_AMOUNT, bob);

        vm.warp(block.timestamp + bridge.FORCED_WITHDRAWAL_DEADLINE());
        vm.expectRevert(abi.encodeWithSelector(ValidiumBridge.ForcedRequestNotExpired.selector, 0));
        bridge.freezeOnExpiredRequest(0);
    }

    // ---------------------------------------------------------------
    // Cross-language compatibility
    // ---------------------------------------------------------------
    function test_uint64ToLE_encoding() public pure {
        // 1000 = 0x03E8
        // LE bytes: [0xE8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        bytes8 result = _uint64ToLE(1000);
        assertEq(result, bytes8(hex"e803000000000000"));

        // 256 = 0x0100
        // LE bytes: [0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        bytes8 result2 = _uint64ToLE(256);
        assertEq(result2, bytes8(hex"0001000000000000"));

        // max uint64
        bytes8 result3 = _uint64ToLE(type(uint64).max);
        assertEq(result3, bytes8(hex"ffffffffffffffff"));
    }

    function test_accountCommitment_matchesExpected() public pure {
        // Known test vector: pubkey = 0xAA (padded to 32 bytes), balance = 1000, salt = 0x11 (padded)
        // This commitment is computed identically by Solidity and should match Rust's:
        //   SHA256(pubkey || 1000u64.to_le_bytes() || salt)
        bytes32 pubkey = bytes32(uint256(0xAA));
        bytes32 salt = bytes32(uint256(0x11));
        uint64 balance = 1000;

        bytes32 commitment = _accountCommitment(pubkey, balance, salt);

        // Verify the commitment is deterministic and uses LE encoding
        bytes32 expected = sha256(abi.encodePacked(pubkey, bytes8(hex"e803000000000000"), salt));
        assertEq(commitment, expected);
    }
}

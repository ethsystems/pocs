// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IERC20} from "forge-std/src/interfaces/IERC20.sol";
import {IRiscZeroVerifier} from "./interfaces/IRiscZeroVerifier.sol";

/// @title ValidiumBridge
/// @notice Bridge contract for depositing and withdrawing ERC20 tokens using
///         RISC Zero ZK proofs for membership verification and withdrawal authorization.
/// @dev See SPEC.md for the full protocol specification.
///      Double-spend prevention relies on sequential root checks:
///      each operation changes stateRoot, making stale proofs instantly invalid.
///      Escape hatch: if operator disappears, users can freeze the bridge after
///      ESCAPE_TIMEOUT and withdraw by revealing their balance on-chain.
contract ValidiumBridge {
    // TODO: Production should use OpenZeppelin SafeERC20 for safe token transfers
    // See: https://docs.openzeppelin.com/contracts/5.x/api/token/erc20#SafeERC20

    /// @notice The ERC20 token managed by this bridge.
    IERC20 public immutable token;

    /// @notice The RISC Zero verifier contract used to validate proofs.
    IRiscZeroVerifier public immutable verifier;

    /// @notice Merkle root of the current account state.
    bytes32 public stateRoot;

    /// @notice Address of the operator who deployed the contract.
    address public operator;

    /// @notice Merkle root of the allowlist used for membership verification.
    bytes32 public allowlistRoot;

    /// @notice Image ID for the membership proof guest program.
    bytes32 public immutable MEMBERSHIP_IMAGE_ID;

    /// @notice Image ID for the withdrawal proof guest program.
    bytes32 public immutable WITHDRAWAL_IMAGE_ID;

    /// @notice Image ID for the transfer proof guest program.
    bytes32 public immutable TRANSFER_IMAGE_ID;

    /// @notice Timestamp of the last proof submission (withdrawal or transfer batch).
    uint256 public lastProofTimestamp;

    /// @notice Whether the bridge is frozen (escape hatch activated).
    bool public frozen;

    /// @notice Tracks which leaf indices have been claimed via escape withdrawal.
    mapping(uint256 => bool) public claimed;

    /// @notice Maps pubkey → depositor address for front-running protection on escape withdrawal.
    mapping(bytes32 => address) public escapeAddress;

    /// @notice Duration of operator inactivity before the bridge can be frozen.
    uint256 public constant ESCAPE_TIMEOUT = 7 days;

    /// @notice Duration before an unprocessed forced withdrawal request triggers a freeze.
    uint256 public constant FORCED_WITHDRAWAL_DEADLINE = 1 days;

    /// @notice Counter for forced withdrawal request IDs.
    uint256 public forcedRequestCount;

    struct ForcedRequest {
        bytes32 oldRoot;
        bytes32 newRoot;
        uint64 amount;
        address recipient;
        uint256 deadline;
    }

    /// @notice Pending forced withdrawal requests.
    mapping(uint256 => ForcedRequest) public forcedRequests;

    error StaleState(bytes32 expected, bytes32 provided);
    error InvalidAmount();
    error NotFrozen();
    error AlreadyFrozen();
    error TimeoutNotReached();
    error AlreadyClaimed(uint256 leafIndex);
    error InvalidMerkleProof();
    error ForcedRequestNotFound(uint256 requestId);
    error ForcedRequestNotExpired(uint256 requestId);
    error NotEscapeAddress();
    error PubkeyAlreadyClaimed();

    event Deposit(address indexed depositor, bytes32 pubkey, uint256 amount);
    event Withdrawal(address indexed recipient, uint256 amount);
    event TransferBatchPosted(bytes32 indexed oldRoot, bytes32 indexed newRoot);
    event Frozen(uint256 timestamp);
    event EscapeWithdrawal(uint256 indexed leafIndex, address indexed recipient, uint64 amount);
    event ForcedWithdrawalRequested(uint256 indexed requestId, address indexed recipient, uint64 amount, uint256 deadline);
    event ForcedWithdrawalProcessed(uint256 indexed requestId);

    constructor(
        IERC20 _token,
        IRiscZeroVerifier _verifier,
        bytes32 _initialRoot,
        bytes32 _allowlistRoot,
        bytes32 _membershipImageId,
        bytes32 _withdrawalImageId,
        bytes32 _transferImageId
    ) {
        token = _token;
        verifier = _verifier;
        stateRoot = _initialRoot;
        allowlistRoot = _allowlistRoot;
        MEMBERSHIP_IMAGE_ID = _membershipImageId;
        WITHDRAWAL_IMAGE_ID = _withdrawalImageId;
        TRANSFER_IMAGE_ID = _transferImageId;
        operator = msg.sender;
        lastProofTimestamp = block.timestamp;
    }

    /// @notice Deposit tokens into the bridge after verifying membership proof.
    /// @param amount The number of tokens to deposit.
    /// @param pubkey The depositor's public key for the off-chain account.
    /// @param membershipSeal The RISC Zero proof seal for membership verification.
    function deposit(uint256 amount, bytes32 pubkey, bytes calldata membershipSeal) external {
        if (frozen) revert AlreadyFrozen();
        if (amount == 0) revert InvalidAmount();

        // Verify membership proof: journal = abi.encodePacked(allowlistRoot, pubkey)
        // Binding pubkey in the journal prevents proof reuse with arbitrary keys
        bytes memory membershipJournal = abi.encodePacked(allowlistRoot, pubkey);
        verifier.verify(membershipSeal, MEMBERSHIP_IMAGE_ID, sha256(membershipJournal));

        // CEI: effects before interaction
        address existing = escapeAddress[pubkey];
        if (existing != address(0) && existing != msg.sender) revert PubkeyAlreadyClaimed();
        escapeAddress[pubkey] = msg.sender;

        require(token.transferFrom(msg.sender, address(this), amount), "Deposit transfer failed");

        emit Deposit(msg.sender, pubkey, amount);
    }

    /// @notice Withdraw tokens from the bridge by verifying a withdrawal proof.
    /// @param seal The RISC Zero proof seal.
    /// @param oldRoot The pre-transition Merkle root committed in the proof.
    /// @param newRoot The post-transition Merkle root committed in the proof.
    /// @param amount The amount of tokens to withdraw (uint64 for 8-byte big-endian journal encoding).
    /// @param recipient The address to receive the withdrawn tokens.
    function withdraw(bytes calldata seal, bytes32 oldRoot, bytes32 newRoot, uint64 amount, address recipient)
        external
    {
        if (frozen) revert AlreadyFrozen();
        if (oldRoot != stateRoot) revert StaleState(stateRoot, oldRoot);
        if (amount == 0) revert InvalidAmount();

        // Journal: oldRoot (32) + newRoot (32) + amount (8) + recipient (20) = 92 bytes
        bytes memory journal = abi.encodePacked(oldRoot, newRoot, amount, recipient);
        verifier.verify(seal, WITHDRAWAL_IMAGE_ID, sha256(journal));

        // CEI: effects before interaction
        stateRoot = newRoot;
        lastProofTimestamp = block.timestamp;

        require(token.transfer(recipient, amount), "Withdrawal transfer failed");

        emit Withdrawal(recipient, amount);
    }

    /// @notice Post a transfer batch proof to keep the bridge root in sync with off-chain transfers.
    /// @param seal The RISC Zero proof seal for the transfer.
    /// @param oldRoot The pre-transition Merkle root.
    /// @param newRoot The post-transition Merkle root.
    function postTransferBatch(bytes calldata seal, bytes32 oldRoot, bytes32 newRoot) external {
        if (frozen) revert AlreadyFrozen();
        if (oldRoot != stateRoot) revert StaleState(stateRoot, oldRoot);

        bytes memory journal = abi.encodePacked(oldRoot, newRoot);
        verifier.verify(seal, TRANSFER_IMAGE_ID, sha256(journal));

        stateRoot = newRoot;
        lastProofTimestamp = block.timestamp;

        emit TransferBatchPosted(oldRoot, newRoot);
    }

    /// @notice Freeze the bridge after the operator has been inactive for ESCAPE_TIMEOUT.
    function freeze() external {
        if (frozen) revert AlreadyFrozen();
        if (block.timestamp <= lastProofTimestamp + ESCAPE_TIMEOUT) revert TimeoutNotReached();

        frozen = true;
        emit Frozen(block.timestamp);
    }

    /// @notice Request a forced withdrawal. User submits a valid ZK withdrawal proof;
    ///         the operator must process it before the deadline or the bridge can be frozen.
    function requestForcedWithdrawal(
        bytes calldata seal,
        bytes32 oldRoot,
        bytes32 newRoot,
        uint64 amount,
        address recipient
    ) external {
        if (frozen) revert AlreadyFrozen();
        if (oldRoot != stateRoot) revert StaleState(stateRoot, oldRoot);
        if (amount == 0) revert InvalidAmount();

        bytes memory journal = abi.encodePacked(oldRoot, newRoot, amount, recipient);
        verifier.verify(seal, WITHDRAWAL_IMAGE_ID, sha256(journal));

        uint256 requestId = forcedRequestCount++;
        uint256 deadline = block.timestamp + FORCED_WITHDRAWAL_DEADLINE;
        forcedRequests[requestId] = ForcedRequest({
            oldRoot: oldRoot,
            newRoot: newRoot,
            amount: amount,
            recipient: recipient,
            deadline: deadline
        });

        emit ForcedWithdrawalRequested(requestId, recipient, amount, deadline);
    }

    /// @notice Process a pending forced withdrawal request. Callable by anyone (typically the operator).
    ///         Requires that stateRoot still matches the request's oldRoot.
    function processForcedWithdrawal(uint256 requestId) external {
        if (frozen) revert AlreadyFrozen();
        ForcedRequest memory req = forcedRequests[requestId];
        if (req.deadline == 0) revert ForcedRequestNotFound(requestId);

        if (stateRoot != req.oldRoot) revert StaleState(req.oldRoot, stateRoot);

        // Apply the state transition
        stateRoot = req.newRoot;
        lastProofTimestamp = block.timestamp;

        delete forcedRequests[requestId];

        require(token.transfer(req.recipient, req.amount), "Forced withdrawal transfer failed");

        emit ForcedWithdrawalProcessed(requestId);
        emit Withdrawal(req.recipient, req.amount);
    }

    /// @notice Freeze the bridge because a forced withdrawal request expired without being processed.
    function freezeOnExpiredRequest(uint256 requestId) external {
        if (frozen) revert AlreadyFrozen();
        ForcedRequest memory req = forcedRequests[requestId];
        if (req.deadline == 0) revert ForcedRequestNotFound(requestId);
        if (block.timestamp <= req.deadline) revert ForcedRequestNotExpired(requestId);

        frozen = true;
        emit Frozen(block.timestamp);
    }

    /// @notice Emergency withdrawal when the bridge is frozen. Reveals balance on-chain.
    /// @param leafIndex The account's position in the Merkle tree.
    /// @param pubkey The account's public key.
    /// @param balance The account's balance.
    /// @param salt The account's salt.
    /// @param merkleProof The sibling path proving inclusion in the state root.
    function escapeWithdraw(
        uint256 leafIndex,
        bytes32 pubkey,
        uint64 balance,
        bytes32 salt,
        bytes32[] calldata merkleProof
    ) external {
        if (!frozen) revert NotFrozen();
        if (claimed[leafIndex]) revert AlreadyClaimed(leafIndex);
        if (balance == 0) revert InvalidAmount();

        bytes32 leaf = _accountCommitment(pubkey, balance, salt);
        if (!_verifyMerkleProof(leaf, leafIndex, merkleProof, stateRoot)) revert InvalidMerkleProof();
        if (msg.sender != escapeAddress[pubkey]) revert NotEscapeAddress();

        // CEI: effects before interaction
        claimed[leafIndex] = true;

        require(token.transfer(msg.sender, balance), "Escape transfer failed");

        emit EscapeWithdrawal(leafIndex, msg.sender, balance);
    }

    /// @dev Compute account commitment matching Rust: SHA256(pubkey || balance_le || salt)
    function _accountCommitment(bytes32 pubkey, uint64 balance, bytes32 salt) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(pubkey, _uint64ToLE(balance), salt));
    }

    /// @dev Convert uint64 to little-endian bytes (matches Rust u64::to_le_bytes()).
    ///      bytes8 stores MSB first, so the least-significant source byte goes to the highest shift.
    function _uint64ToLE(uint64 value) internal pure returns (bytes8) {
        uint64 reversed = (uint64(uint8(value)) << 56) | (uint64(uint8(value >> 8)) << 48)
            | (uint64(uint8(value >> 16)) << 40) | (uint64(uint8(value >> 24)) << 32)
            | (uint64(uint8(value >> 32)) << 24) | (uint64(uint8(value >> 40)) << 16)
            | (uint64(uint8(value >> 48)) << 8) | uint64(uint8(value >> 56));
        return bytes8(reversed);
    }

    /// @dev Verify a binary SHA-256 Merkle proof.
    ///      The loop consumes exactly proof.length bits of `index`, so any index at or
    ///      above 2**proof.length would verify identically to index % 2**proof.length.
    ///      Requiring index == 0 after the loop rejects those aliases; without it the
    ///      same (leaf, proof) re-verifies at index + k*2**depth, and since `claimed`
    ///      is keyed on the full index each alias is a fresh slot.
    function _verifyMerkleProof(bytes32 leaf, uint256 index, bytes32[] calldata proof, bytes32 root)
        internal
        pure
        returns (bool)
    {
        bytes32 computed = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            if (index & 1 == 0) {
                computed = sha256(abi.encodePacked(computed, proof[i]));
            } else {
                computed = sha256(abi.encodePacked(proof[i], computed));
            }
            index >>= 1;
        }
        return computed == root && index == 0;
    }
}

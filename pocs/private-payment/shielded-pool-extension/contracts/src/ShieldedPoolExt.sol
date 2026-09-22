// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin-contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin-contracts/token/ERC20/utils/SafeERC20.sol";
import {IVerifier} from "./interfaces/IVerifier.sol";
import {LeanIMT, LeanIMTData} from "@zk-kit/packages/lean-imt/contracts/LeanIMT.sol";
import {PoseidonT3} from "poseidon-solidity/PoseidonT3.sol";

/// @title ShieldedPoolExt
/// @notice Privacy-preserving payment pool extended with epoch-based nullifiers
///         and PIR-served reads (research prototype). See ../../SPEC.md.
/// @dev Current scope: deposits, epoch rollover, and the full spend path —
///      `transfer` (2-in-2-out) and `withdraw` (single input). `currentEpoch`
///      advances via `rolloverEpoch()`, freezing each epoch's active-nullifier
///      root. Both spend functions run the two-proof path (wallet spend proof +
///      relayer insertion proof), advancing `activeNullifierRoot`/
///      `activeLeafCount` via the shared `_verifyInsertionAndAdvance` helper.
contract ShieldedPoolExt {
    using SafeERC20 for IERC20;
    using LeanIMT for LeanIMTData;

    /// @notice Maximum number of historical commitment roots retained.
    uint256 public constant MAX_HISTORICAL_ROOTS = 100;

    /// @notice LeanIMT commitment tree (append-only; membership only).
    LeanIMTData internal _tree;

    // Historical commitment-root buffer. Deposits and transfers populate it; it
    // is *consumed* at spend time, when `transfer` (and later `withdraw`) pin the
    // spend proof's `commitment_root` to a recent root via `isKnownRoot`.
    /// @notice Historical commitment roots (circular buffer).
    bytes32[100] public historicalRoots;
    /// @notice Next write index into the historical-roots buffer.
    uint256 public historicalRootIndex;
    /// @notice Superseded commitment roots still accepted in proofs.
    mapping(bytes32 => bool) public validRoots;

    /// @notice Tokens accepted by the pool.
    mapping(address => bool) public supportedTokens;

    /// @notice Verifier for the deposit proof (IVerifier.verify).
    IVerifier public depositVerifier;

    /// @notice Verifier for the wallet's transfer spend proof (zero-knowledge).
    IVerifier public transferVerifier;

    /// @notice Verifier for the relayer's 2-insertion proof used by `transfer`
    ///         (advances the active nullifier tree by k=2; not zero-knowledge).
    IVerifier public insertionVerifier;

    /// @notice Verifier for the wallet's withdraw spend proof (zero-knowledge).
    IVerifier public withdrawVerifier;

    /// @notice Verifier for the relayer's 1-insertion proof used by `withdraw`
    ///         (advances the active nullifier tree by k=1; not zero-knowledge).
    ///         Distinct from `insertionVerifier`: the insertion circuit's leaf
    ///         count is fixed per circuit, so k=1 and k=2 are separate artifacts.
    IVerifier public withdrawInsertionVerifier;

    /// @notice Hash of the chain-update circuit's verifying key (SPEC `FixedVK`),
    ///         fixed at deployment. Supplied as a spend-proof public input so a
    ///         valid proof is pinned to the legitimate chain-update circuit; a
    ///         spend recursing over a forged chain circuit cannot verify.
    bytes32 public immutable chainVkHash;

    /// @notice Contract owner (PoC: also the epoch-rollover trigger in later slices).
    address public owner;

    /// @notice Current epoch, bound into each deposited note's commitment as
    ///         `epoch_created`. Advanced by `rolloverEpoch()`.
    uint64 public currentEpoch;

    /// @notice Frozen active-nullifier-tree root per past epoch `e`.
    mapping(uint64 => bytes32) public frozenNullifierRoots;

    /// @notice Root of the current epoch's active nullifier tree. Advanced by the
    ///         transfer/withdraw spend path; reset to `emptyImtRoot` on rollover.
    bytes32 public activeNullifierRoot;

    /// @notice Next free leaf index in the active nullifier tree (canonical append
    ///         index). Starts at 1: index 0 is the indexed tree's genesis leaf
    ///         (the bootstrap low-leaf for sorted-low-leaf insertion), so real
    ///         nullifiers append from index 1. NB: the SPEC's rolloverEpoch
    ///         pseudocode resets this to 0; the genesis-leaf bootstrap makes 1 the
    ///         correct value (reconciliation flagged in review).
    uint64 public activeLeafCount;

    /// @notice Root of an empty active nullifier tree (genesis-leaf-only tree).
    ///         The SPEC's `EMPTY_IMT_ROOT`; fixed at deployment.
    bytes32 public immutable emptyImtRoot;

    event Deposit(bytes32 indexed commitment, address indexed token, uint256 amount, bytes encryptedNote);
    /// @dev `nullifier1`/`nullifier2` are the per-input active nullifiers η; replicas
    ///      replay them in event order to rebuild the active indexed tree.
    event Transfer(
        bytes32 indexed nullifier1,
        bytes32 indexed nullifier2,
        bytes32 commitment1,
        bytes32 commitment2,
        bytes encryptedNotes
    );
    /// @dev `nullifier` is the spent note's active η; replicas replay it (in event
    ///      order, interleaved with `Transfer`) to rebuild the active indexed tree.
    event Withdraw(bytes32 indexed nullifier, address indexed recipient, address indexed token, uint256 amount);
    event EpochRollover(uint64 indexed epoch, bytes32 root);
    event TokenAdded(address indexed token);
    event TokenRemoved(address indexed token);
    event DepositVerifierUpdated(address indexed oldVerifier, address indexed newVerifier);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    error OnlyOwner();
    error UnsupportedToken();
    error ZeroAmount();
    error InvalidProof();
    error InvalidRoot();
    error ZeroAddress();
    error TokenAlreadySupported();
    error TokenNotSupported();

    modifier onlyOwner() {
        _onlyOwner();
        _;
    }

    function _onlyOwner() internal view {
        if (msg.sender != owner) revert OnlyOwner();
    }

    constructor(
        address _depositVerifier,
        address _transferVerifier,
        address _insertionVerifier,
        address _withdrawVerifier,
        address _withdrawInsertionVerifier,
        bytes32 _chainVkHash,
        bytes32 _emptyImtRoot
    ) {
        if (_depositVerifier == address(0)) revert ZeroAddress();
        if (_transferVerifier == address(0)) revert ZeroAddress();
        if (_insertionVerifier == address(0)) revert ZeroAddress();
        if (_withdrawVerifier == address(0)) revert ZeroAddress();
        if (_withdrawInsertionVerifier == address(0)) revert ZeroAddress();
        depositVerifier = IVerifier(_depositVerifier);
        transferVerifier = IVerifier(_transferVerifier);
        insertionVerifier = IVerifier(_insertionVerifier);
        withdrawVerifier = IVerifier(_withdrawVerifier);
        withdrawInsertionVerifier = IVerifier(_withdrawInsertionVerifier);
        chainVkHash = _chainVkHash;
        emptyImtRoot = _emptyImtRoot;
        activeNullifierRoot = _emptyImtRoot;
        activeLeafCount = 1; // index 0 is the indexed tree's genesis leaf
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    /// @notice Current commitment-tree root.
    function commitmentRoot() public view returns (bytes32) {
        return bytes32(_tree.root());
    }

    /// @notice Number of commitments inserted into the tree.
    function getCommitmentCount() external view returns (uint256) {
        return _tree.size;
    }

    /// @notice Deposit tokens, minting a note committed at the current epoch.
    /// @dev Deposit-proof public inputs are [commitment, token, amount, currentEpoch].
    ///      The contract supplies `currentEpoch` as the final input, so a valid
    ///      proof enforces `epoch_created == currentEpoch` on the new commitment.
    /// @param proof Deposit ZK proof.
    /// @param commitment The note commitment (binds `epoch_created`).
    /// @param token ERC-20 token address.
    /// @param amount Amount to deposit.
    /// @param encryptedNote Encrypted note payload for viewing-key holders.
    function deposit(
        bytes calldata proof,
        bytes32 commitment,
        address token,
        uint256 amount,
        bytes calldata encryptedNote
    ) external {
        if (!supportedTokens[token]) revert UnsupportedToken();
        if (amount == 0) revert ZeroAmount();

        bytes32[] memory publicInputs = new bytes32[](4);
        publicInputs[0] = commitment;
        publicInputs[1] = bytes32(uint256(uint160(token)));
        publicInputs[2] = bytes32(amount);
        publicInputs[3] = bytes32(uint256(currentEpoch));

        if (!depositVerifier.verify(proof, publicInputs)) revert InvalidProof();

        _tree.insert(uint256(commitment));
        _recordRoot();
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);

        emit Deposit(commitment, token, amount, encryptedNote);
    }

    /// @notice Recompute the chain accumulator a spend's per-input chain proof
    ///         must match: fold `frozenNullifierRoots[e]` for
    ///         `e in [epochCreated, currentEpoch)` under Poseidon, seeded at 0.
    /// @dev Mirrors the chain-update circuit's accumulator fold
    ///      (`hash_2([acc, frozen_root])`). PoseidonT3 is the same primitive the
    ///      LeanIMT uses for the commitment tree, so the on-chain and in-circuit
    ///      hashes agree. Cost is O(currentEpoch - epochCreated); bounded by
    ///      coarse epochs (SPEC "Epoch Cadence"). A note created in the current
    ///      epoch yields 0 (the genesis chain proof's accumulator).
    function expectedChainAccumulator(uint64 epochCreated) public view returns (bytes32) {
        uint256 acc = 0;
        for (uint64 e = epochCreated; e < currentEpoch; e++) {
            acc = PoseidonT3.hash([acc, uint256(frozenNullifierRoots[e])]);
        }
        return bytes32(acc);
    }

    /// @notice Spend two input notes into two output notes (2-in-2-out), advancing
    ///         the active nullifier tree via the relayer's insertion proof.
    /// @dev Two-proof spend path (SPEC "Private Transfer"). The contract supplies
    ///      every state-pinned public input, so a valid proof is forced to match
    ///      contract state:
    ///      - spend proof: `current_epoch`, `chainVkHash`, and the per-input
    ///        `expectedChainAccumulator(epochCreated[i])` (realizing the SPEC's
    ///        `accumulator == expectedChainAccumulator(...)` check by construction);
    ///      - insertion proof: `pre_active_root = activeNullifierRoot` and
    ///        `pre_leaf_count = activeLeafCount`.
    ///      Cross-proof binding (SPEC "Cross-proof binding") is structural: the
    ///      same `nullifiers` array is fed to both verifiers, so both proofs are
    ///      pinned to one identical ordered η list — no element-wise comparison
    ///      needed. Active-epoch double-spend and in-tx duplicate η are caught by
    ///      the insertion proof's sorted-low-leaf step, so the contract keeps no
    ///      nullifier set and runs no uniqueness check.
    /// @param spendProof Wallet spend proof (commitment membership, chain-proof
    ///        recursion, nullifier derivation).
    /// @param insertionProof Relayer insertion proof advancing the active tree.
    /// @param nullifiers Per-input active nullifiers η; bound across both proofs.
    /// @param outputCommitments Output-note commitments (minted at currentEpoch).
    /// @param root Commitment-tree root the spend proof was built against.
    /// @param epochCreated Per-input note creation epoch. Bound to each input's
    ///        commitment by the spend proof, so a caller cannot misreport it.
    /// @param postActiveRoot New active-tree root attested by the insertion proof.
    /// @param encryptedNotes Encrypted output-note payloads for viewing-key holders.
    function transfer(
        bytes calldata spendProof,
        bytes calldata insertionProof,
        bytes32[2] calldata nullifiers,
        bytes32[2] calldata outputCommitments,
        bytes32 root,
        uint64[2] calldata epochCreated,
        bytes32 postActiveRoot,
        bytes calldata encryptedNotes
    ) external {
        if (!isKnownRoot(root)) revert InvalidRoot();

        // Spend proof: 11 public inputs in circuit declaration order (see
        // circuits/transfer/src/main.nr). The contract pins current_epoch,
        // chainVkHash, and the per-input expected accumulators.
        bytes32[] memory spendInputs = new bytes32[](11);
        spendInputs[0] = nullifiers[0];
        spendInputs[1] = nullifiers[1];
        spendInputs[2] = outputCommitments[0];
        spendInputs[3] = outputCommitments[1];
        spendInputs[4] = root;
        spendInputs[5] = bytes32(uint256(currentEpoch));
        spendInputs[6] = chainVkHash;
        spendInputs[7] = bytes32(uint256(epochCreated[0]));
        spendInputs[8] = bytes32(uint256(epochCreated[1]));
        spendInputs[9] = expectedChainAccumulator(epochCreated[0]);
        spendInputs[10] = expectedChainAccumulator(epochCreated[1]);
        if (!transferVerifier.verify(spendProof, spendInputs)) revert InvalidProof();

        // Insertion proof (k=2). Cross-proof binding: the SAME `nullifiers` fed to
        // the spend proof above are the insertion proof's η list, so one caller-
        // supplied list pins both proofs to an identical list — a relayer whose
        // insertion proof covers a different list fails the insertion verify, and a
        // wallet whose spend proof covers a different list fails the spend verify.
        // There is no second list to assert equal.
        bytes32[] memory nullifierList = new bytes32[](2);
        nullifierList[0] = nullifiers[0];
        nullifierList[1] = nullifiers[1];
        _verifyInsertionAndAdvance(insertionVerifier, insertionProof, nullifierList, postActiveRoot);

        // Append the two output commitments.
        _tree.insert(uint256(outputCommitments[0]));
        _tree.insert(uint256(outputCommitments[1]));
        _recordRoot();

        emit Transfer(nullifiers[0], nullifiers[1], outputCommitments[0], outputCommitments[1], encryptedNotes);
    }

    /// @notice Withdraw a single input note's full value to `recipient`, advancing
    ///         the active nullifier tree via the relayer's 1-insertion proof.
    /// @dev Single-input spend path (SPEC "Withdraw (extended)"): the same two-proof
    ///      structure as `transfer` with k=1. State-pinned public inputs and the
    ///      cross-proof η binding work exactly as in `transfer` (which see). Funds
    ///      move out last, after all state changes (checks-effects-interactions).
    /// @param spendProof Wallet withdraw spend proof.
    /// @param insertionProof Relayer 1-insertion proof advancing the active tree.
    /// @param nullifier The spent note's active nullifier η; bound across both proofs.
    /// @param token ERC-20 token being withdrawn (bound to the note by the proof).
    /// @param amount Amount leaving the pool (bound to the note by the proof).
    /// @param recipient Address that receives the withdrawn funds.
    /// @param root Commitment-tree root the spend proof was built against.
    /// @param epochCreated The note's creation epoch (bound to its commitment by
    ///        the spend proof, so a caller cannot misreport it).
    /// @param postActiveRoot New active-tree root attested by the insertion proof.
    function withdraw(
        bytes calldata spendProof,
        bytes calldata insertionProof,
        bytes32 nullifier,
        address token,
        uint256 amount,
        address recipient,
        bytes32 root,
        uint64 epochCreated,
        bytes32 postActiveRoot
    ) external {
        if (!supportedTokens[token]) revert UnsupportedToken();
        if (amount == 0) revert ZeroAmount();
        if (recipient == address(0)) revert ZeroAddress();
        if (!isKnownRoot(root)) revert InvalidRoot();

        // Spend proof: 9 public inputs in circuit declaration order (see
        // circuits/withdraw/src/main.nr). The contract pins current_epoch,
        // chainVkHash, and the expected accumulator.
        bytes32[] memory spendInputs = new bytes32[](9);
        spendInputs[0] = nullifier;
        spendInputs[1] = bytes32(uint256(uint160(token)));
        spendInputs[2] = bytes32(amount);
        spendInputs[3] = bytes32(uint256(uint160(recipient)));
        spendInputs[4] = root;
        spendInputs[5] = bytes32(uint256(currentEpoch));
        spendInputs[6] = chainVkHash;
        spendInputs[7] = bytes32(uint256(epochCreated));
        spendInputs[8] = expectedChainAccumulator(epochCreated);
        if (!withdrawVerifier.verify(spendProof, spendInputs)) revert InvalidProof();

        // Insertion proof (k=1). Cross-proof binding: the SAME `nullifier` fed to
        // the spend proof above is the insertion proof's η list (see `transfer`).
        bytes32[] memory nullifierList = new bytes32[](1);
        nullifierList[0] = nullifier;
        _verifyInsertionAndAdvance(withdrawInsertionVerifier, insertionProof, nullifierList, postActiveRoot);

        // Interactions last: send the withdrawn funds out.
        IERC20(token).safeTransfer(recipient, amount);

        emit Withdraw(nullifier, recipient, token, amount);
    }

    /// @notice Roll over to the next epoch: freeze the current active-nullifier
    ///         root and reset the active tree. PoC: owner-only; production would
    ///         use a decentralized trigger.
    /// @dev Emits `EpochRollover(frozenEpoch, frozenRoot)`.
    function rolloverEpoch() external onlyOwner {
        uint64 frozenEpoch = currentEpoch;
        bytes32 frozenRoot = activeNullifierRoot;

        frozenNullifierRoots[frozenEpoch] = frozenRoot;
        activeNullifierRoot = emptyImtRoot;
        activeLeafCount = 1;
        currentEpoch = frozenEpoch + 1;

        emit EpochRollover(frozenEpoch, frozenRoot);
    }

    /// @notice Add a supported token.
    function addSupportedToken(address token) external onlyOwner {
        if (token == address(0)) revert ZeroAddress();
        if (supportedTokens[token]) revert TokenAlreadySupported();
        supportedTokens[token] = true;
        emit TokenAdded(token);
    }

    /// @notice Remove a supported token.
    function removeSupportedToken(address token) external onlyOwner {
        if (!supportedTokens[token]) revert TokenNotSupported();
        supportedTokens[token] = false;
        emit TokenRemoved(token);
    }

    /// @notice True if `root` is the current or a retained historical root.
    function isKnownRoot(bytes32 root) public view returns (bool) {
        if (root == commitmentRoot()) return true;
        return validRoots[root];
    }

    /// @notice Update the deposit verifier.
    function setDepositVerifier(address newVerifier) external onlyOwner {
        if (newVerifier == address(0)) revert ZeroAddress();
        emit DepositVerifierUpdated(address(depositVerifier), newVerifier);
        depositVerifier = IVerifier(newVerifier);
    }

    /// @notice Transfer ownership of the contract.
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    /// @dev Verify the relayer's insertion proof and advance the active tree by
    ///      `nullifierList.length` leaves. Shared by `transfer` (k=2) and
    ///      `withdraw` (k=1). Insertion public inputs are
    ///      `[pre_active_root, post_active_root, pre_leaf_count, η_1..k]`; the
    ///      contract pins the pre-state (`activeNullifierRoot`/`activeLeafCount`),
    ///      so a proof built against a stale root reverts and the relayer rebuilds.
    ///      `nullifierList` is the shared η list that also feeds the spend proof,
    ///      which is what binds the two proofs together (see `transfer`).
    function _verifyInsertionAndAdvance(
        IVerifier insVerifier,
        bytes calldata insertionProof,
        bytes32[] memory nullifierList,
        bytes32 postActiveRoot
    ) internal {
        uint256 k = nullifierList.length;
        bytes32[] memory insertionInputs = new bytes32[](3 + k);
        insertionInputs[0] = activeNullifierRoot;
        insertionInputs[1] = postActiveRoot;
        insertionInputs[2] = bytes32(uint256(activeLeafCount));
        for (uint256 i = 0; i < k; i++) {
            insertionInputs[3 + i] = nullifierList[i];
        }
        if (!insVerifier.verify(insertionProof, insertionInputs)) revert InvalidProof();

        activeNullifierRoot = postActiveRoot;
        activeLeafCount += uint64(k);
    }

    /// @dev Record the current root, once per operation after its final insert,
    ///      so intermediate roots never enter the window (parent spec,
    ///      2/SHIELDED-POOL 4.4).
    function _recordRoot() internal {
        bytes32 currentRoot = commitmentRoot();
        bytes32 evictedRoot = historicalRoots[historicalRootIndex];
        if (evictedRoot != bytes32(0)) {
            delete validRoots[evictedRoot];
        }
        validRoots[currentRoot] = true;
        historicalRoots[historicalRootIndex] = currentRoot;
        historicalRootIndex = (historicalRootIndex + 1) % MAX_HISTORICAL_ROOTS;
    }
}

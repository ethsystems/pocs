// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin-contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin-contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin-contracts/utils/ReentrancyGuard.sol";
import {IVerifier} from "./interfaces/IVerifier.sol";
import {IAttestationRegistry} from "./interfaces/IAttestationRegistry.sol";
import {LeanIMT, LeanIMTData} from "@zk-kit/packages/lean-imt/contracts/LeanIMT.sol";

/// @title ShieldedPool
/// @notice Privacy-preserving payment pool with KYC-gated entry
/// @dev Implements UTXO model with commitments/nullifiers for unlinkable transfers
contract ShieldedPool is ReentrancyGuard {
    using SafeERC20 for IERC20;
    using LeanIMT for LeanIMTData;

    /// @notice Maximum number of historical roots to store
    uint256 public constant MAX_HISTORICAL_ROOTS = 100;

    /// @notice BN254 scalar field modulus.
    /// @dev Every field-typed public input MUST be strictly less than this before it reaches
    /// the verifier, so the raw bytes32 the pool stores and compares (nullifiers, commitments)
    /// equals the field element the proof commits to. Without it, a non-canonical nullifier
    /// `N + P_BN254` reduces to the same field element as `N` inside the verifier but is a
    /// distinct bytes32 key here, enabling a double-spend / in-pool mint. Enforcing it in the
    /// pool keeps money-integrity independent of whichever verifier is installed via
    /// applyVerifier. Spec 2/SHIELDED-POOL §4.6 (MUST).
    uint256 internal constant P_BN254 =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @notice Upper bound (exclusive) on token amounts, per spec §5.3 (amount < 2^128).
    uint256 internal constant MAX_AMOUNT = 1 << 128;

    /// @notice Wait between proposing a verifier and installing it (2/SHIELDED-POOL section 6.1).
    /// @dev Gives depositors and auditors time to check the proposed verifier and exit first.
    uint256 public constant VERIFIER_DELAY = 2 days;

    /// @notice How long a matured proposal stays applicable before it lapses.
    /// @dev Without a lapse, the owner could hold a matured proposal and apply it at any later
    /// time with no new event, so a user who deposits after maturity gets no exit window. One
    /// day is enough for a multisig to execute a planned apply, and it bounds how stale a
    /// proposal a depositor must check for. A lapsed proposal must be re-proposed, which
    /// restarts the delay and emits a fresh VerifierProposed.
    uint256 public constant VERIFIER_APPLY_WINDOW = 1 days;

    /// @notice LeanIMT tree data storage for commitments
    LeanIMTData internal _tree;

    /// @notice Historical roots stored in a circular buffer
    bytes32[100] public historicalRoots;

    /// @notice Current index in the historical roots buffer
    uint256 public historicalRootIndex;

    /// @notice Mapping of root to validity status
    mapping(bytes32 => bool) public validRoots;

    /// @notice Spent nullifiers (double-spend prevention)
    mapping(bytes32 => bool) public nullifiers;

    /// @notice Supported tokens for the pool
    mapping(address => bool) public supportedTokens;

    /// @notice ZK proof verifier
    IVerifier public verifier;

    /// @notice Attestation registry for KYC verification
    IAttestationRegistry public attestationRegistry;

    /// @notice Contract owner
    address public owner;

    /// @notice Verifier proposed by the owner, or zero when none is pending
    /// @dev Appended after the original slots so the earlier storage layout is unchanged.
    address public pendingVerifier;

    /// @notice Earliest timestamp at which pendingVerifier can be applied
    uint256 public verifierApplyTime;

    /// @notice Code hash of pendingVerifier, pinned at proposal time
    /// @dev applyVerifier rejects the proposal if the code at the address changed during the
    /// delay (EIP-7702 delegation re-point, CREATE2 deploy-after-propose). The hash does not
    /// cover code behind a proxy or behind the inner verifier addresses, so the installed
    /// verifier and everything it calls must still be non-upgradeable.
    bytes32 public pendingVerifierCodeHash;

    // Events
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
    event AttestationRegistryUpdated(address indexed oldRegistry, address indexed newRegistry);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    // Errors
    error OnlyOwner();
    error UnsupportedToken();
    error ZeroAmount();
    error InvalidProof();
    error NullifierAlreadySpent();
    error IdenticalNullifiers();
    error InvalidRoot();
    error ZeroAddress();
    error TokenAlreadySupported();
    error TokenNotSupported();
    error PublicInputGeFieldModulus();
    error AmountTooLarge();
    error FundingAddressMismatch();
    error NoPendingVerifier();
    error VerifierDelayNotElapsed();
    error VerifierHasNoCode();
    error VerifierCodeChanged();
    error VerifierProposalLapsed();

    modifier onlyOwner() {
        _onlyOwner();
        _;
    }

    function _onlyOwner() internal view {
        if (msg.sender != owner) revert OnlyOwner();
    }

    constructor(address _verifier, address _attestationRegistry) {
        if (_verifier == address(0) || _attestationRegistry == address(0)) {
            revert ZeroAddress();
        }
        verifier = IVerifier(_verifier);
        attestationRegistry = IAttestationRegistry(_attestationRegistry);
        owner = msg.sender;
        // LeanIMT doesn't require explicit initialization
        emit OwnershipTransferred(address(0), msg.sender);
    }

    /// @notice Get the current commitment Merkle root
    /// @return The current root of the commitment tree
    function commitmentRoot() public view returns (bytes32) {
        return bytes32(_tree.root());
    }

    /// @notice Get the number of commitments in the tree
    /// @return The commitment count
    function getCommitmentCount() external view returns (uint256) {
        return _tree.size;
    }

    /// @notice Deposit tokens into the shielded pool
    /// @dev Tokens are pulled only from the funding address bound into the proof (spec §5.3),
    /// and the funding address must be the caller. The circuit does not constrain the funding
    /// address, so without this guard any attested key holder could bind another address that
    /// holds an outstanding approval and deposit against it. Relayed deposits would need an
    /// authorisation signature from the funding address; not implemented in this PoC.
    /// @param proof ZK proof of valid deposit
    /// @param commitment The note commitment
    /// @param token ERC-20 token address
    /// @param amount Amount to deposit
    /// @param fundingAddress Address the tokens are pulled from (bound in the proof)
    /// @param encryptedNote Encrypted note for viewing key holders
    function deposit(
        bytes calldata proof,
        bytes32 commitment,
        address token,
        uint256 amount,
        address fundingAddress,
        bytes calldata encryptedNote
    ) external nonReentrant {
        if (!supportedTokens[token]) revert UnsupportedToken();
        if (amount == 0) revert ZeroAmount();
        if (amount >= MAX_AMOUNT) revert AmountTooLarge();
        if (fundingAddress == address(0)) revert ZeroAddress();
        if (msg.sender != fundingAddress) revert FundingAddressMismatch();

        // Build public inputs for verification. The payload commitment is derived here
        // from the submitted bytes, so a payload that differs from the one the prover
        // committed to fails proof verification (spec §4.6).
        bytes32[] memory publicInputs = new bytes32[](6);
        publicInputs[0] = commitment;
        publicInputs[1] = bytes32(uint256(uint160(token)));
        publicInputs[2] = bytes32(amount);
        publicInputs[3] = bytes32(uint256(uint160(fundingAddress)));
        publicInputs[4] = attestationRegistry.attestationRoot();
        publicInputs[5] = payloadCommitment(encryptedNote);

        // Reject non-canonical field inputs before the verifier reduces them mod P_BN254
        _requireCanonicalInputs(publicInputs);

        // Verify the deposit proof
        if (!verifier.verifyDeposit(proof, publicInputs)) revert InvalidProof();

        // Add commitment to tree and update root tracking
        _tree.insert(uint256(commitment));
        _recordRoot();

        // Insertion and its event complete before the external call (spec §4.6), so a
        // hook-bearing token cannot interleave another insertion ahead of this event and
        // diverge log-order replay from the tree.
        emit Deposit(commitment, token, amount, encryptedNote);

        // Pull tokens from the funding address bound in the proof, never from msg.sender
        IERC20(token).safeTransferFrom(fundingAddress, address(this), amount);
    }

    /// @notice Transfer notes within the shielded pool (2-in-2-out)
    /// @param proof ZK proof of valid transfer
    /// @param inputNullifiers Nullifiers for the two input notes
    /// @param outputCommitments Commitments for the two output notes
    /// @param root Commitment tree root used for the proof
    /// @param encryptedNotes Encrypted notes for viewing key holders
    function transfer(
        bytes calldata proof,
        bytes32[2] calldata inputNullifiers,
        bytes32[2] calldata outputCommitments,
        bytes32 root,
        bytes calldata encryptedNotes
    ) external nonReentrant {
        // Check nullifiers are not identical
        if (inputNullifiers[0] == inputNullifiers[1]) {
            revert IdenticalNullifiers();
        }

        // Check nullifiers haven't been spent
        if (nullifiers[inputNullifiers[0]]) revert NullifierAlreadySpent();
        if (nullifiers[inputNullifiers[1]]) revert NullifierAlreadySpent();

        // Verify root is valid (current or historical)
        if (!isKnownRoot(root)) revert InvalidRoot();

        // Build public inputs for verification
        bytes32[] memory publicInputs = new bytes32[](6);
        publicInputs[0] = inputNullifiers[0];
        publicInputs[1] = inputNullifiers[1];
        publicInputs[2] = outputCommitments[0];
        publicInputs[3] = outputCommitments[1];
        publicInputs[4] = root;
        publicInputs[5] = payloadCommitment(encryptedNotes);

        // Reject non-canonical field inputs (esp. the nullifiers) before the verifier
        // reduces them mod P_BN254; without this, n1 = n0 + P_BN254 passes the raw-bytes
        // IdenticalNullifiers guard above while aliasing n0 inside the proof.
        _requireCanonicalInputs(publicInputs);

        // Verify the transfer proof
        if (!verifier.verifyTransfer(proof, publicInputs)) {
            revert InvalidProof();
        }

        // Mark nullifiers as spent
        nullifiers[inputNullifiers[0]] = true;
        nullifiers[inputNullifiers[1]] = true;

        // Add new commitments
        _tree.insert(uint256(outputCommitments[0]));
        _tree.insert(uint256(outputCommitments[1]));
        _recordRoot();

        emit Transfer(
            inputNullifiers[0], inputNullifiers[1], outputCommitments[0], outputCommitments[1], encryptedNotes
        );
    }

    /// @notice Withdraw tokens from the shielded pool
    /// @dev No supported-token check: removing a token must not block withdrawals of existing
    /// notes (2/SHIELDED-POOL section 4.4). The proof binds the token to the note. Under a sound
    /// verifier, every note carries the token of the deposit it descends from (the transfer
    /// circuit keeps one token across all four notes), and deposits require a supported token.
    /// @param proof ZK proof of valid withdrawal
    /// @param nullifier Nullifier for the note being spent
    /// @param token ERC-20 token address
    /// @param amount Amount to withdraw
    /// @param recipient Address to receive tokens
    /// @param root Commitment tree root used for the proof
    function withdraw(
        bytes calldata proof,
        bytes32 nullifier,
        address token,
        uint256 amount,
        address recipient,
        bytes32 root
    ) external nonReentrant {
        if (amount == 0) revert ZeroAmount();
        if (amount >= MAX_AMOUNT) revert AmountTooLarge();
        if (recipient == address(0)) revert ZeroAddress();

        // Check nullifier hasn't been spent
        if (nullifiers[nullifier]) revert NullifierAlreadySpent();

        // Verify root is valid
        if (!isKnownRoot(root)) revert InvalidRoot();

        // Build public inputs for verification
        bytes32[] memory publicInputs = new bytes32[](5);
        publicInputs[0] = nullifier;
        publicInputs[1] = bytes32(uint256(uint160(token)));
        publicInputs[2] = bytes32(amount);
        publicInputs[3] = bytes32(uint256(uint160(recipient)));
        publicInputs[4] = root;

        // Reject non-canonical field inputs (esp. the nullifier) before the verifier
        // reduces them mod P_BN254, so the raw bytes32 spent-key equals the field element.
        _requireCanonicalInputs(publicInputs);

        // Verify the withdraw proof
        if (!verifier.verifyWithdraw(proof, publicInputs)) {
            revert InvalidProof();
        }

        // Mark nullifier as spent
        nullifiers[nullifier] = true;

        // Transfer tokens to recipient (checks-effects-interactions)
        IERC20(token).safeTransfer(recipient, amount);

        emit Withdraw(nullifier, recipient, token, amount);
    }

    /// @notice Add a supported token
    /// @param token ERC-20 token address to add
    function addSupportedToken(address token) external onlyOwner {
        if (token == address(0)) revert ZeroAddress();
        if (supportedTokens[token]) revert TokenAlreadySupported();

        supportedTokens[token] = true;
        emit TokenAdded(token);
    }

    /// @notice Remove a supported token
    /// @param token ERC-20 token address to remove
    function removeSupportedToken(address token) external onlyOwner {
        if (!supportedTokens[token]) revert TokenNotSupported();

        supportedTokens[token] = false;
        emit TokenRemoved(token);
    }

    /// @notice Check if a root is known (current or historical)
    /// @param root The root to check
    /// @return True if the root is valid
    function isKnownRoot(bytes32 root) public view returns (bool) {
        if (root == commitmentRoot()) return true;
        return validRoots[root];
    }

    /// @notice Propose a new verifier; it can be applied after VERIFIER_DELAY
    /// @dev A new proposal replaces any pending one and restarts the delay. The proposed
    /// address must already hold code, and its code hash is pinned so the code holders check
    /// during the delay is the code that gets installed.
    /// @param newVerifier New verifier contract address
    function proposeVerifier(address newVerifier) external onlyOwner {
        if (newVerifier == address(0)) revert ZeroAddress();
        if (newVerifier.code.length == 0) revert VerifierHasNoCode();
        uint256 applyTime = block.timestamp + VERIFIER_DELAY;
        pendingVerifier = newVerifier;
        verifierApplyTime = applyTime;
        pendingVerifierCodeHash = newVerifier.codehash;
        emit VerifierProposed(newVerifier, applyTime, newVerifier.codehash);
    }

    /// @notice Install the pending verifier once the delay has elapsed
    /// @dev Succeeds while verifierApplyTime <= block.timestamp <= verifierApplyTime +
    /// VERIFIER_APPLY_WINDOW. After that the proposal has lapsed: cancel it or re-propose.
    function applyVerifier() external onlyOwner {
        address newVerifier = pendingVerifier;
        if (newVerifier == address(0)) revert NoPendingVerifier();
        if (block.timestamp < verifierApplyTime) revert VerifierDelayNotElapsed();
        if (block.timestamp > verifierApplyTime + VERIFIER_APPLY_WINDOW) revert VerifierProposalLapsed();
        if (newVerifier.codehash != pendingVerifierCodeHash) revert VerifierCodeChanged();
        emit VerifierUpdated(address(verifier), newVerifier);
        verifier = IVerifier(newVerifier);
        delete pendingVerifier;
        delete verifierApplyTime;
        delete pendingVerifierCodeHash;
    }

    /// @notice Discard the pending verifier
    function cancelVerifier() external onlyOwner {
        address cancelled = pendingVerifier;
        if (cancelled == address(0)) revert NoPendingVerifier();
        delete pendingVerifier;
        delete verifierApplyTime;
        delete pendingVerifierCodeHash;
        emit VerifierCancelled(cancelled);
    }

    /// @notice Update the attestation registry address
    /// @param newRegistry New attestation registry address
    function setAttestationRegistry(address newRegistry) external onlyOwner {
        if (newRegistry == address(0)) revert ZeroAddress();
        emit AttestationRegistryUpdated(address(attestationRegistry), newRegistry);
        attestationRegistry = IAttestationRegistry(newRegistry);
    }

    /// @notice Transfer ownership of the contract
    /// @param newOwner Address of the new owner
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    /// @notice Commitment to an encrypted payload, as bound into deposit and transfer proofs
    /// @dev keccak256 of the payload reduced mod P_BN254 so the value is a canonical field
    /// element. The prover commits to this value as a public input; the pool recomputes it from
    /// the bytes actually submitted, so a relayer that garbles the payload cannot land the
    /// operation (spec §4.6). Withdraw carries no encrypted payload and has no such input.
    /// @param payload The encrypted note bytes as submitted
    /// @return The payload commitment
    function payloadCommitment(bytes calldata payload) public pure returns (bytes32) {
        return bytes32(uint256(keccak256(payload)) % P_BN254);
    }

    /// @notice Revert unless every public input is a canonical field element (< P_BN254)
    /// @dev Defense-in-depth for spec §4.6. The pool keys nullifiers and inserts commitments by
    /// raw bytes32, while the verifier consumes the same inputs mod P_BN254. Enforcing canonicity
    /// here makes the two encodings identical by construction, so money-integrity no longer
    /// depends on the installed verifier catching non-canonical inputs (see applyVerifier).
    /// @param publicInputs The public inputs about to be passed to the verifier
    function _requireCanonicalInputs(bytes32[] memory publicInputs) internal pure {
        for (uint256 i = 0; i < publicInputs.length; i++) {
            if (uint256(publicInputs[i]) >= P_BN254) revert PublicInputGeFieldModulus();
        }
    }

    /// @notice Record the current root in the historical window
    /// @dev Called once per operation, after its final insertion, so intermediate roots of a
    /// multi-insert operation never enter the window (2/SHIELDED-POOL section 4.4)
    function _recordRoot() internal {
        bytes32 currentRoot = commitmentRoot();

        // Evict the old root being overwritten from the valid set
        bytes32 evictedRoot = historicalRoots[historicalRootIndex];
        if (evictedRoot != bytes32(0)) {
            delete validRoots[evictedRoot];
        }

        validRoots[currentRoot] = true;
        historicalRoots[historicalRootIndex] = currentRoot;
        historicalRootIndex = (historicalRootIndex + 1) % MAX_HISTORICAL_ROOTS;
    }
}

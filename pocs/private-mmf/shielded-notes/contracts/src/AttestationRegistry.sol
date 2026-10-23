// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IAttestationRegistry} from "./interfaces/IAttestationRegistry.sol";
import {LeanIMT, LeanIMTData} from "@zk-kit/packages/lean-imt/contracts/LeanIMT.sol";
import {PoseidonT6} from "poseidon-solidity/PoseidonT6.sol";
import {AccessControl} from "@openzeppelin-contracts/access/AccessControl.sol";
import {PublicInputs} from "./PublicInputs.sol";

/// @title AttestationRegistry
/// @notice Attestations of owner values by a single attester, the transfer
///         agent. Changed from the base: one attester, set by governance under
///         the timelock; no attester-revocation tree; no contract calendar,
///         since uniform expiry dates are the agent's policy. Revocation is by
///         lapse, and raising the generation floor retires every leaf at once;
///         `revokeAttester` raises it for an attester governance stops trusting.
/// @dev The pool reads this contract; this contract never reads the pool, or
///      neither is deployable second.
contract AttestationRegistry is IAttestationRegistry, AccessControl {
    using LeanIMT for LeanIMTData;

    bytes32 public constant ATTESTER_ROLE = keccak256("ATTESTER_ROLE");
    bytes32 public constant TIMELOCK_ROLE = keccak256("TIMELOCK_ROLE");

    /// @dev One ring slot per batch, not per leaf.
    uint256 public constant MAX_HISTORICAL_ROOTS = 300;

    /// @notice The circuits' attestation tree has depth 20
    ///         (`MAX_ATTESTATION_TREE_DEPTH`, `domain.nr`). Past 2^20 leaves the
    ///         paths grow to 21 and no attestation proves against a new root, so
    ///         the registry stops there; renewals add leaves, so this bounds the
    ///         registry's life (SPEC, Attestation Registry).
    uint256 public constant MAX_ATTESTATIONS = 1 << 20;

    uint256 public immutable EPOCH_SECONDS;
    uint256 public immutable MAX_ATTESTATION_EPOCHS;
    uint256 public immutable OVERLAP_EPOCHS;
    uint256 public immutable MIN_BATCH_SIZE;

    LeanIMTData internal _attestationTree;

    bytes32[MAX_HISTORICAL_ROOTS] public historicalAttestationRoots;
    uint256 public historicalAttestationRootIndex;
    mapping(bytes32 => bool) internal _validAttestationRoots;

    address public attester;
    uint64 public currentGeneration;
    /// @notice When the last batch was issued, by any attester; 0 before the first.
    uint64 public lastIssuedAt;

    uint64 internal _minAcceptedGeneration;
    uint64 public pendingMinAcceptedGeneration;
    uint256 public minAcceptedGenerationActivationEpoch;

    event AttestationAdded(
        bytes32 indexed leaf,
        bytes32 indexed owner,
        address indexed attester,
        uint64 generation,
        uint64 issuedAt,
        uint64 expiresAt
    );
    event AttesterSet(address indexed attester);
    event AttesterRevoked(address indexed attester, bool leavesRetired);
    event MinAcceptedGenerationQueued(uint64 value, uint256 activationEpoch);

    error ZeroEpochSeconds();
    error ZeroAddress();
    error BatchTooSmall();
    error MinBatchSizeZero();
    error ExpiryOutOfInterval();
    error WrongGeneration();
    error ActivationNotFuture();
    error GenerationNotIncreasing();
    error OverlapTooLarge();
    error RegistryFull();
    error NonCanonicalOwner();
    error NoAttester();
    error TrustedUntilInFuture();

    constructor(
        uint256 epochSeconds,
        uint256 maxAttestationEpochs,
        uint256 overlapEpochs,
        uint256 minBatchSize,
        address attester_,
        address timelock
    ) {
        if (epochSeconds == 0) revert ZeroEpochSeconds();
        if (attester_ == address(0) || timelock == address(0)) revert ZeroAddress();
        if (overlapEpochs >= maxAttestationEpochs) revert OverlapTooLarge();
        if (minBatchSize == 0) revert MinBatchSizeZero();

        EPOCH_SECONDS = epochSeconds;
        MAX_ATTESTATION_EPOCHS = maxAttestationEpochs;
        OVERLAP_EPOCHS = overlapEpochs;
        MIN_BATCH_SIZE = minBatchSize;

        _grantRole(TIMELOCK_ROLE, timelock);
        // Governance can hand its own role over; without this, nobody holds the
        // role's admin and the registry's governance could never move.
        _setRoleAdmin(TIMELOCK_ROLE, TIMELOCK_ROLE);
        _setAttester(attester_);

        minAcceptedGenerationActivationEpoch = type(uint256).max;
    }

    function currentEpoch() public view returns (uint256) {
        return block.timestamp / EPOCH_SECONDS;
    }

    // ========== Attestation issuance ==========

    /// @notice One root advance for the whole batch. The registry computes
    ///         every leaf itself; a call accepting precomputed leaves could
    ///         enforce none of the checks below. The agent pads each batch to
    ///         at least `MIN_BATCH_SIZE` and uses the period's uniform expiry.
    function addAttestations(bytes32[] calldata owners, uint64 expiresAt, uint64 generation)
        external
        onlyRole(ATTESTER_ROLE)
    {
        uint256 n = owners.length;
        if (n < MIN_BATCH_SIZE) revert BatchTooSmall();
        if (_attestationTree.size + n > MAX_ATTESTATIONS) revert RegistryFull();

        _checkExpiry(expiresAt);
        _checkGeneration(generation);

        bytes32 rootBefore = attestationRoot();
        uint64 issuedAt = uint64(block.timestamp);
        lastIssuedAt = issuedAt;

        for (uint256 i = 0; i < n; i++) {
            // Poseidon reduces its inputs, so `owner + p` would hash like `owner`,
            // and clients reading the raw value from the event would reject it.
            if (uint256(owners[i]) >= PublicInputs.BN254_MODULUS) revert NonCanonicalOwner();
            bytes32 leaf = _attestationLeaf(owners[i], generation, issuedAt, expiresAt);
            _attestationTree.insert(uint256(leaf));
            emit AttestationAdded(leaf, owners[i], msg.sender, generation, issuedAt, expiresAt);
        }

        _advanceAttestationRoot(rootBefore);
    }

    /// @dev The floor keeps the registry from issuing an attestation no circuit
    ///      accepts. The ceiling keeps expiry working as revocation: an
    ///      attestation issued in epoch e is usable through epoch
    ///      e + MAX_ATTESTATION_EPOCHS + OVERLAP_EPOCHS - 1 at most.
    function _checkExpiry(uint64 expiresAt) internal view {
        uint256 epoch = currentEpoch();
        if (
            expiresAt < (epoch + 1) * EPOCH_SECONDS
                || expiresAt >= (epoch + 1 + MAX_ATTESTATION_EPOCHS + OVERLAP_EPOCHS) * EPOCH_SECONDS
        ) revert ExpiryOutOfInterval();
    }

    function _checkGeneration(uint64 generation) internal {
        uint64 gen = currentGeneration;
        if (generation != gen && generation != gen + 1) revert WrongGeneration();
        if (generation > gen) currentGeneration = generation;
    }

    /// @dev attestation_leaf = Poseidon1(owner, attester, generation, issued_at, expires_at)
    function _attestationLeaf(bytes32 owner, uint64 generation, uint64 issuedAt, uint64 expiresAt)
        internal
        view
        returns (bytes32)
    {
        return bytes32(
            PoseidonT6.hash(
                [
                    uint256(owner),
                    uint256(uint160(msg.sender)),
                    uint256(generation),
                    uint256(issuedAt),
                    uint256(expiresAt)
                ]
            )
        );
    }

    function _advanceAttestationRoot(bytes32 rootBefore) internal {
        if (rootBefore == bytes32(0)) return;

        bytes32 evicted = historicalAttestationRoots[historicalAttestationRootIndex];
        if (evicted != bytes32(0)) delete _validAttestationRoots[evicted];

        _validAttestationRoots[rootBefore] = true;
        historicalAttestationRoots[historicalAttestationRootIndex] = rootBefore;
        historicalAttestationRootIndex = (historicalAttestationRootIndex + 1) % MAX_HISTORICAL_ROOTS;
    }

    function attestationRoot() public view returns (bytes32) {
        return bytes32(_attestationTree.root());
    }

    function isKnownAttestationRoot(bytes32 attestationRoot_) external view returns (bool) {
        if (attestationRoot_ == attestationRoot()) return true;
        return _validAttestationRoots[attestationRoot_];
    }

    function getAttestationCount() external view returns (uint256) {
        return _attestationTree.size;
    }

    // ========== Governance ==========

    /// @notice Timelocked. Replaces the single attester, as part of replacing
    ///         the transfer agent (the pool's `setTransferAgent` is the other half).
    ///         It retires no leaf: in a planned replacement the outgoing
    ///         attester's leaves stay valid until they lapse, and the successor
    ///         renews them. Also installs a successor after `revokeAttester`.
    function setAttester(address newAttester) external onlyRole(TIMELOCK_ROLE) {
        if (newAttester == address(0)) revert ZeroAddress();
        _revokeRole(ATTESTER_ROLE, attester);
        _setAttester(newAttester);
    }

    function _setAttester(address newAttester) internal {
        attester = newAttester;
        _grantRole(ATTESTER_ROLE, newAttester);
        emit AttesterSet(newAttester);
    }

    /// @notice Timelocked. Removes the attester and installs none, for when
    ///         governance stops trusting it; `setAttester` installs a successor,
    ///         in the same timelock batch or later. If anything was issued after
    ///         `trustedUntil`, every leaf is retired from the next epoch: the floor
    ///         rises past the last generation issued, read here once the role is
    ///         gone, so an attester that sees this call queued cannot attest past
    ///         it. This replaces any raise still pending. A successor can attest
    ///         at the new floor at once. With nothing issued after `trustedUntil`
    ///         (a lost key, or an agent leaving), every leaf stays valid until it
    ///         lapses.
    function revokeAttester(uint64 trustedUntil) external onlyRole(TIMELOCK_ROLE) {
        address revoked = attester;
        if (revoked == address(0)) revert NoAttester();
        if (trustedUntil > block.timestamp) revert TrustedUntilInFuture();
        _revokeRole(ATTESTER_ROLE, revoked);
        attester = address(0);

        bool retire = lastIssuedAt > trustedUntil;
        if (retire) {
            uint64 floor = currentGeneration + 1;
            if (floor > minAcceptedGeneration()) _queueMinAcceptedGeneration(floor, currentEpoch() + 1);
        }
        emit AttesterRevoked(revoked, retire);
    }

    /// @notice Timelocked, future activation epoch. Retires every leaf below
    ///         `newValue` at once, so the batch call already accepts the
    ///         successor generation ahead of the cutover.
    function raiseMinAcceptedGeneration(uint64 newValue, uint256 activationEpoch) external onlyRole(TIMELOCK_ROLE) {
        if (activationEpoch <= currentEpoch()) revert ActivationNotFuture();
        if (newValue <= minAcceptedGeneration()) revert GenerationNotIncreasing();
        _queueMinAcceptedGeneration(newValue, activationEpoch);
    }

    function _queueMinAcceptedGeneration(uint64 newValue, uint256 activationEpoch) internal {
        if (
            minAcceptedGenerationActivationEpoch != type(uint256).max
                && currentEpoch() >= minAcceptedGenerationActivationEpoch
        ) {
            _minAcceptedGeneration = pendingMinAcceptedGeneration;
        }

        pendingMinAcceptedGeneration = newValue;
        minAcceptedGenerationActivationEpoch = activationEpoch;
        emit MinAcceptedGenerationQueued(newValue, activationEpoch);
    }

    function minAcceptedGeneration() public view returns (uint256) {
        if (
            minAcceptedGenerationActivationEpoch != type(uint256).max
                && currentEpoch() >= minAcceptedGenerationActivationEpoch
        ) {
            return pendingMinAcceptedGeneration;
        }
        return _minAcceptedGeneration;
    }
}

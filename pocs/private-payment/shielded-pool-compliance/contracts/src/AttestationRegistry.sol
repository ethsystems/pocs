// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IAttestationRegistry} from "./interfaces/IAttestationRegistry.sol";
import {AttesterRevocationTree, AttesterRevocationTreeData} from "./AttesterRevocationTree.sol";
import {LeanIMT, LeanIMTData} from "@zk-kit/packages/lean-imt/contracts/LeanIMT.sol";
import {PoseidonT6} from "poseidon-solidity/PoseidonT6.sol";
import {AccessControl} from "@openzeppelin-contracts/access/AccessControl.sol";
import {SafeCast} from "@openzeppelin-contracts/utils/math/SafeCast.sol";

/// @title AttestationRegistry
/// @notice KYC attestation issuance and attester revocation for the compliance
///         extension. Rewritten from the parent: batched issuance, constrained
///         calendar-uniform expiry, generation-tagged leaves, and revocation by
///         lapse rather than by leaf removal.
/// @dev The pool reads this contract; this contract never reads the pool, or
///      neither is deployable second.
contract AttestationRegistry is IAttestationRegistry, AccessControl {
    using LeanIMT for LeanIMTData;
    using AttesterRevocationTree for AttesterRevocationTreeData;

    bytes32 public constant ATTESTER_ROLE = keccak256("ATTESTER_ROLE");
    bytes32 public constant TIMELOCK_ROLE = keccak256("TIMELOCK_ROLE");

    /// @dev A gated transfer opens three attestation leaves and burns one ring
    ///      slot per batch advance, not per leaf, so this is sized against
    ///      batch-issuance frequency rather than per-leaf traffic.
    uint256 public constant MAX_HISTORICAL_ROOTS = 300;

    uint256 public immutable EPOCH_SECONDS;
    uint256 public immutable MAX_ATTESTATION_EPOCHS;
    uint256 public immutable MIN_COHORT_SIZE;
    uint256 public immutable OVERLAP_EPOCHS;

    LeanIMTData internal _attestationTree;
    AttesterRevocationTreeData internal _revocationTree;

    bytes32[MAX_HISTORICAL_ROOTS] public historicalAttestationRoots;
    uint256 public historicalAttestationRootIndex;
    mapping(bytes32 => bool) internal _validAttestationRoots;

    uint64 public currentGeneration;

    uint64 internal _minAcceptedGeneration;
    uint64 public pendingMinAcceptedGeneration;
    uint256 public minAcceptedGenerationActivationEpoch;

    event AttestationAdded(
        bytes32 indexed leaf,
        bytes32 indexed subjectPubkeyHash,
        address indexed attester,
        uint64 generation,
        uint64 issuedAt,
        uint64 expiresAt
    );
    event AttesterAdded(address indexed attester);
    event AttesterRemoved(address indexed attester);
    event AttesterRevocationLowered(address indexed attester, uint64 revokedAtEpoch);
    event MinAcceptedGenerationQueued(uint64 value, uint256 activationEpoch);

    error ZeroEpochSeconds();
    error ZeroAddress();
    error CohortTooSmall();
    error ExpiryOutOfInterval();
    error ExpiryNotOnCalendar();
    error WrongGeneration();
    error UnknownAttester();
    error RevocationNotMonotone();
    error ActivationNotFuture();
    error GenerationNotIncreasing();
    error OverlapTooLarge();
    error MinCohortSizeZero();

    constructor(
        uint256 epochSeconds,
        uint256 maxAttestationEpochs,
        uint256 minCohortSize,
        address admin,
        address timelock,
        uint256 overlapEpochs
    ) {
        if (epochSeconds == 0) revert ZeroEpochSeconds();
        if (admin == address(0) || timelock == address(0)) revert ZeroAddress();
        if (overlapEpochs >= maxAttestationEpochs) revert OverlapTooLarge();
        if (minCohortSize == 0) revert MinCohortSizeZero();

        EPOCH_SECONDS = epochSeconds;
        MAX_ATTESTATION_EPOCHS = maxAttestationEpochs;
        MIN_COHORT_SIZE = minCohortSize;
        OVERLAP_EPOCHS = overlapEpochs;

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(TIMELOCK_ROLE, timelock);

        minAcceptedGenerationActivationEpoch = type(uint256).max;
        _revocationTree.init();
    }

    function currentEpoch() public view returns (uint256) {
        return block.timestamp / EPOCH_SECONDS;
    }

    // ========== Attestation issuance ==========

    /// @notice One root advance for the whole batch. The registry computes
    ///         every leaf itself; a call accepting precomputed leaves could
    ///         enforce none of the checks below.
    function addAttestations(bytes32[] calldata subjectPubkeyHashes, uint64 expiresAt, uint64 generation)
        external
        onlyRole(ATTESTER_ROLE)
    {
        uint256 n = subjectPubkeyHashes.length;
        if (n < MIN_COHORT_SIZE) revert CohortTooSmall();

        _checkExpiry(expiresAt);
        _checkGeneration(generation);

        bytes32 rootBefore = attestationRoot();
        uint64 issuedAt = uint64(block.timestamp);

        for (uint256 i = 0; i < n; i++) {
            _issueOne(subjectPubkeyHashes[i], generation, issuedAt, expiresAt);
        }

        _advanceAttestationRoot(rootBefore);
    }

    function _checkExpiry(uint64 expiresAt) internal view {
        uint256 epoch = currentEpoch();
        if (
            expiresAt < (epoch + 1) * EPOCH_SECONDS
                || expiresAt >= (epoch + 1 + MAX_ATTESTATION_EPOCHS + OVERLAP_EPOCHS) * EPOCH_SECONDS
        ) revert ExpiryOutOfInterval();

        bool onCalendar = expiresAt == _calendarExpiry(epoch);
        if (!onCalendar && _inOverlapWindow(epoch)) {
            onCalendar = expiresAt == _nextCalendarExpiry(epoch);
        }
        if (!onCalendar) revert ExpiryNotOnCalendar();
    }

    function _checkGeneration(uint64 generation) internal {
        uint64 gen = currentGeneration;
        if (generation != gen && generation != gen + 1) revert WrongGeneration();
        if (generation > gen) currentGeneration = generation;
    }

    function _issueOne(bytes32 subjectPubkeyHash, uint64 generation, uint64 issuedAt, uint64 expiresAt) internal {
        bytes32 leaf = _attestationLeaf(subjectPubkeyHash, generation, issuedAt, expiresAt);
        _attestationTree.insert(uint256(leaf));
        emit AttestationAdded(leaf, subjectPubkeyHash, msg.sender, generation, issuedAt, expiresAt);
    }

    function _attestationLeaf(bytes32 subjectPubkeyHash, uint64 generation, uint64 issuedAt, uint64 expiresAt)
        internal
        view
        returns (bytes32)
    {
        return bytes32(
            PoseidonT6.hash(
                [
                    uint256(subjectPubkeyHash),
                    uint256(uint160(msg.sender)),
                    uint256(generation),
                    uint256(issuedAt),
                    uint256(expiresAt)
                ]
            )
        );
    }

    /// @dev `expiresAt` MUST equal the published calendar's value for the
    ///      current period so the period alone fixes it. Periods are
    ///      `MAX_ATTESTATION_EPOCHS` long with no overlap, and every calendar
    ///      value this produces sits inside the interval `addAttestations`
    ///      already checks.
    /// @dev Checked downcast: `EPOCH_SECONDS` is a constructor immutable checked only
    ///      against zero, so an absurd deployment value would otherwise truncate here
    ///      and produce a calendar value `addAttestations` would then accept.
    function _calendarExpiry(uint256 epoch) internal view returns (uint64) {
        uint256 period = epoch / MAX_ATTESTATION_EPOCHS;
        uint256 boundaryEpoch = (period + 1) * MAX_ATTESTATION_EPOCHS;
        return SafeCast.toUint64(boundaryEpoch * EPOCH_SECONDS);
    }

    function _nextCalendarExpiry(uint256 epoch) internal view returns (uint64) {
        uint256 period = epoch / MAX_ATTESTATION_EPOCHS;
        return SafeCast.toUint64((period + 2) * MAX_ATTESTATION_EPOCHS * EPOCH_SECONDS);
    }

    function _inOverlapWindow(uint256 epoch) internal view returns (bool) {
        if (OVERLAP_EPOCHS == 0) return false;
        uint256 boundary = (epoch / MAX_ATTESTATION_EPOCHS + 1) * MAX_ATTESTATION_EPOCHS;
        return epoch + OVERLAP_EPOCHS >= boundary;
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

    // ========== Attester management ==========

    /// @notice Immediate, not timelocked. Inserts the attester's initial
    ///         `type(uint64).max` pair, without which no subject of that
    ///         attester can satisfy the in-circuit gadget.
    function addAttester(address attester) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (attester == address(0)) revert ZeroAddress();
        _grantRole(ATTESTER_ROLE, attester);
        _revocationTree.insert(attester);
        emit AttesterAdded(attester);
    }

    /// @notice Immediate, not timelocked. Frees the attester's slot, so any
    ///         subject holding a witness for it can no longer prove inclusion
    ///         against the resulting `attesterRevocationRoot`.
    function removeAttester(address attester) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _revokeRole(ATTESTER_ROLE, attester);
        _revocationTree.remove(attester);
        emit AttesterRemoved(attester);
    }

    /// @notice Timelocked. `newRevokedAtEpoch` MUST be below the attester's
    ///         current value and at or above `currentEpoch()`.
    function lowerRevocation(address attester, uint64 newRevokedAtEpoch) external onlyRole(TIMELOCK_ROLE) {
        if (!_revocationTree.contains(attester)) revert UnknownAttester();

        uint64 current = _revocationTree.revokedAtEpochOf(attester);
        if (newRevokedAtEpoch >= current || newRevokedAtEpoch < currentEpoch()) revert RevocationNotMonotone();

        _revocationTree.lower(attester, newRevokedAtEpoch);
        emit AttesterRevocationLowered(attester, newRevokedAtEpoch);
    }

    function attesterRevocationRoot() external view returns (bytes32) {
        return _revocationTree.root();
    }

    function revokedAtEpoch(address attester) external view returns (uint64) {
        return _revocationTree.revokedAtEpochOf(attester);
    }

    function isAttester(address attester) external view returns (bool) {
        return _revocationTree.contains(attester);
    }

    // ========== Generation floor ==========

    /// @notice Timelocked, future activation epoch. Retires every leaf below
    ///         `newValue` at once, so the batch call already accepts the
    ///         successor generation ahead of the cutover.
    function raiseMinAcceptedGeneration(uint64 newValue, uint256 activationEpoch) external onlyRole(TIMELOCK_ROLE) {
        if (activationEpoch <= currentEpoch()) revert ActivationNotFuture();
        if (newValue <= minAcceptedGeneration()) revert GenerationNotIncreasing();

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

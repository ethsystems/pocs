// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin-contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin-contracts/token/ERC20/utils/SafeERC20.sol";
import {AccessControl} from "@openzeppelin-contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin-contracts/utils/ReentrancyGuard.sol";
import {IVerifier} from "./interfaces/IVerifier.sol";
import {IUltraVerifier} from "./interfaces/IUltraVerifier.sol";
import {IAttestationRegistry} from "./interfaces/IAttestationRegistry.sol";
import {
    PublicInputs,
    DepositPublicInputs,
    TransferPublicInputs,
    WithdrawPublicInputs,
    UngatedWithdrawPublicInputs
} from "./PublicInputs.sol";
import {LeanIMT, LeanIMTData} from "@zk-kit/packages/lean-imt/contracts/LeanIMT.sol";

/// @title ShieldedPool
/// @notice Privacy-preserving payment pool with continuous compliance coverage.
///         Extends the parent shielded pool with three gated circuits (deposit,
///         transfer, gated withdraw) that carry a compliance note alongside
///         value, plus an ungated withdraw entry point routed to a
///         blocked-funds account for parties the gated paths can no longer
///         serve.
/// @dev Every one of the five external entry points below follows the same
///      nine-step order: pause check, canonicalize, promote a due pending
///      policy, per-operation predicates, verify, mark nullifiers, insert
///      commitments, emit, then any token transfer. Insertion and the event
///      MUST both land before the token call, or a reentrant transfer hook
///      can interleave its own leaves ahead of the outer call's event; LeanIMT
///      is positional, so that divergence would be permanent.
contract ShieldedPool is AccessControl, ReentrancyGuard {
    using SafeERC20 for IERC20;
    using LeanIMT for LeanIMTData;

    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant CURATOR_ROLE = keccak256("CURATOR_ROLE");
    bytes32 public constant COMMITTEE_ROLE = keccak256("COMMITTEE_ROLE");

    /// @dev A gated transfer inserts three leaves and one ring slot is burned
    ///      per leaf, not per operation, so this is sized against
    ///      leaf-insertion frequency rather than operation count.
    uint256 public constant MAX_HISTORICAL_ROOTS = 300;

    uint8 public constant OP_DEPOSIT = 0;
    uint8 public constant OP_WITHDRAW = 1;

    uint256 public immutable EPOCH_SECONDS;
    address public immutable TOKEN;
    IAttestationRegistry public immutable attestationRegistry;
    uint256 public immutable TIMELOCK_DELAY_SECONDS;

    uint256 public immutable MAX_PAUSE_EPOCHS;
    uint256 public immutable MAX_BLOCKED_EXIT_PAUSE_EPOCHS;
    uint256 public immutable PAUSE_BUDGET_EPOCHS;
    uint256 public immutable PAUSE_WINDOW_EPOCHS;

    LeanIMTData internal _tree;
    bytes32[MAX_HISTORICAL_ROOTS] public historicalRoots;
    uint256 public historicalRootIndex;
    mapping(bytes32 => bool) internal _validRoots;

    mapping(bytes32 => bool) public nullifiers;

    address public activeVerifier;
    bytes32 public activePolicySourceHash;
    address public pendingVerifier;
    bytes32 public pendingPolicySourceHash;
    uint256 public policyActivationEpoch;

    address public ungatedWithdrawVerifier;
    address public blockedFundsAccount;
    mapping(bytes32 => uint256) public blockedBalance;
    uint256 public singleTxThreshold;
    mapping(address => bool) public blockedDestination;
    mapping(bytes32 => bool) public auditGrant;
    uint64 public committeeVersion;

    uint256 public pausedUntilEpoch;
    uint256 public blockedExitPausedUntilEpoch;
    uint256 public pauseBudgetSpent;
    uint256 public pauseWindowStart;
    bool public guardianArmed;

    event Deposit(
        bytes32 indexed commitment,
        uint256 amount,
        bytes32 indexed velocityNullifier,
        bytes32 complianceCommitment,
        bytes encryptedNotes
    );
    event Transfer(
        bytes32 indexed nullifier0,
        bytes32 indexed nullifier1,
        bytes32 commitmentOut0,
        bytes32 commitmentOut1,
        bytes32 velocityNullifier,
        bytes32 complianceCommitment,
        bytes encryptedNotes
    );
    event Withdraw(
        bytes32 indexed nullifier,
        address indexed recipient,
        uint256 amount,
        bytes32 velocityNullifier,
        bytes32 complianceCommitment,
        bytes encryptedNotes
    );
    event WithdrawBlocked(bytes32 indexed nullifier, uint256 amount);
    event SizeFlag(bytes32 indexed velocityNullifier, uint8 op, uint256 amount);
    event PolicyQueued(
        address verifier, bytes32 policySourceHash, uint256 activationEpoch, string sourceUri, bytes32 toolchainId
    );
    event PolicyActivated(address verifier, bytes32 policySourceHash);
    event PolicyCancelled();
    event UngatedWithdrawVerifierUpdated(address verifier);
    event BlockedFundsAccountUpdated(address account);
    event BlockedFundsClaimed(bytes32 indexed nullifier, uint256 amount);
    event SingleTxThresholdUpdated(uint256 value);
    event DestinationBlocked(address indexed destination, bool blocked);
    event AuditGrantRecorded(bytes32 indexed scopeCommitment);
    event CommitteeVersionSet(uint64 version, bytes32 committeeHash);
    event PausedSet(uint256 untilEpoch, bool blockedExit);

    error BlockedDestination();
    error WrongEpoch();
    error WrongToken();
    error WrongEpochSeconds();
    error WrongPolicySourceHash();
    error WrongGeneration();
    error WrongAttesterRevocationRoot();
    error UnknownRoot();
    error NullifierSpent();
    error DuplicateNullifier();
    error NotBlockedFundsAccount();
    error ContractPaused();
    error InvalidProof();
    error ZeroAmount();
    error ZeroAddress();
    error ZeroEpochSeconds();
    error EpochSecondsTooLarge();
    error ActivationNotFuture();
    error NotGuardianOrAdmin();
    error GuardianNotArmed();
    error PauseCeilingExceeded();
    error PauseBudgetExceeded();
    error BlockedExitCeilingNotShorter();
    error BlockedFundsAccountLocked();
    error BlockedFundsAccountUnset();
    error ActivationTooSoon();
    error PayloadMismatch();

    struct ConstructorParams {
        address token;
        address attestationRegistry;
        address initialVerifier;
        bytes32 initialPolicySourceHash;
        address ungatedWithdrawVerifier;
        address blockedFundsAccount;
        uint256 singleTxThreshold;
        uint256 epochSeconds;
        uint256 timelockDelaySeconds;
        uint256 maxPauseEpochs;
        uint256 maxBlockedExitPauseEpochs;
        uint256 pauseBudgetEpochs;
        uint256 pauseWindowEpochs;
        address timelockController;
        address guardian;
        address curator;
        address committee;
    }

    constructor(ConstructorParams memory p) {
        if (
            p.token == address(0) || p.attestationRegistry == address(0) || p.initialVerifier == address(0)
                || p.ungatedWithdrawVerifier == address(0) || p.blockedFundsAccount == address(0)
                || p.timelockController == address(0) || p.guardian == address(0) || p.curator == address(0)
                || p.committee == address(0)
        ) {
            revert ZeroAddress();
        }
        if (p.epochSeconds == 0) revert ZeroEpochSeconds();
        if (p.epochSeconds > block.timestamp) revert EpochSecondsTooLarge();
        if (p.maxBlockedExitPauseEpochs >= p.maxPauseEpochs) revert BlockedExitCeilingNotShorter();

        EPOCH_SECONDS = p.epochSeconds;
        TOKEN = p.token;
        attestationRegistry = IAttestationRegistry(p.attestationRegistry);
        TIMELOCK_DELAY_SECONDS = p.timelockDelaySeconds;

        MAX_PAUSE_EPOCHS = p.maxPauseEpochs;
        MAX_BLOCKED_EXIT_PAUSE_EPOCHS = p.maxBlockedExitPauseEpochs;
        PAUSE_BUDGET_EPOCHS = p.pauseBudgetEpochs;
        PAUSE_WINDOW_EPOCHS = p.pauseWindowEpochs;

        // A mutual reference would make neither contract deployable second, so the
        // pool reads the registry's value here and never the reverse.
        if (attestationRegistry.EPOCH_SECONDS() != EPOCH_SECONDS) revert WrongEpochSeconds();

        activeVerifier = p.initialVerifier;
        activePolicySourceHash = p.initialPolicySourceHash;
        policyActivationEpoch = type(uint256).max;

        ungatedWithdrawVerifier = p.ungatedWithdrawVerifier;
        blockedFundsAccount = p.blockedFundsAccount;
        singleTxThreshold = p.singleTxThreshold;

        guardianArmed = true;
        pauseWindowStart = currentEpoch();

        _grantRole(DEFAULT_ADMIN_ROLE, p.timelockController);
        _grantRole(GUARDIAN_ROLE, p.guardian);
        _grantRole(CURATOR_ROLE, p.curator);
        _grantRole(COMMITTEE_ROLE, p.committee);
    }

    function currentEpoch() public view returns (uint256) {
        return block.timestamp / EPOCH_SECONDS;
    }

    // ========== Value-preserving entry points ==========

    struct DepositParams {
        bytes proof;
        bytes32 commitment;
        uint256 token;
        uint256 amount;
        bytes32 attestationRoot;
        bytes32 velocityNullifier;
        bytes32 complianceCommitmentOut;
        uint256 epoch;
        uint256 epochSeconds;
        bytes32 policySourceHash;
        bytes32 commitmentRoot;
        bytes32 attesterRevocationRoot;
        uint256 minAcceptedGeneration;
        bytes32 payloadCommitment;
        bytes encryptedNotes;
    }

    function deposit(DepositParams calldata p) external nonReentrant {
        if (currentEpoch() < pausedUntilEpoch) revert ContractPaused();

        bytes32[] memory inputs = new bytes32[](DepositPublicInputs.LENGTH);
        inputs[DepositPublicInputs.COMMITMENT] = p.commitment;
        inputs[DepositPublicInputs.TOKEN] = bytes32(p.token);
        inputs[DepositPublicInputs.AMOUNT] = bytes32(p.amount);
        inputs[DepositPublicInputs.ATTESTATION_ROOT] = p.attestationRoot;
        inputs[DepositPublicInputs.VELOCITY_NULLIFIER] = p.velocityNullifier;
        inputs[DepositPublicInputs.COMPLIANCE_COMMITMENT_OUT] = p.complianceCommitmentOut;
        inputs[DepositPublicInputs.EPOCH] = bytes32(p.epoch);
        inputs[DepositPublicInputs.EPOCH_SECONDS] = bytes32(p.epochSeconds);
        inputs[DepositPublicInputs.POLICY_SOURCE_HASH] = p.policySourceHash;
        inputs[DepositPublicInputs.COMMITMENT_ROOT] = p.commitmentRoot;
        inputs[DepositPublicInputs.ATTESTER_REVOCATION_ROOT] = p.attesterRevocationRoot;
        inputs[DepositPublicInputs.MIN_ACCEPTED_GENERATION] = bytes32(p.minAcceptedGeneration);
        inputs[DepositPublicInputs.PAYLOAD_COMMITMENT] = p.payloadCommitment;
        PublicInputs.requireCanonical(inputs);

        _maybePromotePolicy();

        if (p.token != uint256(uint160(TOKEN))) revert WrongToken();
        if (p.amount == 0) revert ZeroAmount();
        if (p.epoch != currentEpoch()) revert WrongEpoch();
        if (p.epochSeconds != EPOCH_SECONDS) revert WrongEpochSeconds();
        if (p.policySourceHash != activePolicySourceHash) revert WrongPolicySourceHash();
        if (nullifiers[p.velocityNullifier]) revert NullifierSpent();
        if (!isKnownRoot(p.commitmentRoot)) revert UnknownRoot();
        _checkRegistry(p.attestationRoot, p.attesterRevocationRoot, p.minAcceptedGeneration);
        if (uint256(p.payloadCommitment) != uint256(keccak256(p.encryptedNotes)) % PublicInputs.BN254_MODULUS) {
            revert PayloadMismatch();
        }

        if (!IVerifier(activeVerifier).verifyDeposit(p.proof, inputs)) revert InvalidProof();

        nullifiers[p.velocityNullifier] = true;

        _insertCommitment(uint256(p.commitment));
        _insertCommitment(uint256(p.complianceCommitmentOut));

        emit Deposit(p.commitment, p.amount, p.velocityNullifier, p.complianceCommitmentOut, p.encryptedNotes);
        if (p.amount > singleTxThreshold) emit SizeFlag(p.velocityNullifier, OP_DEPOSIT, p.amount);

        // Solvency accounting assumes TOKEN transfers exactly p.amount; a
        // fee-on-transfer or rebasing token under-collateralizes the pool.
        IERC20(TOKEN).safeTransferFrom(msg.sender, address(this), p.amount);
    }

    struct TransferParams {
        bytes proof;
        bytes32 nullifier0;
        bytes32 nullifier1;
        bytes32 commitmentOut0;
        bytes32 commitmentOut1;
        bytes32 commitmentRoot;
        bytes32 velocityNullifier;
        bytes32 complianceCommitmentOut;
        uint256 epoch;
        uint256 epochSeconds;
        bytes32 policySourceHash;
        bytes32 attestationRoot;
        bytes32 attesterRevocationRoot;
        uint256 minAcceptedGeneration;
        bytes32 payloadCommitment;
        bytes encryptedNotes;
    }

    function transfer(TransferParams calldata p) external nonReentrant {
        if (currentEpoch() < pausedUntilEpoch) revert ContractPaused();

        bytes32[] memory inputs = new bytes32[](TransferPublicInputs.LENGTH);
        inputs[TransferPublicInputs.NULLIFIER_0] = p.nullifier0;
        inputs[TransferPublicInputs.NULLIFIER_1] = p.nullifier1;
        inputs[TransferPublicInputs.COMMITMENT_OUT_0] = p.commitmentOut0;
        inputs[TransferPublicInputs.COMMITMENT_OUT_1] = p.commitmentOut1;
        inputs[TransferPublicInputs.COMMITMENT_ROOT] = p.commitmentRoot;
        inputs[TransferPublicInputs.VELOCITY_NULLIFIER] = p.velocityNullifier;
        inputs[TransferPublicInputs.COMPLIANCE_COMMITMENT_OUT] = p.complianceCommitmentOut;
        inputs[TransferPublicInputs.EPOCH] = bytes32(p.epoch);
        inputs[TransferPublicInputs.EPOCH_SECONDS] = bytes32(p.epochSeconds);
        inputs[TransferPublicInputs.POLICY_SOURCE_HASH] = p.policySourceHash;
        inputs[TransferPublicInputs.ATTESTATION_ROOT] = p.attestationRoot;
        inputs[TransferPublicInputs.ATTESTER_REVOCATION_ROOT] = p.attesterRevocationRoot;
        inputs[TransferPublicInputs.MIN_ACCEPTED_GENERATION] = bytes32(p.minAcceptedGeneration);
        inputs[TransferPublicInputs.PAYLOAD_COMMITMENT] = p.payloadCommitment;
        PublicInputs.requireCanonical(inputs);

        _maybePromotePolicy();

        if (p.epoch != currentEpoch()) revert WrongEpoch();
        if (p.epochSeconds != EPOCH_SECONDS) revert WrongEpochSeconds();
        if (p.policySourceHash != activePolicySourceHash) revert WrongPolicySourceHash();
        if (p.nullifier0 == p.nullifier1 || p.nullifier0 == p.velocityNullifier || p.nullifier1 == p.velocityNullifier)
        {
            revert DuplicateNullifier();
        }
        if (nullifiers[p.nullifier0] || nullifiers[p.nullifier1] || nullifiers[p.velocityNullifier]) {
            revert NullifierSpent();
        }
        if (!isKnownRoot(p.commitmentRoot)) revert UnknownRoot();
        _checkRegistry(p.attestationRoot, p.attesterRevocationRoot, p.minAcceptedGeneration);
        if (uint256(p.payloadCommitment) != uint256(keccak256(p.encryptedNotes)) % PublicInputs.BN254_MODULUS) {
            revert PayloadMismatch();
        }

        if (!IVerifier(activeVerifier).verifyTransfer(p.proof, inputs)) revert InvalidProof();

        nullifiers[p.nullifier0] = true;
        nullifiers[p.nullifier1] = true;
        nullifiers[p.velocityNullifier] = true;

        _insertCommitment(uint256(p.commitmentOut0));
        _insertCommitment(uint256(p.commitmentOut1));
        _insertCommitment(uint256(p.complianceCommitmentOut));

        emit Transfer(
            p.nullifier0,
            p.nullifier1,
            p.commitmentOut0,
            p.commitmentOut1,
            p.velocityNullifier,
            p.complianceCommitmentOut,
            p.encryptedNotes
        );
    }

    struct WithdrawParams {
        bytes proof;
        bytes32 nullifier;
        uint256 token;
        uint256 amount;
        address recipient;
        bytes32 commitmentRoot;
        bytes32 velocityNullifier;
        bytes32 complianceCommitmentOut;
        uint256 epoch;
        uint256 epochSeconds;
        bytes32 policySourceHash;
        bytes32 attestationRoot;
        bytes32 attesterRevocationRoot;
        uint256 minAcceptedGeneration;
        bytes32 payloadCommitment;
        bytes encryptedNotes;
    }

    function withdraw(WithdrawParams calldata p) external nonReentrant {
        if (currentEpoch() < pausedUntilEpoch) revert ContractPaused();

        bytes32[] memory inputs = new bytes32[](WithdrawPublicInputs.LENGTH);
        inputs[WithdrawPublicInputs.NULLIFIER] = p.nullifier;
        inputs[WithdrawPublicInputs.TOKEN] = bytes32(p.token);
        inputs[WithdrawPublicInputs.AMOUNT] = bytes32(p.amount);
        inputs[WithdrawPublicInputs.RECIPIENT] = bytes32(uint256(uint160(p.recipient)));
        inputs[WithdrawPublicInputs.COMMITMENT_ROOT] = p.commitmentRoot;
        inputs[WithdrawPublicInputs.VELOCITY_NULLIFIER] = p.velocityNullifier;
        inputs[WithdrawPublicInputs.COMPLIANCE_COMMITMENT_OUT] = p.complianceCommitmentOut;
        inputs[WithdrawPublicInputs.EPOCH] = bytes32(p.epoch);
        inputs[WithdrawPublicInputs.EPOCH_SECONDS] = bytes32(p.epochSeconds);
        inputs[WithdrawPublicInputs.POLICY_SOURCE_HASH] = p.policySourceHash;
        inputs[WithdrawPublicInputs.ATTESTATION_ROOT] = p.attestationRoot;
        inputs[WithdrawPublicInputs.ATTESTER_REVOCATION_ROOT] = p.attesterRevocationRoot;
        inputs[WithdrawPublicInputs.MIN_ACCEPTED_GENERATION] = bytes32(p.minAcceptedGeneration);
        inputs[WithdrawPublicInputs.PAYLOAD_COMMITMENT] = p.payloadCommitment;
        PublicInputs.requireCanonical(inputs);

        _maybePromotePolicy();

        if (p.token != uint256(uint160(TOKEN))) revert WrongToken();
        if (p.amount == 0) revert ZeroAmount();
        if (p.recipient == address(0)) revert ZeroAddress();
        if (p.epoch != currentEpoch()) revert WrongEpoch();
        if (p.epochSeconds != EPOCH_SECONDS) revert WrongEpochSeconds();
        if (p.policySourceHash != activePolicySourceHash) revert WrongPolicySourceHash();
        if (p.nullifier == p.velocityNullifier) revert DuplicateNullifier();
        if (nullifiers[p.nullifier] || nullifiers[p.velocityNullifier]) revert NullifierSpent();
        if (!isKnownRoot(p.commitmentRoot)) revert UnknownRoot();
        _checkRegistry(p.attestationRoot, p.attesterRevocationRoot, p.minAcceptedGeneration);
        if (blockedDestination[p.recipient]) revert BlockedDestination();
        if (uint256(p.payloadCommitment) != uint256(keccak256(p.encryptedNotes)) % PublicInputs.BN254_MODULUS) {
            revert PayloadMismatch();
        }

        if (!IVerifier(activeVerifier).verifyWithdraw(p.proof, inputs)) revert InvalidProof();

        nullifiers[p.nullifier] = true;
        nullifiers[p.velocityNullifier] = true;

        _insertCommitment(uint256(p.complianceCommitmentOut));

        emit Withdraw(
            p.nullifier, p.recipient, p.amount, p.velocityNullifier, p.complianceCommitmentOut, p.encryptedNotes
        );
        if (p.amount > singleTxThreshold) emit SizeFlag(p.velocityNullifier, OP_WITHDRAW, p.amount);

        IERC20(TOKEN).safeTransfer(p.recipient, p.amount);
    }

    struct WithdrawBlockedParams {
        bytes proof;
        bytes32 nullifier;
        uint256 token;
        uint256 amount;
        address recipient;
        bytes32 commitmentRoot;
    }

    /// @notice The parent's unmodified ungated withdraw circuit. Applies none
    ///         of the epoch, attestation, velocity-nullifier, policy, or
    ///         destination-blocklist checks; credits `blockedBalance` instead
    ///         of transferring, so the administrator of `blockedFundsAccount`
    ///         claims it through `claimBlocked`.
    function withdrawBlocked(WithdrawBlockedParams calldata p) external nonReentrant {
        if (currentEpoch() < blockedExitPausedUntilEpoch) revert ContractPaused();

        bytes32[] memory inputs = new bytes32[](UngatedWithdrawPublicInputs.LENGTH);
        inputs[UngatedWithdrawPublicInputs.NULLIFIER] = p.nullifier;
        inputs[UngatedWithdrawPublicInputs.TOKEN] = bytes32(p.token);
        inputs[UngatedWithdrawPublicInputs.AMOUNT] = bytes32(p.amount);
        inputs[UngatedWithdrawPublicInputs.RECIPIENT] = bytes32(uint256(uint160(p.recipient)));
        inputs[UngatedWithdrawPublicInputs.COMMITMENT_ROOT] = p.commitmentRoot;
        PublicInputs.requireCanonical(inputs);

        _maybePromotePolicy();

        if (p.token != uint256(uint160(TOKEN))) revert WrongToken();
        if (p.amount == 0) revert ZeroAmount();
        if (nullifiers[p.nullifier]) revert NullifierSpent();
        if (!isKnownRoot(p.commitmentRoot)) revert UnknownRoot();
        if (blockedFundsAccount == address(0)) revert BlockedFundsAccountUnset();

        if (!IUltraVerifier(ungatedWithdrawVerifier).verify(p.proof, inputs)) revert InvalidProof();

        nullifiers[p.nullifier] = true;

        blockedBalance[p.nullifier] += p.amount;

        emit WithdrawBlocked(p.nullifier, p.amount);
    }

    /// @notice Zeroes the credited balance before transferring, and only ever
    ///         pays `blockedFundsAccount`: the exit of last resort is a claim
    ///         against one named, publicly known party.
    function claimBlocked(bytes32 nullifier) external nonReentrant {
        if (msg.sender != blockedFundsAccount) revert NotBlockedFundsAccount();

        uint256 amount = blockedBalance[nullifier];
        blockedBalance[nullifier] = 0;

        emit BlockedFundsClaimed(nullifier, amount);

        IERC20(TOKEN).safeTransfer(blockedFundsAccount, amount);
    }

    // ========== Views ==========

    function commitmentRoot() public view returns (bytes32) {
        return bytes32(_tree.root());
    }

    function getCommitmentCount() external view returns (uint256) {
        return _tree.size;
    }

    function isKnownRoot(bytes32 root_) public view returns (bool) {
        if (root_ == commitmentRoot()) return true;
        return _validRoots[root_];
    }

    /// @notice Applies the same promotion condition the entry points write on,
    ///         without writing. Between an activation epoch's start and its
    ///         first pool call the stored hash names the outgoing policy while
    ///         this view already reports the incoming one.
    function effectivePolicy() external view returns (address verifier, bytes32 sourceHash) {
        if (pendingVerifier != address(0) && currentEpoch() >= policyActivationEpoch) {
            return (pendingVerifier, pendingPolicySourceHash);
        }
        return (activeVerifier, activePolicySourceHash);
    }

    // ========== Governance ==========

    /// @notice Owner-only, timelocked queuing of the pending pair, with an
    ///         activation floor the pool enforces on top of the external
    ///         timelock. Promotes any earlier pending pair whose activation
    ///         epoch has already elapsed before installing the new one.
    ///         `cancelPolicy` is the guardian's immediate, pause-available
    ///         recourse against a queued policy.
    function setPolicy(
        address verifier,
        bytes32 sourceHash,
        uint256 activationEpoch,
        string calldata sourceUri,
        bytes32 toolchainId
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (verifier.code.length == 0) revert ZeroAddress();
        if (activationEpoch <= currentEpoch()) revert ActivationNotFuture();
        uint256 minDelayEpochs = (TIMELOCK_DELAY_SECONDS + EPOCH_SECONDS - 1) / EPOCH_SECONDS;
        if (activationEpoch < currentEpoch() + minDelayEpochs + 1) revert ActivationTooSoon();

        _maybePromotePolicy();

        pendingVerifier = verifier;
        pendingPolicySourceHash = sourceHash;
        policyActivationEpoch = activationEpoch;

        emit PolicyQueued(verifier, sourceHash, activationEpoch, sourceUri, toolchainId);
    }

    /// @notice Cancels a still-queued pending pair. Promotes any pending pair
    ///         whose activation epoch has already elapsed before cancelling,
    ///         so this can never revert an already-active policy.
    function cancelPolicy() external {
        _requireGuardianOrAdmin();

        _maybePromotePolicy();

        pendingVerifier = address(0);
        pendingPolicySourceHash = bytes32(0);
        policyActivationEpoch = type(uint256).max;

        emit PolicyCancelled();
    }

    function setUngatedWithdrawVerifier(address newVerifier) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newVerifier.code.length == 0) revert ZeroAddress();
        ungatedWithdrawVerifier = newVerifier;
        emit UngatedWithdrawVerifierUpdated(newVerifier);
    }

    /// @notice Reverts while either pause is active and for one timelock delay
    ///         after the later of the two lifts.
    function setBlockedFundsAccount(address newAccount) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newAccount == address(0)) revert ZeroAddress();

        uint256 epoch = currentEpoch();
        if (epoch < pausedUntilEpoch || epoch < blockedExitPausedUntilEpoch) revert BlockedFundsAccountLocked();

        uint256 laterLiftEpoch =
            pausedUntilEpoch > blockedExitPausedUntilEpoch ? pausedUntilEpoch : blockedExitPausedUntilEpoch;
        if (block.timestamp < laterLiftEpoch * EPOCH_SECONDS + TIMELOCK_DELAY_SECONDS) {
            revert BlockedFundsAccountLocked();
        }

        blockedFundsAccount = newAccount;
        emit BlockedFundsAccountUpdated(newAccount);
    }

    /// @notice Not timelocked. Drives only `SizeFlag`.
    function setSingleTxThreshold(uint256 newThreshold) external onlyRole(CURATOR_ROLE) {
        singleTxThreshold = newThreshold;
        emit SingleTxThresholdUpdated(newThreshold);
    }

    /// @notice Not timelocked: the blocklist is exact-current and read at
    ///         execution time.
    function setBlockedDestination(address destination, bool blocked) external onlyRole(CURATOR_ROLE) {
        blockedDestination[destination] = blocked;
        emit DestinationBlocked(destination, blocked);
    }

    function recordGrant(bytes32 scopeCommitment) external onlyRole(COMMITTEE_ROLE) {
        auditGrant[scopeCommitment] = true;
        emit AuditGrantRecorded(scopeCommitment);
    }

    function setCommittee(bytes32 committeeHash) external onlyRole(DEFAULT_ADMIN_ROLE) {
        committeeVersion += 1;
        emit CommitteeVersionSet(committeeVersion, committeeHash);
    }

    /// @notice Each pause is capped by its own ceiling, the blocked exit's
    ///         shorter, and debited against a cumulative budget that resets
    ///         every `PAUSE_WINDOW_EPOCHS`. Exhausting the budget disarms the
    ///         guardian until `rearmGuardian` runs.
    function pause(uint256 untilEpoch, bool blockedExit) external onlyRole(GUARDIAN_ROLE) {
        if (!guardianArmed) revert GuardianNotArmed();

        uint256 epoch = currentEpoch();
        uint256 ceiling = blockedExit ? MAX_BLOCKED_EXIT_PAUSE_EPOCHS : MAX_PAUSE_EPOCHS;
        if (untilEpoch <= epoch || untilEpoch - epoch > ceiling) revert PauseCeilingExceeded();

        if (epoch >= pauseWindowStart + PAUSE_WINDOW_EPOCHS) {
            pauseWindowStart = epoch;
            pauseBudgetSpent = 0;
        }

        uint256 requested = untilEpoch - epoch;
        if (pauseBudgetSpent + requested > PAUSE_BUDGET_EPOCHS) revert PauseBudgetExceeded();
        pauseBudgetSpent += requested;
        if (pauseBudgetSpent >= PAUSE_BUDGET_EPOCHS) guardianArmed = false;

        if (blockedExit) {
            blockedExitPausedUntilEpoch = untilEpoch;
        } else {
            pausedUntilEpoch = untilEpoch;
        }

        emit PausedSet(untilEpoch, blockedExit);
    }

    function rearmGuardian() external onlyRole(DEFAULT_ADMIN_ROLE) {
        guardianArmed = true;
        pauseBudgetSpent = 0;
        pauseWindowStart = currentEpoch();
    }

    // ========== Internal ==========

    function _requireGuardianOrAdmin() internal view {
        if (!hasRole(GUARDIAN_ROLE, msg.sender) && !hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            revert NotGuardianOrAdmin();
        }
    }

    /// @dev Without the non-zero guard and the sentinel, the first call after
    ///      deployment would promote an empty pending pair.
    function _maybePromotePolicy() internal {
        if (pendingVerifier != address(0) && currentEpoch() >= policyActivationEpoch) {
            activeVerifier = pendingVerifier;
            activePolicySourceHash = pendingPolicySourceHash;
            emit PolicyActivated(activeVerifier, activePolicySourceHash);

            pendingVerifier = address(0);
            pendingPolicySourceHash = bytes32(0);
            policyActivationEpoch = type(uint256).max;
        }
    }

    function _checkRegistry(bytes32 attestationRoot_, bytes32 attesterRevocationRoot_, uint256 minAcceptedGeneration_)
        internal
        view
    {
        if (!attestationRegistry.isKnownAttestationRoot(attestationRoot_)) revert UnknownRoot();
        if (attesterRevocationRoot_ != attestationRegistry.attesterRevocationRoot()) {
            revert WrongAttesterRevocationRoot();
        }
        if (minAcceptedGeneration_ != attestationRegistry.minAcceptedGeneration()) revert WrongGeneration();
    }

    function _insertCommitment(uint256 leaf) internal {
        bytes32 currentRoot = commitmentRoot();
        if (currentRoot != bytes32(0)) {
            bytes32 evicted = historicalRoots[historicalRootIndex];
            if (evicted != bytes32(0)) delete _validRoots[evicted];

            _validRoots[currentRoot] = true;
            historicalRoots[historicalRootIndex] = currentRoot;
            historicalRootIndex = (historicalRootIndex + 1) % MAX_HISTORICAL_ROOTS;
        }

        _tree.insert(leaf);
    }
}

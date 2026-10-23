// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin-contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin-contracts/token/ERC20/utils/SafeERC20.sol";
import {AccessControl} from "@openzeppelin-contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin-contracts/utils/ReentrancyGuard.sol";
import {Math} from "@openzeppelin-contracts/utils/math/Math.sol";
import {IVerifier} from "./interfaces/IVerifier.sol";
import {IAttestationRegistry} from "./interfaces/IAttestationRegistry.sol";
import {PublicInputs, DepositPublicInputs, TransferPublicInputs, WithdrawPublicInputs} from "./PublicInputs.sol";
import {LeanIMT, LeanIMTData} from "@zk-kit/packages/lean-imt/contracts/LeanIMT.sol";

/// @title ShieldedPool (shielded notes)
/// @notice Omnibus pool for one fund's permissioned share token. The pool is one
///         holder of the token; notes hold units, valued at the multiplier
///         m = floor(B * S / U), which the pool derives from its token balance
///         B and the total units U at every deposit and withdrawal.
/// @dev Every entry point follows the same order: pause check, build and
///      canonicalize the public inputs, per-operation checks, verify, mark
///      nullifiers, insert commitments, emit, then any token transfer, then the
///      multiplier check and update. Insertion and the event MUST land before
///      the token call, or a reentrant transfer hook could interleave its own
///      leaves ahead of the outer call's event; LeanIMT is positional, so that
///      divergence would be permanent. The three value-moving entry points are
///      `nonReentrant`.
contract ShieldedPool is AccessControl, ReentrancyGuard {
    using SafeERC20 for IERC20;
    using LeanIMT for LeanIMTData;

    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    uint256 public constant MAX_HISTORICAL_ROOTS = 300;

    /// @notice The epoch length the circuits hard-code (`domain.nr`); the pool
    ///         accepts no other, or attestation expiry would stop meaning time.
    uint256 public constant CIRCUIT_EPOCH_SECONDS = 86400;

    /// @notice Multiplier scale: m = S means one unit is worth one share.
    uint256 public constant S = 1e18;

    uint256 public immutable EPOCH_SECONDS;
    address public immutable TOKEN;
    IAttestationRegistry public immutable attestationRegistry;

    uint256 public immutable MAX_PAUSE_EPOCHS;
    uint256 public immutable PAUSE_BUDGET_EPOCHS;
    uint256 public immutable PAUSE_WINDOW_EPOCHS;

    LeanIMTData internal _tree;
    bytes32[MAX_HISTORICAL_ROOTS] public historicalRoots;
    uint256 public historicalRootIndex;
    mapping(bytes32 => bool) internal _validRoots;

    mapping(bytes32 => bool) public nullifiers;

    /// @notice U, the units held in all notes.
    uint256 public totalUnits;
    /// @notice m after the last deposit, withdrawal or checkpoint. A lower m
    ///         reverts a deposit or withdrawal, and halts the pool at a checkpoint.
    uint256 public lastMultiplier;
    /// @notice Set when a checkpoint finds m below lastMultiplier. Deposits and
    ///         withdrawals revert until governance clears it.
    bool public halted;

    IVerifier public verifier;
    bytes32 public claimKeyHash;
    address public transferAgent;

    uint256 public registerKeyX;
    uint256 public registerKeyY;
    uint64 public registerKeyVersion;

    uint256 public pausedUntilEpoch;
    uint256 public pauseBudgetSpent;
    uint256 public pauseWindowStart;
    bool public guardianArmed;

    event Deposit(
        bytes32 indexed commitment,
        uint64 units,
        uint256 shares,
        uint256[2] feedR,
        uint256[8] feedCt,
        bytes recipientPayload
    );
    event Transfer(
        bytes32 indexed nullifier0,
        bytes32 indexed nullifier1,
        bytes32 commitment0,
        bytes32 commitment1,
        uint256[2] feedR,
        uint256[16] feedCt,
        bytes recipientPayload
    );
    event Withdraw(bytes32 indexed nullifier, address indexed recipient, uint64 units, uint256 shares);
    event Checkpoint(uint256 epoch, uint256 balance, uint256 totalUnits, uint256 multiplier, bytes32 registerHash);
    event Halted(uint256 multiplier, uint256 lastMultiplier);
    event HaltCleared(uint256 multiplier);
    event GrantRecorded(bytes32 indexed scopeCommitment);
    event RegisterKeyRotated(uint64 version, uint256 x, uint256 y);
    event VerifierSet(address verifier);
    event ClaimKeyHashSet(bytes32 claimKeyHash);
    event TransferAgentSet(address transferAgent);
    event PausedSet(uint256 untilEpoch);
    event GuardianRearmed();

    error ContractPaused();
    error WrongEpoch();
    error InvalidFeedPoint();
    error UnknownRoot();
    error NullifierSpent();
    error DuplicateNullifier();
    error InvalidProof();
    error ZeroUnits();
    error EmptyPool();
    error ZeroAddress();
    error EpochSecondsTooLarge();
    error WrongEpochSeconds();
    error MultiplierDecreased();
    error MultiplierNotRestored();
    error UnitsChanged();
    error PoolHalted();
    error NotHalted();
    error NotTransferAgent();
    error InvalidRegisterKey();
    error WrongRegisterKeyVersion();
    error NonCanonicalClaimKeyHash();
    error GuardianNotArmed();
    error PauseCeilingExceeded();
    error PauseBudgetExceeded();
    error InvalidPauseParams();

    struct ConstructorParams {
        address token;
        address attestationRegistry;
        address verifier;
        bytes32 claimKeyHash;
        address transferAgent;
        uint256 registerKeyX;
        uint256 registerKeyY;
        uint256 epochSeconds;
        uint256 maxPauseEpochs;
        uint256 pauseBudgetEpochs;
        uint256 pauseWindowEpochs;
        address timelockController;
        address guardian;
    }

    modifier onlyTransferAgent() {
        if (msg.sender != transferAgent) revert NotTransferAgent();
        _;
    }

    constructor(ConstructorParams memory p) {
        if (
            p.token == address(0) || p.attestationRegistry == address(0) || p.verifier == address(0)
                || p.transferAgent == address(0) || p.timelockController == address(0) || p.guardian == address(0)
        ) {
            revert ZeroAddress();
        }
        if (p.epochSeconds != CIRCUIT_EPOCH_SECONDS) revert WrongEpochSeconds();
        if (p.epochSeconds > block.timestamp) revert EpochSecondsTooLarge();
        if (uint256(p.claimKeyHash) >= PublicInputs.BN254_MODULUS) revert NonCanonicalClaimKeyHash();
        if (!PublicInputs.onGrumpkin(p.registerKeyX, p.registerKeyY)) revert InvalidRegisterKey();
        // A zero window would reset the budget at every pause, and a budget that
        // fills the window would let the guardian keep the pool paused.
        if (
            p.maxPauseEpochs == 0 || p.maxPauseEpochs > p.pauseBudgetEpochs
                || p.pauseBudgetEpochs >= p.pauseWindowEpochs
        ) revert InvalidPauseParams();

        EPOCH_SECONDS = p.epochSeconds;
        TOKEN = p.token;
        attestationRegistry = IAttestationRegistry(p.attestationRegistry);
        MAX_PAUSE_EPOCHS = p.maxPauseEpochs;
        PAUSE_BUDGET_EPOCHS = p.pauseBudgetEpochs;
        PAUSE_WINDOW_EPOCHS = p.pauseWindowEpochs;

        // A mutual reference would make neither contract deployable second, so the
        // pool reads the registry's value here and never the reverse.
        if (attestationRegistry.EPOCH_SECONDS() != EPOCH_SECONDS) revert WrongEpochSeconds();

        verifier = IVerifier(p.verifier);
        claimKeyHash = p.claimKeyHash;
        transferAgent = p.transferAgent;
        registerKeyX = p.registerKeyX;
        registerKeyY = p.registerKeyY;
        lastMultiplier = S;

        guardianArmed = true;
        pauseWindowStart = currentEpoch();

        _grantRole(DEFAULT_ADMIN_ROLE, p.timelockController);
        _grantRole(GUARDIAN_ROLE, p.guardian);
    }

    function currentEpoch() public view returns (uint256) {
        return block.timestamp / EPOCH_SECONDS;
    }

    // ========== Value-moving entry points ==========

    struct DepositParams {
        bytes proof;
        bytes32 commitment;
        uint64 units;
        bytes32 attestationRoot;
        uint256 epoch;
        uint256[2] feedR;
        uint256[8] feedCt;
        bytes recipientPayload;
    }

    /// @notice Mints one note for the owner value the proof names and pulls
    ///         ceil(units * m / S) shares from the caller. What ties the two is
    ///         the owner's plan signature, which names the caller as the
    ///         funding address. The funding address, token, chain, pool,
    ///         generation floor and register key are filled in from state, so a
    ///         proof built for any other value fails.
    function deposit(DepositParams calldata p) external nonReentrant {
        _requireNotPaused();

        bytes32[] memory inputs = new bytes32[](DepositPublicInputs.LENGTH);
        inputs[DepositPublicInputs.COMMITMENT] = p.commitment;
        inputs[DepositPublicInputs.TOKEN] = bytes32(uint256(uint160(TOKEN)));
        inputs[DepositPublicInputs.UNITS] = bytes32(uint256(p.units));
        inputs[DepositPublicInputs.FUNDING_ADDRESS] = bytes32(uint256(uint160(msg.sender)));
        inputs[DepositPublicInputs.ATTESTATION_ROOT] = p.attestationRoot;
        inputs[DepositPublicInputs.MIN_ACCEPTED_GENERATION] = bytes32(attestationRegistry.minAcceptedGeneration());
        inputs[DepositPublicInputs.EPOCH] = bytes32(p.epoch);
        inputs[DepositPublicInputs.CHAIN_ID] = bytes32(block.chainid);
        inputs[DepositPublicInputs.POOL] = bytes32(uint256(uint160(address(this))));
        inputs[DepositPublicInputs.REGISTER_KEY_X] = bytes32(registerKeyX);
        inputs[DepositPublicInputs.REGISTER_KEY_Y] = bytes32(registerKeyY);
        inputs[DepositPublicInputs.FEED_R_X] = bytes32(p.feedR[0]);
        inputs[DepositPublicInputs.FEED_R_Y] = bytes32(p.feedR[1]);
        for (uint256 i = 0; i < p.feedCt.length; i++) {
            inputs[DepositPublicInputs.FEED_CT + i] = bytes32(p.feedCt[i]);
        }
        inputs[DepositPublicInputs.PAYLOAD_COMMITMENT] = PublicInputs.payloadCommitment(p.recipientPayload);
        PublicInputs.requireCanonical(inputs);

        if (p.units == 0) revert ZeroUnits();
        // An empty pool's first deposit is the transfer agent's, so no holder
        // can be the only one in it, donate shares, and leave m inflated for
        // good (SPEC, Multiplier Rules). The agent's seed then keeps U above 0.
        if (totalUnits == 0 && msg.sender != transferAgent) revert EmptyPool();
        _checkEpoch(p.epoch);
        _checkFeedPoint(p.feedR);
        if (!attestationRegistry.isKnownAttestationRoot(p.attestationRoot)) revert UnknownRoot();
        uint256 m = _checkedMultiplier();

        if (!verifier.verifyDeposit(p.proof, inputs)) revert InvalidProof();

        _tree.insert(uint256(p.commitment));
        _recordRoot();
        totalUnits += p.units;

        uint256 shares = Math.mulDiv(p.units, m, S, Math.Rounding.Ceil);
        emit Deposit(p.commitment, p.units, shares, p.feedR, p.feedCt, p.recipientPayload);

        IERC20(TOKEN).safeTransferFrom(msg.sender, address(this), shares);
        _settleMultiplier(m);
    }

    struct TransferParams {
        bytes proof;
        bytes32 nullifier0;
        bytes32 nullifier1;
        bytes32 commitmentOut0;
        bytes32 commitmentOut1;
        bytes32 commitmentRoot;
        bytes32 attestationRoot;
        uint256 epoch;
        uint256[2] feedR;
        uint256[16] feedCt;
        bytes recipientPayload;
    }

    /// @notice Spends two notes and creates two, on either the owner path or the
    ///         claim path; the proof does not say which. Moves no shares, so it
    ///         works while the multiplier is halted.
    function transfer(TransferParams calldata p) external nonReentrant {
        _requireNotPaused();

        bytes32[] memory inputs = new bytes32[](TransferPublicInputs.LENGTH);
        inputs[TransferPublicInputs.NULLIFIER_0] = p.nullifier0;
        inputs[TransferPublicInputs.NULLIFIER_1] = p.nullifier1;
        inputs[TransferPublicInputs.COMMITMENT_OUT_0] = p.commitmentOut0;
        inputs[TransferPublicInputs.COMMITMENT_OUT_1] = p.commitmentOut1;
        inputs[TransferPublicInputs.COMMITMENT_ROOT] = p.commitmentRoot;
        inputs[TransferPublicInputs.ATTESTATION_ROOT] = p.attestationRoot;
        inputs[TransferPublicInputs.MIN_ACCEPTED_GENERATION] = bytes32(attestationRegistry.minAcceptedGeneration());
        inputs[TransferPublicInputs.EPOCH] = bytes32(p.epoch);
        inputs[TransferPublicInputs.CHAIN_ID] = bytes32(block.chainid);
        inputs[TransferPublicInputs.POOL] = bytes32(uint256(uint160(address(this))));
        inputs[TransferPublicInputs.CLAIM_KEY_HASH] = claimKeyHash;
        inputs[TransferPublicInputs.REGISTER_KEY_X] = bytes32(registerKeyX);
        inputs[TransferPublicInputs.REGISTER_KEY_Y] = bytes32(registerKeyY);
        inputs[TransferPublicInputs.FEED_R_X] = bytes32(p.feedR[0]);
        inputs[TransferPublicInputs.FEED_R_Y] = bytes32(p.feedR[1]);
        for (uint256 i = 0; i < p.feedCt.length; i++) {
            inputs[TransferPublicInputs.FEED_CT + i] = bytes32(p.feedCt[i]);
        }
        inputs[TransferPublicInputs.PAYLOAD_COMMITMENT] = PublicInputs.payloadCommitment(p.recipientPayload);
        PublicInputs.requireCanonical(inputs);

        _checkEpoch(p.epoch);
        _checkFeedPoint(p.feedR);
        if (p.nullifier0 == p.nullifier1) revert DuplicateNullifier();
        if (nullifiers[p.nullifier0] || nullifiers[p.nullifier1]) revert NullifierSpent();
        if (!isKnownRoot(p.commitmentRoot)) revert UnknownRoot();
        if (!attestationRegistry.isKnownAttestationRoot(p.attestationRoot)) revert UnknownRoot();

        if (!verifier.verifyTransfer(p.proof, inputs)) revert InvalidProof();

        nullifiers[p.nullifier0] = true;
        nullifiers[p.nullifier1] = true;

        _tree.insert(uint256(p.commitmentOut0));
        _tree.insert(uint256(p.commitmentOut1));
        _recordRoot();

        emit Transfer(
            p.nullifier0, p.nullifier1, p.commitmentOut0, p.commitmentOut1, p.feedR, p.feedCt, p.recipientPayload
        );
    }

    struct WithdrawParams {
        bytes proof;
        bytes32 nullifier;
        uint64 units;
        address recipient;
        bytes32 commitmentRoot;
        bytes32 attestationRoot;
        uint256 epoch;
    }

    /// @notice Spends one whole note and pays floor(units * m / S) shares to
    ///         `recipient`. The public token's compliance applies to it.
    function withdraw(WithdrawParams calldata p) external nonReentrant {
        _requireNotPaused();

        bytes32[] memory inputs = new bytes32[](WithdrawPublicInputs.LENGTH);
        inputs[WithdrawPublicInputs.NULLIFIER] = p.nullifier;
        inputs[WithdrawPublicInputs.TOKEN] = bytes32(uint256(uint160(TOKEN)));
        inputs[WithdrawPublicInputs.UNITS] = bytes32(uint256(p.units));
        inputs[WithdrawPublicInputs.RECIPIENT] = bytes32(uint256(uint160(p.recipient)));
        inputs[WithdrawPublicInputs.COMMITMENT_ROOT] = p.commitmentRoot;
        inputs[WithdrawPublicInputs.ATTESTATION_ROOT] = p.attestationRoot;
        inputs[WithdrawPublicInputs.MIN_ACCEPTED_GENERATION] = bytes32(attestationRegistry.minAcceptedGeneration());
        inputs[WithdrawPublicInputs.EPOCH] = bytes32(p.epoch);
        inputs[WithdrawPublicInputs.CHAIN_ID] = bytes32(block.chainid);
        inputs[WithdrawPublicInputs.POOL] = bytes32(uint256(uint160(address(this))));
        PublicInputs.requireCanonical(inputs);

        if (p.units == 0) revert ZeroUnits();
        if (p.recipient == address(0)) revert ZeroAddress();
        _checkEpoch(p.epoch);
        if (nullifiers[p.nullifier]) revert NullifierSpent();
        if (!isKnownRoot(p.commitmentRoot)) revert UnknownRoot();
        if (!attestationRegistry.isKnownAttestationRoot(p.attestationRoot)) revert UnknownRoot();
        uint256 m = _checkedMultiplier();

        if (!verifier.verifyWithdraw(p.proof, inputs)) revert InvalidProof();

        nullifiers[p.nullifier] = true;
        totalUnits -= p.units;

        uint256 shares = Math.mulDiv(p.units, m, S);
        emit Withdraw(p.nullifier, p.recipient, p.units, shares);

        IERC20(TOKEN).safeTransfer(p.recipient, shares);
        _settleMultiplier(m);
    }

    // ========== Transfer agent ==========

    /// @notice Daily reconciliation: the agent has rebuilt its register from the
    ///         feed and the nullifier set and checked its units total against U.
    ///         `expectedUnits` is U in that snapshot: a deposit or withdrawal
    ///         landing in between would pair the hash with other totals, so the
    ///         checkpoint reverts and the agent takes a new snapshot.
    function checkpoint(bytes32 registerHash, uint256 expectedUnits) external onlyTransferAgent {
        if (totalUnits != expectedUnits) revert UnitsChanged();
        uint256 m = multiplier();
        emit Checkpoint(currentEpoch(), IERC20(TOKEN).balanceOf(address(this)), totalUnits, m, registerHash);
        if (m < lastMultiplier) {
            if (!halted) {
                halted = true;
                emit Halted(m, lastMultiplier);
            }
        } else {
            lastMultiplier = m;
        }
    }

    /// @notice Logs a disclosure made under a mandate; the scope stays a
    ///         commitment, opened off-chain.
    function recordGrant(bytes32 scopeCommitment) external onlyTransferAgent {
        emit GrantRecorded(scopeCommitment);
    }

    /// @notice Rotates the register key at once. Proofs built for the old key
    ///         then fail, and wallets rebuild them.
    function setRegisterKey(uint256 x, uint256 y, uint64 version) external onlyTransferAgent {
        if (version != registerKeyVersion + 1) revert WrongRegisterKeyVersion();
        if (!PublicInputs.onGrumpkin(x, y)) revert InvalidRegisterKey();
        registerKeyX = x;
        registerKeyY = y;
        registerKeyVersion = version;
        emit RegisterKeyRotated(version, x, y);
    }

    // ========== Views ==========

    /// @notice m = floor(B * S / U). While U = 0, m is `lastMultiplier`: S
    ///         before the first deposit, and the last value recorded if the
    ///         pool is ever emptied.
    function multiplier() public view returns (uint256) {
        if (totalUnits == 0) return lastMultiplier;
        return Math.mulDiv(IERC20(TOKEN).balanceOf(address(this)), S, totalUnits);
    }

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

    // ========== Governance ==========

    /// @notice Timelocked. Lifts a halt once m is back at lastMultiplier, which
    ///         nothing lowers while the pool is halted. The pool cannot tell
    ///         returned shares from yield, so whether the missing shares came
    ///         back is governance's check before it proposes this call; clearing
    ///         once yield alone has restored m accepts the loss as forgone yield.
    ///         A loss during the timelock delay, or a total loss, keeps the pool
    ///         halted; accepting a loss pro rata is a Future Extension of the SPEC.
    function clearHalt() external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (!halted) revert NotHalted();
        if (multiplier() < lastMultiplier) revert MultiplierNotRestored();
        halted = false;
        uint256 m = multiplier();
        lastMultiplier = m;
        emit HaltCleared(m);
    }

    function setVerifier(address newVerifier) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newVerifier.code.length == 0) revert ZeroAddress();
        verifier = IVerifier(newVerifier);
        emit VerifierSet(newVerifier);
    }

    /// @notice Timelocked. Poseidon1 of the claim key's four 128-bit limbs.
    function setClaimKeyHash(bytes32 newClaimKeyHash) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (uint256(newClaimKeyHash) >= PublicInputs.BN254_MODULUS) revert NonCanonicalClaimKeyHash();
        claimKeyHash = newClaimKeyHash;
        emit ClaimKeyHashSet(newClaimKeyHash);
    }

    /// @notice Timelocked. One half of replacing the transfer agent; the other
    ///         is the registry's `setAttester`.
    function setTransferAgent(address newTransferAgent) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newTransferAgent == address(0)) revert ZeroAddress();
        transferAgent = newTransferAgent;
        emit TransferAgentSet(newTransferAgent);
    }

    /// @notice Each pause is capped by `MAX_PAUSE_EPOCHS` and debited against a
    ///         cumulative budget that resets every `PAUSE_WINDOW_EPOCHS`.
    ///         Exhausting the budget disarms the guardian until `rearmGuardian`.
    ///         A pause stops claims too, since a claim is a transfer.
    function pause(uint256 untilEpoch) external onlyRole(GUARDIAN_ROLE) {
        if (!guardianArmed) revert GuardianNotArmed();

        uint256 epoch = currentEpoch();
        if (untilEpoch <= epoch || untilEpoch - epoch > MAX_PAUSE_EPOCHS) revert PauseCeilingExceeded();

        if (epoch >= pauseWindowStart + PAUSE_WINDOW_EPOCHS) {
            pauseWindowStart = epoch;
            pauseBudgetSpent = 0;
        }

        uint256 requested = untilEpoch - epoch;
        if (pauseBudgetSpent + requested > PAUSE_BUDGET_EPOCHS) revert PauseBudgetExceeded();
        pauseBudgetSpent += requested;
        if (pauseBudgetSpent >= PAUSE_BUDGET_EPOCHS) guardianArmed = false;

        pausedUntilEpoch = untilEpoch;
        emit PausedSet(untilEpoch);
    }

    function rearmGuardian() external onlyRole(DEFAULT_ADMIN_ROLE) {
        guardianArmed = true;
        pauseBudgetSpent = 0;
        pauseWindowStart = currentEpoch();
        emit GuardianRearmed();
    }

    // ========== Internal ==========

    function _requireNotPaused() internal view {
        if (currentEpoch() < pausedUntilEpoch) revert ContractPaused();
    }

    /// @dev The plan's expiry is private; the circuit checks it against this
    ///      epoch, so pinning the epoch also bounds the expiry.
    function _checkEpoch(uint256 epoch) internal view {
        if (epoch != currentEpoch()) revert WrongEpoch();
    }

    /// @dev The circuit already rejects R at infinity and derives R on the
    ///      curve; this is the cheap on-chain form of the same rule.
    function _checkFeedPoint(uint256[2] calldata feedR) internal pure {
        if (!PublicInputs.onGrumpkin(feedR[0], feedR[1])) revert InvalidFeedPoint();
    }

    /// @dev m only falls if shares leave the pool other than by withdrawal, which
    ///      the public token's exemption of the pool prevents (SPEC, Multiplier
    ///      Rules). A deposit or withdrawal that finds it fallen reverts, which
    ///      records nothing; a checkpoint that finds it sets `halted`, which
    ///      keeps both reverting even after later yield raises m again, until
    ///      governance clears it.
    function _checkedMultiplier() internal view returns (uint256 m) {
        if (halted) revert PoolHalted();
        m = multiplier();
        if (m < lastMultiplier) revert MultiplierDecreased();
    }

    /// @dev After the token call. Moving exactly the shares asked for cannot
    ///      lower m (deposits round up, withdrawals down), so a lower m means
    ///      the token also moved shares out of the pool during the call, through
    ///      a hook or an upgrade. Storing that m as the baseline would hide the
    ///      loss from every later check; reverting undoes the outflow too. With
    ///      no units left, m is undefined and keeps its last value.
    function _settleMultiplier(uint256 m) internal {
        uint256 mAfter = multiplier();
        if (totalUnits != 0 && mAfter < m) revert MultiplierDecreased();
        lastMultiplier = mAfter;
    }

    /// @dev Called once per operation, after its final insert, so intermediate
    ///      roots never enter the window (parent spec, 2/SHIELDED-POOL 4.4).
    function _recordRoot() internal {
        bytes32 currentRoot = commitmentRoot();
        bytes32 evicted = historicalRoots[historicalRootIndex];
        if (evicted != bytes32(0)) delete _validRoots[evicted];

        _validRoots[currentRoot] = true;
        historicalRoots[historicalRootIndex] = currentRoot;
        historicalRootIndex = (historicalRootIndex + 1) % MAX_HISTORICAL_ROOTS;
    }
}

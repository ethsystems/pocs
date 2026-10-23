#!/usr/bin/env python3
"""Check-removal check for the shielded-notes contracts.

Removes or weakens one check at a time in a copy of the Foundry project, runs
`forge test`, and reports each mutation:

  KILLED     some test failed: the check is guarded
  SURVIVED   every test passed: removing the check goes unnoticed
  INVALID    the mutated contract does not compile
  ANCHOR?    the source text was not found: update MUTATIONS

Every check whose removal matters should be KILLED. EXPECTED_SURVIVORS lists
the ones that may survive and why. The script exits non-zero on any other
survivor, an invalid mutation or a missing anchor.

Each mutation is located by its exact source text, so editing a contract can
break an anchor; the script then reports ANCHOR? rather than passing. Update
MUTATIONS together with the contracts.

Usage: python3 scripts/mutate-contracts.py [scratch dir]
Defaults: a temporary directory. Takes several minutes; forge is taken from
$FORGE_PATH or ~/.foundry/bin.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
WORK = sys.argv[1] if len(sys.argv) > 1 else tempfile.mkdtemp(prefix="sn-contract-mutants-")
FORGE = os.environ.get("FORGE_PATH", os.path.expanduser("~/.foundry/bin/forge"))


def drop_line(line):
    def f(text):
        return text.replace(line + "\n", "", 1)
    return line, f


def swap(old, new):
    def f(text):
        return text.replace(old, new, 1)
    return old, f


P = "contracts/src/ShieldedPool.sol"
R = "contracts/src/AttestationRegistry.sol"
C = "contracts/src/CompositeVerifier.sol"
I = "contracts/src/PublicInputs.sol"

DEPOSIT_EFFECTS = (
    "        _tree.insert(uint256(p.commitment));\n"
    "        _recordRoot();\n"
    "        totalUnits += p.units;\n"
    "\n"
    "        uint256 shares = Math.mulDiv(p.units, m, S, Math.Rounding.Ceil);\n"
    "        emit Deposit(p.commitment, p.units, shares, p.feedR, p.feedCt, p.recipientPayload);\n"
    "\n"
    "        IERC20(TOKEN).safeTransferFrom(msg.sender, address(this), shares);\n"
)
WITHDRAW_EFFECTS = (
    "        nullifiers[p.nullifier] = true;\n"
    "        totalUnits -= p.units;\n"
    "\n"
    "        uint256 shares = Math.mulDiv(p.units, m, S);\n"
    "        emit Withdraw(p.nullifier, p.recipient, p.units, shares);\n"
    "\n"
    "        IERC20(TOKEN).safeTransfer(p.recipient, shares);\n"
)

MUTATIONS = [
    # deposit
    ("D pause", P, swap(
        "    function deposit(DepositParams calldata p) external nonReentrant {\n        _requireNotPaused();\n",
        "    function deposit(DepositParams calldata p) external nonReentrant {\n")),
    ("D canonical inputs", P, swap(
        "        PublicInputs.requireCanonical(inputs);\n\n        if (p.units == 0) revert ZeroUnits();\n        // An empty pool",
        "        if (p.units == 0) revert ZeroUnits();\n        // An empty pool")),
    ("D zero units", P, swap(
        "        if (p.units == 0) revert ZeroUnits();\n        // An empty pool",
        "        // An empty pool")),
    ("D empty pool takes the agent's deposit only", P, drop_line(
        "        if (totalUnits == 0 && msg.sender != transferAgent) revert EmptyPool();")),
    ("D epoch", P, swap(
        "revert EmptyPool();\n        _checkEpoch(p.epoch);\n",
        "revert EmptyPool();\n")),
    ("D feed point", P, swap(
        "        _checkFeedPoint(p.feedR);\n        if (!attestationRegistry",
        "        if (!attestationRegistry")),
    ("D attestation root", P, swap(
        "        if (!attestationRegistry.isKnownAttestationRoot(p.attestationRoot)) revert UnknownRoot();\n"
        "        uint256 m = _checkedMultiplier();\n\n        if (!verifier.verifyDeposit",
        "        uint256 m = _checkedMultiplier();\n\n        if (!verifier.verifyDeposit")),
    ("D multiplier before", P, swap(
        "        uint256 m = _checkedMultiplier();\n\n        if (!verifier.verifyDeposit",
        "        uint256 m = multiplier();\n\n        if (!verifier.verifyDeposit")),
    ("D verify", P, drop_line("        if (!verifier.verifyDeposit(p.proof, inputs)) revert InvalidProof();")),
    ("D rounds up", P, swap("Math.mulDiv(p.units, m, S, Math.Rounding.Ceil)", "Math.mulDiv(p.units, m, S)")),
    ("D token call before notes and event", P, swap(DEPOSIT_EFFECTS,
        "        uint256 shares = Math.mulDiv(p.units, m, S, Math.Rounding.Ceil);\n"
        "        IERC20(TOKEN).safeTransferFrom(msg.sender, address(this), shares);\n"
        "        _tree.insert(uint256(p.commitment));\n"
        "        _recordRoot();\n"
        "        totalUnits += p.units;\n"
        "        emit Deposit(p.commitment, p.units, shares, p.feedR, p.feedCt, p.recipientPayload);\n")),
    ("D token call before notes only", P, swap(DEPOSIT_EFFECTS,
        "        uint256 shares = Math.mulDiv(p.units, m, S, Math.Rounding.Ceil);\n"
        "        emit Deposit(p.commitment, p.units, shares, p.feedR, p.feedCt, p.recipientPayload);\n"
        "        IERC20(TOKEN).safeTransferFrom(msg.sender, address(this), shares);\n"
        "        _tree.insert(uint256(p.commitment));\n"
        "        _recordRoot();\n"
        "        totalUnits += p.units;\n")),
    ("D multiplier after unchecked", P, swap(
        "        IERC20(TOKEN).safeTransferFrom(msg.sender, address(this), shares);\n        _settleMultiplier(m);",
        "        IERC20(TOKEN).safeTransferFrom(msg.sender, address(this), shares);\n        lastMultiplier = multiplier();")),
    # transfer
    ("T pause", P, swap(
        "    function transfer(TransferParams calldata p) external nonReentrant {\n        _requireNotPaused();\n",
        "    function transfer(TransferParams calldata p) external nonReentrant {\n")),
    ("T canonical inputs", P, swap(
        "        PublicInputs.requireCanonical(inputs);\n\n        _checkEpoch(p.epoch);\n        _checkFeedPoint(p.feedR);\n        if (p.nullifier0",
        "        _checkEpoch(p.epoch);\n        _checkFeedPoint(p.feedR);\n        if (p.nullifier0")),
    ("T epoch", P, swap(
        "        _checkEpoch(p.epoch);\n        _checkFeedPoint(p.feedR);\n        if (p.nullifier0",
        "        _checkFeedPoint(p.feedR);\n        if (p.nullifier0")),
    ("T feed point", P, swap(
        "        _checkFeedPoint(p.feedR);\n        if (p.nullifier0",
        "        if (p.nullifier0")),
    ("T duplicate nullifier", P, drop_line("        if (p.nullifier0 == p.nullifier1) revert DuplicateNullifier();")),
    ("T spent nullifier", P, drop_line("        if (nullifiers[p.nullifier0] || nullifiers[p.nullifier1]) revert NullifierSpent();")),
    ("T spent check on the second nullifier", P, swap(
        "if (nullifiers[p.nullifier0] || nullifiers[p.nullifier1]) revert NullifierSpent();",
        "if (nullifiers[p.nullifier0]) revert NullifierSpent();")),
    ("T commitment root", P, swap(
        "        if (!isKnownRoot(p.commitmentRoot)) revert UnknownRoot();\n"
        "        if (!attestationRegistry.isKnownAttestationRoot(p.attestationRoot)) revert UnknownRoot();\n\n"
        "        if (!verifier.verifyTransfer",
        "        if (!attestationRegistry.isKnownAttestationRoot(p.attestationRoot)) revert UnknownRoot();\n\n"
        "        if (!verifier.verifyTransfer")),
    ("T attestation root", P, swap(
        "        if (!attestationRegistry.isKnownAttestationRoot(p.attestationRoot)) revert UnknownRoot();\n\n"
        "        if (!verifier.verifyTransfer",
        "        if (!verifier.verifyTransfer")),
    ("T verify", P, drop_line("        if (!verifier.verifyTransfer(p.proof, inputs)) revert InvalidProof();")),
    ("T mark nullifier 0", P, drop_line("        nullifiers[p.nullifier0] = true;")),
    ("T mark nullifier 1", P, drop_line("        nullifiers[p.nullifier1] = true;")),
    # withdraw
    ("W pause", P, swap(
        "    function withdraw(WithdrawParams calldata p) external nonReentrant {\n        _requireNotPaused();\n",
        "    function withdraw(WithdrawParams calldata p) external nonReentrant {\n")),
    ("W canonical inputs", P, swap(
        "        PublicInputs.requireCanonical(inputs);\n\n        if (p.units == 0) revert ZeroUnits();\n        if (p.recipient",
        "        if (p.units == 0) revert ZeroUnits();\n        if (p.recipient")),
    ("W zero units", P, swap(
        "        if (p.units == 0) revert ZeroUnits();\n        if (p.recipient",
        "        if (p.recipient")),
    ("W zero recipient", P, drop_line("        if (p.recipient == address(0)) revert ZeroAddress();")),
    ("W epoch", P, swap(
        "        if (p.recipient == address(0)) revert ZeroAddress();\n        _checkEpoch(p.epoch);\n",
        "        if (p.recipient == address(0)) revert ZeroAddress();\n")),
    ("W spent nullifier", P, drop_line("        if (nullifiers[p.nullifier]) revert NullifierSpent();")),
    ("W commitment root", P, swap(
        "        if (!isKnownRoot(p.commitmentRoot)) revert UnknownRoot();\n"
        "        if (!attestationRegistry.isKnownAttestationRoot(p.attestationRoot)) revert UnknownRoot();\n"
        "        uint256 m",
        "        if (!attestationRegistry.isKnownAttestationRoot(p.attestationRoot)) revert UnknownRoot();\n"
        "        uint256 m")),
    ("W attestation root", P, swap(
        "        if (!attestationRegistry.isKnownAttestationRoot(p.attestationRoot)) revert UnknownRoot();\n"
        "        uint256 m = _checkedMultiplier();\n\n        if (!verifier.verifyWithdraw",
        "        uint256 m = _checkedMultiplier();\n\n        if (!verifier.verifyWithdraw")),
    ("W multiplier before", P, swap(
        "        uint256 m = _checkedMultiplier();\n\n        if (!verifier.verifyWithdraw",
        "        uint256 m = multiplier();\n\n        if (!verifier.verifyWithdraw")),
    ("W verify", P, drop_line("        if (!verifier.verifyWithdraw(p.proof, inputs)) revert InvalidProof();")),
    ("W mark nullifier", P, drop_line("        nullifiers[p.nullifier] = true;")),
    ("W rounds down", P, swap("Math.mulDiv(p.units, m, S);", "Math.mulDiv(p.units, m, S, Math.Rounding.Ceil);")),
    ("W token call before event", P, swap(WITHDRAW_EFFECTS,
        "        nullifiers[p.nullifier] = true;\n"
        "        totalUnits -= p.units;\n"
        "        uint256 shares = Math.mulDiv(p.units, m, S);\n"
        "        IERC20(TOKEN).safeTransfer(p.recipient, shares);\n"
        "        emit Withdraw(p.nullifier, p.recipient, p.units, shares);\n")),
    ("W token call before notes", P, swap(WITHDRAW_EFFECTS,
        "        uint256 shares = Math.mulDiv(p.units, m, S);\n"
        "        emit Withdraw(p.nullifier, p.recipient, p.units, shares);\n"
        "        IERC20(TOKEN).safeTransfer(p.recipient, shares);\n"
        "        nullifiers[p.nullifier] = true;\n"
        "        totalUnits -= p.units;\n")),
    ("W multiplier after unchecked", P, swap(
        "        IERC20(TOKEN).safeTransfer(p.recipient, shares);\n        _settleMultiplier(m);",
        "        IERC20(TOKEN).safeTransfer(p.recipient, shares);\n        lastMultiplier = multiplier();")),
    # the multiplier after the token call
    ("M after-call check against lastMultiplier", P, swap(
        "if (totalUnits != 0 && mAfter < m) revert MultiplierDecreased();",
        "if (totalUnits != 0 && mAfter < lastMultiplier) revert MultiplierDecreased();")),
    ("M after-call check", P, drop_line("        if (totalUnits != 0 && mAfter < m) revert MultiplierDecreased();")),
    ("M after-call check on an empty pool", P, swap("if (totalUnits != 0 && mAfter < m)", "if (mAfter < m)")),
    ("M after-call record", P, drop_line("        lastMultiplier = mAfter;")),
    ("M empty pool returns S", P, swap("        if (totalUnits == 0) return lastMultiplier;", "        if (totalUnits == 0) return S;")),
    # transfer agent
    ("A agent only", P, drop_line("        if (msg.sender != transferAgent) revert NotTransferAgent();")),
    ("A checkpoint snapshot", P, drop_line("        if (totalUnits != expectedUnits) revert UnitsChanged();")),
    ("A checkpoint latches", P, drop_line("                halted = true;")),
    ("A checkpoint records", P, swap("        } else {\n            lastMultiplier = m;\n        }", "        }")),
    ("A checkpoint records while halted", P, swap(
        "        } else {\n            lastMultiplier = m;\n        }",
        "        } else if (!halted) {\n            lastMultiplier = m;\n        }")),
    ("A register key version", P, drop_line("        if (version != registerKeyVersion + 1) revert WrongRegisterKeyVersion();")),
    ("A register key on curve", P, drop_line("        if (!PublicInputs.onGrumpkin(x, y)) revert InvalidRegisterKey();")),
    # governance
    ("G clear only when halted", P, drop_line("        if (!halted) revert NotHalted();")),
    ("G clear only when restored", P, drop_line("        if (multiplier() < lastMultiplier) revert MultiplierNotRestored();")),
    ("G clear records", P, swap(
        "        uint256 m = multiplier();\n        lastMultiplier = m;\n        emit HaltCleared(m);",
        "        uint256 m = multiplier();\n        emit HaltCleared(m);")),
    ("G verifier has code", P, drop_line("        if (newVerifier.code.length == 0) revert ZeroAddress();")),
    ("G claim key hash canonical", P, drop_line(
        "        if (uint256(newClaimKeyHash) >= PublicInputs.BN254_MODULUS) revert NonCanonicalClaimKeyHash();")),
    ("G rearm event", P, drop_line("        emit GuardianRearmed();")),
    ("G rearm resets the budget", P, swap(
        "        guardianArmed = true;\n        pauseBudgetSpent = 0;\n        pauseWindowStart = currentEpoch();\n",
        "        guardianArmed = true;\n")),
    ("G transfer agent not zero", P, drop_line("        if (newTransferAgent == address(0)) revert ZeroAddress();")),
    ("G daily epoch", P, drop_line("        if (p.epochSeconds != CIRCUIT_EPOCH_SECONDS) revert WrongEpochSeconds();")),
    ("G pause parameters", P, swap(") revert InvalidPauseParams();", ") {}")),
    # pause
    ("P guardian armed", P, drop_line("        if (!guardianArmed) revert GuardianNotArmed();")),
    ("P ceiling", P, drop_line(
        "        if (untilEpoch <= epoch || untilEpoch - epoch > MAX_PAUSE_EPOCHS) revert PauseCeilingExceeded();")),
    ("P window reset", P, swap("            pauseWindowStart = epoch;\n            pauseBudgetSpent = 0;\n", "")),
    ("P budget", P, drop_line("        if (pauseBudgetSpent + requested > PAUSE_BUDGET_EPOCHS) revert PauseBudgetExceeded();")),
    ("P disarm", P, drop_line("        if (pauseBudgetSpent >= PAUSE_BUDGET_EPOCHS) guardianArmed = false;")),
    ("P root ring eviction", P, drop_line("        if (evicted != bytes32(0)) delete _validRoots[evicted];")),
    # registry
    ("R batch size", R, drop_line("        if (n < MIN_BATCH_SIZE) revert BatchTooSmall();")),
    ("R capacity", R, drop_line("        if (_attestationTree.size + n > MAX_ATTESTATIONS) revert RegistryFull();")),
    ("R canonical owner", R, drop_line(
        "            if (uint256(owners[i]) >= PublicInputs.BN254_MODULUS) revert NonCanonicalOwner();")),
    ("R expiry interval", R, drop_line("        _checkExpiry(expiresAt);")),
    ("R generation step", R, drop_line("        _checkGeneration(generation);")),
    ("R root ring eviction", R, drop_line("        if (evicted != bytes32(0)) delete _validAttestationRoots[evicted];")),
    ("R floor commits the active raise", R, drop_line("            _minAcceptedGeneration = pendingMinAcceptedGeneration;")),
    ("R floor increases", R, drop_line("        if (newValue <= minAcceptedGeneration()) revert GenerationNotIncreasing();")),
    ("R floor activates later", R, drop_line("        if (activationEpoch <= currentEpoch()) revert ActivationNotFuture();")),
    ("R old attester revoked", R, drop_line("        _revokeRole(ATTESTER_ROLE, attester);")),
    ("R last issuance recorded", R, drop_line("        lastIssuedAt = issuedAt;")),
    ("R revocation needs an attester", R, drop_line("        if (revoked == address(0)) revert NoAttester();")),
    ("R trusted-until not in the future", R, drop_line(
        "        if (trustedUntil > block.timestamp) revert TrustedUntilInFuture();")),
    ("R revocation removes the role", R, drop_line("        _revokeRole(ATTESTER_ROLE, revoked);")),
    ("R revocation clears the attester", R, drop_line("        attester = address(0);")),
    ("R revocation retires only after a later issuance", R, swap(
        "bool retire = lastIssuedAt > trustedUntil;", "bool retire = lastIssuedAt >= trustedUntil;")),
    ("R revocation retires after a later issuance", R, swap(
        "bool retire = lastIssuedAt > trustedUntil;", "bool retire = false;")),
    ("R revocation floor past the last generation", R, swap(
        "uint64 floor = currentGeneration + 1;", "uint64 floor = currentGeneration;")),
    ("R revocation never lowers the floor", R, swap(
        "if (floor > minAcceptedGeneration()) _queueMinAcceptedGeneration(", "_queueMinAcceptedGeneration(")),
    ("R revocation retires from the next epoch", R, swap(
        "_queueMinAcceptedGeneration(floor, currentEpoch() + 1);", "_queueMinAcceptedGeneration(floor, currentEpoch() + 2);")),
    # composite verifier
    ("C slots have code", C, swap(") revert NoCode();", ") {}")),
    ("C deposit routed to its own verifier", C, swap(
        "return DEPOSIT_VERIFIER.verify(proof, publicInputs);", "return WITHDRAW_VERIFIER.verify(proof, publicInputs);")),
    # one role check removed at a time, per gated function
    ("A checkpoint agent only", P, swap(
        "function checkpoint(bytes32 registerHash, uint256 expectedUnits) external onlyTransferAgent {",
        "function checkpoint(bytes32 registerHash, uint256 expectedUnits) external {")),
    ("A recordGrant agent only", P, swap(
        "function recordGrant(bytes32 scopeCommitment) external onlyTransferAgent {",
        "function recordGrant(bytes32 scopeCommitment) external {")),
    ("A setRegisterKey agent only", P, swap(
        "function setRegisterKey(uint256 x, uint256 y, uint64 version) external onlyTransferAgent {",
        "function setRegisterKey(uint256 x, uint256 y, uint64 version) external {")),
    ("G clearHalt governance only", P, swap(
        "function clearHalt() external onlyRole(DEFAULT_ADMIN_ROLE) {", "function clearHalt() external {")),
    ("G setVerifier governance only", P, swap(
        "function setVerifier(address newVerifier) external onlyRole(DEFAULT_ADMIN_ROLE) {",
        "function setVerifier(address newVerifier) external {")),
    ("G setClaimKeyHash governance only", P, swap(
        "function setClaimKeyHash(bytes32 newClaimKeyHash) external onlyRole(DEFAULT_ADMIN_ROLE) {",
        "function setClaimKeyHash(bytes32 newClaimKeyHash) external {")),
    ("G setTransferAgent governance only", P, swap(
        "function setTransferAgent(address newTransferAgent) external onlyRole(DEFAULT_ADMIN_ROLE) {",
        "function setTransferAgent(address newTransferAgent) external {")),
    ("G rearmGuardian governance only", P, swap(
        "function rearmGuardian() external onlyRole(DEFAULT_ADMIN_ROLE) {", "function rearmGuardian() external {")),
    ("P pause guardian only", P, swap(
        "function pause(uint256 untilEpoch) external onlyRole(GUARDIAN_ROLE) {",
        "function pause(uint256 untilEpoch) external {")),
    ("R addAttestations attester only", R, drop_line("        onlyRole(ATTESTER_ROLE)")),
    ("R setAttester timelock only", R, swap(
        "function setAttester(address newAttester) external onlyRole(TIMELOCK_ROLE) {",
        "function setAttester(address newAttester) external {")),
    ("R raiseMinAcceptedGeneration timelock only", R, swap(
        "function raiseMinAcceptedGeneration(uint64 newValue, uint256 activationEpoch) external onlyRole(TIMELOCK_ROLE) {",
        "function raiseMinAcceptedGeneration(uint64 newValue, uint256 activationEpoch) external {")),
    ("R revokeAttester timelock only", R, swap(
        "function revokeAttester(uint64 trustedUntil) external onlyRole(TIMELOCK_ROLE) {",
        "function revokeAttester(uint64 trustedUntil) external {")),
    # public inputs
    ("I Grumpkin coordinates below the modulus", I, drop_line("        if (x >= p || y >= p) return false;")),
]

# None: every mutation should be killed.
EXPECTED_SURVIVORS = set()

if os.path.exists(WORK):
    shutil.rmtree(WORK)
os.makedirs(WORK)
shutil.copy(os.path.join(ROOT, "foundry.toml"), WORK)
# The build cache comes along, so each mutant recompiles only what it touches.
shutil.copytree(os.path.join(ROOT, "contracts"), os.path.join(WORK, "contracts"),
                ignore=shutil.ignore_patterns("broadcast"))
os.symlink(os.path.realpath(os.path.join(ROOT, "dependencies")), os.path.join(WORK, "dependencies"))
env = {**os.environ, "FOUNDRY_DISABLE_NIGHTLY_WARNING": "1"}

problems = []
for name, rel, (anchor, mutate) in MUTATIONS:
    path = os.path.join(WORK, rel)
    original = open(path).read()
    if original.count(anchor) != 1:
        print(f"{name:<40} | ANCHOR? found {original.count(anchor)} times", flush=True)
        problems.append(name)
        continue
    open(path, "w").write(mutate(original))
    run = subprocess.run([FORGE, "test"], cwd=WORK, capture_output=True, text=True, timeout=900, env=env)
    out = run.stdout + run.stderr
    open(path, "w").write(original)
    if "Compiler run failed" in out:
        verdict = "INVALID"
        problems.append(name)
    elif run.returncode == 0:
        verdict = "SURVIVED" + (" (expected)" if name in EXPECTED_SURVIVORS else "")
        if name not in EXPECTED_SURVIVORS:
            problems.append(name)
    else:
        # forge lists each failure twice: as it runs, and in its summary. An
        # invariant failure prints its name further on; name its suite instead.
        failed = list(dict.fromkeys(re.findall(r"\[FAIL[^\]]*\] (\w+)\(", out)))
        failed = failed or list(dict.fromkeys(re.findall(r"failing tests? in \S+:(\w+)", out)))
        verdict = f"KILLED by {len(failed)}: " + ", ".join(failed[:3])
    print(f"{name:<40} | {verdict}", flush=True)

shutil.rmtree(WORK)
print()
print("Unexpected:", ", ".join(problems) if problems else "none")
sys.exit(1 if problems else 0)

#!/usr/bin/env python3
"""Constraint-removal check for the shielded-notes circuits.

Removes or weakens one constraint at a time in a copy of `circuits/`, runs the
affected package's Noir tests, and reports each mutation:

  KILLED     some test failed: the constraint is guarded
  SURVIVED   every test passed: removing the constraint goes unnoticed
  INVALID    the mutated circuit does not compile
  ANCHOR?    the source line was not found: update MUTATIONS

Every constraint whose removal matters should be KILLED. EXPECTED_SURVIVORS
lists the ones that may survive and why. The script exits non-zero on any
other survivor, an invalid mutation or a missing anchor.

Each mutation is located by its exact source text, so editing a circuit can
break an anchor; the script then reports ANCHOR? rather than passing. Update
MUTATIONS together with the circuits.

Usage: python3 scripts/mutate-circuits.py [circuits dir] [scratch dir]
Defaults: ../circuits next to this script, and a temporary directory.
Takes several minutes; nargo is taken from $NARGO_PATH or ~/.nargo/bin.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "circuits")
WORK = sys.argv[2] if len(sys.argv) > 2 else tempfile.mkdtemp(prefix="sn-mutants-")
NARGO = os.environ.get("NARGO_PATH", os.path.expanduser("~/.nargo/bin/nargo"))


def drop_call(anchor):
    """Remove a whole statement that starts with `anchor` and ends at its `);`."""
    def f(text):
        i = text.index(anchor)
        j = text.index(");\n", i) + 3
        return text[:i] + text[j:]
    return anchor, f


def drop_line(line):
    def f(text):
        return text.replace(line + "\n", "", 1)
    return line, f


def swap(old, new):
    def f(text):
        return text.replace(old, new, 1)
    return old, f


def swap_all(anchor, old, new):
    """Replace every `old`, located by the unique `anchor`: a change made on
    both sides of a pair at once, which round-trip tests cannot see."""
    def f(text):
        return text.replace(old, new)
    return anchor, f


T, D, W = "transfer/src/main.nr", "deposit/src/main.nr", "withdraw/src/main.nr"

MUTATIONS = [
    # transfer
    ("T token 160 bits", T, drop_line("    token.assert_max_bit_size::<160>();")),
    ("T input 0 depth bound", T, drop_line("    assert(inputs[0].proof_length <= domain::MAX_COMMITMENT_TREE_DEPTH);")),
    ("T input 0 inclusion", T, drop_call("    merkle::verify(\n        c_in_0,")),
    ("T nullifier_0", T, drop_line('    assert(nullifier_0 == note::nullifier(c_in_0, nk), "nullifier mismatch");')),
    ("T input 1 inclusion skipped", T, swap("    if inputs[1].units != 0 {", "    if false {")),
    ("T input 1 depth bound", T, drop_line("        assert(inputs[1].proof_length <= domain::MAX_COMMITMENT_TREE_DEPTH);")),
    ("T nullifier_1", T, drop_line('    assert(nullifier_1 == note::nullifier(c_in_1, nk), "nullifier mismatch");')),
    ("T output 0 token", T, drop_line('    assert(outputs[0].token == token, "token mismatch");')),
    ("T output 1 token", T, drop_line('    assert(outputs[1].token == token, "token mismatch");')),
    ("T commitment_out_0", T, drop_line('    assert(commitment_out_0 == outputs[0].commitment(), "commitment mismatch");')),
    ("T commitment_out_1", T, drop_line('    assert(commitment_out_1 == outputs[1].commitment(), "commitment mismatch");')),
    ("T conservation", T, drop_call("    assert(\n        inputs[0].units + inputs[1].units")),
    ("T conservation weakened to >=", T, swap(
        "inputs[0].units + inputs[1].units == outputs[0].units + outputs[1].units",
        "inputs[0].units + inputs[1].units >= outputs[0].units + outputs[1].units")),
    ("T owner-path input attestation", T, drop_call("        attestation::verify(\n            owner_in,")),
    ("T owner-path input 0 lock", T, drop_line("        lock::check_input(inputs[0].lock, inputs[0].lock_opening, epoch);")),
    ("T owner-path input 1 lock", T, drop_line("        lock::check_input(inputs[1].lock, inputs[1].lock_opening, epoch);")),
    ("T owner-path output 0 unlocked", T, drop_line('        assert(outputs[0].lock == 0, "owner path cannot create locks");')),
    ("T owner-path output 1 unlocked", T, drop_line('        assert(outputs[1].lock == 0, "owner path cannot create locks");')),
    ("T output attestations only output 0", T, swap("    for j in 0..2 {\n        if (!claim)", "    for j in 0..1 {\n        if (!claim)")),
    ("T output attestations never", T, swap("        if (!claim) | (outputs[j].owner != owner_in) {", "        if false {")),
    ("T output attestations claim-path skip for all", T, swap("        if (!claim) | (outputs[j].owner != owner_in) {", "        if !claim {")),
    ("T feed_r", T, drop_line('    assert(feed_r == derived_r, "feed mismatch");')),
    ("T feed lock terms", T, drop_line("        lock::check_terms(outputs[j].lock, output_locks[j]);")),
    ("T feed only output 0", T, swap("    for j in 0..2 {\n        lock::check_terms", "    for j in 0..1 {\n        lock::check_terms")),
    ("T feed ciphertext", T, drop_line('            assert(feed_ct[domain::FEED_FIELDS * j + i] == ct[i], "feed mismatch");')),
    ("T claim key hash", T, drop_line('        assert(owner::key_hash(claim_key) == claim_key_hash, "claim key mismatch");')),
    ("T signer always owner", T, swap("    let signer = if claim { claim_key } else { owner_key };", "    let signer = owner_key;")),
    ("T signer always claim key", T, swap("    let signer = if claim { claim_key } else { owner_key };", "    let signer = claim_key;")),
    ("T plan path constant", T, swap("            path: claim as Field,", "            path: 0,")),
    ("T plan expiry check", T, drop_line("    plan::check_expiry(epoch, expiry);")),
    ("T plan expiry field", T, swap("            expiry,\n", "            expiry: 0,\n")),
    ("T plan signature", T, drop_line("    plan::verify_signature(signer, signature, digest);")),
    # call sites: lapse, the generation floor and holds, with this circuit's epoch and floor
    ("T input 0 lock at the next epoch", T, swap("lock::check_input(inputs[0].lock, inputs[0].lock_opening, epoch);", "lock::check_input(inputs[0].lock, inputs[0].lock_opening, epoch + 1);")),
    ("T input 1 lock at the next epoch", T, swap("lock::check_input(inputs[1].lock, inputs[1].lock_opening, epoch);", "lock::check_input(inputs[1].lock, inputs[1].lock_opening, epoch + 1);")),
    ("T input 1 lock ignoring holds", T, swap("lock::check_input(inputs[1].lock, inputs[1].lock_opening, epoch);", "lock::check_input(inputs[1].lock, inputs[1].lock_opening, 0xfffffffffffffffe);")),
    ("T input attestation without the floor", T, swap("            owner_in,\n            input_attestation,\n            epoch,\n            min_accepted_generation,", "            owner_in,\n            input_attestation,\n            epoch,\n            0,")),
    ("T output attestations without the floor", T, swap("                output_attestations[j],\n                epoch,\n                min_accepted_generation,", "                output_attestations[j],\n                epoch,\n                0,")),
    ("T input attestation at the previous epoch", T, swap("            owner_in,\n            input_attestation,\n            epoch,\n", "            owner_in,\n            input_attestation,\n            epoch - 1,\n")),
    ("T output attestations at the previous epoch", T, swap("                output_attestations[j],\n                epoch,\n", "                output_attestations[j],\n                epoch - 1,\n")),
    ("T output attestations at epoch 0", T, swap("                output_attestations[j],\n                epoch,\n", "                output_attestations[j],\n                0,\n")),
    # deposit
    ("D token 160 bits", D, drop_line("    token.assert_max_bit_size::<160>();")),
    ("D funding address 160 bits", D, drop_line("    funding_address.assert_max_bit_size::<160>();")),
    ("D commitment", D, drop_line('    assert(commitment == note.commitment(), "commitment mismatch");')),
    ("D attestation", D, drop_call("    attestation::verify(\n        owner,")),
    ("D feed_r", D, drop_line('    assert(feed_r == derived_r, "feed mismatch");')),
    ("D feed ciphertext", D, drop_line('    assert(feed_ct == feed::encrypt(k, note, NO_LOCK, 0), "feed mismatch");')),
    ("D plan public_units", D, swap("            public_units: units as Field,", "            public_units: 0,")),
    ("D plan recipient", D, swap("            recipient: funding_address,", "            recipient: 0,")),
    ("D plan expiry check", D, drop_line("    plan::check_expiry(epoch, expiry);")),
    ("D plan expiry field", D, swap("            expiry,\n", "            expiry: 0,\n")),
    ("D plan signature", D, drop_line("    plan::verify_signature(owner_key, signature, digest);")),
    ("D attestation without the floor", D, swap("        attestation_witness,\n        epoch,\n        min_accepted_generation,", "        attestation_witness,\n        epoch,\n        0,")),
    # withdraw
    ("W token 160 bits", W, drop_line("    token.assert_max_bit_size::<160>();")),
    ("W recipient 160 bits", W, drop_line("    recipient.assert_max_bit_size::<160>();")),
    ("W units", W, drop_line('    assert(input.units == units, "units mismatch");')),
    ("W units weakened to >=", W, swap(
        'assert(input.units == units, "units mismatch");', 'assert(input.units >= units, "units mismatch");')),
    ("W depth bound", W, drop_line("    assert(input.proof_length <= domain::MAX_COMMITMENT_TREE_DEPTH);")),
    ("W inclusion", W, drop_call("    merkle::verify(\n        commitment,")),
    ("W nullifier", W, drop_line('    assert(nullifier == note::nullifier(commitment, nk), "nullifier mismatch");')),
    ("W attestation", W, drop_call("    attestation::verify(\n        owner,")),
    ("W lock", W, drop_line("    lock::check_input(input.lock, input.lock_opening, epoch);")),
    ("W lock check as lock == 0", W, swap(
        "    lock::check_input(input.lock, input.lock_opening, epoch);", '    assert(input.lock == 0, "note is locked");')),
    ("W lock check at epoch 0", W, swap(
        "    lock::check_input(input.lock, input.lock_opening, epoch);",
        "    lock::check_input(input.lock, input.lock_opening, 0);")),
    ("W plan public_units", W, swap("            public_units: units as Field,", "            public_units: 0,")),
    ("W plan recipient", W, swap("            recipient,\n", "            recipient: 0,\n")),
    ("W plan expiry check", W, drop_line("    plan::check_expiry(epoch, expiry);")),
    ("W plan expiry field", W, swap("            expiry,\n", "            expiry: 0,\n")),
    ("W plan signature", W, drop_line("    plan::verify_signature(owner_key, signature, digest);")),
    ("W lock at the next epoch", W, swap("lock::check_input(input.lock, input.lock_opening, epoch);", "lock::check_input(input.lock, input.lock_opening, epoch + 1);")),
    ("W lock ignoring holds", W, swap("lock::check_input(input.lock, input.lock_opening, epoch);", "lock::check_input(input.lock, input.lock_opening, 0xfffffffffffffffe);")),
    ("W attestation without the floor", W, swap("        attestation_witness,\n        epoch,\n        min_accepted_generation,", "        attestation_witness,\n        epoch,\n        0,")),
    ("W attestation at the previous epoch", W, swap("        attestation_witness,\n        epoch,\n", "        attestation_witness,\n        epoch - 1,\n")),
    # library, checked against the whole workspace
    ("L lock opening hash", "lib/src/lock.nr", drop_line('        assert(lock_value(opening) == lock, "lock opening mismatch");')),
    ("L lock release epoch", "lib/src/lock.nr", drop_line('        assert(epoch >= opening.release_after, "note is locked");')),
    ("L lock terms zero when unlocked", "lib/src/lock.nr", drop_call("        assert(\n            (terms.reason == 0)")),
    ("L lock terms zero without reason", "lib/src/lock.nr", swap(
        "(terms.reason == 0) & (terms.release_after == 0)", "(terms.release_after == 0)")),
    ("L lock terms zero without claim_party", "lib/src/lock.nr", swap(
        "(terms.release_after == 0) & (terms.claim_party == 0)", "(terms.release_after == 0)")),
    ("L lock terms hash", "lib/src/lock.nr", drop_line('        assert(lock_value(terms) == lock, "lock terms mismatch");')),
    ("L lock terms reason", "lib/src/lock.nr", drop_call("        assert(\n            (terms.reason == domain::LOCK_FREEZE)")),
    ("L feed scalar lo 128 bits", "lib/src/feed.nr", drop_line("    secret.lo.assert_max_bit_size::<128>();")),
    ("L feed scalar hi 128 bits", "lib/src/feed.nr", drop_line("    secret.hi.assert_max_bit_size::<128>();")),
    ("L feed point at infinity", "lib/src/feed.nr", drop_line('    assert((big_r.x != 0) | (big_r.y != 0), "feed point at infinity");')),
    # Formats shared with Rust and Solidity, changed on both sides of the circuit
    # at once: only the known-answer tests see these.
    ("L feed fields reason and claim_party swapped", "lib/src/feed.nr", swap(
        "terms.reason, terms.release_after as Field, terms.claim_party]",
        "terms.claim_party, terms.release_after as Field, terms.reason]")),
    ("L feed fields units and owner swapped", "lib/src/feed.nr", swap(
        "[n[0], n[1], n[2], n[3], n[4], terms.reason", "[n[0], n[2], n[1], n[3], n[4], terms.reason")),
    ("L keystream index without the output", "lib/src/feed.nr", swap_all(
        "pub fn encrypt(k: Field, note: Note, terms: LockOpening, j: u32)",
        "(domain::FEED_FIELDS * j + i) as Field", "i as Field")),
    ("L attestation leaf without the attester", "lib/src/attestation.nr", swap(
        "[owner, w.attester, w.generation as Field", "[owner, 0, w.generation as Field")),
    ("L attestation depth bound", "lib/src/attestation.nr", drop_line("    assert(w.proof_length <= domain::MAX_ATTESTATION_TREE_DEPTH);")),
    ("L attestation inclusion", "lib/src/attestation.nr", drop_call("    merkle::verify(\n        leaf(owner, w),")),
    ("L attestation expiry", "lib/src/attestation.nr", drop_line('    assert((epoch + 1) * domain::EPOCH_SECONDS <= w.expires_at, "attestation expired");')),
    ("L attestation generation", "lib/src/attestation.nr", drop_line('    assert(w.generation >= min_accepted_generation, "attestation generation retired");')),
    ("L merkle root", "lib/src/merkle.nr", drop_line('    assert(computed == root, "merkle proof failed");')),
    ("L signature check", "lib/src/plan.nr", drop_call("    assert(\n        std::ecdsa_secp256k1::verify_signature")),
    ("L plan expiry", "lib/src/plan.nr", drop_line('    assert((epoch + 1) * domain::EPOCH_SECONDS <= expiry, "plan expired");')),
]

PACKAGE = {T: "sn_transfer", D: "sn_deposit", W: "sn_withdraw"}

# Equivalent mutants: removing them changes no result. `binary_merkle_root`
# loops over MAX_DEPTH levels and skips those at or past `depth`, so a depth
# above the maximum computes the same root as the maximum.
EXPECTED_SURVIVORS = {
    "T input 0 depth bound",
    "T input 1 depth bound",
    "W depth bound",
    "L attestation depth bound",
}

if os.path.exists(WORK):
    shutil.rmtree(WORK)
shutil.copytree(SRC, WORK, ignore=shutil.ignore_patterns("target"))

problems = []
for name, rel, (anchor, mutate) in MUTATIONS:
    path = os.path.join(WORK, rel)
    original = open(path).read()
    if original.count(anchor) != 1:
        print(f"{name:<45} | ANCHOR? found {original.count(anchor)} times", flush=True)
        problems.append(name)
        continue
    open(path, "w").write(mutate(original))
    args = [NARGO, "test"] + (["--package", PACKAGE[rel]] if rel in PACKAGE else ["--workspace"])
    run = subprocess.run(args, cwd=WORK, capture_output=True, text=True, timeout=900)
    out = run.stdout + run.stderr
    open(path, "w").write(original)
    if "Aborting due to" in out:
        verdict = "INVALID"
        problems.append(name)
    elif run.returncode == 0:
        verdict = "SURVIVED" + (" (expected)" if name in EXPECTED_SURVIVORS else "")
        if name not in EXPECTED_SURVIVORS:
            problems.append(name)
    else:
        failed = re.findall(r"Testing (\S+::\S+) \.\.\. \S*FAIL", out)
        verdict = f"KILLED by {len(failed)}: " + ", ".join(t.split("::")[-1] for t in failed[:3])
    print(f"{name:<45} | {verdict}", flush=True)

shutil.rmtree(WORK)
print()
print("Unexpected:", ", ".join(problems) if problems else "none")
sys.exit(1 if problems else 0)

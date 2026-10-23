use crate::domain;
use crate::hasher::{hash_2, hash_5};
use crate::merkle;

// Private witnesses for one attestation leaf. The registry built the leaf from
// the agent's call and published its fields; the prover supplies them privately
// so the proof does not reveal which leaf it opens (SPEC, Shared Gadgets).
pub struct AttestationWitness {
    pub attester: Field,
    pub generation: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub proof_length: u32,
    pub indices: [bool; domain::MAX_ATTESTATION_TREE_DEPTH],
    pub path: [Field; domain::MAX_ATTESTATION_TREE_DEPTH],
}

// attestation_leaf = Poseidon1(owner, attester, generation, issued_at, expires_at).
pub fn leaf(owner: Field, w: AttestationWitness) -> Field {
    hash_5(
        [owner, w.attester, w.generation as Field, w.issued_at as Field, w.expires_at as Field],
    )
}

// Checks that `owner` holds a current attestation: membership, expiry covering
// the end of the current epoch, and the generation floor. The base's
// attester-revocation check is gone: there is one attester, and raising the
// generation floor retires every leaf at once.
pub fn verify(
    owner: Field,
    w: AttestationWitness,
    epoch: u64,
    min_accepted_generation: u64,
    attestation_root: Field,
) {
    assert(w.proof_length <= domain::MAX_ATTESTATION_TREE_DEPTH);
    merkle::verify(
        leaf(owner, w),
        attestation_root,
        w.proof_length,
        w.indices,
        w.path,
    );
    assert((epoch + 1) * domain::EPOCH_SECONDS <= w.expires_at, "attestation expired");
    assert(w.generation >= min_accepted_generation, "attestation generation retired");
}

// A depth-1 tree holding `owner`'s leaf, for tests.
pub fn single_leaf_fixture(owner: Field, expires_at: u64) -> (AttestationWitness, Field) {
    let mut path = [0; domain::MAX_ATTESTATION_TREE_DEPTH];
    path[0] = 0x1234;
    let w = AttestationWitness {
        attester: 0xa11ce,
        generation: 1,
        issued_at: 1_700_000_000,
        expires_at,
        proof_length: 1,
        indices: [false; domain::MAX_ATTESTATION_TREE_DEPTH],
        path,
    };
    let root = merkle::binary_merkle_root(hash_2, leaf(owner, w), 1, w.indices, w.path);
    (w, root)
}

// A depth-1 tree holding two owners' leaves, for tests.
pub fn two_leaf_fixture(
    a: Field,
    a_expires_at: u64,
    b: Field,
    b_expires_at: u64,
) -> (AttestationWitness, AttestationWitness, Field) {
    let mut wa = AttestationWitness {
        attester: 0xa11ce,
        generation: 1,
        issued_at: 1_700_000_000,
        expires_at: a_expires_at,
        proof_length: 1,
        indices: [false; domain::MAX_ATTESTATION_TREE_DEPTH],
        path: [0; domain::MAX_ATTESTATION_TREE_DEPTH],
    };
    let mut wb = wa;
    wb.expires_at = b_expires_at;
    let leaf_a = leaf(a, wa);
    let leaf_b = leaf(b, wb);
    wa.path[0] = leaf_b;
    wb.path[0] = leaf_a;
    wb.indices[0] = true;
    (wa, wb, hash_2([leaf_a, leaf_b]))
}

#[test]
fn test_verify_happy_path() {
    let (w, root) = single_leaf_fixture(0xbeef, 200 * domain::EPOCH_SECONDS);
    verify(0xbeef, w, 100, 1, root);
}

#[test(should_fail_with = "merkle proof failed")]
fn test_verify_other_owner_fails() {
    let (w, root) = single_leaf_fixture(0xbeef, 200 * domain::EPOCH_SECONDS);
    verify(0xbeee, w, 100, 1, root);
}

#[test]
fn test_verify_last_covered_epoch_passes() {
    // Covers the end of epoch 199, so epoch 199 is the last one it accepts.
    let (w, root) = single_leaf_fixture(0xbeef, 200 * domain::EPOCH_SECONDS);
    verify(0xbeef, w, 199, 1, root);
}

#[test(should_fail_with = "attestation expired")]
fn test_verify_expired_fails() {
    let (w, root) = single_leaf_fixture(0xbeef, 200 * domain::EPOCH_SECONDS);
    verify(0xbeef, w, 200, 1, root);
}

#[test(should_fail_with = "attestation generation retired")]
fn test_verify_retired_generation_fails() {
    let (w, root) = single_leaf_fixture(0xbeef, 200 * domain::EPOCH_SECONDS);
    verify(0xbeef, w, 100, 2, root);
}

// Known answer, also pinned in the registry's tests: the leaf the registry
// emits when the agent 0xa6e7 attests owner 0x0e1 at epoch 1000 for 30 epochs.
// It fixes the leaf's field order, which a change on both sides at once would
// leave every other test passing.
#[test]
fn test_known_answer_leaf() {
    let w = AttestationWitness {
        attester: 0xa6e7,
        generation: 0,
        issued_at: 1000 * domain::EPOCH_SECONDS,
        expires_at: 1030 * domain::EPOCH_SECONDS,
        proof_length: 0,
        indices: [false; domain::MAX_ATTESTATION_TREE_DEPTH],
        path: [0; domain::MAX_ATTESTATION_TREE_DEPTH],
    };
    assert(leaf(0x0e1, w) == 0x063a450b852c613c5446bb5185c94f06f4b20628601388b87462d939b7013332);
}

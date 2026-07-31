use crate::domain;
use crate::hasher::{hash_2, hash_5};
use crate::merkle;

// Private witnesses for one screened key. Bundled so a circuit running
// several instances (transfer runs three) does not carry the fields flat.
pub struct AttestationWitness {
    pub attester: Field,
    pub generation: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub att_proof_length: u32,
    pub att_indices: [bool; domain::MAX_ATTESTATION_TREE_DEPTH],
    pub att_path: [Field; domain::MAX_ATTESTATION_TREE_DEPTH],
    pub revoked_at: u64,
    pub rev_indices: [bool; domain::ATTESTER_TREE_DEPTH],
    pub rev_path: [Field; domain::ATTESTER_TREE_DEPTH],
}

// Screens one attested pubkey: membership, expiry, generation floor, and
// attester non-revocation. Revocation binds through a root because `attester`
// stays a private witness; the contract has no key to read a mapping by. An
// empty revocation slot carries revoked_at = 0, and no epoch satisfies
// `epoch < 0`, so an empty leaf can never pass.
pub fn verify_instance(
    pubkey: Field,
    attester: Field,
    generation: u64,
    issued_at: u64,
    expires_at: u64,
    epoch: u64,
    min_accepted_generation: u64,
    attestation_root: Field,
    att_proof_length: u32,
    att_indices: [bool; domain::MAX_ATTESTATION_TREE_DEPTH],
    att_path: [Field; domain::MAX_ATTESTATION_TREE_DEPTH],
    revoked_at: u64,
    attester_revocation_root: Field,
    rev_indices: [bool; domain::ATTESTER_TREE_DEPTH],
    rev_path: [Field; domain::ATTESTER_TREE_DEPTH],
) {
    assert(att_proof_length <= domain::MAX_ATTESTATION_TREE_DEPTH);

    let leaf = hash_5([
        pubkey,
        attester,
        generation as Field,
        issued_at as Field,
        expires_at as Field,
    ]);
    merkle::verify(
        leaf,
        attestation_root,
        att_proof_length,
        att_indices,
        att_path,
    );
    assert((epoch + 1) * domain::EPOCH_SECONDS <= expires_at, "attestation expired");
    assert(generation >= min_accepted_generation, "attestation generation retired");

    // Leaf and interior nodes both use hash_2 here, no arity separation; safe only
    // because revoked_at is u64-typed, so no interior-node preimage (Field, Field)
    // can range-check as a leaf's revoked_at. Widening revoked_at to Field reopens
    // interior-node-as-leaf forgery.
    let rev = hash_2([attester, revoked_at as Field]);
    merkle::verify(
        rev,
        attester_revocation_root,
        domain::ATTESTER_TREE_DEPTH,
        rev_indices,
        rev_path,
    );
    assert(epoch < revoked_at, "attester revoked");
}

fn no_att_indices() -> [bool; domain::MAX_ATTESTATION_TREE_DEPTH] {
    [false; domain::MAX_ATTESTATION_TREE_DEPTH]
}

fn no_att_path() -> [Field; domain::MAX_ATTESTATION_TREE_DEPTH] {
    [0; domain::MAX_ATTESTATION_TREE_DEPTH]
}

fn no_rev_indices() -> [bool; domain::ATTESTER_TREE_DEPTH] {
    [false; domain::ATTESTER_TREE_DEPTH]
}

fn no_rev_path() -> [Field; domain::ATTESTER_TREE_DEPTH] {
    [0; domain::ATTESTER_TREE_DEPTH]
}

struct Fixture {
    pubkey: Field,
    attester: Field,
    generation: u64,
    issued_at: u64,
    expires_at: u64,
    epoch: u64,
    min_accepted_generation: u64,
    attestation_root: Field,
    att_indices: [bool; domain::MAX_ATTESTATION_TREE_DEPTH],
    att_path: [Field; domain::MAX_ATTESTATION_TREE_DEPTH],
    revoked_at: u64,
    attester_revocation_root: Field,
    rev_indices: [bool; domain::ATTESTER_TREE_DEPTH],
    rev_path: [Field; domain::ATTESTER_TREE_DEPTH],
}

fn valid_fixture() -> Fixture {
    let pubkey: Field = 0xbeef;
    let attester: Field = 0xa11ce;
    let generation: u64 = 3;
    let issued_at: u64 = 1_700_000_000;
    let expires_at: u64 = 200 * domain::EPOCH_SECONDS;
    let epoch: u64 = 100;
    let min_accepted_generation: u64 = 2;

    let leaf = hash_5([
        pubkey,
        attester,
        generation as Field,
        issued_at as Field,
        expires_at as Field,
    ]);
    let att_indices = no_att_indices();
    let mut att_path = no_att_path();
    att_path[0] = 0x1234;
    let attestation_root =
        crate::merkle::binary_merkle_root(hash_2, leaf, 1, att_indices, att_path);

    let revoked_at: u64 = 0xffffffffffffffff;
    let rev = hash_2([attester, revoked_at as Field]);
    let rev_indices = no_rev_indices();
    let rev_path = no_rev_path();
    let attester_revocation_root = crate::merkle::binary_merkle_root(
        hash_2,
        rev,
        domain::ATTESTER_TREE_DEPTH,
        rev_indices,
        rev_path,
    );

    Fixture {
        pubkey,
        attester,
        generation,
        issued_at,
        expires_at,
        epoch,
        min_accepted_generation,
        attestation_root,
        att_indices,
        att_path,
        revoked_at,
        attester_revocation_root,
        rev_indices,
        rev_path,
    }
}

#[test]
fn test_verify_instance_happy_path() {
    let f = valid_fixture();
    verify_instance(
        f.pubkey,
        f.attester,
        f.generation,
        f.issued_at,
        f.expires_at,
        f.epoch,
        f.min_accepted_generation,
        f.attestation_root,
        1,
        f.att_indices,
        f.att_path,
        f.revoked_at,
        f.attester_revocation_root,
        f.rev_indices,
        f.rev_path,
    );
}

#[test]
fn test_deterministic_leaf_hashing() {
    let a = hash_5([1, 2, 3, 4, 5]);
    let b = hash_5([1, 2, 3, 4, 5]);
    assert(a == b);
}

#[test(should_fail_with = "attestation expired")]
fn test_verify_instance_lapsed_expiry_fails() {
    let mut f = valid_fixture();
    // epoch has already rolled past the interval expires_at commits to.
    f.epoch = 400;
    verify_instance(
        f.pubkey,
        f.attester,
        f.generation,
        f.issued_at,
        f.expires_at,
        f.epoch,
        f.min_accepted_generation,
        f.attestation_root,
        1,
        f.att_indices,
        f.att_path,
        f.revoked_at,
        f.attester_revocation_root,
        f.rev_indices,
        f.rev_path,
    );
}

#[test(should_fail_with = "attestation generation retired")]
fn test_verify_instance_generation_below_minimum_fails() {
    let mut f = valid_fixture();
    f.min_accepted_generation = f.generation + 1;
    verify_instance(
        f.pubkey,
        f.attester,
        f.generation,
        f.issued_at,
        f.expires_at,
        f.epoch,
        f.min_accepted_generation,
        f.attestation_root,
        1,
        f.att_indices,
        f.att_path,
        f.revoked_at,
        f.attester_revocation_root,
        f.rev_indices,
        f.rev_path,
    );
}

#[test(should_fail_with = "attester revoked")]
fn test_verify_instance_epoch_at_or_past_revocation_fails() {
    let attester: Field = 0xa11ce;
    let revoked_at: u64 = 50;
    let rev = hash_2([attester, revoked_at as Field]);
    let rev_indices = no_rev_indices();
    let rev_path = no_rev_path();
    let attester_revocation_root = crate::merkle::binary_merkle_root(
        hash_2,
        rev,
        domain::ATTESTER_TREE_DEPTH,
        rev_indices,
        rev_path,
    );

    let mut f = valid_fixture();
    f.attester = attester;
    f.revoked_at = revoked_at;
    f.attester_revocation_root = attester_revocation_root;
    f.epoch = revoked_at; // epoch == revoked_at must already fail

    verify_instance(
        f.pubkey,
        f.attester,
        f.generation,
        f.issued_at,
        f.expires_at,
        f.epoch,
        f.min_accepted_generation,
        f.attestation_root,
        1,
        f.att_indices,
        f.att_path,
        f.revoked_at,
        f.attester_revocation_root,
        f.rev_indices,
        f.rev_path,
    );
}

#[test(should_fail_with = "attester revoked")]
fn test_verify_instance_empty_revocation_slot_never_passes() {
    // An empty slot hashes Poseidon1(attester, 0), carrying revoked_at = 0. No
    // epoch satisfies `epoch < 0` for a u64, so the leaf can never authorize a
    // subject, even at the minimum epoch 0.
    let mut f = valid_fixture();
    let revoked_at: u64 = 0;
    let rev = hash_2([f.attester, revoked_at as Field]);
    let rev_indices = no_rev_indices();
    let rev_path = no_rev_path();
    let attester_revocation_root = crate::merkle::binary_merkle_root(
        hash_2,
        rev,
        domain::ATTESTER_TREE_DEPTH,
        rev_indices,
        rev_path,
    );
    f.revoked_at = revoked_at;
    f.attester_revocation_root = attester_revocation_root;
    f.epoch = 0;

    verify_instance(
        f.pubkey,
        f.attester,
        f.generation,
        f.issued_at,
        f.expires_at,
        f.epoch,
        f.min_accepted_generation,
        f.attestation_root,
        1,
        f.att_indices,
        f.att_path,
        f.revoked_at,
        f.attester_revocation_root,
        f.rev_indices,
        f.rev_path,
    );
}

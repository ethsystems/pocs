use spc_lib::attestation::{self, AttestationWitness};
use spc_lib::compliance::{self, ComplianceInputs};
use spc_lib::domain;
use spc_lib::hasher::{hash_1, hash_2, hash_4};
use spc_lib::merkle;
use spc_lib::policy;
use spc_lib::tx_facts::{sat_add, TxFacts};

// Transfer: spends up to two owned notes, mints two output notes, and
// advances the sender's compliance chain. Public-input order MUST match
// `TransferPublicInputs` in `contracts/src/PublicInputs.sol` index for
// index; `compliance_commitment_out` sits at index 6 here, at index 5 on
// deposit, and that asymmetry is fixed by the SPEC.
fn main(
    nullifier_0: pub Field,
    nullifier_1: pub Field,
    commitment_out_0: pub Field,
    commitment_out_1: pub Field,
    commitment_root: pub Field,
    velocity_nullifier: pub Field,
    compliance_commitment_out: pub Field,
    epoch: pub u64,
    epoch_seconds: pub u64,
    policy_source_hash: pub Field,
    attestation_root: pub Field,
    attester_revocation_root: pub Field,
    min_accepted_generation: pub u64,
    payload_commitment: pub Field,
    spending_key: Field,
    token_in_0: Field,
    amount_in_0: u64,
    salt_in_0: Field,
    token_in_1: Field,
    amount_in_1: u64,
    salt_in_1: Field,
    token_out_0: Field,
    amount_out_0: u64,
    owner_out_0: Field,
    salt_out_0: Field,
    token_out_1: Field,
    amount_out_1: u64,
    owner_out_1: Field,
    salt_out_1: Field,
    proof_length_0: u32,
    proof_length_1: u32,
    path_0: [Field; domain::MAX_COMMITMENT_TREE_DEPTH],
    indices_0: [bool; domain::MAX_COMMITMENT_TREE_DEPTH],
    path_1: [Field; domain::MAX_COMMITMENT_TREE_DEPTH],
    indices_1: [bool; domain::MAX_COMMITMENT_TREE_DEPTH],
    subject_attestation: AttestationWitness,
    out0_attestation: AttestationWitness,
    out1_attestation: AttestationWitness,
    seq: u64,
    epoch_in: u64,
    prev: policy::State,
    flags_in: u64,
    cp_in: [Field; 2],
    amt_in: [u64; 2],
    exit_in: Field,
    salt_in: Field,
    salt_out: Field,
    cn_proof_length: u32,
    cn_indices: [bool; domain::MAX_COMMITMENT_TREE_DEPTH],
    cn_path: [Field; domain::MAX_COMMITMENT_TREE_DEPTH],
) {
    // payload_commitment is unconstrained here: the contract recomputes
    // keccak256(encryptedNotes) mod r and checks it against this input
    // before calling the verifier, so a replayer would need a second
    // preimage on keccak to substitute the payload without invalidating
    // the proof.
    let _ = payload_commitment;
    let owner_pubkey = hash_1([spending_key]);

    assert(token_in_0 == token_in_1);
    assert(token_in_0 == token_out_0);
    assert(token_in_0 == token_out_1);
    token_in_0.assert_max_bit_size::<160>();
    assert(proof_length_0 <= domain::MAX_COMMITMENT_TREE_DEPTH);
    assert(proof_length_1 <= domain::MAX_COMMITMENT_TREE_DEPTH);

    let commitment_in_0 = hash_4([token_in_0, amount_in_0 as Field, owner_pubkey, salt_in_0]);
    merkle::verify(
        commitment_in_0,
        commitment_root,
        proof_length_0,
        indices_0,
        path_0,
    );
    assert(nullifier_0 == hash_2([commitment_in_0, spending_key]));

    // A one-input transfer pads the second input with a zero-value note.
    // The commitment and nullifier stay constrained; only inclusion is
    // skipped, since a zero note is never inserted into the tree.
    let is_zero_note = amount_in_1 == 0;
    let commitment_in_1 = hash_4([token_in_1, amount_in_1 as Field, owner_pubkey, salt_in_1]);
    if !is_zero_note {
        merkle::verify(
            commitment_in_1,
            commitment_root,
            proof_length_1,
            indices_1,
            path_1,
        );
    }
    assert(nullifier_1 == hash_2([commitment_in_1, spending_key]));

    assert(
        commitment_out_0
            == hash_4(
                [token_out_0, amount_out_0 as Field, owner_out_0, salt_out_0],
            ),
    );
    assert(
        commitment_out_1
            == hash_4(
                [token_out_1, amount_out_1 as Field, owner_out_1, salt_out_1],
            ),
    );

    assert(amount_in_0 + amount_in_1 == amount_out_0 + amount_out_1);

    attestation::verify_instance(
        owner_pubkey,
        subject_attestation.attester,
        subject_attestation.generation,
        subject_attestation.issued_at,
        subject_attestation.expires_at,
        epoch,
        min_accepted_generation,
        attestation_root,
        subject_attestation.att_proof_length,
        subject_attestation.att_indices,
        subject_attestation.att_path,
        subject_attestation.revoked_at,
        attester_revocation_root,
        subject_attestation.rev_indices,
        subject_attestation.rev_path,
    );
    attestation::verify_instance(
        owner_out_0,
        out0_attestation.attester,
        out0_attestation.generation,
        out0_attestation.issued_at,
        out0_attestation.expires_at,
        epoch,
        min_accepted_generation,
        attestation_root,
        out0_attestation.att_proof_length,
        out0_attestation.att_indices,
        out0_attestation.att_path,
        out0_attestation.revoked_at,
        attester_revocation_root,
        out0_attestation.rev_indices,
        out0_attestation.rev_path,
    );
    attestation::verify_instance(
        owner_out_1,
        out1_attestation.attester,
        out1_attestation.generation,
        out1_attestation.issued_at,
        out1_attestation.expires_at,
        epoch,
        min_accepted_generation,
        attestation_root,
        out1_attestation.att_proof_length,
        out1_attestation.att_indices,
        out1_attestation.att_path,
        out1_attestation.revoked_at,
        attester_revocation_root,
        out1_attestation.rev_indices,
        out1_attestation.rev_path,
    );

    let mut value_out: u64 = 0;
    if owner_out_0 != owner_pubkey {
        value_out = sat_add(value_out, amount_out_0);
    }
    if owner_out_1 != owner_pubkey {
        value_out = sat_add(value_out, amount_out_1);
    }

    let tx = TxFacts {
        epoch,
        seq,
        token: token_in_0,
        subject: owner_pubkey,
        counterparty: [owner_out_0, owner_out_1],
        value_in: 0,
        value_out,
        exit: domain::NO_EXIT,
    };

    compliance::run(
        ComplianceInputs {
            epoch,
            epoch_seconds,
            policy_source_hash,
            commitment_root,
            velocity_nullifier,
            compliance_commitment_out,
            spending_key,
            owner_pubkey,
            seq,
            epoch_in,
            prev,
            flags_in,
            cp_in,
            amt_in,
            exit_in,
            salt_in,
            salt_out,
            cn_proof_length,
            cn_indices,
            cn_path,
        },
        tx,
        amount_out_0,
        amount_out_1,
    );
}

mod tests {
    use super::main;
    use spc_lib::attestation::AttestationWitness;
    use spc_lib::domain;
    use spc_lib::hasher::{hash_1, hash_2, hash_4, hash_5};
    use spc_lib::merkle;
    use spc_lib::policy;
    use spc_lib::policy_tag;
    use spc_lib::state;
    use spc_lib::tx_facts::TxFacts;

    fn no_cn_indices() -> [bool; domain::MAX_COMMITMENT_TREE_DEPTH] {
        [false; domain::MAX_COMMITMENT_TREE_DEPTH]
    }

    fn no_cn_path() -> [Field; domain::MAX_COMMITMENT_TREE_DEPTH] {
        [0; domain::MAX_COMMITMENT_TREE_DEPTH]
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

    // Every pubkey the test screens shares one attester, one revocation
    // slot, and one attestation tree so every attestation instance verifies
    // against the same pair of roots.
    struct Cohort {
        attestation_root: Field,
        attester_revocation_root: Field,
        attester: Field,
        revoked_at: u64,
    }

    fn cohort_for(pubkeys: [Field; 3]) -> Cohort {
        let attester: Field = 0xfeed;
        let generation: u64 = 1;
        let issued_at: u64 = 1_700_000_000;
        let expires_at: u64 = 200 * domain::EPOCH_SECONDS;

        // Depth-2 tree over the three screened pubkeys, sibling positions
        // filled with zero leaves.
        let leaf_0 = hash_5([
            pubkeys[0],
            attester,
            generation as Field,
            issued_at as Field,
            expires_at as Field,
        ]);
        let leaf_1 = hash_5([
            pubkeys[1],
            attester,
            generation as Field,
            issued_at as Field,
            expires_at as Field,
        ]);
        let leaf_2 = hash_5([
            pubkeys[2],
            attester,
            generation as Field,
            issued_at as Field,
            expires_at as Field,
        ]);
        let node_01 = hash_2([leaf_0, leaf_1]);
        let attestation_root = hash_2([node_01, leaf_2]);

        let revoked_at: u64 = 0xffffffffffffffff;
        let rev_leaf = hash_2([attester, revoked_at as Field]);
        let rev_indices = no_rev_indices();
        let rev_path = no_rev_path();
        let attester_revocation_root = merkle::binary_merkle_root(
            hash_2,
            rev_leaf,
            domain::ATTESTER_TREE_DEPTH,
            rev_indices,
            rev_path,
        );

        Cohort { attestation_root, attester_revocation_root, attester, revoked_at }
    }

    struct Fixture {
        nullifier_0: Field,
        nullifier_1: Field,
        commitment_out_0: Field,
        commitment_out_1: Field,
        commitment_root: Field,
        velocity_nullifier: Field,
        compliance_commitment_out: Field,
        epoch: u64,
        epoch_seconds: u64,
        policy_source_hash: Field,
        attestation_root: Field,
        attester_revocation_root: Field,
        min_accepted_generation: u64,
        payload_commitment: Field,
        spending_key: Field,
        token_in_0: Field,
        amount_in_0: u64,
        salt_in_0: Field,
        token_in_1: Field,
        amount_in_1: u64,
        salt_in_1: Field,
        token_out_0: Field,
        amount_out_0: u64,
        owner_out_0: Field,
        salt_out_0: Field,
        token_out_1: Field,
        amount_out_1: u64,
        owner_out_1: Field,
        salt_out_1: Field,
        proof_length_0: u32,
        proof_length_1: u32,
        path_0: [Field; domain::MAX_COMMITMENT_TREE_DEPTH],
        indices_0: [bool; domain::MAX_COMMITMENT_TREE_DEPTH],
        path_1: [Field; domain::MAX_COMMITMENT_TREE_DEPTH],
        indices_1: [bool; domain::MAX_COMMITMENT_TREE_DEPTH],
        subject_attestation: AttestationWitness,
        out0_attestation: AttestationWitness,
        out1_attestation: AttestationWitness,
        seq: u64,
        epoch_in: u64,
        prev: policy::State,
        flags_in: u64,
        cp_in: [Field; 2],
        amt_in: [u64; 2],
        exit_in: Field,
        salt_in: Field,
        salt_out: Field,
        cn_proof_length: u32,
        cn_indices: [bool; domain::MAX_COMMITMENT_TREE_DEPTH],
        cn_path: [Field; domain::MAX_COMMITMENT_TREE_DEPTH],
    }

    // Two real inputs (600 + 400), one output to a recipient (700), change
    // (300) back to the subject.
    fn valid_fixture() -> Fixture {
        let spending_key: Field = 0xdeadbeef;
        let owner_pubkey = hash_1([spending_key]);
        let token: Field = 0x1234567890abcdef1234567890abcdef12345678;
        let epoch: u64 = 100;

        let amount_in_0: u64 = 600;
        let salt_in_0: Field = 0xaaaa;
        let amount_in_1: u64 = 400;
        let salt_in_1: Field = 0xbbbb;

        let recipient_key: Field = 0xcafe;
        let owner_out_0 = hash_1([recipient_key]);
        let amount_out_0: u64 = 700;
        let salt_out_0: Field = 0xcccc;
        let owner_out_1 = owner_pubkey; // change
        let amount_out_1: u64 = 300;
        let salt_out_1: Field = 0xdddd;

        let commitment_in_0 = hash_4([token, amount_in_0 as Field, owner_pubkey, salt_in_0]);
        let commitment_in_1 = hash_4([token, amount_in_1 as Field, owner_pubkey, salt_in_1]);
        let nullifier_0 = hash_2([commitment_in_0, spending_key]);
        let nullifier_1 = hash_2([commitment_in_1, spending_key]);

        let commitment_out_0 = hash_4([token, amount_out_0 as Field, owner_out_0, salt_out_0]);
        let commitment_out_1 = hash_4([token, amount_out_1 as Field, owner_out_1, salt_out_1]);

        let proof_length_0: u32 = 1;
        let proof_length_1: u32 = 1;
        let node_01 = hash_2([commitment_in_0, commitment_in_1]);
        let mut path_0 = [0; domain::MAX_COMMITMENT_TREE_DEPTH];
        let indices_0 = [false; domain::MAX_COMMITMENT_TREE_DEPTH];
        path_0[0] = commitment_in_1;
        let mut path_1 = [0; domain::MAX_COMMITMENT_TREE_DEPTH];
        let mut indices_1 = [false; domain::MAX_COMMITMENT_TREE_DEPTH];
        path_1[0] = commitment_in_0;
        indices_1[0] = true;
        let commitment_root = node_01;

        let cohort = cohort_for([owner_pubkey, owner_out_0, owner_out_1]);
        let leaf_0 = hash_5([
            owner_pubkey,
            cohort.attester,
            1,
            1_700_000_000,
            200 * domain::EPOCH_SECONDS as Field,
        ]);
        let leaf_1 = hash_5([
            owner_out_0,
            cohort.attester,
            1,
            1_700_000_000,
            200 * domain::EPOCH_SECONDS as Field,
        ]);
        let leaf_2 = hash_5([
            owner_out_1,
            cohort.attester,
            1,
            1_700_000_000,
            200 * domain::EPOCH_SECONDS as Field,
        ]);
        let node_att_01 = hash_2([leaf_0, leaf_1]);

        // subject at position 0 of the {0,1} pair, sibling leaf_1, then
        // sibling leaf_2 at depth 1.
        let subject_att_indices = no_att_indices();
        let mut subject_att_path = no_att_path();
        subject_att_path[0] = leaf_1;
        subject_att_path[1] = leaf_2;

        let mut out0_att_indices = no_att_indices();
        let mut out0_att_path = no_att_path();
        out0_att_indices[0] = true;
        out0_att_path[0] = leaf_0;
        out0_att_path[1] = leaf_2;

        let mut out1_att_indices = no_att_indices();
        let mut out1_att_path = no_att_path();
        out1_att_indices[0] = true;
        out1_att_path[0] = node_att_01;

        let subject_attestation = AttestationWitness {
            attester: cohort.attester,
            generation: 1,
            issued_at: 1_700_000_000,
            expires_at: 200 * domain::EPOCH_SECONDS,
            att_proof_length: 2,
            att_indices: subject_att_indices,
            att_path: subject_att_path,
            revoked_at: cohort.revoked_at,
            rev_indices: no_rev_indices(),
            rev_path: no_rev_path(),
        };
        let out0_attestation = AttestationWitness {
            attester: cohort.attester,
            generation: 1,
            issued_at: 1_700_000_000,
            expires_at: 200 * domain::EPOCH_SECONDS,
            att_proof_length: 2,
            att_indices: out0_att_indices,
            att_path: out0_att_path,
            revoked_at: cohort.revoked_at,
            rev_indices: no_rev_indices(),
            rev_path: no_rev_path(),
        };
        let out1_attestation = AttestationWitness {
            attester: cohort.attester,
            generation: 1,
            issued_at: 1_700_000_000,
            expires_at: 200 * domain::EPOCH_SECONDS,
            att_proof_length: 1,
            att_indices: out1_att_indices,
            att_path: out1_att_path,
            revoked_at: cohort.revoked_at,
            rev_indices: no_rev_indices(),
            rev_path: no_rev_path(),
        };

        let seq: u64 = 0;
        let prev = policy::zero();
        let flags_in: u64 = 0;
        let salt_out: Field = 0x1111;

        let tx = TxFacts {
            epoch,
            seq,
            token,
            subject: owner_pubkey,
            counterparty: [owner_out_0, owner_out_1],
            value_in: 0,
            value_out: amount_out_0, // only owner_out_0 is a non-subject recipient
            exit: domain::NO_EXIT,
        };
        let next = policy::advance(prev, tx);
        let flags_out = policy::evaluate(tx, prev, next);
        let facts_out = hash_5([
            owner_out_0,
            amount_out_0 as Field,
            owner_out_1,
            amount_out_1 as Field,
            domain::NO_EXIT,
        ]);
        let state_out = hash_5([
            epoch as Field,
            1,
            state::commit(policy_tag::STATE_TAG, next),
            flags_out as Field,
            facts_out,
        ]);
        let compliance_commitment_out = hash_4([domain::CN_TAG, owner_pubkey, state_out, salt_out]);
        let velocity_nullifier = hash_4([domain::VN_TAG, spending_key, epoch as Field, 0]);

        Fixture {
            nullifier_0,
            nullifier_1,
            commitment_out_0,
            commitment_out_1,
            commitment_root,
            velocity_nullifier,
            compliance_commitment_out,
            epoch,
            epoch_seconds: domain::EPOCH_SECONDS,
            policy_source_hash: policy_tag::POLICY_SOURCE_HASH,
            attestation_root: cohort.attestation_root,
            attester_revocation_root: cohort.attester_revocation_root,
            min_accepted_generation: 1,
            payload_commitment: 0,
            spending_key,
            token_in_0: token,
            amount_in_0,
            salt_in_0,
            token_in_1: token,
            amount_in_1,
            salt_in_1,
            token_out_0: token,
            amount_out_0,
            owner_out_0,
            salt_out_0,
            token_out_1: token,
            amount_out_1,
            owner_out_1,
            salt_out_1,
            proof_length_0,
            proof_length_1,
            path_0,
            indices_0,
            path_1,
            indices_1,
            subject_attestation,
            out0_attestation,
            out1_attestation,
            seq,
            epoch_in: epoch,
            prev,
            flags_in,
            cp_in: [domain::NO_COUNTERPARTY, domain::NO_COUNTERPARTY],
            amt_in: [0, 0],
            exit_in: domain::NO_EXIT,
            salt_in: 0,
            salt_out,
            cn_proof_length: 0,
            cn_indices: no_cn_indices(),
            cn_path: no_cn_path(),
        }
    }

    fn run_fixture(f: Fixture) {
        main(
            f.nullifier_0,
            f.nullifier_1,
            f.commitment_out_0,
            f.commitment_out_1,
            f.commitment_root,
            f.velocity_nullifier,
            f.compliance_commitment_out,
            f.epoch,
            f.epoch_seconds,
            f.policy_source_hash,
            f.attestation_root,
            f.attester_revocation_root,
            f.min_accepted_generation,
            f.payload_commitment,
            f.spending_key,
            f.token_in_0,
            f.amount_in_0,
            f.salt_in_0,
            f.token_in_1,
            f.amount_in_1,
            f.salt_in_1,
            f.token_out_0,
            f.amount_out_0,
            f.owner_out_0,
            f.salt_out_0,
            f.token_out_1,
            f.amount_out_1,
            f.owner_out_1,
            f.salt_out_1,
            f.proof_length_0,
            f.proof_length_1,
            f.path_0,
            f.indices_0,
            f.path_1,
            f.indices_1,
            f.subject_attestation,
            f.out0_attestation,
            f.out1_attestation,
            f.seq,
            f.epoch_in,
            f.prev,
            f.flags_in,
            f.cp_in,
            f.amt_in,
            f.exit_in,
            f.salt_in,
            f.salt_out,
            f.cn_proof_length,
            f.cn_indices,
            f.cn_path,
        );
    }

    #[test]
    fn test_transfer_happy_path() {
        run_fixture(valid_fixture());
    }

    #[test]
    fn test_transfer_two_inputs_unequal_depth_happy_path() {
        // Both inputs are real, co-resident notes at different LeanIMT depths:
        // commitment_in_0 pairs with a filler leaf at depth 0, commitment_in_1
        // has no sibling at that level and is promoted straight to depth 1.
        let mut f = valid_fixture();
        let owner_pubkey = hash_1([f.spending_key]);
        let commitment_in_0 = hash_4([
            f.token_in_0,
            f.amount_in_0 as Field,
            owner_pubkey,
            f.salt_in_0,
        ]);
        let commitment_in_1 = hash_4([
            f.token_in_1,
            f.amount_in_1 as Field,
            owner_pubkey,
            f.salt_in_1,
        ]);

        let filler_leaf: Field = 0x5555;
        let node_01 = hash_2([commitment_in_0, filler_leaf]);
        f.commitment_root = hash_2([node_01, commitment_in_1]);

        f.proof_length_0 = 2;
        f.path_0 = [0; domain::MAX_COMMITMENT_TREE_DEPTH];
        f.indices_0 = [false; domain::MAX_COMMITMENT_TREE_DEPTH];
        f.path_0[0] = filler_leaf;
        f.path_0[1] = commitment_in_1;

        f.proof_length_1 = 1;
        f.path_1 = [0; domain::MAX_COMMITMENT_TREE_DEPTH];
        f.indices_1 = [false; domain::MAX_COMMITMENT_TREE_DEPTH];
        f.path_1[0] = node_01;
        f.indices_1[0] = true;

        assert(f.proof_length_0 != f.proof_length_1);
        run_fixture(f);
    }

    #[test(should_fail)]
    fn test_transfer_unscreened_owner_out_1_fails() {
        // owner_out_1 set to an unattested sentinel: the unconditional third
        // attestation instance has no leaf to open.
        let mut f = valid_fixture();
        f.owner_out_1 = domain::NO_COUNTERPARTY;
        f.commitment_out_1 = hash_4([
            f.token_out_1,
            f.amount_out_1 as Field,
            f.owner_out_1,
            f.salt_out_1,
        ]);
        run_fixture(f);
    }

    #[test(should_fail)]
    fn test_transfer_value_out_omits_non_subject_output_fails() {
        // compliance_commitment_out was minted assuming value_out ==
        // amount_out_0 (700); the circuit itself recomputes value_out from
        // owner_out_0/owner_out_1, so a forged compliance_commitment_out
        // that used a smaller total fails the final equality.
        let mut f = valid_fixture();
        let owner_pubkey = hash_1([f.spending_key]);
        let tx = TxFacts {
            epoch: f.epoch,
            seq: f.seq,
            token: f.token_in_0,
            subject: owner_pubkey,
            counterparty: [f.owner_out_0, f.owner_out_1],
            value_in: 0,
            value_out: 0, // omits amount_out_0
            exit: domain::NO_EXIT,
        };
        let next = policy::advance(f.prev, tx);
        let flags_out = policy::evaluate(tx, f.prev, next);
        let facts_out = hash_5([
            f.owner_out_0,
            f.amount_out_0 as Field,
            f.owner_out_1,
            f.amount_out_1 as Field,
            domain::NO_EXIT,
        ]);
        let state_out = hash_5([
            f.epoch as Field,
            1,
            state::commit(policy_tag::STATE_TAG, next),
            flags_out as Field,
            facts_out,
        ]);
        f.compliance_commitment_out = hash_4([domain::CN_TAG, owner_pubkey, state_out, f.salt_out]);
        run_fixture(f);
    }

    #[test(should_fail)]
    fn test_transfer_mismatched_policy_source_hash_fails() {
        let mut f = valid_fixture();
        f.policy_source_hash = f.policy_source_hash + 1;
        run_fixture(f);
    }

    #[test(should_fail)]
    fn test_transfer_token_at_2_pow_160_fails() {
        let mut f = valid_fixture();
        let two_pow_160: Field = 1461501637330902918203684832716283019655932542976;
        f.token_in_0 = two_pow_160;
        f.token_in_1 = two_pow_160;
        f.token_out_0 = two_pow_160;
        f.token_out_1 = two_pow_160;
        let owner_pubkey = hash_1([f.spending_key]);
        f.nullifier_0 = hash_2([
            hash_4(
                [two_pow_160, f.amount_in_0 as Field, owner_pubkey, f.salt_in_0],
            ),
            f.spending_key,
        ]);
        f.nullifier_1 = hash_2([
            hash_4(
                [two_pow_160, f.amount_in_1 as Field, owner_pubkey, f.salt_in_1],
            ),
            f.spending_key,
        ]);
        f.commitment_out_0 = hash_4([
            two_pow_160,
            f.amount_out_0 as Field,
            f.owner_out_0,
            f.salt_out_0,
        ]);
        f.commitment_out_1 = hash_4([
            two_pow_160,
            f.amount_out_1 as Field,
            f.owner_out_1,
            f.salt_out_1,
        ]);
        run_fixture(f);
    }

    #[test(should_fail)]
    fn test_transfer_reused_seq_fails() {
        let mut f = valid_fixture();
        f.prev = policy::State { s: [7] };
        run_fixture(f);
    }

    #[test]
    fn test_transfer_zero_note_padding_happy_path() {
        let spending_key: Field = 0xdeadbeef;
        let owner_pubkey = hash_1([spending_key]);
        let token: Field = 0x1234567890abcdef1234567890abcdef12345678;
        let epoch: u64 = 100;

        let amount_in_0: u64 = 1000;
        let salt_in_0: Field = 0xaaaa;
        let amount_in_1: u64 = 0;
        let salt_in_1: Field = 0xbbbb;

        let recipient_key: Field = 0xcafe;
        let owner_out_0 = hash_1([recipient_key]);
        let amount_out_0: u64 = 700;
        let salt_out_0: Field = 0xcccc;
        let owner_out_1 = owner_pubkey;
        let amount_out_1: u64 = 300;
        let salt_out_1: Field = 0xdddd;

        let commitment_in_0 = hash_4([token, amount_in_0 as Field, owner_pubkey, salt_in_0]);
        let commitment_in_1 = hash_4([token, amount_in_1 as Field, owner_pubkey, salt_in_1]);
        let nullifier_0 = hash_2([commitment_in_0, spending_key]);
        let nullifier_1 = hash_2([commitment_in_1, spending_key]);

        let commitment_out_0 = hash_4([token, amount_out_0 as Field, owner_out_0, salt_out_0]);
        let commitment_out_1 = hash_4([token, amount_out_1 as Field, owner_out_1, salt_out_1]);

        let proof_length_0: u32 = 1;
        let proof_length_1: u32 = 0;
        let mut path_0 = [0; domain::MAX_COMMITMENT_TREE_DEPTH];
        let indices_0 = [false; domain::MAX_COMMITMENT_TREE_DEPTH];
        path_0[0] = 0x5555;
        let commitment_root = hash_2([commitment_in_0, 0x5555]);
        // Zero note is not in the tree; its proof is never checked.
        let path_1 = [0; domain::MAX_COMMITMENT_TREE_DEPTH];
        let indices_1 = [false; domain::MAX_COMMITMENT_TREE_DEPTH];

        let cohort = cohort_for([owner_pubkey, owner_out_0, owner_out_1]);
        let leaf_0 = hash_5([
            owner_pubkey,
            cohort.attester,
            1,
            1_700_000_000,
            200 * domain::EPOCH_SECONDS as Field,
        ]);
        let leaf_1 = hash_5([
            owner_out_0,
            cohort.attester,
            1,
            1_700_000_000,
            200 * domain::EPOCH_SECONDS as Field,
        ]);
        let leaf_2 = hash_5([
            owner_out_1,
            cohort.attester,
            1,
            1_700_000_000,
            200 * domain::EPOCH_SECONDS as Field,
        ]);
        let node_att_01 = hash_2([leaf_0, leaf_1]);

        let subject_att_indices = no_att_indices();
        let mut subject_att_path = no_att_path();
        subject_att_path[0] = leaf_1;
        subject_att_path[1] = leaf_2;

        let mut out0_att_indices = no_att_indices();
        let mut out0_att_path = no_att_path();
        out0_att_indices[0] = true;
        out0_att_path[0] = leaf_0;
        out0_att_path[1] = leaf_2;

        let mut out1_att_indices = no_att_indices();
        let mut out1_att_path = no_att_path();
        out1_att_indices[0] = true;
        out1_att_path[0] = node_att_01;

        let subject_attestation = AttestationWitness {
            attester: cohort.attester,
            generation: 1,
            issued_at: 1_700_000_000,
            expires_at: 200 * domain::EPOCH_SECONDS,
            att_proof_length: 2,
            att_indices: subject_att_indices,
            att_path: subject_att_path,
            revoked_at: cohort.revoked_at,
            rev_indices: no_rev_indices(),
            rev_path: no_rev_path(),
        };
        let out0_attestation = AttestationWitness {
            attester: cohort.attester,
            generation: 1,
            issued_at: 1_700_000_000,
            expires_at: 200 * domain::EPOCH_SECONDS,
            att_proof_length: 2,
            att_indices: out0_att_indices,
            att_path: out0_att_path,
            revoked_at: cohort.revoked_at,
            rev_indices: no_rev_indices(),
            rev_path: no_rev_path(),
        };
        let out1_attestation = AttestationWitness {
            attester: cohort.attester,
            generation: 1,
            issued_at: 1_700_000_000,
            expires_at: 200 * domain::EPOCH_SECONDS,
            att_proof_length: 1,
            att_indices: out1_att_indices,
            att_path: out1_att_path,
            revoked_at: cohort.revoked_at,
            rev_indices: no_rev_indices(),
            rev_path: no_rev_path(),
        };

        let seq: u64 = 0;
        let prev = policy::zero();
        let salt_out: Field = 0x1111;

        let tx = TxFacts {
            epoch,
            seq,
            token,
            subject: owner_pubkey,
            counterparty: [owner_out_0, owner_out_1],
            value_in: 0,
            value_out: amount_out_0,
            exit: domain::NO_EXIT,
        };
        let next = policy::advance(prev, tx);
        let flags_out = policy::evaluate(tx, prev, next);
        let facts_out = hash_5([
            owner_out_0,
            amount_out_0 as Field,
            owner_out_1,
            amount_out_1 as Field,
            domain::NO_EXIT,
        ]);
        let state_out = hash_5([
            epoch as Field,
            1,
            state::commit(policy_tag::STATE_TAG, next),
            flags_out as Field,
            facts_out,
        ]);
        let compliance_commitment_out = hash_4([domain::CN_TAG, owner_pubkey, state_out, salt_out]);
        let velocity_nullifier = hash_4([domain::VN_TAG, spending_key, epoch as Field, 0]);

        main(
            nullifier_0,
            nullifier_1,
            commitment_out_0,
            commitment_out_1,
            commitment_root,
            velocity_nullifier,
            compliance_commitment_out,
            epoch,
            domain::EPOCH_SECONDS,
            policy_tag::POLICY_SOURCE_HASH,
            cohort.attestation_root,
            cohort.attester_revocation_root,
            1,
            0,
            spending_key,
            token,
            amount_in_0,
            salt_in_0,
            token,
            amount_in_1,
            salt_in_1,
            token,
            amount_out_0,
            owner_out_0,
            salt_out_0,
            token,
            amount_out_1,
            owner_out_1,
            salt_out_1,
            proof_length_0,
            proof_length_1,
            path_0,
            indices_0,
            path_1,
            indices_1,
            subject_attestation,
            out0_attestation,
            out1_attestation,
            seq,
            epoch,
            prev,
            0,
            [domain::NO_COUNTERPARTY, domain::NO_COUNTERPARTY],
            [0, 0],
            domain::NO_EXIT,
            0,
            salt_out,
            0,
            no_cn_indices(),
            no_cn_path(),
        );
    }

    #[test(should_fail)]
    fn test_transfer_zero_note_unconstrained_nullifier_1_fails() {
        let spending_key: Field = 0xdeadbeef;
        let owner_pubkey = hash_1([spending_key]);
        let token: Field = 0x1234567890abcdef1234567890abcdef12345678;
        let epoch: u64 = 100;

        let amount_in_0: u64 = 1000;
        let salt_in_0: Field = 0xaaaa;
        let amount_in_1: u64 = 0;
        let salt_in_1: Field = 0xbbbb;

        let recipient_key: Field = 0xcafe;
        let owner_out_0 = hash_1([recipient_key]);
        let amount_out_0: u64 = 700;
        let salt_out_0: Field = 0xcccc;
        let owner_out_1 = owner_pubkey;
        let amount_out_1: u64 = 300;
        let salt_out_1: Field = 0xdddd;

        let commitment_in_0 = hash_4([token, amount_in_0 as Field, owner_pubkey, salt_in_0]);
        let nullifier_0 = hash_2([commitment_in_0, spending_key]);
        // Arbitrary value in place of Poseidon1(commitment_in_1, spending_key).
        let nullifier_1: Field = 0xdeadbeefcafebabe;

        let commitment_out_0 = hash_4([token, amount_out_0 as Field, owner_out_0, salt_out_0]);
        let commitment_out_1 = hash_4([token, amount_out_1 as Field, owner_out_1, salt_out_1]);

        let proof_length_0: u32 = 1;
        let proof_length_1: u32 = 0;
        let mut path_0 = [0; domain::MAX_COMMITMENT_TREE_DEPTH];
        let indices_0 = [false; domain::MAX_COMMITMENT_TREE_DEPTH];
        path_0[0] = 0x5555;
        let commitment_root = hash_2([commitment_in_0, 0x5555]);
        let path_1 = [0; domain::MAX_COMMITMENT_TREE_DEPTH];
        let indices_1 = [false; domain::MAX_COMMITMENT_TREE_DEPTH];

        let cohort = cohort_for([owner_pubkey, owner_out_0, owner_out_1]);
        let leaf_0 = hash_5([
            owner_pubkey,
            cohort.attester,
            1,
            1_700_000_000,
            200 * domain::EPOCH_SECONDS as Field,
        ]);
        let leaf_1 = hash_5([
            owner_out_0,
            cohort.attester,
            1,
            1_700_000_000,
            200 * domain::EPOCH_SECONDS as Field,
        ]);
        let leaf_2 = hash_5([
            owner_out_1,
            cohort.attester,
            1,
            1_700_000_000,
            200 * domain::EPOCH_SECONDS as Field,
        ]);
        let node_att_01 = hash_2([leaf_0, leaf_1]);

        let subject_att_indices = no_att_indices();
        let mut subject_att_path = no_att_path();
        subject_att_path[0] = leaf_1;
        subject_att_path[1] = leaf_2;

        let mut out0_att_indices = no_att_indices();
        let mut out0_att_path = no_att_path();
        out0_att_indices[0] = true;
        out0_att_path[0] = leaf_0;
        out0_att_path[1] = leaf_2;

        let mut out1_att_indices = no_att_indices();
        let mut out1_att_path = no_att_path();
        out1_att_indices[0] = true;
        out1_att_path[0] = node_att_01;

        let subject_attestation = AttestationWitness {
            attester: cohort.attester,
            generation: 1,
            issued_at: 1_700_000_000,
            expires_at: 200 * domain::EPOCH_SECONDS,
            att_proof_length: 2,
            att_indices: subject_att_indices,
            att_path: subject_att_path,
            revoked_at: cohort.revoked_at,
            rev_indices: no_rev_indices(),
            rev_path: no_rev_path(),
        };
        let out0_attestation = AttestationWitness {
            attester: cohort.attester,
            generation: 1,
            issued_at: 1_700_000_000,
            expires_at: 200 * domain::EPOCH_SECONDS,
            att_proof_length: 2,
            att_indices: out0_att_indices,
            att_path: out0_att_path,
            revoked_at: cohort.revoked_at,
            rev_indices: no_rev_indices(),
            rev_path: no_rev_path(),
        };
        let out1_attestation = AttestationWitness {
            attester: cohort.attester,
            generation: 1,
            issued_at: 1_700_000_000,
            expires_at: 200 * domain::EPOCH_SECONDS,
            att_proof_length: 1,
            att_indices: out1_att_indices,
            att_path: out1_att_path,
            revoked_at: cohort.revoked_at,
            rev_indices: no_rev_indices(),
            rev_path: no_rev_path(),
        };

        let seq: u64 = 0;
        let prev = policy::zero();
        let salt_out: Field = 0x1111;

        let tx = TxFacts {
            epoch,
            seq,
            token,
            subject: owner_pubkey,
            counterparty: [owner_out_0, owner_out_1],
            value_in: 0,
            value_out: amount_out_0,
            exit: domain::NO_EXIT,
        };
        let next = policy::advance(prev, tx);
        let flags_out = policy::evaluate(tx, prev, next);
        let facts_out = hash_5([
            owner_out_0,
            amount_out_0 as Field,
            owner_out_1,
            amount_out_1 as Field,
            domain::NO_EXIT,
        ]);
        let state_out = hash_5([
            epoch as Field,
            1,
            state::commit(policy_tag::STATE_TAG, next),
            flags_out as Field,
            facts_out,
        ]);
        let compliance_commitment_out = hash_4([domain::CN_TAG, owner_pubkey, state_out, salt_out]);
        let velocity_nullifier = hash_4([domain::VN_TAG, spending_key, epoch as Field, 0]);

        main(
            nullifier_0,
            nullifier_1,
            commitment_out_0,
            commitment_out_1,
            commitment_root,
            velocity_nullifier,
            compliance_commitment_out,
            epoch,
            domain::EPOCH_SECONDS,
            policy_tag::POLICY_SOURCE_HASH,
            cohort.attestation_root,
            cohort.attester_revocation_root,
            1,
            0,
            spending_key,
            token,
            amount_in_0,
            salt_in_0,
            token,
            amount_in_1,
            salt_in_1,
            token,
            amount_out_0,
            owner_out_0,
            salt_out_0,
            token,
            amount_out_1,
            owner_out_1,
            salt_out_1,
            proof_length_0,
            proof_length_1,
            path_0,
            indices_0,
            path_1,
            indices_1,
            subject_attestation,
            out0_attestation,
            out1_attestation,
            seq,
            epoch,
            prev,
            0,
            [domain::NO_COUNTERPARTY, domain::NO_COUNTERPARTY],
            [0, 0],
            domain::NO_EXIT,
            0,
            salt_out,
            0,
            no_cn_indices(),
            no_cn_path(),
        );
    }
}

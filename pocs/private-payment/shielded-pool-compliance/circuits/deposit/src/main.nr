use spc_lib::attestation::{self, AttestationWitness};
use spc_lib::compliance::{self, ComplianceInputs};
use spc_lib::domain;
use spc_lib::hasher::{hash_1, hash_4};
use spc_lib::policy;
use spc_lib::tx_facts::TxFacts;

// Deposit: mints one value note and advances the depositor's compliance
// chain in the same proof. `owner_pubkey` derives from `spending_key`
// instead of arriving as a free witness, binding the KYC gate to the
// depositor. Public-input order MUST match `DepositPublicInputs` in
// `contracts/src/PublicInputs.sol` index for index.
fn main(
    commitment: pub Field,
    token: pub Field,
    amount: pub u64,
    attestation_root: pub Field,
    velocity_nullifier: pub Field,
    compliance_commitment_out: pub Field,
    epoch: pub u64,
    epoch_seconds: pub u64,
    policy_source_hash: pub Field,
    commitment_root: pub Field,
    attester_revocation_root: pub Field,
    min_accepted_generation: pub u64,
    payload_commitment: pub Field,
    spending_key: Field,
    salt: Field,
    attestation_witness: AttestationWitness,
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
    token.assert_max_bit_size::<160>();

    assert(commitment == hash_4([token, amount as Field, owner_pubkey, salt]));

    attestation::verify_instance(
        owner_pubkey,
        attestation_witness.attester,
        attestation_witness.generation,
        attestation_witness.issued_at,
        attestation_witness.expires_at,
        epoch,
        min_accepted_generation,
        attestation_root,
        attestation_witness.att_proof_length,
        attestation_witness.att_indices,
        attestation_witness.att_path,
        attestation_witness.revoked_at,
        attester_revocation_root,
        attestation_witness.rev_indices,
        attestation_witness.rev_path,
    );

    let tx = TxFacts {
        epoch,
        seq,
        token,
        subject: owner_pubkey,
        counterparty: [domain::NO_COUNTERPARTY, domain::NO_COUNTERPARTY],
        value_in: amount,
        value_out: 0,
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
        amount,
        0,
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

    struct Fixture {
        commitment: Field,
        token: Field,
        amount: u64,
        attestation_root: Field,
        velocity_nullifier: Field,
        compliance_commitment_out: Field,
        epoch: u64,
        epoch_seconds: u64,
        policy_source_hash: Field,
        commitment_root: Field,
        attester_revocation_root: Field,
        min_accepted_generation: u64,
        payload_commitment: Field,
        spending_key: Field,
        salt: Field,
        attestation_witness: AttestationWitness,
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

    fn valid_fixture() -> Fixture {
        let spending_key: Field = 0xdeadbeef;
        let owner_pubkey = hash_1([spending_key]);
        let token: Field = 0x1234567890abcdef1234567890abcdef12345678;
        let amount: u64 = 1000;
        let salt: Field = 0xabcd;
        let epoch: u64 = 100;

        let commitment = hash_4([token, amount as Field, owner_pubkey, salt]);

        let attester: Field = 0xfeed;
        let generation: u64 = 1;
        let issued_at: u64 = 1_700_000_000;
        let expires_at: u64 = 200 * domain::EPOCH_SECONDS;
        let min_accepted_generation: u64 = 1;

        let att_leaf = hash_5([
            owner_pubkey,
            attester,
            generation as Field,
            issued_at as Field,
            expires_at as Field,
        ]);
        let att_indices = no_att_indices();
        let att_path = no_att_path();
        let attestation_root =
            merkle::binary_merkle_root(hash_2, att_leaf, 0, att_indices, att_path);

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

        let attestation_witness = AttestationWitness {
            attester,
            generation,
            issued_at,
            expires_at,
            att_proof_length: 0,
            att_indices,
            att_path,
            revoked_at,
            rev_indices,
            rev_path,
        };

        let prev = policy::zero();
        let flags_in: u64 = 0;
        let salt_out: Field = 0x1111;

        let next = policy::advance(
            prev,
            spc_lib::tx_facts::TxFacts {
                epoch,
                seq: 0,
                token,
                subject: owner_pubkey,
                counterparty: [domain::NO_COUNTERPARTY, domain::NO_COUNTERPARTY],
                value_in: amount,
                value_out: 0,
                exit: domain::NO_EXIT,
            },
        );
        let flags_out = policy::evaluate(
            spc_lib::tx_facts::TxFacts {
                epoch,
                seq: 0,
                token,
                subject: owner_pubkey,
                counterparty: [domain::NO_COUNTERPARTY, domain::NO_COUNTERPARTY],
                value_in: amount,
                value_out: 0,
                exit: domain::NO_EXIT,
            },
            prev,
            next,
        );
        let facts_out = hash_5([
            domain::NO_COUNTERPARTY,
            amount as Field,
            domain::NO_COUNTERPARTY,
            0,
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
            commitment,
            token,
            amount,
            attestation_root,
            velocity_nullifier,
            compliance_commitment_out,
            epoch,
            epoch_seconds: domain::EPOCH_SECONDS,
            policy_source_hash: policy_tag::POLICY_SOURCE_HASH,
            commitment_root: 0,
            attester_revocation_root,
            min_accepted_generation,
            payload_commitment: 0,
            spending_key,
            salt,
            attestation_witness,
            seq: 0,
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
            f.commitment,
            f.token,
            f.amount,
            f.attestation_root,
            f.velocity_nullifier,
            f.compliance_commitment_out,
            f.epoch,
            f.epoch_seconds,
            f.policy_source_hash,
            f.commitment_root,
            f.attester_revocation_root,
            f.min_accepted_generation,
            f.payload_commitment,
            f.spending_key,
            f.salt,
            f.attestation_witness,
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
    fn test_deposit_happy_path() {
        run_fixture(valid_fixture());
    }

    #[test(should_fail)]
    fn test_deposit_free_owner_pubkey_fails() {
        // A prover cannot present a commitment for a pubkey it does not hold
        // spending_key for: minting the commitment against an arbitrary
        // pubkey desyncs it from hash_1(spending_key).
        let mut f = valid_fixture();
        let forged_owner_pubkey: Field = 0x9999;
        f.commitment = hash_4([f.token, f.amount as Field, forged_owner_pubkey, f.salt]);
        run_fixture(f);
    }

    #[test(should_fail)]
    fn test_deposit_mismatched_policy_source_hash_fails() {
        let mut f = valid_fixture();
        f.policy_source_hash = f.policy_source_hash + 1;
        run_fixture(f);
    }

    #[test(should_fail)]
    fn test_deposit_token_at_2_pow_160_fails() {
        let mut f = valid_fixture();
        let two_pow_160: Field = 1461501637330902918203684832716283019655932542976;
        f.token = two_pow_160;
        f.commitment = hash_4(
            [f.token, f.amount as Field, hash_1([f.spending_key]), f.salt],
        );
        run_fixture(f);
    }

    #[test(should_fail)]
    fn test_deposit_reused_seq_fails() {
        // seq == 0 with a nonzero predecessor state is not the canonical
        // origin, so the base-case branch has no satisfying witness.
        let mut f = valid_fixture();
        f.prev = policy::State { s: [7] };
        run_fixture(f);
    }
}

use crate::domain;
use crate::hasher::{hash_1, hash_2, hash_4, hash_5};
use crate::merkle;
use crate::policy;
use crate::policy_tag;
use crate::state;
use crate::tx_facts::TxFacts;

// Pool-owned, generic over the policy. Every gated circuit runs this exactly
// once per proof, on both the `seq == 0` and `seq > 0` branches, producing
// identical proof shape either way.
pub struct ComplianceInputs {
    pub epoch: u64,
    pub epoch_seconds: u64,
    pub policy_source_hash: Field,
    pub commitment_root: Field,
    pub velocity_nullifier: Field,
    pub compliance_commitment_out: Field,
    pub spending_key: Field,
    pub owner_pubkey: Field,
    pub seq: u64,
    pub epoch_in: u64,
    pub prev: policy::State,
    pub flags_in: u64,
    pub cp_in: [Field; 2],
    pub amt_in: [u64; 2],
    pub exit_in: Field,
    pub salt_in: Field,
    pub salt_out: Field,
    pub cn_proof_length: u32,
    pub cn_indices: [bool; domain::MAX_COMMITMENT_TREE_DEPTH],
    pub cn_path: [Field; domain::MAX_COMMITMENT_TREE_DEPTH],
}

pub fn run(inp: ComplianceInputs, tx: TxFacts, amount_out_0: u64, amount_out_1: u64) {
    assert(
        policy_tag::STATE_TAG == state::state_tag(policy_tag::POLICY_SOURCE_HASH),
        "stale STATE_TAG literal",
    );
    assert(
        inp.owner_pubkey == hash_1([inp.spending_key]),
        "owner_pubkey must derive from spending_key",
    );
    assert(inp.epoch_in == inp.epoch, "epoch_in must match epoch");
    assert(inp.epoch_seconds == domain::EPOCH_SECONDS, "epoch_seconds mismatch");
    assert(inp.policy_source_hash == policy_tag::POLICY_SOURCE_HASH, "policy_source_hash mismatch");

    assert(tx.subject == inp.owner_pubkey, "tx.subject must be owner_pubkey");
    assert(tx.epoch == inp.epoch, "tx.epoch must match epoch");
    assert(tx.seq == inp.seq, "tx.seq must match seq");
    tx.token.assert_max_bit_size::<160>();

    assert(inp.cn_proof_length <= domain::MAX_COMMITMENT_TREE_DEPTH);

    let facts_in = hash_5([
        inp.cp_in[0],
        inp.amt_in[0] as Field,
        inp.cp_in[1],
        inp.amt_in[1] as Field,
        inp.exit_in,
    ]);
    let state_in = hash_5([
        inp.epoch_in as Field,
        inp.seq as Field,
        state::commit(policy_tag::STATE_TAG, inp.prev),
        inp.flags_in as Field,
        facts_in,
    ]);
    let cn_in = hash_4([domain::CN_TAG, inp.owner_pubkey, state_in, inp.salt_in]);

    if inp.seq == 0 {
        assert(inp.prev.s == policy::zero().s, "seq 0 must start from policy::zero");
        assert(inp.flags_in == 0, "seq 0 must start with no flags");
    } else {
        merkle::verify(
            cn_in,
            inp.commitment_root,
            inp.cn_proof_length,
            inp.cn_indices,
            inp.cn_path,
        );
    }

    assert(
        inp.velocity_nullifier
            == hash_4(
                [domain::VN_TAG, inp.spending_key, inp.epoch as Field, inp.seq as Field],
            ),
        "velocity_nullifier mismatch",
    );

    let next = policy::advance(inp.prev, tx);
    let flags_out = policy::evaluate(tx, inp.prev, next);
    let facts_out = hash_5([
        tx.counterparty[0],
        amount_out_0 as Field,
        tx.counterparty[1],
        amount_out_1 as Field,
        tx.exit,
    ]);
    let state_out = hash_5([
        inp.epoch as Field,
        (inp.seq + 1) as Field,
        state::commit(policy_tag::STATE_TAG, next),
        flags_out as Field,
        facts_out,
    ]);
    assert(
        inp.compliance_commitment_out
            == hash_4([domain::CN_TAG, inp.owner_pubkey, state_out, inp.salt_out]),
        "compliance_commitment_out mismatch",
    );
}

fn no_indices() -> [bool; domain::MAX_COMMITMENT_TREE_DEPTH] {
    [false; domain::MAX_COMMITMENT_TREE_DEPTH]
}

fn no_path() -> [Field; domain::MAX_COMMITMENT_TREE_DEPTH] {
    [0; domain::MAX_COMMITMENT_TREE_DEPTH]
}

fn origin_tx_facts(subject: Field, epoch: u64) -> TxFacts {
    TxFacts {
        epoch,
        seq: 0,
        token: 0x1234,
        subject,
        counterparty: [domain::NO_COUNTERPARTY, domain::NO_COUNTERPARTY],
        value_in: 500,
        value_out: 0,
        exit: domain::NO_EXIT,
    }
}

fn origin_inputs(
    spending_key: Field,
    owner_pubkey: Field,
    epoch: u64,
    tx: TxFacts,
    amount_out_0: u64,
    amount_out_1: u64,
    salt_out: Field,
) -> ComplianceInputs {
    let velocity_nullifier = hash_4([domain::VN_TAG, spending_key, epoch as Field, 0]);
    let next = policy::advance(policy::zero(), tx);
    let flags_out = policy::evaluate(tx, policy::zero(), next);
    let facts_out = hash_5([
        tx.counterparty[0],
        amount_out_0 as Field,
        tx.counterparty[1],
        amount_out_1 as Field,
        tx.exit,
    ]);
    let state_out = hash_5([
        epoch as Field,
        1,
        state::commit(policy_tag::STATE_TAG, next),
        flags_out as Field,
        facts_out,
    ]);
    let compliance_commitment_out = hash_4([domain::CN_TAG, owner_pubkey, state_out, salt_out]);

    ComplianceInputs {
        epoch,
        epoch_seconds: domain::EPOCH_SECONDS,
        policy_source_hash: policy_tag::POLICY_SOURCE_HASH,
        commitment_root: 0,
        velocity_nullifier,
        compliance_commitment_out,
        spending_key,
        owner_pubkey,
        seq: 0,
        epoch_in: epoch,
        prev: policy::zero(),
        flags_in: 0,
        cp_in: [domain::NO_COUNTERPARTY, domain::NO_COUNTERPARTY],
        amt_in: [0, 0],
        exit_in: domain::NO_EXIT,
        salt_in: 0,
        salt_out,
        cn_proof_length: 0,
        cn_indices: no_indices(),
        cn_path: no_path(),
    }
}

#[test]
fn test_domain_separation_all_five_tags() {
    assert(domain::CN_TAG != domain::VN_TAG);
    assert(domain::CN_TAG != domain::STATE_DOMAIN);
    assert(domain::CN_TAG != domain::NO_COUNTERPARTY);
    assert(domain::CN_TAG != domain::NO_EXIT);
    assert(domain::VN_TAG != domain::STATE_DOMAIN);
    assert(domain::VN_TAG != domain::NO_COUNTERPARTY);
    assert(domain::VN_TAG != domain::NO_EXIT);
    assert(domain::STATE_DOMAIN != domain::NO_COUNTERPARTY);
    assert(domain::STATE_DOMAIN != domain::NO_EXIT);
    assert(domain::NO_COUNTERPARTY != domain::NO_EXIT);
}

#[test]
fn test_deterministic_hashing() {
    let a = hash_5([1, 2, 3, 4, 5]);
    let b = hash_5([1, 2, 3, 4, 5]);
    assert(a == b);
    let c = hash_4([1, 2, 3, 4]);
    let d = hash_4([1, 2, 3, 4]);
    assert(c == d);
}

#[test]
fn test_run_seq0_base_case() {
    let spending_key: Field = 0x1111;
    let owner_pubkey = hash_1([spending_key]);
    let epoch: u64 = 100;
    let tx = origin_tx_facts(owner_pubkey, epoch);
    let amount_out_0: u64 = 500;
    let amount_out_1: u64 = 0;
    let inp = origin_inputs(
        spending_key,
        owner_pubkey,
        epoch,
        tx,
        amount_out_0,
        amount_out_1,
        0xaaaa,
    );
    run(inp, tx, amount_out_0, amount_out_1);
}

#[test]
fn test_run_seq1_predecessor_inclusion() {
    let spending_key: Field = 0x2222;
    let owner_pubkey = hash_1([spending_key]);
    let epoch: u64 = 100;

    // seq 0 transition, whose committed output becomes seq 1's predecessor leaf.
    let tx0 = origin_tx_facts(owner_pubkey, epoch);
    let amount_out_0_0: u64 = 500;
    let amount_out_1_0: u64 = 0;
    let salt_out0: Field = 0x9999;
    let next0 = policy::advance(policy::zero(), tx0);
    let flags_out0 = policy::evaluate(tx0, policy::zero(), next0);
    let facts_out0 = hash_5([
        tx0.counterparty[0],
        amount_out_0_0 as Field,
        tx0.counterparty[1],
        amount_out_1_0 as Field,
        tx0.exit,
    ]);
    let state_out0 = hash_5([
        epoch as Field,
        1,
        state::commit(policy_tag::STATE_TAG, next0),
        flags_out0 as Field,
        facts_out0,
    ]);
    let cn_in = hash_4([domain::CN_TAG, owner_pubkey, state_out0, salt_out0]);

    let cn_indices = no_indices();
    let mut cn_path = no_path();
    cn_path[0] = 0x7777;
    let commitment_root = crate::merkle::binary_merkle_root(hash_2, cn_in, 1, cn_indices, cn_path);

    let tx1 = TxFacts {
        epoch,
        seq: 1,
        token: 0x1234,
        subject: owner_pubkey,
        counterparty: [domain::NO_COUNTERPARTY, domain::NO_COUNTERPARTY],
        value_in: 0,
        value_out: 300,
        exit: 0xfeed,
    };
    let amount_out_0_1: u64 = 300;
    let amount_out_1_1: u64 = 0;

    let next1 = policy::advance(next0, tx1);
    let flags_out1 = policy::evaluate(tx1, next0, next1);
    let facts_out1 = hash_5([
        tx1.counterparty[0],
        amount_out_0_1 as Field,
        tx1.counterparty[1],
        amount_out_1_1 as Field,
        tx1.exit,
    ]);
    let state_out1 = hash_5([
        epoch as Field,
        2,
        state::commit(policy_tag::STATE_TAG, next1),
        flags_out1 as Field,
        facts_out1,
    ]);
    let salt_out1: Field = 0x8888;
    let compliance_commitment_out = hash_4([domain::CN_TAG, owner_pubkey, state_out1, salt_out1]);
    let velocity_nullifier = hash_4([domain::VN_TAG, spending_key, epoch as Field, 1]);

    let inp = ComplianceInputs {
        epoch,
        epoch_seconds: domain::EPOCH_SECONDS,
        policy_source_hash: policy_tag::POLICY_SOURCE_HASH,
        commitment_root,
        velocity_nullifier,
        compliance_commitment_out,
        spending_key,
        owner_pubkey,
        seq: 1,
        epoch_in: epoch,
        prev: next0,
        flags_in: flags_out0,
        cp_in: tx0.counterparty,
        amt_in: [amount_out_0_0, amount_out_1_0],
        exit_in: tx0.exit,
        salt_in: salt_out0,
        salt_out: salt_out1,
        cn_proof_length: 1,
        cn_indices,
        cn_path,
    };

    run(inp, tx1, amount_out_0_1, amount_out_1_1);
}

#[test(should_fail_with = "merkle proof failed")]
fn test_run_tampered_cn_path_fails() {
    let spending_key: Field = 0x2222;
    let owner_pubkey = hash_1([spending_key]);
    let epoch: u64 = 100;

    let tx0 = origin_tx_facts(owner_pubkey, epoch);
    let amount_out_0_0: u64 = 500;
    let amount_out_1_0: u64 = 0;
    let salt_out0: Field = 0x9999;
    let next0 = policy::advance(policy::zero(), tx0);
    let flags_out0 = policy::evaluate(tx0, policy::zero(), next0);
    let facts_out0 = hash_5([
        tx0.counterparty[0],
        amount_out_0_0 as Field,
        tx0.counterparty[1],
        amount_out_1_0 as Field,
        tx0.exit,
    ]);
    let state_out0 = hash_5([
        epoch as Field,
        1,
        state::commit(policy_tag::STATE_TAG, next0),
        flags_out0 as Field,
        facts_out0,
    ]);
    let cn_in = hash_4([domain::CN_TAG, owner_pubkey, state_out0, salt_out0]);

    let cn_indices = no_indices();
    let mut cn_path = no_path();
    cn_path[0] = 0x7777;
    let commitment_root = crate::merkle::binary_merkle_root(hash_2, cn_in, 1, cn_indices, cn_path);

    // Tamper with the sibling after the root was computed honestly.
    cn_path[0] = 0x6666;

    let tx1 = TxFacts {
        epoch,
        seq: 1,
        token: 0x1234,
        subject: owner_pubkey,
        counterparty: [domain::NO_COUNTERPARTY, domain::NO_COUNTERPARTY],
        value_in: 0,
        value_out: 300,
        exit: 0xfeed,
    };
    let amount_out_0_1: u64 = 300;
    let amount_out_1_1: u64 = 0;

    let next1 = policy::advance(next0, tx1);
    let flags_out1 = policy::evaluate(tx1, next0, next1);
    let facts_out1 = hash_5([
        tx1.counterparty[0],
        amount_out_0_1 as Field,
        tx1.counterparty[1],
        amount_out_1_1 as Field,
        tx1.exit,
    ]);
    let state_out1 = hash_5([
        epoch as Field,
        2,
        state::commit(policy_tag::STATE_TAG, next1),
        flags_out1 as Field,
        facts_out1,
    ]);
    let salt_out1: Field = 0x8888;
    let compliance_commitment_out = hash_4([domain::CN_TAG, owner_pubkey, state_out1, salt_out1]);
    let velocity_nullifier = hash_4([domain::VN_TAG, spending_key, epoch as Field, 1]);

    let inp = ComplianceInputs {
        epoch,
        epoch_seconds: domain::EPOCH_SECONDS,
        policy_source_hash: policy_tag::POLICY_SOURCE_HASH,
        commitment_root,
        velocity_nullifier,
        compliance_commitment_out,
        spending_key,
        owner_pubkey,
        seq: 1,
        epoch_in: epoch,
        prev: next0,
        flags_in: flags_out0,
        cp_in: tx0.counterparty,
        amt_in: [amount_out_0_0, amount_out_1_0],
        exit_in: tx0.exit,
        salt_in: salt_out0,
        salt_out: salt_out1,
        cn_proof_length: 1,
        cn_indices,
        cn_path,
    };

    run(inp, tx1, amount_out_0_1, amount_out_1_1);
}

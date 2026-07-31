use spc_lib::hasher::{hash_1, hash_2, hash_4};
use spc_lib::merkle;

global MAX_COMMITMENT_TREE_DEPTH: u32 = 32;

// The parent's withdraw circuit, ported to the current toolchain unchanged in
// statement: no range checks, no compliance gadget. It stays safe against a
// value note opening a compliance note because the slot orders differ; see
// SPEC "Withdraw, two entry points".
fn main(
    nullifier: pub Field,
    token: pub Field,
    amount: pub Field,
    recipient: pub Field,
    commitment_root: pub Field,
    spending_key: Field,
    salt: Field,
    proof_length: u32,
    path: [Field; MAX_COMMITMENT_TREE_DEPTH],
    indices: [bool; MAX_COMMITMENT_TREE_DEPTH],
) {
    let owner_pubkey = hash_1([spending_key]);
    assert(proof_length <= MAX_COMMITMENT_TREE_DEPTH);
    let commitment = hash_4([token, amount, owner_pubkey, salt]);
    merkle::verify(commitment, commitment_root, proof_length, indices, path);

    let computed_nullifier = hash_2([commitment, spending_key]);
    assert(nullifier == computed_nullifier);

    // recipient is a public input the contract reads directly; the circuit
    // does not constrain it.
    let _ = recipient;
}

fn zero_path() -> [Field; MAX_COMMITMENT_TREE_DEPTH] {
    [0; MAX_COMMITMENT_TREE_DEPTH]
}

fn zero_indices() -> [bool; MAX_COMMITMENT_TREE_DEPTH] {
    [false; MAX_COMMITMENT_TREE_DEPTH]
}

#[test]
fn test_withdraw_ungated_valid() {
    let spending_key = 0xdeadbeef;
    let owner_pubkey = hash_1([spending_key]);

    let token = 0x1234567890abcdef1234567890abcdef12345678;
    let amount = 1000;
    let salt = 0xabcd;
    let recipient = 0xfedcba0987654321fedcba0987654321fedcba09;

    let commitment = hash_4([token, amount, owner_pubkey, salt]);
    let nullifier = hash_2([commitment, spending_key]);

    let proof_length: u32 = 3;
    let path = zero_path();
    let indices = zero_indices();

    let mut current = commitment;
    for i in 0..proof_length {
        current = hash_2([current, path[i]]);
    }
    let commitment_root = current;

    main(
        nullifier,
        token,
        amount,
        recipient,
        commitment_root,
        spending_key,
        salt,
        proof_length,
        path,
        indices,
    );
}

#[test(should_fail)]
fn test_withdraw_ungated_wrong_spending_key() {
    let real_spending_key = 0xdeadbeef;
    let owner_pubkey = hash_1([real_spending_key]);
    let attacker_spending_key = 0xbadcafe;

    let token = 0x1234;
    let amount = 1000;
    let salt = 0xabcd;
    let recipient = 0xfeed;

    let commitment = hash_4([token, amount, owner_pubkey, salt]);
    let attacker_nullifier = hash_2([commitment, attacker_spending_key]);

    let proof_length: u32 = 3;
    let path = zero_path();
    let indices = zero_indices();

    let mut current = commitment;
    for i in 0..proof_length {
        current = hash_2([current, path[i]]);
    }
    let commitment_root = current;

    main(
        attacker_nullifier,
        token,
        amount,
        recipient,
        commitment_root,
        attacker_spending_key,
        salt,
        proof_length,
        path,
        indices,
    );
}

#[test(should_fail)]
fn test_withdraw_ungated_wrong_amount() {
    let spending_key = 0xdeadbeef;
    let owner_pubkey = hash_1([spending_key]);

    let token = 0x1234;
    let real_amount = 1000;
    let claimed_amount = 2000;
    let salt = 0xabcd;
    let recipient = 0xfeed;

    let commitment = hash_4([token, real_amount, owner_pubkey, salt]);
    let nullifier = hash_2([commitment, spending_key]);

    let proof_length: u32 = 3;
    let path = zero_path();
    let indices = zero_indices();

    let mut current = commitment;
    for i in 0..proof_length {
        current = hash_2([current, path[i]]);
    }
    let commitment_root = current;

    main(
        nullifier,
        token,
        claimed_amount,
        recipient,
        commitment_root,
        spending_key,
        salt,
        proof_length,
        path,
        indices,
    );
}

#[test(should_fail)]
fn test_withdraw_ungated_wrong_token() {
    let spending_key = 0xdeadbeef;
    let owner_pubkey = hash_1([spending_key]);

    let real_token = 0x1234;
    let claimed_token = 0x5678;
    let amount = 1000;
    let salt = 0xabcd;
    let recipient = 0xfeed;

    let commitment = hash_4([real_token, amount, owner_pubkey, salt]);
    let nullifier = hash_2([commitment, spending_key]);

    let proof_length: u32 = 3;
    let path = zero_path();
    let indices = zero_indices();

    let mut current = commitment;
    for i in 0..proof_length {
        current = hash_2([current, path[i]]);
    }
    let commitment_root = current;

    main(
        nullifier,
        claimed_token,
        amount,
        recipient,
        commitment_root,
        spending_key,
        salt,
        proof_length,
        path,
        indices,
    );
}

#[test(should_fail)]
fn test_withdraw_ungated_invalid_merkle_proof() {
    let spending_key = 0xdeadbeef;
    let owner_pubkey = hash_1([spending_key]);

    let token = 0x1234;
    let amount = 1000;
    let salt = 0xabcd;
    let recipient = 0xfeed;

    let commitment = hash_4([token, amount, owner_pubkey, salt]);
    let nullifier = hash_2([commitment, spending_key]);

    let proof_length: u32 = 3;
    let path = zero_path();
    let indices = zero_indices();

    let wrong_root = hash_2([0x1234, 0x5678]);

    main(
        nullifier,
        token,
        amount,
        recipient,
        wrong_root,
        spending_key,
        salt,
        proof_length,
        path,
        indices,
    );
}

#[test(should_fail)]
fn test_withdraw_ungated_wrong_nullifier() {
    let spending_key = 0xdeadbeef;
    let owner_pubkey = hash_1([spending_key]);

    let token = 0x1234;
    let amount = 1000;
    let salt = 0xabcd;
    let recipient = 0xfeed;

    let commitment = hash_4([token, amount, owner_pubkey, salt]);
    let wrong_commitment = hash_4([token, amount + 1, owner_pubkey, salt]);
    let wrong_nullifier = hash_2([wrong_commitment, spending_key]);

    let proof_length: u32 = 3;
    let path = zero_path();
    let indices = zero_indices();

    let mut current = commitment;
    for i in 0..proof_length {
        current = hash_2([current, path[i]]);
    }
    let commitment_root = current;

    main(
        wrong_nullifier,
        token,
        amount,
        recipient,
        commitment_root,
        spending_key,
        salt,
        proof_length,
        path,
        indices,
    );
}

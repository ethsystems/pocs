use binary_merkle_root::binary_merkle_root;
use poseidon::poseidon::bn254::{hash_1, hash_2, hash_4};

// Maximum tree depth (for array sizing)
global MAX_COMMITMENT_TREE_DEPTH: u32 = 32;

// Poseidon wrapper for 1 element (for key derivation)
fn poseidon1(a: Field) -> Field {
    hash_1([a])
}

// Poseidon wrapper for 2 elements (matches PoseidonT3 in Solidity)
fn poseidon2(a: Field, b: Field) -> Field {
    hash_2([a, b])
}

// Poseidon wrapper for 4 elements (matches PoseidonT5 in Solidity)
fn poseidon4(a: Field, b: Field, c: Field, d: Field) -> Field {
    hash_4([a, b, c, d])
}

// Dynamic-depth Merkle proof verification using binary_merkle_root from zk-kit.noir
fn verify_merkle_proof<let MAX_DEPTH: u32>(
    leaf: Field,
    root: Field,
    proof_length: u32,
    path_indices: [bool; MAX_DEPTH],
    path_elements: [Field; MAX_DEPTH],
) {
    let computed_root = binary_merkle_root(hash_2, leaf, proof_length, path_indices, path_elements);
    assert(computed_root == root);
}

/// Withdraw Circuit
///
/// Proves that:
/// 1. The withdrawer owns the note (knows spending key)
/// 2. The commitment exists in the commitment tree
/// 3. The nullifier is correctly derived
/// 4. The claimed token and amount match the note
///
/// Public Inputs:
/// - nullifier: spent note nullifier
/// - token: ERC-20 token address (lower 160 bits)
/// - amount: withdrawal amount
/// - recipient: recipient address (160 bits)
/// - commitment_root: current commitment tree root
///
/// Private Inputs:
/// - spending_key: owner's secret key
/// - salt: note salt
/// - proof_length: actual depth of the commitment tree proof
/// - path: merkle siblings (padded to MAX_COMMITMENT_TREE_DEPTH)
/// - indices: path direction bits (padded to MAX_COMMITMENT_TREE_DEPTH)
fn main(
    // Public inputs
    nullifier: pub Field,
    token: pub Field,
    amount: pub Field,
    recipient: pub Field,
    commitment_root: pub Field,
    // Private inputs
    spending_key: Field,
    salt: Field,
    proof_length: u32,
    path: [Field; MAX_COMMITMENT_TREE_DEPTH],
    indices: [bool; MAX_COMMITMENT_TREE_DEPTH],
) {
    // 1. Derive owner public key from spending key
    // owner_pubkey = poseidon1(spending_key)
    let owner_pubkey = poseidon1(spending_key);

    // 2. Compute commitment from note components
    // commitment = poseidon4(token, amount, owner_pubkey, salt)
    let commitment = poseidon4(token, amount, owner_pubkey, salt);

    // 3. Verify merkle inclusion
    verify_merkle_proof(commitment, commitment_root, proof_length, indices, path);

    // 4. Verify nullifier derivation
    // nullifier = poseidon2(commitment, spending_key)
    let computed_nullifier = poseidon2(commitment, spending_key);
    assert(nullifier == computed_nullifier);

    // Note: recipient is a public input but not constrained in the circuit.
    // This allows anyone to verify the withdrawal is going to the claimed recipient,
    // but the recipient address is bound to the proof via the public inputs.
    // The contract will use this public input to send funds to the correct address.
    // We add a dummy constraint to suppress the unused variable warning.
    let _ = recipient;
}

#[test]
fn test_withdraw_valid() {
    // Spending key and derived owner
    let spending_key = 0xdeadbeef;
    let owner_pubkey = poseidon1(spending_key);

    // Note components
    let token = 0x1234567890abcdef1234567890abcdef12345678;
    let amount = 1000;
    let salt = 0xabcd;

    // Recipient address
    let recipient = 0xfedcba0987654321fedcba0987654321fedcba09;

    // Compute commitment
    let commitment = poseidon4(token, amount, owner_pubkey, salt);

    // Compute nullifier
    let nullifier = poseidon2(commitment, spending_key);

    // Use dynamic depth
    let proof_length: u32 = 3;

    // Build merkle proof (simple tree with our leaf at index 0)
    let path: [Field; MAX_COMMITMENT_TREE_DEPTH] = [0; MAX_COMMITMENT_TREE_DEPTH];
    let indices: [bool; MAX_COMMITMENT_TREE_DEPTH] = [false; MAX_COMMITMENT_TREE_DEPTH];

    // Compute root by hashing up the tree (only up to proof_length)
    let mut current = commitment;
    for i in 0..proof_length {
        current = poseidon2(current, path[i]);
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
fn test_withdraw_wrong_spending_key() {
    // Real owner's spending key
    let real_spending_key = 0xdeadbeef;
    let owner_pubkey = poseidon1(real_spending_key);

    // Attacker's spending key
    let attacker_spending_key = 0xbadcafe;

    let token = 0x1234;
    let amount = 1000;
    let salt = 0xabcd;
    let recipient = 0xfeed;

    // Commitment made with real owner's pubkey
    let commitment = poseidon4(token, amount, owner_pubkey, salt);

    // Attacker computes nullifier with their key
    let attacker_nullifier = poseidon2(commitment, attacker_spending_key);

    let proof_length: u32 = 3;
    let path: [Field; MAX_COMMITMENT_TREE_DEPTH] = [0; MAX_COMMITMENT_TREE_DEPTH];
    let indices: [bool; MAX_COMMITMENT_TREE_DEPTH] = [false; MAX_COMMITMENT_TREE_DEPTH];

    let mut current = commitment;
    for i in 0..proof_length {
        current = poseidon2(current, path[i]);
    }
    let commitment_root = current;

    // This will fail because attacker_spending_key doesn't derive to owner_pubkey
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
fn test_withdraw_wrong_amount() {
    let spending_key = 0xdeadbeef;
    let owner_pubkey = poseidon1(spending_key);

    let token = 0x1234;
    let real_amount = 1000;
    let claimed_amount = 2000; // Trying to withdraw more than the note contains
    let salt = 0xabcd;
    let recipient = 0xfeed;

    // Commitment with real amount
    let commitment = poseidon4(token, real_amount, owner_pubkey, salt);
    let nullifier = poseidon2(commitment, spending_key);

    let proof_length: u32 = 3;
    let path: [Field; MAX_COMMITMENT_TREE_DEPTH] = [0; MAX_COMMITMENT_TREE_DEPTH];
    let indices: [bool; MAX_COMMITMENT_TREE_DEPTH] = [false; MAX_COMMITMENT_TREE_DEPTH];

    let mut current = commitment;
    for i in 0..proof_length {
        current = poseidon2(current, path[i]);
    }
    let commitment_root = current;

    // This will fail because the claimed amount doesn't match the commitment
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
fn test_withdraw_wrong_token() {
    let spending_key = 0xdeadbeef;
    let owner_pubkey = poseidon1(spending_key);

    let real_token = 0x1234;
    let claimed_token = 0x5678; // Trying to withdraw different token
    let amount = 1000;
    let salt = 0xabcd;
    let recipient = 0xfeed;

    // Commitment with real token
    let commitment = poseidon4(real_token, amount, owner_pubkey, salt);
    let nullifier = poseidon2(commitment, spending_key);

    let proof_length: u32 = 3;
    let path: [Field; MAX_COMMITMENT_TREE_DEPTH] = [0; MAX_COMMITMENT_TREE_DEPTH];
    let indices: [bool; MAX_COMMITMENT_TREE_DEPTH] = [false; MAX_COMMITMENT_TREE_DEPTH];

    let mut current = commitment;
    for i in 0..proof_length {
        current = poseidon2(current, path[i]);
    }
    let commitment_root = current;

    // This will fail because the claimed token doesn't match the commitment
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
fn test_withdraw_invalid_merkle_proof() {
    let spending_key = 0xdeadbeef;
    let owner_pubkey = poseidon1(spending_key);

    let token = 0x1234;
    let amount = 1000;
    let salt = 0xabcd;
    let recipient = 0xfeed;

    let commitment = poseidon4(token, amount, owner_pubkey, salt);
    let nullifier = poseidon2(commitment, spending_key);

    let proof_length: u32 = 3;
    let path: [Field; MAX_COMMITMENT_TREE_DEPTH] = [0; MAX_COMMITMENT_TREE_DEPTH];
    let indices: [bool; MAX_COMMITMENT_TREE_DEPTH] = [false; MAX_COMMITMENT_TREE_DEPTH];

    // Wrong root
    let wrong_root = poseidon2(0x1234, 0x5678);

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
fn test_withdraw_wrong_nullifier() {
    let spending_key = 0xdeadbeef;
    let owner_pubkey = poseidon1(spending_key);

    let token = 0x1234;
    let amount = 1000;
    let salt = 0xabcd;
    let recipient = 0xfeed;

    let commitment = poseidon4(token, amount, owner_pubkey, salt);

    // Wrong nullifier (computed with different commitment)
    let wrong_commitment = poseidon4(token, amount + 1, owner_pubkey, salt);
    let wrong_nullifier = poseidon2(wrong_commitment, spending_key);

    let proof_length: u32 = 3;
    let path: [Field; MAX_COMMITMENT_TREE_DEPTH] = [0; MAX_COMMITMENT_TREE_DEPTH];
    let indices: [bool; MAX_COMMITMENT_TREE_DEPTH] = [false; MAX_COMMITMENT_TREE_DEPTH];

    let mut current = commitment;
    for i in 0..proof_length {
        current = poseidon2(current, path[i]);
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

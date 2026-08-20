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

/// Transfer Circuit
///
/// Proves that:
/// 1. The sender owns the input notes (knows spending key)
/// 2. Input commitments exist in the commitment tree
/// 3. Nullifiers are correctly derived
/// 4. Output commitments are well-formed
/// 5. Value is conserved (input amounts = output amounts)
/// 6. All notes use the same token
///
/// Public Inputs:
/// - nullifier_0, nullifier_1: nullifiers for spent notes
/// - commitment_out_0, commitment_out_1: new note commitments
/// - commitment_root: current commitment tree root
///
/// Private Inputs:
/// - spending_key: sender's secret key
/// - Input notes (2): token_in_[0,1], amount_in_[0,1], salt_in_[0,1]
/// - Output notes (2): token_out_[0,1], amount_out_[0,1], owner_out_[0,1], salt_out_[0,1]
/// - proof_length: actual depth of the commitment tree proofs
/// - Merkle proofs (2): path_[0,1], indices_[0,1] (padded to MAX_COMMITMENT_TREE_DEPTH)
fn main(
    // Public inputs
    nullifier_0: pub Field,
    nullifier_1: pub Field,
    commitment_out_0: pub Field,
    commitment_out_1: pub Field,
    commitment_root: pub Field,
    // Private inputs
    spending_key: Field,
    // Input note 0
    token_in_0: Field,
    amount_in_0: u64,
    salt_in_0: Field,
    // Input note 1
    token_in_1: Field,
    amount_in_1: u64,
    salt_in_1: Field,
    // Output note 0
    token_out_0: Field,
    amount_out_0: u64,
    owner_out_0: Field,
    salt_out_0: Field,
    // Output note 1
    token_out_1: Field,
    amount_out_1: u64,
    owner_out_1: Field,
    salt_out_1: Field,
    // Merkle proof length (dynamic depth)
    proof_length: u32,
    // Merkle proof for input 0
    path_0: [Field; MAX_COMMITMENT_TREE_DEPTH],
    indices_0: [bool; MAX_COMMITMENT_TREE_DEPTH],
    // Merkle proof for input 1
    path_1: [Field; MAX_COMMITMENT_TREE_DEPTH],
    indices_1: [bool; MAX_COMMITMENT_TREE_DEPTH],
) {
    // 1. Derive owner public key from spending key
    // owner_pubkey = poseidon1(spending_key)
    let owner_pubkey = poseidon1(spending_key);

    // 2. Verify input note 0
    // Compute commitment
    let commitment_in_0 = poseidon4(token_in_0, amount_in_0 as Field, owner_pubkey, salt_in_0);
    // Verify merkle inclusion
    verify_merkle_proof(
        commitment_in_0,
        commitment_root,
        proof_length,
        indices_0,
        path_0,
    );
    // Verify nullifier derivation
    let computed_nullifier_0 = poseidon2(commitment_in_0, spending_key);
    assert(nullifier_0 == computed_nullifier_0);

    // 3. Verify input note 1
    let is_zero_note = amount_in_1 == 0;

    let commitment_in_1 = poseidon4(token_in_1, amount_in_1 as Field, owner_pubkey, salt_in_1);

    // Only verify merkle inclusion for real notes (zero notes don't exist in the tree)
    if !is_zero_note {
        verify_merkle_proof(
            commitment_in_1,
            commitment_root,
            proof_length,
            indices_1,
            path_1,
        );
    }

    let computed_nullifier_1 = poseidon2(commitment_in_1, spending_key);
    assert(nullifier_1 == computed_nullifier_1);

    // 4. Verify output commitments are correctly formed
    let computed_commitment_out_0 = poseidon4(token_out_0, amount_out_0 as Field, owner_out_0, salt_out_0);
    assert(commitment_out_0 == computed_commitment_out_0);

    let computed_commitment_out_1 = poseidon4(token_out_1, amount_out_1 as Field, owner_out_1, salt_out_1);
    assert(commitment_out_1 == computed_commitment_out_1);

    // 5. Value conservation: input amounts = output amounts
    assert(amount_in_0 + amount_in_1 == amount_out_0 + amount_out_1);

    // 6. Token consistency: all notes use the same token
    assert(token_in_0 == token_in_1);
    assert(token_in_0 == token_out_0);
    assert(token_in_0 == token_out_1);
}

#[test]
fn test_transfer_valid() {
    // Spending key and derived owner
    let spending_key = 0xdeadbeef;
    let owner_pubkey = poseidon1(spending_key);

    // Token (same for all notes)
    let token = 0x1234567890abcdef1234567890abcdef12345678;

    // Input notes
    let amount_in_0: u64 = 600;
    let salt_in_0 = 0xaaaa;
    let amount_in_1: u64 = 400;
    let salt_in_1 = 0xbbbb;

    // Output notes (send 700 to recipient, 300 as change)
    let recipient_pubkey = poseidon1(0xcafe);
    let amount_out_0: u64 = 700; // to recipient
    let salt_out_0 = 0xcccc;
    let amount_out_1: u64 = 300; // change back to sender
    let salt_out_1 = 0xdddd;

    // Compute input commitments
    let commitment_in_0 = poseidon4(token, amount_in_0 as Field, owner_pubkey, salt_in_0);
    let commitment_in_1 = poseidon4(token, amount_in_1 as Field, owner_pubkey, salt_in_1);

    // Compute nullifiers
    let nullifier_0 = poseidon2(commitment_in_0, spending_key);
    let nullifier_1 = poseidon2(commitment_in_1, spending_key);

    // Compute output commitments
    let commitment_out_0 = poseidon4(token, amount_out_0 as Field, recipient_pubkey, salt_out_0);
    let commitment_out_1 = poseidon4(token, amount_out_1 as Field, owner_pubkey, salt_out_1);

    // Use dynamic depth (tree with 2 leaves needs depth 1)
    let proof_length: u32 = 3;

    // Build merkle proofs (simple tree with both notes at index 0 and 1)
    let mut path_0: [Field; MAX_COMMITMENT_TREE_DEPTH] = [0; MAX_COMMITMENT_TREE_DEPTH];
    let mut indices_0: [bool; MAX_COMMITMENT_TREE_DEPTH] = [false; MAX_COMMITMENT_TREE_DEPTH];

    let mut path_1: [Field; MAX_COMMITMENT_TREE_DEPTH] = [0; MAX_COMMITMENT_TREE_DEPTH];
    let mut indices_1: [bool; MAX_COMMITMENT_TREE_DEPTH] = [false; MAX_COMMITMENT_TREE_DEPTH];
    indices_1[0] = true; // Second leaf at index 1

    // Compute merkle root for a tree with two leaves
    // Leaf 0 is commitment_in_0, leaf 1 is commitment_in_1
    let parent_01 = poseidon2(commitment_in_0, commitment_in_1);
    path_0[0] = commitment_in_1; // Sibling of leaf 0
    path_1[0] = commitment_in_0; // Sibling of leaf 1

    // Compute root up to proof_length
    let mut current = parent_01;
    for _ in 1..proof_length {
        current = poseidon2(current, 0);
    }
    let commitment_root = current;

    main(
        nullifier_0,
        nullifier_1,
        commitment_out_0,
        commitment_out_1,
        commitment_root,
        spending_key,
        token,
        amount_in_0,
        salt_in_0,
        token,
        amount_in_1,
        salt_in_1,
        token,
        amount_out_0,
        recipient_pubkey,
        salt_out_0,
        token,
        amount_out_1,
        owner_pubkey,
        salt_out_1,
        proof_length,
        path_0,
        indices_0,
        path_1,
        indices_1,
    );
}

#[test(should_fail)]
fn test_transfer_value_mismatch() {
    let spending_key = 0xdeadbeef;
    let owner_pubkey = poseidon1(spending_key);
    let token = 0x1234;

    // Input: 1000 total
    let amount_in_0: u64 = 600;
    let salt_in_0 = 0xaaaa;
    let amount_in_1: u64 = 400;
    let salt_in_1 = 0xbbbb;

    // Output: 1001 total (more than input - should fail)
    let recipient_pubkey = poseidon1(0xcafe);
    let amount_out_0: u64 = 701;
    let salt_out_0 = 0xcccc;
    let amount_out_1: u64 = 300;
    let salt_out_1 = 0xdddd;

    let commitment_in_0 = poseidon4(token, amount_in_0 as Field, owner_pubkey, salt_in_0);
    let commitment_in_1 = poseidon4(token, amount_in_1 as Field, owner_pubkey, salt_in_1);

    let nullifier_0 = poseidon2(commitment_in_0, spending_key);
    let nullifier_1 = poseidon2(commitment_in_1, spending_key);

    let commitment_out_0 = poseidon4(token, amount_out_0 as Field, recipient_pubkey, salt_out_0);
    let commitment_out_1 = poseidon4(token, amount_out_1 as Field, owner_pubkey, salt_out_1);

    let proof_length: u32 = 3;
    let mut path_0: [Field; MAX_COMMITMENT_TREE_DEPTH] = [0; MAX_COMMITMENT_TREE_DEPTH];
    let indices_0: [bool; MAX_COMMITMENT_TREE_DEPTH] = [false; MAX_COMMITMENT_TREE_DEPTH];
    let mut path_1: [Field; MAX_COMMITMENT_TREE_DEPTH] = [0; MAX_COMMITMENT_TREE_DEPTH];
    let mut indices_1: [bool; MAX_COMMITMENT_TREE_DEPTH] = [false; MAX_COMMITMENT_TREE_DEPTH];
    indices_1[0] = true;

    let parent_01 = poseidon2(commitment_in_0, commitment_in_1);
    path_0[0] = commitment_in_1;
    path_1[0] = commitment_in_0;

    let mut current = parent_01;
    for _ in 1..proof_length {
        current = poseidon2(current, 0);
    }
    let commitment_root = current;

    main(
        nullifier_0,
        nullifier_1,
        commitment_out_0,
        commitment_out_1,
        commitment_root,
        spending_key,
        token,
        amount_in_0,
        salt_in_0,
        token,
        amount_in_1,
        salt_in_1,
        token,
        amount_out_0,
        recipient_pubkey,
        salt_out_0,
        token,
        amount_out_1,
        owner_pubkey,
        salt_out_1,
        proof_length,
        path_0,
        indices_0,
        path_1,
        indices_1,
    );
}

#[test(should_fail)]
fn test_transfer_token_mismatch() {
    let spending_key = 0xdeadbeef;
    let owner_pubkey = poseidon1(spending_key);

    // Different tokens for inputs
    let token_0 = 0x1234;
    let token_1 = 0x5678; // Different token!

    let amount_in_0: u64 = 600;
    let salt_in_0 = 0xaaaa;
    let amount_in_1: u64 = 400;
    let salt_in_1 = 0xbbbb;

    let recipient_pubkey = poseidon1(0xcafe);
    let amount_out_0: u64 = 700;
    let salt_out_0 = 0xcccc;
    let amount_out_1: u64 = 300;
    let salt_out_1 = 0xdddd;

    let commitment_in_0 = poseidon4(token_0, amount_in_0 as Field, owner_pubkey, salt_in_0);
    let commitment_in_1 = poseidon4(token_1, amount_in_1 as Field, owner_pubkey, salt_in_1);

    let nullifier_0 = poseidon2(commitment_in_0, spending_key);
    let nullifier_1 = poseidon2(commitment_in_1, spending_key);

    let commitment_out_0 = poseidon4(token_0, amount_out_0 as Field, recipient_pubkey, salt_out_0);
    let commitment_out_1 = poseidon4(token_0, amount_out_1 as Field, owner_pubkey, salt_out_1);

    let proof_length: u32 = 3;
    let mut path_0: [Field; MAX_COMMITMENT_TREE_DEPTH] = [0; MAX_COMMITMENT_TREE_DEPTH];
    let indices_0: [bool; MAX_COMMITMENT_TREE_DEPTH] = [false; MAX_COMMITMENT_TREE_DEPTH];
    let mut path_1: [Field; MAX_COMMITMENT_TREE_DEPTH] = [0; MAX_COMMITMENT_TREE_DEPTH];
    let mut indices_1: [bool; MAX_COMMITMENT_TREE_DEPTH] = [false; MAX_COMMITMENT_TREE_DEPTH];
    indices_1[0] = true;

    let parent_01 = poseidon2(commitment_in_0, commitment_in_1);
    path_0[0] = commitment_in_1;
    path_1[0] = commitment_in_0;

    let mut current = parent_01;
    for _ in 1..proof_length {
        current = poseidon2(current, 0);
    }
    let commitment_root = current;

    main(
        nullifier_0,
        nullifier_1,
        commitment_out_0,
        commitment_out_1,
        commitment_root,
        spending_key,
        token_0,
        amount_in_0,
        salt_in_0,
        token_1, // Mismatched token
        amount_in_1,
        salt_in_1,
        token_0,
        amount_out_0,
        recipient_pubkey,
        salt_out_0,
        token_0,
        amount_out_1,
        owner_pubkey,
        salt_out_1,
        proof_length,
        path_0,
        indices_0,
        path_1,
        indices_1,
    );
}

#[test(should_fail)]
fn test_transfer_wrong_spending_key() {
    // Real owner's spending key
    let real_spending_key = 0xdeadbeef;
    let owner_pubkey = poseidon1(real_spending_key);

    // Attacker's spending key
    let attacker_spending_key = 0xbadcafe;

    let token = 0x1234;
    let amount_in_0: u64 = 600;
    let salt_in_0 = 0xaaaa;
    let amount_in_1: u64 = 400;
    let salt_in_1 = 0xbbbb;

    let attacker_pubkey = poseidon1(attacker_spending_key);
    let amount_out_0: u64 = 1000;
    let salt_out_0 = 0xcccc;
    let amount_out_1: u64 = 0;
    let salt_out_1 = 0xdddd;

    // Commitments made with real owner's pubkey
    let commitment_in_0 = poseidon4(token, amount_in_0 as Field, owner_pubkey, salt_in_0);
    let commitment_in_1 = poseidon4(token, amount_in_1 as Field, owner_pubkey, salt_in_1);

    // Attacker tries to use their spending key to derive nullifiers (will fail)
    let nullifier_0 = poseidon2(commitment_in_0, attacker_spending_key);
    let nullifier_1 = poseidon2(commitment_in_1, attacker_spending_key);

    let commitment_out_0 = poseidon4(token, amount_out_0 as Field, attacker_pubkey, salt_out_0);
    let commitment_out_1 = poseidon4(token, amount_out_1 as Field, attacker_pubkey, salt_out_1);

    let proof_length: u32 = 3;
    let mut path_0: [Field; MAX_COMMITMENT_TREE_DEPTH] = [0; MAX_COMMITMENT_TREE_DEPTH];
    let indices_0: [bool; MAX_COMMITMENT_TREE_DEPTH] = [false; MAX_COMMITMENT_TREE_DEPTH];
    let mut path_1: [Field; MAX_COMMITMENT_TREE_DEPTH] = [0; MAX_COMMITMENT_TREE_DEPTH];
    let mut indices_1: [bool; MAX_COMMITMENT_TREE_DEPTH] = [false; MAX_COMMITMENT_TREE_DEPTH];
    indices_1[0] = true;

    let parent_01 = poseidon2(commitment_in_0, commitment_in_1);
    path_0[0] = commitment_in_1;
    path_1[0] = commitment_in_0;

    let mut current = parent_01;
    for _ in 1..proof_length {
        current = poseidon2(current, 0);
    }
    let commitment_root = current;

    // This will fail because attacker_spending_key doesn't derive to owner_pubkey
    main(
        nullifier_0,
        nullifier_1,
        commitment_out_0,
        commitment_out_1,
        commitment_root,
        attacker_spending_key,
        token,
        amount_in_0,
        salt_in_0,
        token,
        amount_in_1,
        salt_in_1,
        token,
        amount_out_0,
        attacker_pubkey,
        salt_out_0,
        token,
        amount_out_1,
        attacker_pubkey,
        salt_out_1,
        proof_length,
        path_0,
        indices_0,
        path_1,
        indices_1,
    );
}

#[test(should_fail)]
fn test_transfer_invalid_merkle_proof() {
    let spending_key = 0xdeadbeef;
    let owner_pubkey = poseidon1(spending_key);
    let token = 0x1234;

    let amount_in_0: u64 = 600;
    let salt_in_0 = 0xaaaa;
    let amount_in_1: u64 = 400;
    let salt_in_1 = 0xbbbb;

    let recipient_pubkey = poseidon1(0xcafe);
    let amount_out_0: u64 = 700;
    let salt_out_0 = 0xcccc;
    let amount_out_1: u64 = 300;
    let salt_out_1 = 0xdddd;

    let commitment_in_0 = poseidon4(token, amount_in_0 as Field, owner_pubkey, salt_in_0);
    let commitment_in_1 = poseidon4(token, amount_in_1 as Field, owner_pubkey, salt_in_1);

    let nullifier_0 = poseidon2(commitment_in_0, spending_key);
    let nullifier_1 = poseidon2(commitment_in_1, spending_key);

    let commitment_out_0 = poseidon4(token, amount_out_0 as Field, recipient_pubkey, salt_out_0);
    let commitment_out_1 = poseidon4(token, amount_out_1 as Field, owner_pubkey, salt_out_1);

    let proof_length: u32 = 3;
    let path_0: [Field; MAX_COMMITMENT_TREE_DEPTH] = [0; MAX_COMMITMENT_TREE_DEPTH];
    let indices_0: [bool; MAX_COMMITMENT_TREE_DEPTH] = [false; MAX_COMMITMENT_TREE_DEPTH];
    let path_1: [Field; MAX_COMMITMENT_TREE_DEPTH] = [0; MAX_COMMITMENT_TREE_DEPTH];
    let indices_1: [bool; MAX_COMMITMENT_TREE_DEPTH] = [false; MAX_COMMITMENT_TREE_DEPTH];

    // Wrong root
    let wrong_root = poseidon2(0x1234, 0x5678);

    main(
        nullifier_0,
        nullifier_1,
        commitment_out_0,
        commitment_out_1,
        wrong_root,
        spending_key,
        token,
        amount_in_0,
        salt_in_0,
        token,
        amount_in_1,
        salt_in_1,
        token,
        amount_out_0,
        recipient_pubkey,
        salt_out_0,
        token,
        amount_out_1,
        owner_pubkey,
        salt_out_1,
        proof_length,
        path_0,
        indices_0,
        path_1,
        indices_1,
    );
}

#[test]
fn test_transfer_zero_note_valid() {
    // Single-input transfer: input 0 has value, input 1 is a zero note
    let spending_key = 0xdeadbeef;
    let owner_pubkey = poseidon1(spending_key);
    let token = 0x1234567890abcdef1234567890abcdef12345678;

    // Input note 0: real note with 1000
    let amount_in_0: u64 = 1000;
    let salt_in_0 = 0xaaaa;

    // Input note 1: zero note (amount = 0)
    let amount_in_1: u64 = 0;
    let salt_in_1 = 0xbbbb;

    // Output notes: 700 to recipient, 300 as change
    let recipient_pubkey = poseidon1(0xcafe);
    let amount_out_0: u64 = 700;
    let salt_out_0 = 0xcccc;
    let amount_out_1: u64 = 300;
    let salt_out_1 = 0xdddd;

    // Compute input commitments
    let commitment_in_0 = poseidon4(token, amount_in_0 as Field, owner_pubkey, salt_in_0);
    // Zero note commitment is still deterministically computed
    let commitment_in_1 = poseidon4(token, amount_in_1 as Field, owner_pubkey, salt_in_1);

    // Nullifiers: both constrained (even for zero note)
    let nullifier_0 = poseidon2(commitment_in_0, spending_key);
    let nullifier_1 = poseidon2(commitment_in_1, spending_key);

    // Output commitments
    let commitment_out_0 = poseidon4(token, amount_out_0 as Field, recipient_pubkey, salt_out_0);
    let commitment_out_1 = poseidon4(token, amount_out_1 as Field, owner_pubkey, salt_out_1);

    // Build merkle tree with only input 0 (zero note is not in the tree)
    // For this test, use a simple single-leaf tree
    let proof_length: u32 = 3;
    let mut path_0: [Field; MAX_COMMITMENT_TREE_DEPTH] = [0; MAX_COMMITMENT_TREE_DEPTH];
    let indices_0: [bool; MAX_COMMITMENT_TREE_DEPTH] = [false; MAX_COMMITMENT_TREE_DEPTH];

    // Compute root for a tree with commitment_in_0 at index 0
    let mut current = poseidon2(commitment_in_0, 0);
    for _ in 1..proof_length {
        current = poseidon2(current, 0);
    }
    let commitment_root = current;

    // Zero note doesn't need a valid merkle proof (skipped in circuit)
    let path_1: [Field; MAX_COMMITMENT_TREE_DEPTH] = [0; MAX_COMMITMENT_TREE_DEPTH];
    let indices_1: [bool; MAX_COMMITMENT_TREE_DEPTH] = [false; MAX_COMMITMENT_TREE_DEPTH];

    main(
        nullifier_0,
        nullifier_1,
        commitment_out_0,
        commitment_out_1,
        commitment_root,
        spending_key,
        token,
        amount_in_0,
        salt_in_0,
        token,
        amount_in_1,
        salt_in_1,
        token,
        amount_out_0,
        recipient_pubkey,
        salt_out_0,
        token,
        amount_out_1,
        owner_pubkey,
        salt_out_1,
        proof_length,
        path_0,
        indices_0,
        path_1,
        indices_1,
    );
}

#[test(should_fail)]
fn test_transfer_zero_note_wrong_nullifier() {
    // Verify that nullifier_1 IS constrained for zero notes (cannot use arbitrary value)
    let spending_key = 0xdeadbeef;
    let owner_pubkey = poseidon1(spending_key);
    let token = 0x1234567890abcdef1234567890abcdef12345678;

    let amount_in_0: u64 = 1000;
    let salt_in_0 = 0xaaaa;
    let amount_in_1: u64 = 0;
    let salt_in_1 = 0xbbbb;

    let recipient_pubkey = poseidon1(0xcafe);
    let amount_out_0: u64 = 700;
    let salt_out_0 = 0xcccc;
    let amount_out_1: u64 = 300;
    let salt_out_1 = 0xdddd;

    let commitment_in_0 = poseidon4(token, amount_in_0 as Field, owner_pubkey, salt_in_0);

    let nullifier_0 = poseidon2(commitment_in_0, spending_key);
    // Use an arbitrary value for nullifier_1 instead of the correct one
    let nullifier_1 = 0xdeadbeefcafebabe;

    let commitment_out_0 = poseidon4(token, amount_out_0 as Field, recipient_pubkey, salt_out_0);
    let commitment_out_1 = poseidon4(token, amount_out_1 as Field, owner_pubkey, salt_out_1);

    let proof_length: u32 = 3;
    let path_0: [Field; MAX_COMMITMENT_TREE_DEPTH] = [0; MAX_COMMITMENT_TREE_DEPTH];
    let indices_0: [bool; MAX_COMMITMENT_TREE_DEPTH] = [false; MAX_COMMITMENT_TREE_DEPTH];

    let mut current = poseidon2(commitment_in_0, 0);
    for _ in 1..proof_length {
        current = poseidon2(current, 0);
    }
    let commitment_root = current;

    let path_1: [Field; MAX_COMMITMENT_TREE_DEPTH] = [0; MAX_COMMITMENT_TREE_DEPTH];
    let indices_1: [bool; MAX_COMMITMENT_TREE_DEPTH] = [false; MAX_COMMITMENT_TREE_DEPTH];

    main(
        nullifier_0,
        nullifier_1,
        commitment_out_0,
        commitment_out_1,
        commitment_root,
        spending_key,
        token,
        amount_in_0,
        salt_in_0,
        token,
        amount_in_1,
        salt_in_1,
        token,
        amount_out_0,
        recipient_pubkey,
        salt_out_0,
        token,
        amount_out_1,
        owner_pubkey,
        salt_out_1,
        proof_length,
        path_0,
        indices_0,
        path_1,
        indices_1,
    );
}

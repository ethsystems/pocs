use binary_merkle_root::binary_merkle_root;
use poseidon::poseidon::bn254::{hash_1, hash_2, hash_4};

// Maximum tree depth (for array sizing)
global MAX_ATTESTATION_TREE_DEPTH: u32 = 20;

// Poseidon wrapper for 4 elements (matches PoseidonT5 in Solidity)
fn poseidon4(a: Field, b: Field, c: Field, d: Field) -> Field {
    hash_4([a, b, c, d])
}

// Poseidon wrapper for 2 elements (matches PoseidonT3 in Solidity)
fn poseidon2(a: Field, b: Field) -> Field {
    hash_2([a, b])
}

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

/// Deposit Circuit
///
/// Proves that:
/// 1. The commitment is correctly formed from the note components
/// 2. The depositor has a valid attestation in the attestation tree
///
/// Public Inputs:
/// - commitment: the note commitment being created
/// - token: ERC-20 token address (lower 160 bits)
/// - amount: deposit amount
/// - attestation_root: current root of attestation tree
///
/// Private Inputs:
/// - owner_pubkey: depositor's spending public key (poseidon hash of spending_key)
/// - salt: random value for hiding
/// - attester: attester address (160 bits)
/// - issued_at: attestation timestamp
/// - expires_at: expiration (0 = no expiry)
/// - attestation_proof_length: actual depth of the attestation tree proof
/// - attestation_path: merkle siblings (padded to MAX_ATTESTATION_TREE_DEPTH)
/// - attestation_indices: path direction bits (padded to MAX_ATTESTATION_TREE_DEPTH)
fn main(
    // Public inputs
    commitment: pub Field,
    token: pub Field,
    amount: pub Field,
    attestation_root: pub Field,
    // Private inputs
    owner_pubkey: Field,
    salt: Field,
    attester: Field,
    issued_at: u64,
    expires_at: u64,
    attestation_proof_length: u32,
    attestation_path: [Field; MAX_ATTESTATION_TREE_DEPTH],
    attestation_indices: [bool; MAX_ATTESTATION_TREE_DEPTH],
) {
    // 1. Verify commitment is correctly formed
    // commitment = poseidon4(token, amount, owner_pubkey, salt)
    let computed_commitment = poseidon4(token, amount, owner_pubkey, salt);
    assert(commitment == computed_commitment);

    // 2. Compute attestation leaf and verify merkle inclusion
    // attestation_leaf = poseidon4(owner_pubkey, attester, issued_at, expires_at)
    let attestation_leaf = poseidon4(
        owner_pubkey,
        attester,
        issued_at as Field,
        expires_at as Field,
    );
    verify_merkle_proof(
        attestation_leaf,
        attestation_root,
        attestation_proof_length,
        attestation_indices,
        attestation_path,
    );
}

#[test]
fn test_deposit_valid() {
    // Test values
    let token = 0x1234567890abcdef1234567890abcdef12345678;
    let amount = 1000;
    let owner_pubkey = hash_1([0xdeadbeef]); // Simulated pubkey derivation
    let salt = 0xabcd1234;
    let attester = 0xfedcba0987654321fedcba0987654321fedcba09;
    let issued_at: u64 = 1700000000;
    let expires_at: u64 = 0; // No expiry

    // Compute commitment
    let commitment = poseidon4(token, amount, owner_pubkey, salt);

    // Compute attestation leaf
    let attestation_leaf = poseidon4(
        owner_pubkey,
        attester,
        issued_at as Field,
        expires_at as Field,
    );

    // Build a simple merkle tree with depth 3 (using dynamic depth)
    let attestation_proof_length: u32 = 3;
    let mut attestation_path: [Field; MAX_ATTESTATION_TREE_DEPTH] = [0; MAX_ATTESTATION_TREE_DEPTH];
    let attestation_indices: [bool; MAX_ATTESTATION_TREE_DEPTH] = [false; MAX_ATTESTATION_TREE_DEPTH];

    // Compute root by hashing up the tree (only up to proof_length)
    let mut current = attestation_leaf;
    for i in 0..attestation_proof_length {
        current = poseidon2(current, attestation_path[i]);
    }
    let attestation_root = current;

    main(
        commitment,
        token,
        amount,
        attestation_root,
        owner_pubkey,
        salt,
        attester,
        issued_at,
        expires_at,
        attestation_proof_length,
        attestation_path,
        attestation_indices,
    );
}

#[test]
fn test_deposit_with_expiry() {
    // Test values with expiration
    let token = 0x1234567890abcdef1234567890abcdef12345678;
    let amount = 500;
    let owner_pubkey = hash_1([0xbeef]);
    let salt = 0x5678;
    let attester = 0xabcdef;
    let issued_at: u64 = 1700000000;
    let expires_at: u64 = 1800000000; // Expires in the future

    let commitment = poseidon4(token, amount, owner_pubkey, salt);
    let attestation_leaf = poseidon4(
        owner_pubkey,
        attester,
        issued_at as Field,
        expires_at as Field,
    );

    let attestation_proof_length: u32 = 3;
    let mut attestation_path: [Field; MAX_ATTESTATION_TREE_DEPTH] = [0; MAX_ATTESTATION_TREE_DEPTH];
    let attestation_indices: [bool; MAX_ATTESTATION_TREE_DEPTH] = [false; MAX_ATTESTATION_TREE_DEPTH];

    let mut current = attestation_leaf;
    for i in 0..attestation_proof_length {
        current = poseidon2(current, attestation_path[i]);
    }
    let attestation_root = current;

    main(
        commitment,
        token,
        amount,
        attestation_root,
        owner_pubkey,
        salt,
        attester,
        issued_at,
        expires_at,
        attestation_proof_length,
        attestation_path,
        attestation_indices,
    );
}

#[test(should_fail)]
fn test_deposit_invalid_commitment() {
    let token = 0x1234;
    let amount = 1000;
    let owner_pubkey = hash_1([0xbeef]);
    let salt = 0xabcd;
    let attester = 0xfeed;
    let issued_at: u64 = 1700000000;
    let expires_at: u64 = 0;

    // Wrong commitment (different salt)
    let wrong_commitment = poseidon4(token, amount, owner_pubkey, 0x9999);

    let attestation_leaf = poseidon4(
        owner_pubkey,
        attester,
        issued_at as Field,
        expires_at as Field,
    );

    let attestation_proof_length: u32 = 3;
    let attestation_path: [Field; MAX_ATTESTATION_TREE_DEPTH] = [0; MAX_ATTESTATION_TREE_DEPTH];
    let attestation_indices: [bool; MAX_ATTESTATION_TREE_DEPTH] = [false; MAX_ATTESTATION_TREE_DEPTH];

    let mut current = attestation_leaf;
    for i in 0..attestation_proof_length {
        current = poseidon2(current, attestation_path[i]);
    }
    let attestation_root = current;

    main(
        wrong_commitment,
        token,
        amount,
        attestation_root,
        owner_pubkey,
        salt,
        attester,
        issued_at,
        expires_at,
        attestation_proof_length,
        attestation_path,
        attestation_indices,
    );
}

#[test(should_fail)]
fn test_deposit_invalid_merkle_proof() {
    let token = 0x1234;
    let amount = 1000;
    let owner_pubkey = hash_1([0xbeef]);
    let salt = 0xabcd;
    let attester = 0xfeed;
    let issued_at: u64 = 1700000000;
    let expires_at: u64 = 0;

    let commitment = poseidon4(token, amount, owner_pubkey, salt);
    let attestation_leaf = poseidon4(
        owner_pubkey,
        attester,
        issued_at as Field,
        expires_at as Field,
    );

    let attestation_proof_length: u32 = 3;
    let attestation_path: [Field; MAX_ATTESTATION_TREE_DEPTH] = [0; MAX_ATTESTATION_TREE_DEPTH];
    let attestation_indices: [bool; MAX_ATTESTATION_TREE_DEPTH] = [false; MAX_ATTESTATION_TREE_DEPTH];

    // Compute a valid root
    let mut current = attestation_leaf;
    for i in 0..attestation_proof_length {
        current = poseidon2(current, attestation_path[i]);
    }

    // Use wrong root
    let wrong_root = poseidon2(current, 0x1234);

    main(
        commitment,
        token,
        amount,
        wrong_root,
        owner_pubkey,
        salt,
        attester,
        issued_at,
        expires_at,
        attestation_proof_length,
        attestation_path,
        attestation_indices,
    );
}

use poseidon;

// Simulates the Note struct from Rust
fn note_commit(
    value: Field,
    salt: Field,
    owner: Field,
    asset_id: Field,
    maturity_date: Field,
) -> Field {
    poseidon::poseidon::bn254::hash_5([value, salt, owner, asset_id, maturity_date])
}

// Simulates the nullifier function from Rust
fn note_nullifier(salt: Field, private_key: Field) -> Field {
    poseidon::poseidon::bn254::hash_2([salt, private_key])
}

fn verify_merkle_proof(
    leaf: Field,
    root: Field,
    path_indices: [bool; TREE_HEIGHT],
    path_elements: [Field; TREE_HEIGHT],
) {
    let mut current = leaf;
    for i in 0..TREE_HEIGHT {
        let sibling = path_elements[i];
        let is_right = path_indices[i];

        // If index is false (left), hash(current, sibling)
        // If index is true (right), hash(sibling, current)
        let mut left = current;
        let mut right = sibling;

        if is_right {
            left = sibling;
            right = current;
        }

        current = poseidon::poseidon::bn254::hash_2([left, right]);
    }
    assert(current == root);
}

global TREE_HEIGHT: u32 = 3;

fn main(
    root: pub Field,
    nullifiers: pub [Field; 2],
    commitments_out: pub [Field; 2],
    // Input note
    input_values: [u64; 2],
    input_salts: [Field; 2],
    input_owner: Field,
    input_asset_id: Field,
    input_maturity_date: pub Field,
    // Merkle Path
    path_indices: [[bool; TREE_HEIGHT]; 2],
    path_elements: [[Field; TREE_HEIGHT]; 2],
    // Output note
    output_values: [u64; 2],
    output_salts: [Field; 2],
    output_owners: [Field; 2],
    output_asset_ids: [Field; 2],
    output_maturity_date: pub Field,
    // Private key
    private_key: Field,
) -> pub (bool) {
    let mut total_input_value: u64 = 0;
    let mut total_output_value: u64 = 0;

    // Only input 1 may be padding: with two zero-value inputs, nothing is checked against the tree
    assert(input_values[0] != 0, "Input 0 must carry value");

    for i in 0..2 {
        let commitment = note_commit(
            input_values[i] as Field,
            input_salts[i],
            input_owner,
            input_asset_id,
            input_maturity_date,
        );

        // Zero-value inputs are padding: skip membership so each one can use a fresh salt
        if input_values[i] != 0 {
            verify_merkle_proof(commitment, root, path_indices[i], path_elements[i]);
        }

        let calculated_nullifier = note_nullifier(input_salts[i], private_key);
        assert(calculated_nullifier == nullifiers[i]);

        total_input_value = total_input_value + input_values[i];
    }

    for i in 0..2 {
        let output_commitments = note_commit(
            output_values[i] as Field,
            output_salts[i],
            output_owners[i],
            output_asset_ids[i],
            output_maturity_date,
        );
        assert(output_commitments == commitments_out[i]);

        total_output_value = total_output_value + output_values[i];

        assert(output_asset_ids[i] == input_asset_id);
    }

    assert(total_input_value == total_output_value);
    assert(input_maturity_date == output_maturity_date);
    assert(input_owner == poseidon::poseidon::bn254::hash_1([private_key]));
    total_output_value == 0
}

#[test]
fn test_main() {
    let private_key = 999;

    let val_in_0: u64 = 100;
    let salt_in_0 = 123;
    let owner_in = poseidon::poseidon::bn254::hash_1([private_key]);
    let asset_id = 1;
    // 2030-01-01 00:00:00 UTC
    let input_maturity_date = 1893456000;
    let comm_in_0 = note_commit(val_in_0 as Field, salt_in_0, owner_in, asset_id, input_maturity_date);

    let val_in_1: u64 = 0;
    let salt_in_1 = 0;
    let comm_in_1 = note_commit(val_in_1 as Field, salt_in_1, owner_in, asset_id, input_maturity_date);

    let leaf_0 = comm_in_0;
    let leaf_1 = comm_in_1;
    let node_0_1 = poseidon::poseidon::bn254::hash_2([leaf_0, leaf_1]);

    let root =
        poseidon::poseidon::bn254::hash_2([poseidon::poseidon::bn254::hash_2([node_0_1, 0]), 0]);

    let val_out_0: u64 = 40;
    let val_out_1: u64 = 60;
    let salt_out_0 = 456;
    let salt_out_1 = 789;

    let comm_out_0 = note_commit(
        val_out_0 as Field,
        salt_out_0,
        owner_in,
        asset_id,
        input_maturity_date,
    );
    let comm_out_1 = note_commit(
        val_out_1 as Field,
        salt_out_1,
        owner_in,
        asset_id,
        input_maturity_date,
    );

    let null_0 = note_nullifier(salt_in_0, private_key);
    let null_1 = note_nullifier(salt_in_1, private_key);

    // Log all the computed values
    println("=== Owner Public Key ===");
    println(f"public key: {owner_in}");

    println("=== Input Commitments ===");
    println(f"comm_in_0: {comm_in_0}");
    println(f"comm_in_1: {comm_in_1}");

    println("=== Merkle Root ===");
    println(f"root: {root}");

    println("=== Nullifiers ===");
    println(f"null_0: {null_0}");
    println(f"null_1: {null_1}");

    println("=== Output Commitments ===");
    println(f"comm_out_0: {comm_out_0}");
    println(f"comm_out_1: {comm_out_1}");

    println("=== Path Elements ===");
    println(f"leaf_0: {leaf_0}");
    println(f"leaf_1: {leaf_1}");
    println(f"node_0_1: {node_0_1}");

    let is_reedem = main(
        root,
        [null_0, null_1],
        [comm_out_0, comm_out_1],
        [val_in_0, val_in_1],
        [salt_in_0, salt_in_1],
        owner_in,
        asset_id,
        input_maturity_date,
        [[false, false, false], [true, false, false]],
        [[leaf_1, 0, 0], [leaf_0, 0, 0]],
        [val_out_0, val_out_1],
        [salt_out_0, salt_out_1],
        [owner_in, owner_in],
        [asset_id, asset_id],
        input_maturity_date,
        private_key,
    );
    println("Is this a reedem operation?");
    println(is_reedem)
}

// Spends one real note that is in the tree, plus a second input with a fresh salt
// that was never added to the tree and carries a bogus Merkle path
fn spend_with_unregistered_second_input(second_value: u64) {
    let private_key = 999;
    let owner = poseidon::poseidon::bn254::hash_1([private_key]);
    let asset_id = 1;
    // 2030-01-01 00:00:00 UTC
    let maturity_date = 1893456000;

    let real_value: u64 = 100;
    let real_salt = 123;
    let real_comm = note_commit(
        real_value as Field,
        real_salt,
        owner,
        asset_id,
        maturity_date,
    );
    // The tree holds only the real note, so every sibling is empty
    let root = poseidon::poseidon::bn254::hash_2([
        poseidon::poseidon::bn254::hash_2([poseidon::poseidon::bn254::hash_2([real_comm, 0]), 0]),
        0,
    ]);

    let second_salt = 0xabcdef;
    let val_out_0: u64 = 40;
    let val_out_1: u64 = real_value + second_value - val_out_0;
    let comm_out_0 = note_commit(val_out_0 as Field, 456, owner, asset_id, maturity_date);
    let comm_out_1 = note_commit(val_out_1 as Field, 789, owner, asset_id, maturity_date);

    let _ = main(
        root,
        [note_nullifier(real_salt, private_key), note_nullifier(second_salt, private_key)],
        [comm_out_0, comm_out_1],
        [real_value, second_value],
        [real_salt, second_salt],
        owner,
        asset_id,
        maturity_date,
        [[false, false, false], [true, true, true]],
        [[0, 0, 0], [5, 6, 7]],
        [val_out_0, val_out_1],
        [456, 789],
        [owner, owner],
        [asset_id, asset_id],
        maturity_date,
        private_key,
    );
}

// A zero-value input is padding: it needs no tree membership, so each one can use a fresh salt
#[test]
fn test_zero_value_input_skips_membership() {
    spend_with_unregistered_second_input(0);
}

// A note with value must still be in the tree
#[test(should_fail)]
fn test_nonzero_input_requires_membership() {
    spend_with_unregistered_second_input(10);
}

// Two zero-value inputs would check nothing against the tree, leaving the root free
#[test(should_fail_with = "Input 0 must carry value")]
fn test_two_zero_value_inputs_rejected() {
    let private_key = 999;
    let owner = poseidon::poseidon::bn254::hash_1([private_key]);
    let asset_id = 1;
    // 2030-01-01 00:00:00 UTC
    let maturity_date = 1893456000;
    let comm_out_0 = note_commit(0, 456, owner, asset_id, maturity_date);
    let comm_out_1 = note_commit(0, 789, owner, asset_id, maturity_date);

    let _ = main(
        // Any root: neither input is checked against it
        12345,
        [note_nullifier(0xabc, private_key), note_nullifier(0xdef, private_key)],
        [comm_out_0, comm_out_1],
        [0, 0],
        [0xabc, 0xdef],
        owner,
        asset_id,
        maturity_date,
        [[true, true, true], [true, true, true]],
        [[5, 6, 7], [5, 6, 7]],
        [0, 0],
        [456, 789],
        [owner, owner],
        [asset_id, asset_id],
        maturity_date,
        private_key,
    );
}

use rpi_lib::hasher;
use rpi_lib::merkle;

fn main(
    // Public inputs
    root: pub Field,
    nullifier: pub Field,
    external_nullifier: pub Field,
    version: pub Field,
    predicate_type: pub Field,
    predicate_attr_index: pub Field,
    predicate_value: pub Field,
    predicate_result: pub Field,
    // Private inputs
    identity_secret: Field,
    attr0: Field,
    attr1: Field,
    attr2: Field,
    attr3: Field,
    proof_length: u32,
    leaf_index_bits: [bool; 20],
    merkle_path: [Field; 20],
) {
    // 1. Version gate -- only version 1 is valid in this PoC.
    assert(version == 1, "unsupported version");

    // 2. Compute attribute hash from the four attribute fields.
    let attr_hash = hasher::hash_attr(version, [attr0, attr1, attr2, attr3]);

    // 3. Compute the leaf commitment from identity secret and attribute hash.
    let leaf = hasher::hash_leaf(identity_secret, attr_hash);

    // 4. Verify Merkle inclusion proof (variable depth from LeanIMT).
    merkle::verify_membership(leaf, root, proof_length, leaf_index_bits, merkle_path);

    // 5. Nullifier derivation -- bind presentation to external nullifier.
    let computed_nullifier = hasher::hash_nullifier(identity_secret, external_nullifier);
    assert(nullifier == computed_nullifier, "nullifier mismatch");

    // 6. Predicate evaluation -- selective disclosure of attr0 or attr1.

    // Only predicate types 0 (equality) and 1 (boolean) are supported.
    assert(predicate_type as u64 < 2, "invalid predicate type");

    // Only attribute indices 0 and 1 are queryable.
    assert(predicate_attr_index as u64 < 2, "invalid predicate attr index");

    // Select the target attribute based on predicate_attr_index.
    let selected = if predicate_attr_index == 0 { attr0 } else { attr1 };

    // Type 0: equality check -- does selected == predicate_value?
    let eq_result = (selected == predicate_value) as Field;

    // Type 1: boolean check -- is selected == 1?
    // When type is 1, predicate_value must be 0 (it is unused for boolean predicates).
    if predicate_type == 1 {
        assert(predicate_value == 0, "predicate_value must be 0 for boolean predicate");
    }
    let bool_result = (selected == 1) as Field;

    // Dispatch: pick the result that matches the predicate type.
    let expected = if predicate_type == 0 { eq_result } else { bool_result };

    // Verify the caller-provided result matches.
    assert(predicate_result == expected, "predicate result mismatch");

    // Result is always binary (0 or 1).
    assert(predicate_result as u64 < 2, "predicate result not binary");
}

#[test]
fn test_membership_circuit() {

    let identity_secret: Field = 12345;
    let version: Field = 1;
    let attr0: Field = 42; // e.g. jurisdiction code
    let attr1: Field = 1;  // e.g. boolean flag (accredited = true)
    let attr2: Field = 100;
    let attr3: Field = 200;

    // Compute leaf
    let attr_hash = hasher::hash_attr(version, [attr0, attr1, attr2, attr3]);
    let leaf = hasher::hash_leaf(identity_secret, attr_hash);

    // Build a Merkle tree of depth 20 with this leaf at index 0.
    // All siblings are zero. We walk up from the leaf, hashing with 0 on the right.
    let mut merkle_path: [Field; 20] = [0; 20];
    let leaf_index_bits: [bool; 20] = [false; 20]; // index 0 means all bits are false

    // Compute the root by hashing up the tree: leaf is always on the left side (bit=0).
    let mut current = leaf;
    for i in 0..20 {
        current = hasher::hash_merkle_node(current, merkle_path[i]);
    }
    let root = current;

    // Compute nullifier
    let external_nullifier: Field = 99999;
    let nullifier = hasher::hash_nullifier(identity_secret, external_nullifier);


    let predicate_type: Field = 0;
    let predicate_attr_index: Field = 0;
    let predicate_value: Field = 42;
    let predicate_result: Field = 1; // 42 == 42 is true

    main(
        root,
        nullifier,
        external_nullifier,
        version,
        predicate_type,
        predicate_attr_index,
        predicate_value,
        predicate_result,
        identity_secret,
        attr0,
        attr1,
        attr2,
        attr3,
        20,
        leaf_index_bits,
        merkle_path,
    );


    let predicate_type2: Field = 1;
    let predicate_attr_index2: Field = 1;
    let predicate_value2: Field = 0; // must be 0 for boolean predicate
    let predicate_result2: Field = 1; // attr1 == 1 is true

    main(
        root,
        nullifier,
        external_nullifier,
        version,
        predicate_type2,
        predicate_attr_index2,
        predicate_value2,
        predicate_result2,
        identity_secret,
        attr0,
        attr1,
        attr2,
        attr3,
        20,
        leaf_index_bits,
        merkle_path,
    );


    let predicate_type3: Field = 0;
    let predicate_attr_index3: Field = 0;
    let predicate_value3: Field = 99; // 42 != 99
    let predicate_result3: Field = 0; // not equal

    main(
        root,
        nullifier,
        external_nullifier,
        version,
        predicate_type3,
        predicate_attr_index3,
        predicate_value3,
        predicate_result3,
        identity_secret,
        attr0,
        attr1,
        attr2,
        attr3,
        20,
        leaf_index_bits,
        merkle_path,
    );
}

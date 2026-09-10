use poseidon::poseidon::bn254::hash_4;

fn main(
    commitment: pub Field,
    token: pub Field,
    amount: pub Field,
    funding_address: pub Field,
    payload_hash: pub Field,
    // 2/SHIELDED-POOL 5.3 permits shielding to a recipient without their secret.
    // Key ownership is the additional E1 constraint of 3/ATTESTED-POOL 5.3.
    owner_pubkey: Field,
    salt: Field,
) {
    amount.assert_max_bit_size::<128>();
    assert(commitment == hash_4([token, amount, owner_pubkey, salt]), "commitment mismatch");
    // The proof binds these inputs; the contract checks funding and hashes the payload.
    let _ = funding_address;
    let _ = payload_hash;
}

#[test]
fn test_recipient_without_spending_secret() {
    let recipient_pubkey = 0x1234;
    main(hash_4([1, 10, recipient_pubkey, 19]), 1, 10, 2, 3, recipient_pubkey, 19);
}

#[test]
fn test_amount_boundaries() {
    for amount in [0, 1, 0xffffffffffffffffffffffffffffffff] {
        main(hash_4([1, amount, 17, 19]), 1, amount, 2, 3, 17, 19);
    }
}

#[test(should_fail_with = "call to assert_max_bit_size")]
fn test_amount_above_u128() {
    let amount: Field = 0x100000000000000000000000000000000;
    main(hash_4([1, amount, 17, 19]), 1, amount, 2, 3, 17, 19);
}

#[test(should_fail_with = "commitment mismatch")]
fn test_changed_token() {
    main(hash_4([1, 10, 17, 19]), 2, 10, 2, 3, 17, 19);
}

#[test(should_fail_with = "commitment mismatch")]
fn test_changed_amount() {
    main(hash_4([1, 10, 17, 19]), 1, 11, 2, 3, 17, 19);
}

#[test(should_fail_with = "commitment mismatch")]
fn test_changed_owner() {
    main(hash_4([1, 10, 17, 19]), 1, 10, 2, 3, 18, 19);
}

#[test(should_fail_with = "commitment mismatch")]
fn test_changed_salt() {
    main(hash_4([1, 10, 17, 19]), 1, 10, 2, 3, 17, 20);
}

#[test]
fn test_core_fixture_matches_rust() {
    main(
        0x234ec6c90742424c1da8c8dd35b92eb3d5b5a77d4d78a8c55b1ae832d830d231,
        1,
        10,
        2,
        0x071c6e27bb36f7813a2746559be0f4630a2fd26e891cfa0ad482f4c376be925b,
        17,
        19,
    );
}

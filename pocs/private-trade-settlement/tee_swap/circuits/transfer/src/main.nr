use binary_merkle_root::binary_merkle_root;
use poseidon::poseidon::bn254::{hash_2, hash_3, hash_8};
use std::embedded_curve_ops::{
    embedded_curve_add, EmbeddedCurvePoint, EmbeddedCurveScalar, fixed_base_scalar_mul,
    multi_scalar_mul,
};

global MAX_DEPTH: u32 = 20;

// Domain separation tags
global DOMAIN_COMMITMENT: Field = 0x109594dc3faa33ceeeac5e46d290040cdf090cb9883904d1337a9cb26e19a5;
global DOMAIN_NULLIFIER: Field = 0x225cbdfee768405fd834228dc85d2f6d1f18901486e2f5c8f1a204fccbb393;
global DOMAIN_STEALTH: Field = 0x89c0b4bea509c4509d7c93f962f79cddfb03f7a8056b159df275ec7e4e6852;
global DOMAIN_SALT_ENC: Field = 0xa55fbcf2316286f724b5fbfb530d536e3829c23ad2d1bd01b87792f785bcc4;
global DOMAIN_BIND_SWAP: Field = 0x558e73d4477300526f0e29f920a317a62cc425034408d58be6dbe7fc484751;
global DOMAIN_BIND_R: Field = 0xb4965ea4c1b3f9e13c36a32782935c2a1b3c49ec54e201de5f4133f2548a94;
global DOMAIN_BIND_META: Field = 0xf3241b2bffce1dd293f941d327f2ce2189f7d423501f0dd76a7da8c407502a;
global DOMAIN_BIND_ENC: Field = 0xd0779ead2e71428d9e8ef698a01482d8f344b17244792086fdc32bdfdf67dd;

fn compute_commitment(
    chain_id: Field,
    value: u64,
    asset_id: Field,
    owner: Field,
    fallback_owner: Field,
    timeout: Field,
    salt: Field,
) -> Field {
    hash_8([
        DOMAIN_COMMITMENT,
        chain_id,
        value as Field,
        asset_id,
        owner,
        fallback_owner,
        timeout,
        salt,
    ])
}

fn compute_nullifier(commitment: Field, salt: Field) -> Field {
    hash_3([DOMAIN_NULLIFIER, commitment, salt])
}

fn verify_merkle_inclusion(
    leaf: Field,
    root: Field,
    proof_length: u32,
    path_indices: [bool; MAX_DEPTH],
    path_elements: [Field; MAX_DEPTH],
) {
    let computed_root = binary_merkle_root(hash_2, leaf, proof_length, path_indices, path_elements);
    assert(computed_root == root);
}

fn derive_public_key(sk_lo: Field, sk_hi: Field) -> EmbeddedCurvePoint {
    let sk = EmbeddedCurveScalar { lo: sk_lo, hi: sk_hi };
    fixed_base_scalar_mul(sk)
}

/// converts `Field` to `EmbeddedCurveScalar`
fn field_to_scalar(f: Field) -> EmbeddedCurveScalar {
    let bytes: [u8; 32] = f.to_be_bytes();
    // Big-endian: bytes[0] is MSB
    // hi = upper 128 bits (bytes[0..16])
    // lo = lower 128 bits (bytes[16..32])
    let mut hi: Field = 0;
    let mut lo: Field = 0;
    for i in 0..16 {
        hi = hi * 256 + bytes[i] as Field;
        lo = lo * 256 + bytes[16 + i] as Field;
    }
    EmbeddedCurveScalar { lo, hi }
}

/// Zero the top 3 bits of a field element, ensuring it fits in 253 bits (< BN254 p).
fn mask_253(f: Field) -> Field {
    let mut bytes: [u8; 32] = f.to_be_bytes();
    bytes[0] &= 0x1F;
    Field::from_be_bytes::<32>(bytes)
}

/// salt encryption
fn xor_fields(a: Field, b: Field) -> Field {
    let a_bytes: [u8; 32] = a.to_be_bytes();
    let b_bytes: [u8; 32] = b.to_be_bytes();
    let mut xor_bytes: [u8; 32] = [0; 32];
    for i in 0..32 {
        xor_bytes[i] = a_bytes[i] ^ b_bytes[i];
    }
    let result = Field::from_be_bytes::<32>(xor_bytes);

    // reject XOR results >= p
    let roundtrip: [u8; 32] = result.to_be_bytes();
    for i in 0..32 {
        assert(roundtrip[i] == xor_bytes[i]);
    }
    result
}

/// lock mode assertions
fn assert_lock_extras_zero(
    swap_id: Field,
    r_lo: Field,
    r_hi: Field,
    pk_meta_x: Field,
    pk_meta_y: Field,
    encrypted_salt: Field,
) {
    assert(swap_id == 0);
    assert(r_lo == 0);
    assert(r_hi == 0);
    assert(pk_meta_x == 0);
    assert(pk_meta_y == 0);
    assert(encrypted_salt == 0);
}

/// Proves one of four operations on time-locked UTXO notes:
///   - Transfer: standard UTXO spend (timeout=0, pk_stealth=0)
///   - Lock:     create swap note with stealth address (timeout>0, pk_stealth!=0, h_swap!=0)
///   - Claim:    spend swap note via stealth key (timeout>0, pk_stealth!=0, h_swap=0)
///   - Refund:   spend swap note via fallback key (timeout>0, pk_stealth=0)
///
/// All modes prove: input commitment + Merkle inclusion + nullifier + output commitment.
/// Lock mode additionally proves: stealth address derivation + 4 binding commitments.
///
// Public input indices:
// [0] nullifier  [1] root  [2] new_commitment  [3] timeout
// [4] pk_stealth [5] h_swap [6] h_R [7] h_meta [8] h_enc
fn main(
    // -- Public inputs (9) --
    nullifier: pub Field,
    root: pub Field,
    new_commitment: pub Field,
    timeout: pub Field,
    pk_stealth: pub Field,
    h_swap: pub Field,
    h_R: pub Field,
    h_meta: pub Field,
    h_enc: pub Field,
    // -- Private: input note --
    sk_lo: Field,
    sk_hi: Field,
    in_chain_id: Field,
    in_value: u64,
    in_asset_id: Field,
    in_owner: Field,
    in_fallback_owner: Field,
    in_timeout: Field,
    in_salt: Field,
    proof_length: u32,
    path_elements: [Field; MAX_DEPTH],
    path_indices: [bool; MAX_DEPTH],
    // -- Private: output note --
    out_chain_id: Field,
    out_value: u64,
    out_asset_id: Field,
    out_owner: Field,
    out_fallback_owner: Field,
    out_timeout: Field,
    out_salt: Field,
    // -- Private: lock-mode extras (must be 0 in non-lock modes) --
    swap_id: Field,
    r_lo: Field,
    r_hi: Field,
    pk_meta_x: Field,
    pk_meta_y: Field,
    encrypted_salt: Field,
) {
    let in_commitment = compute_commitment(
        in_chain_id,
        in_value,
        in_asset_id,
        in_owner,
        in_fallback_owner,
        in_timeout,
        in_salt,
    );

    verify_merkle_inclusion(
        in_commitment,
        root,
        proof_length,
        path_indices,
        path_elements,
    );

    assert(nullifier == compute_nullifier(in_commitment, in_salt));

    let out_commitment = compute_commitment(
        out_chain_id,
        out_value,
        out_asset_id,
        out_owner,
        out_fallback_owner,
        out_timeout,
        out_salt,
    );
    assert(new_commitment == out_commitment);

    // Value conservation: input and output notes must have same value, asset, and chain
    assert(in_value == out_value);
    assert(in_asset_id == out_asset_id);
    assert(in_chain_id == out_chain_id);

    let derived_pk = derive_public_key(sk_lo, sk_hi);

    if timeout == 0 {
        // -- Transfer: standard UTXO spend --
        assert(derived_pk.x == in_owner);
        assert(timeout == in_timeout);
        assert(pk_stealth == 0);
        assert(h_swap == 0);
        assert(h_R == 0);
        assert(h_meta == 0);
        assert(h_enc == 0);
        assert_lock_extras_zero(swap_id, r_lo, r_hi, pk_meta_x, pk_meta_y, encrypted_salt);
    } else if pk_stealth != 0 {
        // Lock/Claim
        assert(derived_pk.x == in_owner);

        if h_swap != 0 {
            // Lock
            assert(timeout == out_timeout);
            // Only standard notes can be locked (prevent re-locking)
            assert(in_timeout == 0);
        } else {
            // Claim
            assert(timeout == in_timeout);
            assert(pk_stealth == in_owner);
            assert(h_R == 0);
            assert(h_meta == 0);
            assert(h_enc == 0);
            assert_lock_extras_zero(swap_id, r_lo, r_hi, pk_meta_x, pk_meta_y, encrypted_salt);
        }
    } else {
        // Refund
        // Contract checks: block.timestamp > timeout
        assert(derived_pk.x == in_fallback_owner);
        assert(timeout == in_timeout);
        assert(h_swap == 0);
        assert(h_R == 0);
        assert(h_meta == 0);
        assert(h_enc == 0);
        assert_lock_extras_zero(swap_id, r_lo, r_hi, pk_meta_x, pk_meta_y, encrypted_salt);
    }

    // Lock binding verification

    if h_swap != 0 {
        // ECDH shared secret: shared = r * pk_meta
        let r_scalar = EmbeddedCurveScalar { lo: r_lo, hi: r_hi };
        let pk_meta = EmbeddedCurvePoint { x: pk_meta_x, y: pk_meta_y };
        let shared = multi_scalar_mul([pk_meta], [r_scalar]);

        // Stealth address: pk_stealth = pk_meta + H(DOMAIN_STEALTH, shared.x) * G
        let stealth_hash = hash_2([DOMAIN_STEALTH, shared.x]);
        let stealth_scalar = field_to_scalar(stealth_hash);
        let stealth_g = fixed_base_scalar_mul(stealth_scalar);
        let pk_stealth_derived = embedded_curve_add(pk_meta, stealth_g);
        assert(pk_stealth_derived.x == pk_stealth);
        assert(out_owner == pk_stealth);

        // Binding commitments
        assert(hash_3([DOMAIN_BIND_SWAP, swap_id, out_salt]) == h_swap);

        let big_r = fixed_base_scalar_mul(r_scalar);
        assert(hash_2([DOMAIN_BIND_R, big_r.x]) == h_R);

        assert(hash_3([DOMAIN_BIND_META, pk_meta_x, out_salt]) == h_meta);

        // Salt encryption verification (enc_key masked to 253 bits for XOR safety)
        let enc_key = mask_253(hash_2([DOMAIN_SALT_ENC, shared.x]));
        let computed_enc_salt = xor_fields(out_salt, enc_key);
        assert(computed_enc_salt == encrypted_salt);
        assert(hash_2([DOMAIN_BIND_ENC, encrypted_salt]) == h_enc);
    }
}

// =========================================
// Test Helpers
// =========================================

/// Compute Merkle root for a single-leaf tree (proof_length=1, leaf at index 0)
fn test_merkle_root(leaf: Field) -> Field {
    hash_2([leaf, 0])
}

fn zero_path_elements() -> [Field; MAX_DEPTH] {
    [0; MAX_DEPTH]
}

fn zero_path_indices() -> [bool; MAX_DEPTH] {
    [false; MAX_DEPTH]
}

// =========================================
// Tests
// =========================================

#[test]
fn test_valid_transfer() {
    let sk_lo: Field = 0xdeadbeef;
    let sk_hi: Field = 0;
    let pk = derive_public_key(sk_lo, sk_hi);
    let owner = pk.x;

    let in_chain_id: Field = 1;
    let in_value: u64 = 1000;
    let in_asset_id: Field = 0x1234;
    let in_fallback_owner: Field = 0;
    let in_timeout: Field = 0;
    let in_salt: Field = 0xaaaa;

    let in_commitment = compute_commitment(
        in_chain_id,
        in_value,
        in_asset_id,
        owner,
        in_fallback_owner,
        in_timeout,
        in_salt,
    );
    let nullifier = compute_nullifier(in_commitment, in_salt);
    let root = test_merkle_root(in_commitment);

    let out_chain_id: Field = 1;
    let out_value: u64 = 1000;
    let out_asset_id: Field = 0x1234;
    let out_owner: Field = 0xcafe;
    let out_fallback_owner: Field = 0;
    let out_timeout: Field = 0;
    let out_salt: Field = 0xbbbb;

    let out_commitment = compute_commitment(
        out_chain_id,
        out_value,
        out_asset_id,
        out_owner,
        out_fallback_owner,
        out_timeout,
        out_salt,
    );

    main(
        nullifier,
        root,
        out_commitment,
        0,
        0,
        0,
        0,
        0,
        0,
        sk_lo,
        sk_hi,
        in_chain_id,
        in_value,
        in_asset_id,
        owner,
        in_fallback_owner,
        in_timeout,
        in_salt,
        1,
        zero_path_elements(),
        zero_path_indices(),
        out_chain_id,
        out_value,
        out_asset_id,
        out_owner,
        out_fallback_owner,
        out_timeout,
        out_salt,
        0,
        0,
        0,
        0,
        0,
        0,
    );
}

#[test]
fn test_valid_lock() {
    let sk_lo: Field = 0xdeadbeef;
    let sk_hi: Field = 0;
    let pk = derive_public_key(sk_lo, sk_hi);
    let owner = pk.x;

    // Input: standard note
    let in_salt: Field = 0xaaaa;
    let in_commitment = compute_commitment(1, 1000, 0x1234, owner, 0, 0, in_salt);
    let nullifier = compute_nullifier(in_commitment, in_salt);
    let root = test_merkle_root(in_commitment);

    // Lock-mode: ephemeral key + counterparty meta key
    let r_lo: Field = 0xcafe;
    let r_hi: Field = 0;
    let r_scalar = EmbeddedCurveScalar { lo: r_lo, hi: r_hi };

    let meta_sk_lo: Field = 0xbabe;
    let pk_meta = derive_public_key(meta_sk_lo, 0);

    // ECDH shared secret
    let shared = multi_scalar_mul([pk_meta], [r_scalar]);

    // Stealth address derivation
    let stealth_hash = hash_2([DOMAIN_STEALTH, shared.x]);
    let stealth_scalar = field_to_scalar(stealth_hash);
    let stealth_g = fixed_base_scalar_mul(stealth_scalar);
    let pk_stealth_point = embedded_curve_add(pk_meta, stealth_g);
    let pk_stealth_val = pk_stealth_point.x;

    // Output: locked note
    let out_timeout: Field = 1000;
    let out_salt: Field = 0xbbbb;
    let out_commitment = compute_commitment(
        1,
        1000,
        0x1234,
        pk_stealth_val,
        owner,
        out_timeout,
        out_salt,
    );

    // Binding commitments
    let swap_id: Field = 0x5555;
    let h_swap_val = hash_3([DOMAIN_BIND_SWAP, swap_id, out_salt]);
    let big_r = fixed_base_scalar_mul(r_scalar);
    let h_R_val = hash_2([DOMAIN_BIND_R, big_r.x]);
    let h_meta_val = hash_3([DOMAIN_BIND_META, pk_meta.x, out_salt]);

    // Salt encryption
    let enc_key = mask_253(hash_2([DOMAIN_SALT_ENC, shared.x]));
    let encrypted_salt_val = xor_fields(out_salt, enc_key);
    let h_enc_val = hash_2([DOMAIN_BIND_ENC, encrypted_salt_val]);

    main(
        nullifier,
        root,
        out_commitment,
        out_timeout,
        pk_stealth_val,
        h_swap_val,
        h_R_val,
        h_meta_val,
        h_enc_val,
        sk_lo,
        sk_hi,
        1,
        1000,
        0x1234,
        owner,
        0,
        0,
        in_salt,
        1,
        zero_path_elements(),
        zero_path_indices(),
        1,
        1000,
        0x1234,
        pk_stealth_val,
        owner,
        out_timeout,
        out_salt,
        swap_id,
        r_lo,
        r_hi,
        pk_meta.x,
        pk_meta.y,
        encrypted_salt_val,
    );
}

#[test]
fn test_valid_claim() {
    // Counterparty (claimer) meta key
    let meta_sk_lo: Field = 0xbabe;
    let meta_sk_hi: Field = 0;
    let pk_meta = derive_public_key(meta_sk_lo, meta_sk_hi);

    // Ephemeral key (from the locker)
    let r_lo: Field = 0xcafe;
    let r_scalar = EmbeddedCurveScalar { lo: r_lo, hi: 0 };

    // ECDH shared secret (claimer computes: sk_meta * R)
    let big_r = fixed_base_scalar_mul(r_scalar);
    let shared = multi_scalar_mul(
        [big_r],
        [EmbeddedCurveScalar { lo: meta_sk_lo, hi: meta_sk_hi }],
    );

    // Stealth key derivation
    let stealth_hash = hash_2([DOMAIN_STEALTH, shared.x]);
    let stealth_scalar = field_to_scalar(stealth_hash);

    // pk_stealth = pk_meta + stealth_scalar * G
    let stealth_g = fixed_base_scalar_mul(stealth_scalar);
    let pk_stealth_point = embedded_curve_add(pk_meta, stealth_g);
    let pk_stealth_val = pk_stealth_point.x;

    // sk_stealth = sk_meta + stealth_hash (as field, then split)
    let sk_stealth_field = meta_sk_lo + stealth_hash;
    let sk_stealth_scalar = field_to_scalar(sk_stealth_field);

    // Verify our derived key matches
    let check_pk = fixed_base_scalar_mul(sk_stealth_scalar);
    assert(check_pk.x == pk_stealth_val);

    // The locked note (input for claim)
    let fallback_owner: Field = 0x9999;
    let in_timeout: Field = 1000;
    let in_salt: Field = 0xbbbb;
    let in_commitment = compute_commitment(
        1,
        1000,
        0x1234,
        pk_stealth_val,
        fallback_owner,
        in_timeout,
        in_salt,
    );
    let nullifier = compute_nullifier(in_commitment, in_salt);
    let root = test_merkle_root(in_commitment);

    // Output: fresh note (re-potting)
    let out_salt: Field = 0xcccc;
    let out_commitment = compute_commitment(1, 1000, 0x1234, pk_meta.x, 0, 0, out_salt);

    main(
        nullifier,
        root,
        out_commitment,
        in_timeout,
        pk_stealth_val,
        0,
        0,
        0,
        0,
        sk_stealth_scalar.lo,
        sk_stealth_scalar.hi,
        1,
        1000,
        0x1234,
        pk_stealth_val,
        fallback_owner,
        in_timeout,
        in_salt,
        1,
        zero_path_elements(),
        zero_path_indices(),
        1,
        1000,
        0x1234,
        pk_meta.x,
        0,
        0,
        out_salt,
        0,
        0,
        0,
        0,
        0,
        0,
    );
}

#[test]
fn test_valid_refund() {
    let fallback_sk_lo: Field = 0xdeadbeef;
    let fallback_sk_hi: Field = 0;
    let fallback_pk = derive_public_key(fallback_sk_lo, fallback_sk_hi);
    let fallback_owner = fallback_pk.x;

    let stealth_owner: Field = 0x1111;
    let in_timeout: Field = 1000;
    let in_salt: Field = 0xaaaa;

    let in_commitment = compute_commitment(
        1,
        1000,
        0x1234,
        stealth_owner,
        fallback_owner,
        in_timeout,
        in_salt,
    );
    let nullifier = compute_nullifier(in_commitment, in_salt);
    let root = test_merkle_root(in_commitment);

    let out_salt: Field = 0xbbbb;
    let out_commitment = compute_commitment(1, 1000, 0x1234, fallback_owner, 0, 0, out_salt);

    main(
        nullifier,
        root,
        out_commitment,
        in_timeout,
        0,
        0,
        0,
        0,
        0,
        fallback_sk_lo,
        fallback_sk_hi,
        1,
        1000,
        0x1234,
        stealth_owner,
        fallback_owner,
        in_timeout,
        in_salt,
        1,
        zero_path_elements(),
        zero_path_indices(),
        1,
        1000,
        0x1234,
        fallback_owner,
        0,
        0,
        out_salt,
        0,
        0,
        0,
        0,
        0,
        0,
    );
}

#[test(should_fail)]
fn test_transfer_wrong_key() {
    let sk_lo: Field = 0xdeadbeef;
    let pk = derive_public_key(sk_lo, 0);

    let in_salt: Field = 0xaaaa;
    let in_commitment = compute_commitment(1, 1000, 0x1234, pk.x, 0, 0, in_salt);
    let nullifier = compute_nullifier(in_commitment, in_salt);
    let root = test_merkle_root(in_commitment);

    let out_salt: Field = 0xbbbb;
    let out_commitment = compute_commitment(1, 1000, 0x1234, 0xcafe, 0, 0, out_salt);

    let wrong_sk_lo: Field = 0xbadcafe;

    main(
        nullifier,
        root,
        out_commitment,
        0,
        0,
        0,
        0,
        0,
        0,
        wrong_sk_lo,
        0,
        1,
        1000,
        0x1234,
        pk.x,
        0,
        0,
        in_salt,
        1,
        zero_path_elements(),
        zero_path_indices(),
        1,
        1000,
        0x1234,
        0xcafe,
        0,
        0,
        out_salt,
        0,
        0,
        0,
        0,
        0,
        0,
    );
}

#[test(should_fail)]
fn test_transfer_wrong_nullifier() {
    let sk_lo: Field = 0xdeadbeef;
    let pk = derive_public_key(sk_lo, 0);

    let in_salt: Field = 0xaaaa;
    let in_commitment = compute_commitment(1, 1000, 0x1234, pk.x, 0, 0, in_salt);
    let root = test_merkle_root(in_commitment);

    let out_salt: Field = 0xbbbb;
    let out_commitment = compute_commitment(1, 1000, 0x1234, 0xcafe, 0, 0, out_salt);

    let wrong_nullifier: Field = 0xdeadbeefcafe;

    main(
        wrong_nullifier,
        root,
        out_commitment,
        0,
        0,
        0,
        0,
        0,
        0,
        sk_lo,
        0,
        1,
        1000,
        0x1234,
        pk.x,
        0,
        0,
        in_salt,
        1,
        zero_path_elements(),
        zero_path_indices(),
        1,
        1000,
        0x1234,
        0xcafe,
        0,
        0,
        out_salt,
        0,
        0,
        0,
        0,
        0,
        0,
    );
}

#[test(should_fail)]
fn test_transfer_wrong_commitment() {
    let sk_lo: Field = 0xdeadbeef;
    let pk = derive_public_key(sk_lo, 0);

    let in_salt: Field = 0xaaaa;
    let in_commitment = compute_commitment(1, 1000, 0x1234, pk.x, 0, 0, in_salt);
    let nullifier = compute_nullifier(in_commitment, in_salt);
    let root = test_merkle_root(in_commitment);

    let wrong_out_commitment: Field = 0xdeadbeef;

    main(
        nullifier,
        root,
        wrong_out_commitment,
        0,
        0,
        0,
        0,
        0,
        0,
        sk_lo,
        0,
        1,
        1000,
        0x1234,
        pk.x,
        0,
        0,
        in_salt,
        1,
        zero_path_elements(),
        zero_path_indices(),
        1,
        1000,
        0x1234,
        0xcafe,
        0,
        0,
        0xbbbb,
        0,
        0,
        0,
        0,
        0,
        0,
    );
}

#[test(should_fail)]
fn test_transfer_wrong_merkle_proof() {
    let sk_lo: Field = 0xdeadbeef;
    let pk = derive_public_key(sk_lo, 0);

    let in_salt: Field = 0xaaaa;
    let in_commitment = compute_commitment(1, 1000, 0x1234, pk.x, 0, 0, in_salt);
    let nullifier = compute_nullifier(in_commitment, in_salt);

    let out_salt: Field = 0xbbbb;
    let out_commitment = compute_commitment(1, 1000, 0x1234, 0xcafe, 0, 0, out_salt);

    let wrong_root: Field = 0xdeadbeef;

    main(
        nullifier,
        wrong_root,
        out_commitment,
        0,
        0,
        0,
        0,
        0,
        0,
        sk_lo,
        0,
        1,
        1000,
        0x1234,
        pk.x,
        0,
        0,
        in_salt,
        1,
        zero_path_elements(),
        zero_path_indices(),
        1,
        1000,
        0x1234,
        0xcafe,
        0,
        0,
        out_salt,
        0,
        0,
        0,
        0,
        0,
        0,
    );
}

#[test(should_fail)]
fn test_claim_wrong_key() {
    let wrong_sk_lo: Field = 0xbadcafe;
    let stealth_owner: Field = 0x1111;
    let in_timeout: Field = 1000;
    let in_salt: Field = 0xaaaa;

    let in_commitment =
        compute_commitment(1, 1000, 0x1234, stealth_owner, 0x9999, in_timeout, in_salt);
    let nullifier = compute_nullifier(in_commitment, in_salt);
    let root = test_merkle_root(in_commitment);

    let wrong_pk = derive_public_key(wrong_sk_lo, 0);
    let out_salt: Field = 0xbbbb;
    let out_commitment = compute_commitment(1, 1000, 0x1234, wrong_pk.x, 0, 0, out_salt);

    main(
        nullifier,
        root,
        out_commitment,
        in_timeout,
        stealth_owner,
        0,
        0,
        0,
        0,
        wrong_sk_lo,
        0,
        1,
        1000,
        0x1234,
        stealth_owner,
        0x9999,
        in_timeout,
        in_salt,
        1,
        zero_path_elements(),
        zero_path_indices(),
        1,
        1000,
        0x1234,
        wrong_pk.x,
        0,
        0,
        out_salt,
        0,
        0,
        0,
        0,
        0,
        0,
    );
}

#[test(should_fail)]
fn test_refund_wrong_key() {
    let wrong_sk_lo: Field = 0xbadcafe;
    let stealth_owner: Field = 0x1111;
    let fallback_owner: Field = 0x9999;
    let in_timeout: Field = 1000;
    let in_salt: Field = 0xaaaa;

    let in_commitment = compute_commitment(
        1,
        1000,
        0x1234,
        stealth_owner,
        fallback_owner,
        in_timeout,
        in_salt,
    );
    let nullifier = compute_nullifier(in_commitment, in_salt);
    let root = test_merkle_root(in_commitment);

    let out_salt: Field = 0xbbbb;
    let out_commitment = compute_commitment(1, 1000, 0x1234, 0xcafe, 0, 0, out_salt);

    main(
        nullifier,
        root,
        out_commitment,
        in_timeout,
        0,
        0,
        0,
        0,
        0,
        wrong_sk_lo,
        0,
        1,
        1000,
        0x1234,
        stealth_owner,
        fallback_owner,
        in_timeout,
        in_salt,
        1,
        zero_path_elements(),
        zero_path_indices(),
        1,
        1000,
        0x1234,
        0xcafe,
        0,
        0,
        out_salt,
        0,
        0,
        0,
        0,
        0,
        0,
    );
}

#[test(should_fail)]
fn test_lock_wrong_stealth() {
    let sk_lo: Field = 0xdeadbeef;
    let pk = derive_public_key(sk_lo, 0);

    let in_salt: Field = 0xaaaa;
    let in_commitment = compute_commitment(1, 1000, 0x1234, pk.x, 0, 0, in_salt);
    let nullifier = compute_nullifier(in_commitment, in_salt);
    let root = test_merkle_root(in_commitment);

    let r_lo: Field = 0xcafe;
    let r_scalar = EmbeddedCurveScalar { lo: r_lo, hi: 0 };
    let pk_meta = derive_public_key(0xbabe, 0);
    let shared = multi_scalar_mul([pk_meta], [r_scalar]);
    let stealth_hash = hash_2([DOMAIN_STEALTH, shared.x]);
    let stealth_scalar = field_to_scalar(stealth_hash);
    let stealth_g = fixed_base_scalar_mul(stealth_scalar);
    let pk_stealth_point = embedded_curve_add(pk_meta, stealth_g);

    let out_timeout: Field = 1000;
    let out_salt: Field = 0xbbbb;
    let out_commitment = compute_commitment(
        1,
        1000,
        0x1234,
        pk_stealth_point.x,
        pk.x,
        out_timeout,
        out_salt,
    );

    let swap_id: Field = 0x5555;
    let h_swap_val = hash_3([DOMAIN_BIND_SWAP, swap_id, out_salt]);
    let big_r = fixed_base_scalar_mul(r_scalar);
    let h_R_val = hash_2([DOMAIN_BIND_R, big_r.x]);
    let h_meta_val = hash_3([DOMAIN_BIND_META, pk_meta.x, out_salt]);
    let enc_key = mask_253(hash_2([DOMAIN_SALT_ENC, shared.x]));
    let encrypted_salt_val = xor_fields(out_salt, enc_key);
    let h_enc_val = hash_2([DOMAIN_BIND_ENC, encrypted_salt_val]);

    let wrong_pk_stealth: Field = 0xdead;

    main(
        nullifier,
        root,
        out_commitment,
        out_timeout,
        wrong_pk_stealth,
        h_swap_val,
        h_R_val,
        h_meta_val,
        h_enc_val,
        sk_lo,
        0,
        1,
        1000,
        0x1234,
        pk.x,
        0,
        0,
        in_salt,
        1,
        zero_path_elements(),
        zero_path_indices(),
        1,
        1000,
        0x1234,
        pk_stealth_point.x,
        pk.x,
        out_timeout,
        out_salt,
        swap_id,
        r_lo,
        0,
        pk_meta.x,
        pk_meta.y,
        encrypted_salt_val,
    );
}

#[test(should_fail)]
fn test_lock_wrong_h_swap() {
    let sk_lo: Field = 0xdeadbeef;
    let pk = derive_public_key(sk_lo, 0);

    let in_salt: Field = 0xaaaa;
    let in_commitment = compute_commitment(1, 1000, 0x1234, pk.x, 0, 0, in_salt);
    let nullifier = compute_nullifier(in_commitment, in_salt);
    let root = test_merkle_root(in_commitment);

    let r_lo: Field = 0xcafe;
    let r_scalar = EmbeddedCurveScalar { lo: r_lo, hi: 0 };
    let pk_meta = derive_public_key(0xbabe, 0);
    let shared = multi_scalar_mul([pk_meta], [r_scalar]);
    let stealth_hash = hash_2([DOMAIN_STEALTH, shared.x]);
    let stealth_scalar = field_to_scalar(stealth_hash);
    let stealth_g = fixed_base_scalar_mul(stealth_scalar);
    let pk_stealth_point = embedded_curve_add(pk_meta, stealth_g);

    let out_timeout: Field = 1000;
    let out_salt: Field = 0xbbbb;
    let out_commitment = compute_commitment(
        1,
        1000,
        0x1234,
        pk_stealth_point.x,
        pk.x,
        out_timeout,
        out_salt,
    );

    let swap_id: Field = 0x5555;
    let wrong_h_swap = hash_3([DOMAIN_BIND_SWAP, 0x6666, out_salt]); // wrong swap_id
    let big_r = fixed_base_scalar_mul(r_scalar);
    let h_R_val = hash_2([DOMAIN_BIND_R, big_r.x]);
    let h_meta_val = hash_3([DOMAIN_BIND_META, pk_meta.x, out_salt]);
    let enc_key = mask_253(hash_2([DOMAIN_SALT_ENC, shared.x]));
    let encrypted_salt_val = xor_fields(out_salt, enc_key);
    let h_enc_val = hash_2([DOMAIN_BIND_ENC, encrypted_salt_val]);

    main(
        nullifier,
        root,
        out_commitment,
        out_timeout,
        pk_stealth_point.x,
        wrong_h_swap,
        h_R_val,
        h_meta_val,
        h_enc_val,
        sk_lo,
        0,
        1,
        1000,
        0x1234,
        pk.x,
        0,
        0,
        in_salt,
        1,
        zero_path_elements(),
        zero_path_indices(),
        1,
        1000,
        0x1234,
        pk_stealth_point.x,
        pk.x,
        out_timeout,
        out_salt,
        swap_id,
        r_lo,
        0,
        pk_meta.x,
        pk_meta.y,
        encrypted_salt_val,
    );
}

#[test(should_fail)]
fn test_transfer_nonzero_lock_extras() {
    let sk_lo: Field = 0xdeadbeef;
    let pk = derive_public_key(sk_lo, 0);

    let in_salt: Field = 0xaaaa;
    let in_commitment = compute_commitment(1, 1000, 0x1234, pk.x, 0, 0, in_salt);
    let nullifier = compute_nullifier(in_commitment, in_salt);
    let root = test_merkle_root(in_commitment);

    let out_salt: Field = 0xbbbb;
    let out_commitment = compute_commitment(1, 1000, 0x1234, 0xcafe, 0, 0, out_salt);

    main(
        nullifier,
        root,
        out_commitment,
        0,
        0,
        0,
        0,
        0,
        0,
        sk_lo,
        0,
        1,
        1000,
        0x1234,
        pk.x,
        0,
        0,
        in_salt,
        1,
        zero_path_elements(),
        zero_path_indices(),
        1,
        1000,
        0x1234,
        0xcafe,
        0,
        0,
        out_salt,
        0x5555, // swap_id != 0 should fail
        0,
        0,
        0,
        0,
        0,
    );
}

#[test(should_fail)]
fn test_lock_timeout_must_match_output() {
    let sk_lo: Field = 0xdeadbeef;
    let pk = derive_public_key(sk_lo, 0);

    let in_salt: Field = 0xaaaa;
    let in_commitment = compute_commitment(1, 1000, 0x1234, pk.x, 0, 0, in_salt);
    let nullifier = compute_nullifier(in_commitment, in_salt);
    let root = test_merkle_root(in_commitment);

    let r_lo: Field = 0xcafe;
    let r_scalar = EmbeddedCurveScalar { lo: r_lo, hi: 0 };
    let pk_meta = derive_public_key(0xbabe, 0);
    let shared = multi_scalar_mul([pk_meta], [r_scalar]);
    let stealth_hash = hash_2([DOMAIN_STEALTH, shared.x]);
    let stealth_scalar = field_to_scalar(stealth_hash);
    let stealth_g = fixed_base_scalar_mul(stealth_scalar);
    let pk_stealth_point = embedded_curve_add(pk_meta, stealth_g);

    let out_timeout: Field = 1000;
    let out_salt: Field = 0xbbbb;
    let out_commitment = compute_commitment(
        1,
        1000,
        0x1234,
        pk_stealth_point.x,
        pk.x,
        out_timeout,
        out_salt,
    );

    let swap_id: Field = 0x5555;
    let h_swap_val = hash_3([DOMAIN_BIND_SWAP, swap_id, out_salt]);
    let big_r = fixed_base_scalar_mul(r_scalar);
    let h_R_val = hash_2([DOMAIN_BIND_R, big_r.x]);
    let h_meta_val = hash_3([DOMAIN_BIND_META, pk_meta.x, out_salt]);
    let enc_key = mask_253(hash_2([DOMAIN_SALT_ENC, shared.x]));
    let encrypted_salt_val = xor_fields(out_salt, enc_key);
    let h_enc_val = hash_2([DOMAIN_BIND_ENC, encrypted_salt_val]);

    // Pass wrong timeout (2000 instead of 1000)
    main(
        nullifier,
        root,
        out_commitment,
        2000,
        pk_stealth_point.x,
        h_swap_val,
        h_R_val,
        h_meta_val,
        h_enc_val,
        sk_lo,
        0,
        1,
        1000,
        0x1234,
        pk.x,
        0,
        0,
        in_salt,
        1,
        zero_path_elements(),
        zero_path_indices(),
        1,
        1000,
        0x1234,
        pk_stealth_point.x,
        pk.x,
        out_timeout,
        out_salt,
        swap_id,
        r_lo,
        0,
        pk_meta.x,
        pk_meta.y,
        encrypted_salt_val,
    );
}

#[test(should_fail)]
fn test_claim_pk_stealth_must_equal_in_owner() {
    let sk_lo: Field = 0xdeadbeef;
    let pk = derive_public_key(sk_lo, 0);

    let in_timeout: Field = 1000;
    let in_salt: Field = 0xaaaa;
    let in_commitment = compute_commitment(1, 1000, 0x1234, pk.x, 0x9999, in_timeout, in_salt);
    let nullifier = compute_nullifier(in_commitment, in_salt);
    let root = test_merkle_root(in_commitment);

    let out_salt: Field = 0xbbbb;
    let out_commitment = compute_commitment(1, 1000, 0x1234, pk.x, 0, 0, out_salt);

    // pk_stealth != in_owner
    let wrong_pk_stealth: Field = 0xdead;

    main(
        nullifier,
        root,
        out_commitment,
        in_timeout,
        wrong_pk_stealth,
        0,
        0,
        0,
        0,
        sk_lo,
        0,
        1,
        1000,
        0x1234,
        pk.x,
        0x9999,
        in_timeout,
        in_salt,
        1,
        zero_path_elements(),
        zero_path_indices(),
        1,
        1000,
        0x1234,
        pk.x,
        0,
        0,
        out_salt,
        0,
        0,
        0,
        0,
        0,
        0,
    );
}

#[test(should_fail)]
fn test_transfer_value_conservation() {
    let sk_lo: Field = 0xdeadbeef;
    let pk = derive_public_key(sk_lo, 0);

    let in_salt: Field = 0xaaaa;
    let in_commitment = compute_commitment(1, 1000, 0x1234, pk.x, 0, 0, in_salt);
    let nullifier = compute_nullifier(in_commitment, in_salt);
    let root = test_merkle_root(in_commitment);

    // Output note with different value (500 instead of 1000)
    let out_salt: Field = 0xbbbb;
    let out_commitment = compute_commitment(1, 500, 0x1234, 0xcafe, 0, 0, out_salt);

    main(
        nullifier,
        root,
        out_commitment,
        0,
        0,
        0,
        0,
        0,
        0,
        sk_lo,
        0,
        1,
        1000,
        0x1234,
        pk.x,
        0,
        0,
        in_salt,
        1,
        zero_path_elements(),
        zero_path_indices(),
        1,
        500,
        0x1234,
        0xcafe,
        0,
        0,
        out_salt,
        0,
        0,
        0,
        0,
        0,
        0,
    );
}

#[test(should_fail)]
fn test_lock_relock_prevention() {
    let sk_lo: Field = 0xdeadbeef;
    let pk = derive_public_key(sk_lo, 0);
    let owner = pk.x;

    // Input: already-locked note (in_timeout != 0)
    let in_salt: Field = 0xaaaa;
    let in_timeout: Field = 500;
    let in_commitment = compute_commitment(1, 1000, 0x1234, owner, 0x9999, in_timeout, in_salt);
    let nullifier = compute_nullifier(in_commitment, in_salt);
    let root = test_merkle_root(in_commitment);

    let r_lo: Field = 0xcafe;
    let r_scalar = EmbeddedCurveScalar { lo: r_lo, hi: 0 };
    let pk_meta = derive_public_key(0xbabe, 0);
    let shared = multi_scalar_mul([pk_meta], [r_scalar]);
    let stealth_hash = hash_2([DOMAIN_STEALTH, shared.x]);
    let stealth_scalar = field_to_scalar(stealth_hash);
    let stealth_g = fixed_base_scalar_mul(stealth_scalar);
    let pk_stealth_point = embedded_curve_add(pk_meta, stealth_g);

    let out_timeout: Field = 1000;
    let out_salt: Field = 0xbbbb;
    let out_commitment = compute_commitment(
        1,
        1000,
        0x1234,
        pk_stealth_point.x,
        owner,
        out_timeout,
        out_salt,
    );

    let swap_id: Field = 0x5555;
    let h_swap_val = hash_3([DOMAIN_BIND_SWAP, swap_id, out_salt]);
    let big_r = fixed_base_scalar_mul(r_scalar);
    let h_R_val = hash_2([DOMAIN_BIND_R, big_r.x]);
    let h_meta_val = hash_3([DOMAIN_BIND_META, pk_meta.x, out_salt]);
    let enc_key = mask_253(hash_2([DOMAIN_SALT_ENC, shared.x]));
    let encrypted_salt_val = xor_fields(out_salt, enc_key);
    let h_enc_val = hash_2([DOMAIN_BIND_ENC, encrypted_salt_val]);

    main(
        nullifier,
        root,
        out_commitment,
        out_timeout,
        pk_stealth_point.x,
        h_swap_val,
        h_R_val,
        h_meta_val,
        h_enc_val,
        sk_lo,
        0,
        1,
        1000,
        0x1234,
        owner,
        0x9999,
        in_timeout, // != 0, triggers assert(in_timeout == 0)
        in_salt,
        1,
        zero_path_elements(),
        zero_path_indices(),
        1,
        1000,
        0x1234,
        pk_stealth_point.x,
        owner,
        out_timeout,
        out_salt,
        swap_id,
        r_lo,
        0,
        pk_meta.x,
        pk_meta.y,
        encrypted_salt_val,
    );
}

#[test(should_fail)]
fn test_lock_out_owner_must_equal_stealth() {
    let sk_lo: Field = 0xdeadbeef;
    let pk = derive_public_key(sk_lo, 0);
    let owner = pk.x;

    let in_salt: Field = 0xaaaa;
    let in_commitment = compute_commitment(1, 1000, 0x1234, owner, 0, 0, in_salt);
    let nullifier = compute_nullifier(in_commitment, in_salt);
    let root = test_merkle_root(in_commitment);

    let r_lo: Field = 0xcafe;
    let r_scalar = EmbeddedCurveScalar { lo: r_lo, hi: 0 };
    let pk_meta = derive_public_key(0xbabe, 0);
    let shared = multi_scalar_mul([pk_meta], [r_scalar]);
    let stealth_hash = hash_2([DOMAIN_STEALTH, shared.x]);
    let stealth_scalar = field_to_scalar(stealth_hash);
    let stealth_g = fixed_base_scalar_mul(stealth_scalar);
    let pk_stealth_point = embedded_curve_add(pk_meta, stealth_g);

    let out_timeout: Field = 1000;
    let out_salt: Field = 0xbbbb;
    // Output owner is NOT pk_stealth
    let wrong_out_owner: Field = 0xdead;
    let out_commitment = compute_commitment(
        1,
        1000,
        0x1234,
        wrong_out_owner,
        owner,
        out_timeout,
        out_salt,
    );

    let swap_id: Field = 0x5555;
    let h_swap_val = hash_3([DOMAIN_BIND_SWAP, swap_id, out_salt]);
    let big_r = fixed_base_scalar_mul(r_scalar);
    let h_R_val = hash_2([DOMAIN_BIND_R, big_r.x]);
    let h_meta_val = hash_3([DOMAIN_BIND_META, pk_meta.x, out_salt]);
    let enc_key = mask_253(hash_2([DOMAIN_SALT_ENC, shared.x]));
    let encrypted_salt_val = xor_fields(out_salt, enc_key);
    let h_enc_val = hash_2([DOMAIN_BIND_ENC, encrypted_salt_val]);

    main(
        nullifier,
        root,
        out_commitment,
        out_timeout,
        pk_stealth_point.x,
        h_swap_val,
        h_R_val,
        h_meta_val,
        h_enc_val,
        sk_lo,
        0,
        1,
        1000,
        0x1234,
        owner,
        0,
        0,
        in_salt,
        1,
        zero_path_elements(),
        zero_path_indices(),
        1,
        1000,
        0x1234,
        wrong_out_owner,
        owner,
        out_timeout,
        out_salt,
        swap_id,
        r_lo,
        0,
        pk_meta.x,
        pk_meta.y,
        encrypted_salt_val,
    );
}

#[test(should_fail)]
fn test_lock_wrong_h_R() {
    let sk_lo: Field = 0xdeadbeef;
    let pk = derive_public_key(sk_lo, 0);
    let owner = pk.x;

    let in_salt: Field = 0xaaaa;
    let in_commitment = compute_commitment(1, 1000, 0x1234, owner, 0, 0, in_salt);
    let nullifier = compute_nullifier(in_commitment, in_salt);
    let root = test_merkle_root(in_commitment);

    let r_lo: Field = 0xcafe;
    let r_scalar = EmbeddedCurveScalar { lo: r_lo, hi: 0 };
    let pk_meta = derive_public_key(0xbabe, 0);
    let shared = multi_scalar_mul([pk_meta], [r_scalar]);
    let stealth_hash = hash_2([DOMAIN_STEALTH, shared.x]);
    let stealth_scalar = field_to_scalar(stealth_hash);
    let stealth_g = fixed_base_scalar_mul(stealth_scalar);
    let pk_stealth_point = embedded_curve_add(pk_meta, stealth_g);

    let out_timeout: Field = 1000;
    let out_salt: Field = 0xbbbb;
    let out_commitment = compute_commitment(
        1,
        1000,
        0x1234,
        pk_stealth_point.x,
        owner,
        out_timeout,
        out_salt,
    );

    let swap_id: Field = 0x5555;
    let h_swap_val = hash_3([DOMAIN_BIND_SWAP, swap_id, out_salt]);
    let wrong_h_R = hash_2([DOMAIN_BIND_R, 0xdead]);
    let h_meta_val = hash_3([DOMAIN_BIND_META, pk_meta.x, out_salt]);
    let enc_key = mask_253(hash_2([DOMAIN_SALT_ENC, shared.x]));
    let encrypted_salt_val = xor_fields(out_salt, enc_key);
    let h_enc_val = hash_2([DOMAIN_BIND_ENC, encrypted_salt_val]);

    main(
        nullifier,
        root,
        out_commitment,
        out_timeout,
        pk_stealth_point.x,
        h_swap_val,
        wrong_h_R,
        h_meta_val,
        h_enc_val,
        sk_lo,
        0,
        1,
        1000,
        0x1234,
        owner,
        0,
        0,
        in_salt,
        1,
        zero_path_elements(),
        zero_path_indices(),
        1,
        1000,
        0x1234,
        pk_stealth_point.x,
        owner,
        out_timeout,
        out_salt,
        swap_id,
        r_lo,
        0,
        pk_meta.x,
        pk_meta.y,
        encrypted_salt_val,
    );
}

#[test(should_fail)]
fn test_lock_wrong_h_meta() {
    let sk_lo: Field = 0xdeadbeef;
    let pk = derive_public_key(sk_lo, 0);
    let owner = pk.x;

    let in_salt: Field = 0xaaaa;
    let in_commitment = compute_commitment(1, 1000, 0x1234, owner, 0, 0, in_salt);
    let nullifier = compute_nullifier(in_commitment, in_salt);
    let root = test_merkle_root(in_commitment);

    let r_lo: Field = 0xcafe;
    let r_scalar = EmbeddedCurveScalar { lo: r_lo, hi: 0 };
    let pk_meta = derive_public_key(0xbabe, 0);
    let shared = multi_scalar_mul([pk_meta], [r_scalar]);
    let stealth_hash = hash_2([DOMAIN_STEALTH, shared.x]);
    let stealth_scalar = field_to_scalar(stealth_hash);
    let stealth_g = fixed_base_scalar_mul(stealth_scalar);
    let pk_stealth_point = embedded_curve_add(pk_meta, stealth_g);

    let out_timeout: Field = 1000;
    let out_salt: Field = 0xbbbb;
    let out_commitment = compute_commitment(
        1,
        1000,
        0x1234,
        pk_stealth_point.x,
        owner,
        out_timeout,
        out_salt,
    );

    let swap_id: Field = 0x5555;
    let h_swap_val = hash_3([DOMAIN_BIND_SWAP, swap_id, out_salt]);
    let big_r = fixed_base_scalar_mul(r_scalar);
    let h_R_val = hash_2([DOMAIN_BIND_R, big_r.x]);
    let wrong_h_meta = hash_3([DOMAIN_BIND_META, 0xdead, out_salt]);
    let enc_key = mask_253(hash_2([DOMAIN_SALT_ENC, shared.x]));
    let encrypted_salt_val = xor_fields(out_salt, enc_key);
    let h_enc_val = hash_2([DOMAIN_BIND_ENC, encrypted_salt_val]);

    main(
        nullifier,
        root,
        out_commitment,
        out_timeout,
        pk_stealth_point.x,
        h_swap_val,
        h_R_val,
        wrong_h_meta,
        h_enc_val,
        sk_lo,
        0,
        1,
        1000,
        0x1234,
        owner,
        0,
        0,
        in_salt,
        1,
        zero_path_elements(),
        zero_path_indices(),
        1,
        1000,
        0x1234,
        pk_stealth_point.x,
        owner,
        out_timeout,
        out_salt,
        swap_id,
        r_lo,
        0,
        pk_meta.x,
        pk_meta.y,
        encrypted_salt_val,
    );
}

#[test(should_fail)]
fn test_lock_wrong_h_enc() {
    let sk_lo: Field = 0xdeadbeef;
    let pk = derive_public_key(sk_lo, 0);
    let owner = pk.x;

    let in_salt: Field = 0xaaaa;
    let in_commitment = compute_commitment(1, 1000, 0x1234, owner, 0, 0, in_salt);
    let nullifier = compute_nullifier(in_commitment, in_salt);
    let root = test_merkle_root(in_commitment);

    let r_lo: Field = 0xcafe;
    let r_scalar = EmbeddedCurveScalar { lo: r_lo, hi: 0 };
    let pk_meta = derive_public_key(0xbabe, 0);
    let shared = multi_scalar_mul([pk_meta], [r_scalar]);
    let stealth_hash = hash_2([DOMAIN_STEALTH, shared.x]);
    let stealth_scalar = field_to_scalar(stealth_hash);
    let stealth_g = fixed_base_scalar_mul(stealth_scalar);
    let pk_stealth_point = embedded_curve_add(pk_meta, stealth_g);

    let out_timeout: Field = 1000;
    let out_salt: Field = 0xbbbb;
    let out_commitment = compute_commitment(
        1,
        1000,
        0x1234,
        pk_stealth_point.x,
        owner,
        out_timeout,
        out_salt,
    );

    let swap_id: Field = 0x5555;
    let h_swap_val = hash_3([DOMAIN_BIND_SWAP, swap_id, out_salt]);
    let big_r = fixed_base_scalar_mul(r_scalar);
    let h_R_val = hash_2([DOMAIN_BIND_R, big_r.x]);
    let h_meta_val = hash_3([DOMAIN_BIND_META, pk_meta.x, out_salt]);
    let enc_key = mask_253(hash_2([DOMAIN_SALT_ENC, shared.x]));
    let encrypted_salt_val = xor_fields(out_salt, enc_key);
    let wrong_h_enc = hash_2([DOMAIN_BIND_ENC, 0xdead]);

    main(
        nullifier,
        root,
        out_commitment,
        out_timeout,
        pk_stealth_point.x,
        h_swap_val,
        h_R_val,
        h_meta_val,
        wrong_h_enc,
        sk_lo,
        0,
        1,
        1000,
        0x1234,
        owner,
        0,
        0,
        in_salt,
        1,
        zero_path_elements(),
        zero_path_indices(),
        1,
        1000,
        0x1234,
        pk_stealth_point.x,
        owner,
        out_timeout,
        out_salt,
        swap_id,
        r_lo,
        0,
        pk_meta.x,
        pk_meta.y,
        encrypted_salt_val,
    );
}

#[test(should_fail)]
fn test_lock_wrong_encrypted_salt() {
    let sk_lo: Field = 0xdeadbeef;
    let pk = derive_public_key(sk_lo, 0);
    let owner = pk.x;

    let in_salt: Field = 0xaaaa;
    let in_commitment = compute_commitment(1, 1000, 0x1234, owner, 0, 0, in_salt);
    let nullifier = compute_nullifier(in_commitment, in_salt);
    let root = test_merkle_root(in_commitment);

    let r_lo: Field = 0xcafe;
    let r_scalar = EmbeddedCurveScalar { lo: r_lo, hi: 0 };
    let pk_meta = derive_public_key(0xbabe, 0);
    let shared = multi_scalar_mul([pk_meta], [r_scalar]);
    let stealth_hash = hash_2([DOMAIN_STEALTH, shared.x]);
    let stealth_scalar = field_to_scalar(stealth_hash);
    let stealth_g = fixed_base_scalar_mul(stealth_scalar);
    let pk_stealth_point = embedded_curve_add(pk_meta, stealth_g);

    let out_timeout: Field = 1000;
    let out_salt: Field = 0xbbbb;
    let out_commitment = compute_commitment(
        1,
        1000,
        0x1234,
        pk_stealth_point.x,
        owner,
        out_timeout,
        out_salt,
    );

    let swap_id: Field = 0x5555;
    let h_swap_val = hash_3([DOMAIN_BIND_SWAP, swap_id, out_salt]);
    let big_r = fixed_base_scalar_mul(r_scalar);
    let h_R_val = hash_2([DOMAIN_BIND_R, big_r.x]);
    let h_meta_val = hash_3([DOMAIN_BIND_META, pk_meta.x, out_salt]);
    let enc_key = mask_253(hash_2([DOMAIN_SALT_ENC, shared.x]));
    let encrypted_salt_val = xor_fields(out_salt, enc_key);
    let h_enc_val = hash_2([DOMAIN_BIND_ENC, encrypted_salt_val]);

    // Pass wrong encrypted_salt private input
    let wrong_encrypted_salt: Field = 0xdead;

    main(
        nullifier,
        root,
        out_commitment,
        out_timeout,
        pk_stealth_point.x,
        h_swap_val,
        h_R_val,
        h_meta_val,
        h_enc_val,
        sk_lo,
        0,
        1,
        1000,
        0x1234,
        owner,
        0,
        0,
        in_salt,
        1,
        zero_path_elements(),
        zero_path_indices(),
        1,
        1000,
        0x1234,
        pk_stealth_point.x,
        owner,
        out_timeout,
        out_salt,
        swap_id,
        r_lo,
        0,
        pk_meta.x,
        pk_meta.y,
        wrong_encrypted_salt,
    );
}

#[test(should_fail)]
fn test_transfer_asset_conservation() {
    let sk_lo: Field = 0xdeadbeef;
    let pk = derive_public_key(sk_lo, 0);

    let in_salt: Field = 0xaaaa;
    let in_commitment = compute_commitment(1, 1000, 0x1234, pk.x, 0, 0, in_salt);
    let nullifier = compute_nullifier(in_commitment, in_salt);
    let root = test_merkle_root(in_commitment);

    // Different asset_id in output
    let out_salt: Field = 0xbbbb;
    let out_commitment = compute_commitment(1, 1000, 0x5678, 0xcafe, 0, 0, out_salt);

    main(
        nullifier,
        root,
        out_commitment,
        0,
        0,
        0,
        0,
        0,
        0,
        sk_lo,
        0,
        1,
        1000,
        0x1234,
        pk.x,
        0,
        0,
        in_salt,
        1,
        zero_path_elements(),
        zero_path_indices(),
        1,
        1000,
        0x5678,
        0xcafe,
        0,
        0,
        out_salt,
        0,
        0,
        0,
        0,
        0,
        0,
    );
}

#[test(should_fail)]
fn test_transfer_chain_conservation() {
    let sk_lo: Field = 0xdeadbeef;
    let pk = derive_public_key(sk_lo, 0);

    let in_salt: Field = 0xaaaa;
    let in_commitment = compute_commitment(1, 1000, 0x1234, pk.x, 0, 0, in_salt);
    let nullifier = compute_nullifier(in_commitment, in_salt);
    let root = test_merkle_root(in_commitment);

    // Different chain_id in output
    let out_salt: Field = 0xbbbb;
    let out_commitment = compute_commitment(2, 1000, 0x1234, 0xcafe, 0, 0, out_salt);

    main(
        nullifier,
        root,
        out_commitment,
        0,
        0,
        0,
        0,
        0,
        0,
        sk_lo,
        0,
        1,
        1000,
        0x1234,
        pk.x,
        0,
        0,
        in_salt,
        1,
        zero_path_elements(),
        zero_path_indices(),
        2,
        1000,
        0x1234,
        0xcafe,
        0,
        0,
        out_salt,
        0,
        0,
        0,
        0,
        0,
        0,
    );
}

#[test(should_fail)]
fn test_transfer_locked_note_rejected() {
    let sk_lo: Field = 0xdeadbeef;
    let pk = derive_public_key(sk_lo, 0);

    // Input note has non-zero timeout (it's locked)
    let in_timeout: Field = 1000;
    let in_salt: Field = 0xaaaa;
    let in_commitment = compute_commitment(1, 1000, 0x1234, pk.x, 0x9999, in_timeout, in_salt);
    let nullifier = compute_nullifier(in_commitment, in_salt);
    let root = test_merkle_root(in_commitment);

    let out_salt: Field = 0xbbbb;
    let out_commitment = compute_commitment(1, 1000, 0x1234, 0xcafe, 0, 0, out_salt);

    // Transfer mode (timeout=0), but in_timeout=1000
    // assert(timeout == in_timeout) -> assert(0 == 1000) -> fail
    main(
        nullifier,
        root,
        out_commitment,
        0,
        0,
        0,
        0,
        0,
        0,
        sk_lo,
        0,
        1,
        1000,
        0x1234,
        pk.x,
        0x9999,
        in_timeout,
        in_salt,
        1,
        zero_path_elements(),
        zero_path_indices(),
        1,
        1000,
        0x1234,
        0xcafe,
        0,
        0,
        out_salt,
        0,
        0,
        0,
        0,
        0,
        0,
    );
}

#[test(should_fail)]
fn test_claim_nonzero_lock_extras() {
    let meta_sk_lo: Field = 0xbabe;
    let meta_sk_hi: Field = 0;
    let pk_meta = derive_public_key(meta_sk_lo, meta_sk_hi);

    let r_lo: Field = 0xcafe;
    let r_scalar = EmbeddedCurveScalar { lo: r_lo, hi: 0 };
    let big_r = fixed_base_scalar_mul(r_scalar);
    let shared = multi_scalar_mul(
        [big_r],
        [EmbeddedCurveScalar { lo: meta_sk_lo, hi: meta_sk_hi }],
    );

    let stealth_hash = hash_2([DOMAIN_STEALTH, shared.x]);
    let stealth_scalar = field_to_scalar(stealth_hash);
    let stealth_g = fixed_base_scalar_mul(stealth_scalar);
    let pk_stealth_point = embedded_curve_add(pk_meta, stealth_g);
    let pk_stealth_val = pk_stealth_point.x;

    let sk_stealth_field = meta_sk_lo + stealth_hash;
    let sk_stealth_scalar = field_to_scalar(sk_stealth_field);

    let fallback_owner: Field = 0x9999;
    let in_timeout: Field = 1000;
    let in_salt: Field = 0xbbbb;
    let in_commitment = compute_commitment(
        1,
        1000,
        0x1234,
        pk_stealth_val,
        fallback_owner,
        in_timeout,
        in_salt,
    );
    let nullifier = compute_nullifier(in_commitment, in_salt);
    let root = test_merkle_root(in_commitment);

    let out_salt: Field = 0xcccc;
    let out_commitment = compute_commitment(1, 1000, 0x1234, pk_meta.x, 0, 0, out_salt);

    // Claim mode but with nonzero swap_id
    main(
        nullifier,
        root,
        out_commitment,
        in_timeout,
        pk_stealth_val,
        0,
        0,
        0,
        0,
        sk_stealth_scalar.lo,
        sk_stealth_scalar.hi,
        1,
        1000,
        0x1234,
        pk_stealth_val,
        fallback_owner,
        in_timeout,
        in_salt,
        1,
        zero_path_elements(),
        zero_path_indices(),
        1,
        1000,
        0x1234,
        pk_meta.x,
        0,
        0,
        out_salt,
        0x5555, // nonzero swap_id should fail
        0,
        0,
        0,
        0,
        0,
    );
}

#[test(should_fail)]
fn test_refund_nonzero_h_swap() {
    let fallback_sk_lo: Field = 0xdeadbeef;
    let fallback_pk = derive_public_key(fallback_sk_lo, 0);
    let fallback_owner = fallback_pk.x;

    let stealth_owner: Field = 0x1111;
    let in_timeout: Field = 1000;
    let in_salt: Field = 0xaaaa;

    let in_commitment = compute_commitment(
        1,
        1000,
        0x1234,
        stealth_owner,
        fallback_owner,
        in_timeout,
        in_salt,
    );
    let nullifier = compute_nullifier(in_commitment, in_salt);
    let root = test_merkle_root(in_commitment);

    let out_salt: Field = 0xbbbb;
    let out_commitment = compute_commitment(1, 1000, 0x1234, fallback_owner, 0, 0, out_salt);

    // Refund mode (pk_stealth=0) but with nonzero h_swap
    main(
        nullifier,
        root,
        out_commitment,
        in_timeout,
        0,
        0xdead, // nonzero h_swap should fail
        0,
        0,
        0,
        fallback_sk_lo,
        0,
        1,
        1000,
        0x1234,
        stealth_owner,
        fallback_owner,
        in_timeout,
        in_salt,
        1,
        zero_path_elements(),
        zero_path_indices(),
        1,
        1000,
        0x1234,
        fallback_owner,
        0,
        0,
        out_salt,
        0,
        0,
        0,
        0,
        0,
        0,
    );
}

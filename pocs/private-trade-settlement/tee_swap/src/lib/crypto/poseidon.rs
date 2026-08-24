use alloy::primitives::{B256, U256, b256};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};

use crate::domain::note::Note;

// ── Field conversions (pub(crate) for use across crypto modules) ──

/// Convert B256 to BN254 field element.
pub(crate) fn b256_to_fr(value: B256) -> Fr {
    Fr::from_be_bytes_mod_order(value.as_ref())
}

/// Convert BN254 field element to B256.
pub(crate) fn fr_to_b256(value: Fr) -> B256 {
    let big_int = value.into_bigint();
    let bytes = big_int.to_bytes_be();
    B256::from_slice(&bytes)
}

// ── Domain tag constants (SHA-256-derived, hardcoded for cross-language matching) ──
//
// These values are deterministic SHA-256 hashes of the domain strings
// with the most significant byte zeroed to fit within the BN254 scalar field.
// They MUST be identical across Rust, Noir, and Solidity.

/// `H("tee_swap.commitment")`
pub const DOMAIN_COMMITMENT: B256 =
    b256!("00109594dc3faa33ceeeac5e46d290040cdf090cb9883904d1337a9cb26e19a5");

/// `H("tee_swap.nullifier")`
pub const DOMAIN_NULLIFIER: B256 =
    b256!("00225cbdfee768405fd834228dc85d2f6d1f18901486e2f5c8f1a204fccbb393");

/// `H("tee_swap.stealth")`
pub const DOMAIN_STEALTH: B256 =
    b256!("0089c0b4bea509c4509d7c93f962f79cddfb03f7a8056b159df275ec7e4e6852");

/// `H("tee_swap.salt_enc")`
pub const DOMAIN_SALT_ENC: B256 =
    b256!("00a55fbcf2316286f724b5fbfb530d536e3829c23ad2d1bd01b87792f785bcc4");

/// `H("tee_swap.bind_swap")`
pub const DOMAIN_BIND_SWAP: B256 =
    b256!("00558e73d4477300526f0e29f920a317a62cc425034408d58be6dbe7fc484751");

/// `H("tee_swap.bind_R")`
pub const DOMAIN_BIND_R: B256 =
    b256!("00b4965ea4c1b3f9e13c36a32782935c2a1b3c49ec54e201de5f4133f2548a94");

/// `H("tee_swap.bind_meta")`
pub const DOMAIN_BIND_META: B256 =
    b256!("00f3241b2bffce1dd293f941d327f2ce2189f7d423501f0dd76a7da8c407502a");

/// `H("tee_swap.bind_enc")`
pub const DOMAIN_BIND_ENC: B256 =
    b256!("00d0779ead2e71428d9e8ef698a01482d8f344b17244792086fdc32bdfdf67dd");

/// `H("tee_swap.swap_id")`
pub const DOMAIN_SWAP_ID: B256 =
    b256!("00bd03aa9914bdbecd974336e5cf1171b81a60634487683d9d813e195a9e6a9e");

// ── Hash functions ──

/// Encode a domain tag string as a B256 field element.
///
/// The UTF-8 bytes are right-aligned (big-endian) in a 32-byte array.
/// The tag must be at most 31 bytes to stay within the BN254 field.
pub fn domain_tag(tag: &str) -> B256 {
    let bytes = tag.as_bytes();
    assert!(
        bytes.len() <= 31,
        "Domain tag must be at most 31 bytes, got {}",
        bytes.len()
    );
    let mut padded = [0u8; 32];
    padded[32 - bytes.len()..].copy_from_slice(bytes);
    B256::from(padded)
}

/// Poseidon hash with 2 inputs (for Merkle tree nodes, stealth derivation).
pub fn poseidon2(a: B256, b: B256) -> B256 {
    let mut hasher =
        Poseidon::<Fr>::new_circom(2).expect("Failed to create Poseidon hasher");
    let inputs = [b256_to_fr(a), b256_to_fr(b)];
    let result = hasher
        .hash(&inputs)
        .expect("Failed to compute Poseidon hash");
    fr_to_b256(result)
}

/// Poseidon hash with 3 inputs (for nullifier, binding commitments).
pub fn poseidon3(a: B256, b: B256, c: B256) -> B256 {
    let mut hasher =
        Poseidon::<Fr>::new_circom(3).expect("Failed to create Poseidon hasher");
    let inputs = [b256_to_fr(a), b256_to_fr(b), b256_to_fr(c)];
    let result = hasher
        .hash(&inputs)
        .expect("Failed to compute Poseidon hash");
    fr_to_b256(result)
}

/// Poseidon hash with 8 inputs (for commitment: domain + 7 note fields).
#[allow(clippy::too_many_arguments)]
pub fn poseidon8(
    a: B256,
    b: B256,
    c: B256,
    d: B256,
    e: B256,
    f: B256,
    g: B256,
    h: B256,
) -> B256 {
    let mut hasher =
        Poseidon::<Fr>::new_circom(8).expect("Failed to create Poseidon hasher");
    let inputs = [
        b256_to_fr(a),
        b256_to_fr(b),
        b256_to_fr(c),
        b256_to_fr(d),
        b256_to_fr(e),
        b256_to_fr(f),
        b256_to_fr(g),
        b256_to_fr(h),
    ];
    let result = hasher
        .hash(&inputs)
        .expect("Failed to compute Poseidon hash");
    fr_to_b256(result)
}

/// Poseidon hash with variable number of inputs (for swap_id with 11 inputs).
/// Supports 1..=16 inputs (Circom-compatible Poseidon).
pub fn poseidon_n(inputs: &[B256]) -> B256 {
    assert!(
        !inputs.is_empty() && inputs.len() <= 16,
        "poseidon_n supports 1..=16 inputs, got {}",
        inputs.len()
    );
    let mut hasher = Poseidon::<Fr>::new_circom(inputs.len())
        .expect("Failed to create Poseidon hasher");
    let fr_inputs: Vec<Fr> = inputs.iter().map(|v| b256_to_fr(*v)).collect();
    let result = hasher
        .hash(&fr_inputs)
        .expect("Failed to compute Poseidon hash");
    fr_to_b256(result)
}

// ── Convenience hashing helpers (match spec §Data Types) ──

/// Commitment hash: H(DOMAIN_COMMITMENT, chain_id, value, asset_id, owner, fallback_owner, timeout, salt)
pub fn commitment_hash(note: &Note) -> B256 {
    let value_b256: B256 = U256::from(note.value).into();
    poseidon8(
        DOMAIN_COMMITMENT,
        note.chain_id,
        value_b256,
        note.asset_id,
        note.owner,
        note.fallback_owner,
        note.timeout,
        note.salt,
    )
}

/// Nullifier hash: H(DOMAIN_NULLIFIER, commitment, salt)
pub fn nullifier_hash(commitment: B256, salt: B256) -> B256 {
    poseidon3(DOMAIN_NULLIFIER, commitment, salt)
}

// ── Binding commitment helpers (spec §Phase 1) ──

/// Binding commitment for swap participation: H(DOMAIN_BIND_SWAP, swap_id, salt)
pub fn bind_swap(swap_id: B256, salt: B256) -> B256 {
    poseidon3(DOMAIN_BIND_SWAP, swap_id, salt)
}

/// Binding commitment for ephemeral key: H(DOMAIN_BIND_R, R.x)
pub fn bind_r(r_x: B256) -> B256 {
    poseidon2(DOMAIN_BIND_R, r_x)
}

/// Binding commitment for counterparty meta key: H(DOMAIN_BIND_META, pk_meta.x, salt)
pub fn bind_meta(pk_meta_x: B256, salt: B256) -> B256 {
    poseidon3(DOMAIN_BIND_META, pk_meta_x, salt)
}

/// Binding commitment for encrypted salt: H(DOMAIN_BIND_ENC, encrypted_salt)
pub fn bind_enc(encrypted_salt: B256) -> B256 {
    poseidon2(DOMAIN_BIND_ENC, encrypted_salt)
}

/// Swap ID derivation: H(DOMAIN_SWAP_ID, value_a, asset_id_a, chain_id_a,
///                        value_b, asset_id_b, chain_id_b, timeout, pk_meta_a, pk_meta_b, nonce)
#[allow(clippy::too_many_arguments)]
pub fn swap_id_hash(
    value_a: u64,
    asset_id_a: B256,
    chain_id_a: B256,
    value_b: u64,
    asset_id_b: B256,
    chain_id_b: B256,
    timeout: B256,
    pk_meta_a: B256,
    pk_meta_b: B256,
    nonce: B256,
) -> B256 {
    poseidon_n(&[
        DOMAIN_SWAP_ID,
        U256::from(value_a).into(),
        asset_id_a,
        chain_id_a,
        U256::from(value_b).into(),
        asset_id_b,
        chain_id_b,
        timeout,
        pk_meta_a,
        pk_meta_b,
        nonce,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_tag_encoding() {
        let tag = domain_tag("tee_swap.commitment");
        let bytes = tag.as_slice();
        // "tee_swap.commitment" is 19 bytes, so first 13 bytes should be zero
        assert!(bytes[..13].iter().all(|&b| b == 0));
        assert_eq!(&bytes[13..], b"tee_swap.commitment");
    }

    #[test]
    #[should_panic(expected = "Domain tag must be at most 31 bytes")]
    fn test_domain_tag_too_long() {
        domain_tag("this string is way too long and exceeds thirty one bytes limit");
    }

    #[test]
    fn test_poseidon2_deterministic() {
        let a = B256::repeat_byte(0x01);
        let b = B256::repeat_byte(0x02);
        let hash1 = poseidon2(a, b);
        let hash2 = poseidon2(a, b);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_poseidon2_order_matters() {
        let a = B256::repeat_byte(0x01);
        let b = B256::repeat_byte(0x02);
        let hash1 = poseidon2(a, b);
        let hash2 = poseidon2(b, a);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_poseidon3_deterministic() {
        let a = B256::repeat_byte(0x01);
        let b = B256::repeat_byte(0x02);
        let c = B256::repeat_byte(0x03);
        let hash1 = poseidon3(a, b, c);
        let hash2 = poseidon3(a, b, c);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_poseidon3_input_sensitivity() {
        let a = B256::repeat_byte(0x01);
        let b = B256::repeat_byte(0x02);
        let c1 = B256::repeat_byte(0x03);
        let c2 = B256::repeat_byte(0x04);
        assert_ne!(poseidon3(a, b, c1), poseidon3(a, b, c2));
    }

    #[test]
    fn test_poseidon8_deterministic() {
        let vals: Vec<B256> = (1..=8).map(B256::repeat_byte).collect();
        let hash1 = poseidon8(
            vals[0], vals[1], vals[2], vals[3], vals[4], vals[5], vals[6], vals[7],
        );
        let hash2 = poseidon8(
            vals[0], vals[1], vals[2], vals[3], vals[4], vals[5], vals[6], vals[7],
        );
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_poseidon8_input_sensitivity() {
        let vals: Vec<B256> = (1..=8).map(B256::repeat_byte).collect();
        let hash1 = poseidon8(
            vals[0], vals[1], vals[2], vals[3], vals[4], vals[5], vals[6], vals[7],
        );
        let hash2 = poseidon8(
            vals[0],
            vals[1],
            vals[2],
            vals[3],
            vals[4],
            vals[5],
            vals[6],
            B256::repeat_byte(0xFF),
        );
        assert_ne!(hash1, hash2);
    }

    // ── poseidon_n tests ──

    #[test]
    fn test_poseidon_n_matches_poseidon2() {
        let a = B256::repeat_byte(0x01);
        let b = B256::repeat_byte(0x02);
        assert_eq!(poseidon2(a, b), poseidon_n(&[a, b]));
    }

    #[test]
    fn test_poseidon_n_matches_poseidon3() {
        let a = B256::repeat_byte(0x01);
        let b = B256::repeat_byte(0x02);
        let c = B256::repeat_byte(0x03);
        assert_eq!(poseidon3(a, b, c), poseidon_n(&[a, b, c]));
    }

    #[test]
    fn test_poseidon_n_11_inputs_deterministic() {
        let inputs: Vec<B256> = (1..=11).map(B256::repeat_byte).collect();
        let hash1 = poseidon_n(&inputs);
        let hash2 = poseidon_n(&inputs);
        assert_eq!(hash1, hash2);
    }

    #[test]
    #[should_panic(expected = "poseidon_n supports 1..=16 inputs")]
    fn test_poseidon_n_empty_panics() {
        poseidon_n(&[]);
    }

    // ── Domain constant tests ──

    // These constants are agreed cross-language values — do NOT change without
    // coordinating with Noir and Solidity implementations.

    /// Derive a domain tag constant: SHA-256(label) with MSB zeroed.
    fn derive_domain_constant(label: &str) -> B256 {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(label.as_bytes());
        let mut bytes: [u8; 32] = hash.into();
        bytes[0] = 0x00;
        B256::from(bytes)
    }

    #[test]
    fn test_domain_constants_match_derivation() {
        assert_eq!(DOMAIN_COMMITMENT, derive_domain_constant("tee_swap.commitment"));
        assert_eq!(DOMAIN_NULLIFIER, derive_domain_constant("tee_swap.nullifier"));
        assert_eq!(DOMAIN_STEALTH, derive_domain_constant("tee_swap.stealth"));
        assert_eq!(DOMAIN_SALT_ENC, derive_domain_constant("tee_swap.salt_enc"));
        assert_eq!(DOMAIN_BIND_SWAP, derive_domain_constant("tee_swap.bind_swap"));
        assert_eq!(DOMAIN_BIND_R, derive_domain_constant("tee_swap.bind_R"));
        assert_eq!(DOMAIN_BIND_META, derive_domain_constant("tee_swap.bind_meta"));
        assert_eq!(DOMAIN_BIND_ENC, derive_domain_constant("tee_swap.bind_enc"));
        assert_eq!(DOMAIN_SWAP_ID, derive_domain_constant("tee_swap.swap_id"));
    }

    #[test]
    fn test_domain_constants_are_nonzero() {
        assert_ne!(DOMAIN_COMMITMENT, B256::ZERO);
        assert_ne!(DOMAIN_NULLIFIER, B256::ZERO);
        assert_ne!(DOMAIN_STEALTH, B256::ZERO);
        assert_ne!(DOMAIN_SALT_ENC, B256::ZERO);
        assert_ne!(DOMAIN_BIND_SWAP, B256::ZERO);
        assert_ne!(DOMAIN_BIND_R, B256::ZERO);
        assert_ne!(DOMAIN_BIND_META, B256::ZERO);
        assert_ne!(DOMAIN_BIND_ENC, B256::ZERO);
        assert_ne!(DOMAIN_SWAP_ID, B256::ZERO);
    }

    #[test]
    fn test_domain_constants_are_distinct() {
        let all = [
            DOMAIN_COMMITMENT,
            DOMAIN_NULLIFIER,
            DOMAIN_STEALTH,
            DOMAIN_SALT_ENC,
            DOMAIN_BIND_SWAP,
            DOMAIN_BIND_R,
            DOMAIN_BIND_META,
            DOMAIN_BIND_ENC,
            DOMAIN_SWAP_ID,
        ];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j], "Domain constants {i} and {j} must differ");
            }
        }
    }

    // ── Binding helper tests ──

    #[test]
    fn test_commitment_hash_deterministic() {
        let note = Note::with_salt(
            B256::left_padding_from(&[1]),
            1000,
            B256::repeat_byte(0xAA),
            B256::repeat_byte(0xBB),
            B256::repeat_byte(0xCC),
            B256::ZERO,
            B256::repeat_byte(0x01),
        );
        assert_eq!(commitment_hash(&note), commitment_hash(&note));
    }

    #[test]
    fn test_nullifier_hash_deterministic() {
        let c = B256::repeat_byte(0x42);
        let s = B256::repeat_byte(0x01);
        assert_eq!(nullifier_hash(c, s), nullifier_hash(c, s));
    }

    #[test]
    fn test_bind_swap_deterministic() {
        let swap_id = B256::repeat_byte(0x10);
        let salt = B256::repeat_byte(0x20);
        assert_eq!(bind_swap(swap_id, salt), bind_swap(swap_id, salt));
    }

    #[test]
    fn test_bind_r_deterministic() {
        let r_x = B256::repeat_byte(0x30);
        assert_eq!(bind_r(r_x), bind_r(r_x));
    }

    #[test]
    fn test_bind_meta_deterministic() {
        let pk = B256::repeat_byte(0x40);
        let salt = B256::repeat_byte(0x50);
        assert_eq!(bind_meta(pk, salt), bind_meta(pk, salt));
    }

    #[test]
    fn test_bind_enc_deterministic() {
        let enc = B256::repeat_byte(0x60);
        assert_eq!(bind_enc(enc), bind_enc(enc));
    }

    #[test]
    fn test_swap_id_hash_deterministic() {
        let h1 = swap_id_hash(
            100,
            B256::repeat_byte(0x01),
            B256::left_padding_from(&[1]),
            200,
            B256::repeat_byte(0x02),
            B256::left_padding_from(&[2]),
            B256::left_padding_from(&[0x01, 0x00]),
            B256::repeat_byte(0xAA),
            B256::repeat_byte(0xBB),
            B256::repeat_byte(0xFF),
        );
        let h2 = swap_id_hash(
            100,
            B256::repeat_byte(0x01),
            B256::left_padding_from(&[1]),
            200,
            B256::repeat_byte(0x02),
            B256::left_padding_from(&[2]),
            B256::left_padding_from(&[0x01, 0x00]),
            B256::repeat_byte(0xAA),
            B256::repeat_byte(0xBB),
            B256::repeat_byte(0xFF),
        );
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_swap_id_hash_nonce_sensitivity() {
        let h1 = swap_id_hash(
            100,
            B256::repeat_byte(0x01),
            B256::left_padding_from(&[1]),
            200,
            B256::repeat_byte(0x02),
            B256::left_padding_from(&[2]),
            B256::left_padding_from(&[0x01, 0x00]),
            B256::repeat_byte(0xAA),
            B256::repeat_byte(0xBB),
            B256::repeat_byte(0x01),
        );
        let h2 = swap_id_hash(
            100,
            B256::repeat_byte(0x01),
            B256::left_padding_from(&[1]),
            200,
            B256::repeat_byte(0x02),
            B256::left_padding_from(&[2]),
            B256::left_padding_from(&[0x01, 0x00]),
            B256::repeat_byte(0xAA),
            B256::repeat_byte(0xBB),
            B256::repeat_byte(0x02),
        );
        assert_ne!(h1, h2);
    }
}

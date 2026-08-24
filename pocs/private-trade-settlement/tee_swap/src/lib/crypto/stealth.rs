use alloy::primitives::B256;
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::PrimeField;
use ark_grumpkin::{Affine, Fr as GrumpkinScalar, Projective};

use super::poseidon::{fr_to_b256, poseidon2, DOMAIN_STEALTH};

// ── Conversion helpers (Grumpkin ↔ B256) ──

/// Convert a Grumpkin affine point's x-coordinate to B256.
/// Grumpkin base field = BN254 scalar field (Fr), so we can use the same conversion.
pub fn affine_x_to_b256(point: &Affine) -> B256 {
    fr_to_b256(point.x)
}

/// Convert a Grumpkin affine point's y-coordinate to B256.
pub fn affine_y_to_b256(point: &Affine) -> B256 {
    fr_to_b256(point.y)
}

/// Convert a B256 to a Grumpkin scalar (BN254 Fq).
/// The scalar is interpreted as big-endian bytes mod the Grumpkin scalar field order.
pub fn b256_to_grumpkin_scalar(value: B256) -> GrumpkinScalar {
    GrumpkinScalar::from_be_bytes_mod_order(value.as_ref())
}

/// Convert a Grumpkin scalar to B256.
pub fn grumpkin_scalar_to_b256(scalar: &GrumpkinScalar) -> B256 {
    use ark_ff::BigInteger;
    let big_int = scalar.into_bigint();
    let bytes = big_int.to_bytes_be();
    B256::from_slice(&bytes)
}

// ── Stealth address derivation (spec §Data Types) ──

/// Derive a stealth public key and the stealth scalar.
///
/// ```text
/// shared_secret = r · pk_meta
/// stealth_scalar = H(DOMAIN_STEALTH, shared_secret.x)
/// pk_stealth = pk_meta + stealth_scalar · G
/// ```
///
/// Returns `(pk_stealth, stealth_scalar)`.
pub fn derive_stealth_pubkey(
    pk_meta: &Projective,
    r: &GrumpkinScalar,
) -> (Affine, GrumpkinScalar) {
    // ECDH shared secret
    let shared = (*pk_meta * *r).into_affine();
    let shared_x = affine_x_to_b256(&shared);

    // stealth_scalar = H(DOMAIN_STEALTH, shared.x)
    let stealth_hash = poseidon2(DOMAIN_STEALTH, shared_x);
    // The hash output is a BN254 Fr element. We interpret it as a Grumpkin scalar.
    // Since Grumpkin scalar field = BN254 base field (Fq), and the hash output is
    // in BN254 Fr, we reduce mod Fq. For the PoC, the hash is small enough that
    // this is fine (hash output < 2^254, both fields are ~254 bits).
    let stealth_scalar = b256_to_grumpkin_scalar(stealth_hash);

    // pk_stealth = pk_meta + stealth_scalar · G
    let stealth_g = Projective::generator() * stealth_scalar;
    let pk_stealth = (*pk_meta + stealth_g).into_affine();

    (pk_stealth, stealth_scalar)
}

/// Derive the stealth secret key from the meta secret key and the revealed ephemeral public key.
///
/// ```text
/// shared_secret = sk_meta · R
/// stealth_scalar = H(DOMAIN_STEALTH, shared_secret.x)
/// sk_stealth = sk_meta + stealth_scalar
/// ```
pub fn derive_stealth_secret(sk_meta: &GrumpkinScalar, r_pub: &Projective) -> GrumpkinScalar {
    // ECDH shared secret (same as sender: sk_meta · R = sk_meta · r · G = r · pk_meta)
    let shared = (*r_pub * *sk_meta).into_affine();
    let shared_x = affine_x_to_b256(&shared);

    // stealth_scalar = H(DOMAIN_STEALTH, shared.x)
    let stealth_hash = poseidon2(DOMAIN_STEALTH, shared_x);
    let stealth_scalar = b256_to_grumpkin_scalar(stealth_hash);

    // sk_stealth = sk_meta + stealth_scalar
    *sk_meta + stealth_scalar
}

/// Compute the ECDH shared secret x-coordinate between an ephemeral key and a meta public key.
///
/// ```text
/// shared_secret.x = (r · pk_meta).x
/// ```
pub fn ecdh_shared_secret_x(pk_meta: &Projective, r: &GrumpkinScalar) -> B256 {
    let shared = (*pk_meta * *r).into_affine();
    affine_x_to_b256(&shared)
}

/// Split a Grumpkin scalar into lo/hi 128-bit limbs (for circuit witness).
///
/// Returns `(lo, hi)` where `scalar = lo + hi * 2^128`.
pub fn scalar_to_lo_hi(scalar: &GrumpkinScalar) -> (B256, B256) {
    use ark_ff::BigInteger;
    let bigint = scalar.into_bigint();
    let bytes = bigint.to_bytes_le();

    let mut lo_bytes = [0u8; 32];
    lo_bytes[..16].copy_from_slice(&bytes[..16]);

    let mut hi_bytes = [0u8; 32];
    hi_bytes[..16].copy_from_slice(&bytes[16..32]);

    // Convert to big-endian B256
    lo_bytes.reverse();
    hi_bytes.reverse();

    (B256::from(lo_bytes), B256::from(hi_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::UniformRand;

    #[test]
    fn test_stealth_derivation_roundtrip() {
        let mut rng = ark_std::test_rng();

        // Meta key pair (receiver)
        let sk_meta = GrumpkinScalar::rand(&mut rng);
        let pk_meta = (Projective::generator() * sk_meta).into_affine();

        // Ephemeral key pair (sender)
        let r = GrumpkinScalar::rand(&mut rng);
        let r_pub = (Projective::generator() * r).into_affine();

        // Sender derives stealth pubkey
        let (pk_stealth, _stealth_scalar) =
            derive_stealth_pubkey(&pk_meta.into(), &r);

        // Receiver derives stealth secret key
        let sk_stealth = derive_stealth_secret(&sk_meta, &r_pub.into());

        // sk_stealth · G should equal pk_stealth
        let derived_pk = (Projective::generator() * sk_stealth).into_affine();
        assert_eq!(derived_pk, pk_stealth);
    }

    #[test]
    fn test_different_ephemeral_keys_produce_different_stealth_addresses() {
        let mut rng = ark_std::test_rng();

        let sk_meta = GrumpkinScalar::rand(&mut rng);
        let pk_meta: Projective = Projective::generator() * sk_meta;

        let r1 = GrumpkinScalar::rand(&mut rng);
        let r2 = GrumpkinScalar::rand(&mut rng);

        let (pk_stealth_1, _) = derive_stealth_pubkey(&pk_meta, &r1);
        let (pk_stealth_2, _) = derive_stealth_pubkey(&pk_meta, &r2);

        assert_ne!(pk_stealth_1, pk_stealth_2);
    }

    #[test]
    fn test_ecdh_shared_secret_symmetry() {
        let mut rng = ark_std::test_rng();

        let sk_meta = GrumpkinScalar::rand(&mut rng);
        let pk_meta: Projective = Projective::generator() * sk_meta;

        let r = GrumpkinScalar::rand(&mut rng);
        let r_pub: Projective = Projective::generator() * r;

        // r · pk_meta == sk_meta · R
        let shared_sender = ecdh_shared_secret_x(&pk_meta, &r);
        let shared_receiver = ecdh_shared_secret_x(&r_pub, &sk_meta);

        assert_eq!(shared_sender, shared_receiver);
    }

    #[test]
    fn test_affine_x_roundtrip() {
        let mut rng = ark_std::test_rng();
        let sk = GrumpkinScalar::rand(&mut rng);
        let pk = (Projective::generator() * sk).into_affine();

        let x_b256 = affine_x_to_b256(&pk);
        assert_ne!(x_b256, B256::ZERO);

        // Verify it's a valid field element by round-tripping through Fr
        let fr = super::super::poseidon::b256_to_fr(x_b256);
        let back = fr_to_b256(fr);
        assert_eq!(x_b256, back);
    }

    #[test]
    fn test_scalar_to_lo_hi() {
        let mut rng = ark_std::test_rng();
        let scalar = GrumpkinScalar::rand(&mut rng);

        let (lo, hi) = scalar_to_lo_hi(&scalar);
        // At least one should be non-zero for a random scalar
        assert!(lo != B256::ZERO || hi != B256::ZERO);
    }
}

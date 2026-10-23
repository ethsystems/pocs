use crate::domain;
use crate::hasher::{hash_2, hash_3, hash_4};

// An ECDSA secp256k1 public key as a custody signer exports it: two 32-byte
// big-endian coordinates. The same bytes feed the owner value and the
// signature check, so one witness serves both (SPEC, Owner Value).
pub struct SpendKey {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

// Packs 16 big-endian bytes, starting at `start`, into one field element. The
// result is below 2^128 by construction, so the limbs are canonical.
fn limb(bytes: [u8; 32], start: u32) -> Field {
    let mut acc: Field = 0;
    for i in 0..16 {
        acc = acc * 256 + bytes[start + i] as Field;
    }
    acc
}

// pk_hash = Poseidon1(pk_x_hi, pk_x_lo, pk_y_hi, pk_y_lo). Also the claim key's
// hash, which the pool stores as `claimKeyHash`.
pub fn key_hash(key: SpendKey) -> Field {
    hash_4(
        [limb(key.x, 0), limb(key.x, 16), limb(key.y, 0), limb(key.y, 16)],
    )
}

pub fn nk_hash(nk: Field) -> Field {
    hash_2([domain::NK_TAG, nk])
}

// owner = Poseidon1(OWNER_TAG, pk_hash, nk_hash).
pub fn owner_value(key: SpendKey, nk: Field) -> Field {
    hash_3([domain::OWNER_TAG, key_hash(key), nk_hash(nk)])
}

#[test]
fn test_limbs_are_big_endian_halves() {
    let mut bytes = [0; 32];
    bytes[15] = 1;
    bytes[31] = 2;
    assert(limb(bytes, 0) == 1);
    assert(limb(bytes, 16) == 2);
    bytes[0] = 0xff;
    assert(limb(bytes, 0) == 0xff000000000000000000000000000001);
}

#[test]
fn test_owner_value_binds_both_keys() {
    let key = SpendKey { x: [1; 32], y: [2; 32] };
    let other = SpendKey { x: [1; 32], y: [3; 32] };
    let owner = owner_value(key, 7);
    assert(owner == owner_value(key, 7));
    assert(owner != owner_value(key, 8));
    assert(owner != owner_value(other, 7));
}

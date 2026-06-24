//! Pure-Rust scalar GF(16) reference oracle. Used in tests as ground truth
//! for the bitsliced in-circuit primitives.
//!
//! GF(16) = GF(2)[x]/(x^4 + x + 1). Each element is a 4-bit nibble; bit `b`
//! is the coefficient of `x^b`. Addition is XOR; multiplication is schoolbook
//! followed by reduction mod the irreducible polynomial.

/// GF(16) addition (XOR).
#[cfg(test)]
#[inline]
pub(crate) fn add(a: u8, b: u8) -> u8 {
    (a ^ b) & 0x0F
}

/// GF(16) multiplication mod `x^4 + x + 1`.
///
/// Matches MAYO-C `simple_arithmetic.h::mul_f` exactly (see `/tmp/MAYO-C/src/`).
#[cfg(test)]
#[inline]
pub(crate) fn mul(a: u8, b: u8) -> u8 {
    let a = a & 0x0F;
    let b = b & 0x0F;
    // carry-less multiply
    let mut p: u8 = 0;
    p ^= ((a >> 0) & 1).wrapping_mul(b);
    p ^= ((a >> 1) & 1).wrapping_mul(b << 1);
    p ^= ((a >> 2) & 1).wrapping_mul(b << 2);
    p ^= ((a >> 3) & 1).wrapping_mul(b << 3);
    // p has up to 8 bits (a, b are 4-bit)
    // reduce mod x^4 + x + 1: x^4 = x + 1, so for each bit i >= 4 of p,
    // contribute 1 << (i - 4) and 1 << (i - 3).
    let top = p & 0xF0;
    ((p ^ (top >> 4) ^ (top >> 3)) & 0x0F) as u8
}

// Packed-nibble layout (MAYO-C "m-vec limb" layout)
//
// A length-64 m-vec is stored in 4 packed `u64`s. Within a packed word,
// nibble `k` (k in 0..16) lives at bit positions `[k*4, k*4 + 4)`.
// Across the 4 packed words, packed[w] holds nibbles `[w*16, w*16+16)`.
//
// Equivalently, byte 0 of a packed word holds nibble 0 in the low 4 bits
// and nibble 1 in the high 4 bits. See MAYO-C `mayo.c::decode/encode`.

/// Pack 64 GF(16) lanes (each in 0..16) into 4 packed `u64`s (MAYO-C layout).
pub(crate) fn pack_lanes(lanes: &[u8; 64]) -> [u64; 4] {
    let mut out = [0u64; 4];
    for (i, &v) in lanes.iter().enumerate() {
        debug_assert!(v < 16, "lane {i} = {v} is not a valid GF(16) element");
        let w = i / 16;
        let k = i % 16;
        out[w] |= ((v & 0x0F) as u64) << (k * 4);
    }
    out
}

/// Inverse of `pack_lanes`.
#[cfg(test)]
pub(crate) fn unpack_lanes(packed: &[u64; 4]) -> [u8; 64] {
    let mut lanes = [0u8; 64];
    for w in 0..4 {
        let pw = packed[w];
        for k in 0..16 {
            lanes[w * 16 + k] = ((pw >> (k * 4)) & 0x0F) as u8;
        }
    }
    lanes
}

// Bitsliced layout
//
// 4 bit-planes; plane `b`'s bit `i` is bit `b` of nibble `i`.

/// Convert 64 GF(16) lanes to a 4-plane bitsliced representation.
pub(crate) fn lanes_to_bitsliced(lanes: &[u8; 64]) -> [u64; 4] {
    let mut planes = [0u64; 4];
    for (i, &v) in lanes.iter().enumerate() {
        debug_assert!(v < 16);
        for b in 0..4 {
            planes[b] |= (((v >> b) & 1) as u64) << i;
        }
    }
    planes
}

/// Inverse of `lanes_to_bitsliced`.
#[cfg(test)]
pub(crate) fn bitsliced_to_lanes(planes: &[u64; 4]) -> [u8; 64] {
    let mut lanes = [0u8; 64];
    for i in 0..64 {
        let mut v = 0u8;
        for b in 0..4 {
            v |= (((planes[b] >> i) & 1) as u8) << b;
        }
        lanes[i] = v;
    }
    lanes
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    /// Independent scalar reference: schoolbook multiply via shift-XOR, then
    /// reduce by directly applying x^4 = x + 1 to each high bit of the product.
    fn mul_ref(a: u8, b: u8) -> u8 {
        let a = (a & 0x0F) as u16;
        let b = (b & 0x0F) as u16;
        let mut p: u16 = 0;
        for i in 0..4 {
            if (a >> i) & 1 == 1 {
                p ^= b << i;
            }
        }
        // reduce: for each set bit at position >= 4, fold it down using
        // x^4 = x + 1, x^5 = x^2 + x, x^6 = x^3 + x^2, x^7 = x^3 + x^2 + x + 1.
        for i in (4..8).rev() {
            if (p >> i) & 1 == 1 {
                p ^= 1 << i;
                // x^i = x^(i-4) * (x + 1) = x^(i-3) + x^(i-4)
                p ^= 1 << (i - 3);
                p ^= 1 << (i - 4);
            }
        }
        (p & 0x0F) as u8
    }

    #[test]
    fn given_full_table_when_mul_then_matches_independent_reference() {
        // KAT against an independent reference: full 16x16 table.
        for a in 0u8..16 {
            for b in 0u8..16 {
                let got = mul(a, b);
                let want = mul_ref(a, b);
                assert_eq!(got, want, "mul({a},{b})={got} != {want}");
            }
        }
    }

    #[test]
    fn given_zero_when_mul_then_returns_zero() {
        for a in 0u8..16 {
            assert_eq!(mul(a, 0), 0);
            assert_eq!(mul(0, a), 0);
        }
    }

    #[test]
    fn given_one_when_mul_then_returns_other() {
        for a in 0u8..16 {
            assert_eq!(mul(a, 1), a);
            assert_eq!(mul(1, a), a);
        }
    }

    #[test]
    fn given_random_triples_when_mul_then_associative() {
        let mut rng = StdRng::seed_from_u64(0xCAFE_BABE);
        for _ in 0..1000 {
            let a: u8 = rng.random_range(0..16);
            let b: u8 = rng.random_range(0..16);
            let c: u8 = rng.random_range(0..16);
            assert_eq!(mul(mul(a, b), c), mul(a, mul(b, c)));
        }
    }

    #[test]
    fn given_random_triples_when_mul_then_distributive_over_add() {
        let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF);
        for _ in 0..1000 {
            let a: u8 = rng.random_range(0..16);
            let b: u8 = rng.random_range(0..16);
            let c: u8 = rng.random_range(0..16);
            // a * (b + c) = a*b + a*c
            assert_eq!(mul(a, add(b, c)), add(mul(a, b), mul(a, c)));
        }
    }

    #[test]
    fn given_pack_unpack_when_round_trip_then_identity() {
        let mut rng = StdRng::seed_from_u64(0x1234_5678);
        for _ in 0..50 {
            let mut lanes = [0u8; 64];
            for v in lanes.iter_mut() {
                *v = rng.random_range(0..16);
            }
            let packed = pack_lanes(&lanes);
            let back = unpack_lanes(&packed);
            assert_eq!(lanes, back);
        }
    }

    #[test]
    fn given_hand_computed_lanes_when_pack_then_layout_matches_mayo_c() {
        // MAYO-C convention: byte 0 holds nibble_0 (low) | nibble_1 (high).
        let mut lanes = [0u8; 64];
        lanes[0] = 0x3;
        lanes[1] = 0xA;
        // packed_word 0: byte 0 should be 0x3 | (0xA << 4) = 0xA3.
        let packed = pack_lanes(&lanes);
        assert_eq!(packed[0] & 0xFF, 0xA3, "byte 0 of packed word 0 is wrong");

        // Setting nibble at index 16 should land in packed_word 1.
        let mut lanes = [0u8; 64];
        lanes[16] = 0x5;
        let packed = pack_lanes(&lanes);
        assert_eq!(packed[0], 0);
        assert_eq!(packed[1] & 0x0F, 0x5);

        // Nibble 17 lives in high nibble of byte 0 of word 1.
        let mut lanes = [0u8; 64];
        lanes[17] = 0xC;
        let packed = pack_lanes(&lanes);
        assert_eq!(packed[1], 0xC0);
    }

    #[test]
    fn given_lanes_when_round_trip_bitsliced_then_identity() {
        let mut rng = StdRng::seed_from_u64(0xABCD);
        for _ in 0..50 {
            let mut lanes = [0u8; 64];
            for v in lanes.iter_mut() {
                *v = rng.random_range(0..16);
            }
            let planes = lanes_to_bitsliced(&lanes);
            let back = bitsliced_to_lanes(&planes);
            assert_eq!(lanes, back);
        }
    }
}

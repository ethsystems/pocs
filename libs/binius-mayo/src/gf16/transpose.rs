//! Bitsliced ↔ packed-nibble transpose.
//!
//! ## Layouts
//!
//! **Packed (MAYO-C "m-vec limb" layout)**: 4 `u64`s. Within a packed word,
//! nibble `k` (0..16) lives at bit positions `[k*4, k*4 + 4)`. Across the 4
//! packed words, `packed[w]` holds nibbles `[w*16, w*16 + 16)`.
//!
//! **Bitsliced**: 4 `u64`s, one per nibble bit. `plane[b].bit(i)` = bit `b`
//! of lane `i`, for `b ∈ 0..4` and `i ∈ 0..64`.
//!
//! ## Index relation
//!
//! Let `i = 16*w + k` for `w ∈ 0..4`, `k ∈ 0..16`. Then:
//!
//! ```text
//! plane[b].bit(16*w + k) = packed[w].bit(4*k + b)
//! ```
//!
//! ## Implementation
//!
//! `packed_to_bitsliced` runs, for each `(w, b)`, a 4-stage delta-swap-style
//! compression that extracts the bits at positions `{b, b+4, ..., b+60}` of
//! `packed[w]` and packs them into the low 16 bits; then those 16 bits are
//! shifted into position `[16*w, 16*w + 16)` of `plane[b]`.
//!
//! `bitsliced_to_packed` is the inverse: it takes 4-bit slices of each plane
//! and spreads/interleaves them back into the packed nibble layout.

use binius_core::word::Word;
use binius_frontend::{CircuitBuilder, Wire};

use super::BitslicedGf16Mvec;

// packed → bitsliced

/// Compress 16 bits at positions `{0, 4, 8, …, 60}` of `x` into the low 16 bits.
///
/// Uses a 4-stage shift+XOR+mask cascade. Bits not at those positions must be
/// zero on entry. XOR is used in lieu of OR because the two terms being merged
/// at each stage have disjoint set bits.
///
/// Cost: 4 ANDs from the masks plus 4 ANDs from the per-stage `shr` (binius64's
/// shift gates emit one AND each), and 4 linear (XOR) constraints. Total: 8
/// AND constraints + 4 linear constraints.
fn compress_stride4_to_low16(b: &CircuitBuilder, x: Wire) -> Wire {
    // Stage 1: bits at {0,4,8,…,60} → bits at {0,1, 8,9, 16,17, …, 56,57}.
    let m1 = b.add_constant(Word(0x0303_0303_0303_0303));
    let s1 = b.shr(x, 3);
    let t1 = b.bxor(x, s1);
    let r1 = b.band(t1, m1);

    // Stage 2: collapse two bytes at a time → bits at {0..3, 16..19, 32..35, 48..51}.
    let m2 = b.add_constant(Word(0x000F_000F_000F_000F));
    let s2 = b.shr(r1, 6);
    let t2 = b.bxor(r1, s2);
    let r2 = b.band(t2, m2);

    // Stage 3: bits at {0..3, 16..19, 32..35, 48..51} → {0..7, 32..39}.
    let m3 = b.add_constant(Word(0x0000_00FF_0000_00FF));
    let s3 = b.shr(r2, 12);
    let t3 = b.bxor(r2, s3);
    let r3 = b.band(t3, m3);

    // Stage 4: bits at {0..7, 32..39} → bits at {0..15}.
    let m4 = b.add_constant(Word(0x0000_0000_0000_FFFF));
    let s4 = b.shr(r3, 24);
    let t4 = b.bxor(r3, s4);
    b.band(t4, m4)
}

/// 4 packed-nibble Words (MAYO-C m-vec-limb layout) → bitsliced 4-plane m-vec.
pub(crate) fn packed_to_bitsliced(
    builder: &CircuitBuilder,
    packed: &[Wire; 4],
) -> BitslicedGf16Mvec {
    let b = builder.subcircuit("gf16/packed_to_bitsliced");
    // Mask to extract every nibble's bit `b` into bit 0 of each nibble:
    //   stride_mask = 0x1111_1111_1111_1111
    let stride_mask = b.add_constant(Word(0x1111_1111_1111_1111));

    // For each plane bit b ∈ 0..4, build a 64-bit Word.
    let bits: [Wire; 4] = core::array::from_fn(|bit_idx| {
        // Per packed word w ∈ 0..4: shift bit `bit_idx` of every nibble down
        // to position 0 of that nibble, mask, compress to low 16, then shift
        // up to byte position [16w, 16w+16).
        let chunks: [Wire; 4] = core::array::from_fn(|w| {
            let pw = packed[w];
            // Shift right by `bit_idx`: each nibble's bit `bit_idx` lands at
            // its bit-0 position. Then mask with 0x1111…1111 to keep only those.
            let shifted = if bit_idx == 0 {
                pw
            } else {
                b.shr(pw, bit_idx as u32)
            };
            let extracted = b.band(shifted, stride_mask);
            // Now bits at positions {0,4,8,…,60}; compress to low 16.
            let compressed = compress_stride4_to_low16(&b, extracted);
            // Shift compressed 16-bit chunk into its target slot in the plane.
            if w == 0 {
                compressed
            } else {
                b.shl(compressed, (16 * w) as u32)
            }
        });
        // The four 16-bit chunks occupy disjoint 16-bit lanes so XOR == OR.
        b.bxor_multi(&chunks)
    });

    BitslicedGf16Mvec { bits }
}

// bitsliced → packed

/// Inverse of `compress_stride4_to_low16`: take the low 16 bits of `x` and
/// expand them to bit positions `{0, 4, 8, …, 60}` (each input bit at index
/// `j ∈ 0..16` placed at output bit position `4*j`).
///
/// Cost: 4 ANDs from the masks plus 4 ANDs from the per-stage `shl`, and 4
/// linear (XOR) constraints. Total: 8 AND constraints + 4 linear constraints.
fn expand_low16_to_stride4(b: &CircuitBuilder, x: Wire) -> Wire {
    // Stage 1: bits {0..15} → bits {0..7, 32..39}.
    let m1 = b.add_constant(Word(0x0000_00FF_0000_00FF));
    let s1 = b.shl(x, 24);
    let t1 = b.bxor(x, s1);
    let r1 = b.band(t1, m1);

    // Stage 2: bits {0..7, 32..39} → bits {0..3, 16..19, 32..35, 48..51}.
    let m2 = b.add_constant(Word(0x000F_000F_000F_000F));
    let s2 = b.shl(r1, 12);
    let t2 = b.bxor(r1, s2);
    let r2 = b.band(t2, m2);

    // Stage 3: bits {0..3, 16..19, …} → bits {0,1, 8,9, …, 56,57}.
    let m3 = b.add_constant(Word(0x0303_0303_0303_0303));
    let s3 = b.shl(r2, 6);
    let t3 = b.bxor(r2, s3);
    let r3 = b.band(t3, m3);

    // Stage 4: bits {0,1, 8,9, …} → bits {0, 4, 8, …, 60}.
    let m4 = b.add_constant(Word(0x1111_1111_1111_1111));
    let s4 = b.shl(r3, 3);
    let t4 = b.bxor(r3, s4);
    b.band(t4, m4)
}

/// Inverse of `packed_to_bitsliced`.
pub(crate) fn bitsliced_to_packed(builder: &CircuitBuilder, bv: &BitslicedGf16Mvec) -> [Wire; 4] {
    let b = builder.subcircuit("gf16/bitsliced_to_packed");
    let mask16 = b.add_constant(Word(0x0000_0000_0000_FFFF));

    // For each packed word w ∈ 0..4, gather the 16 bits per plane that belong
    // to nibbles [16*w, 16*w + 16), expand each plane's chunk to stride-4
    // positions, and XOR-OR them with bit b shift.
    core::array::from_fn(|w| {
        // For each plane bit b, slice plane[b] in the [16*w, 16*w + 16) window.
        let bit_contribs: [Wire; 4] = core::array::from_fn(|bit_idx| {
            let pl = bv.bits[bit_idx];
            // Extract the relevant 16-bit chunk: shift it down to bits 0..15.
            let down = if w == 0 {
                pl
            } else {
                b.shr(pl, (16 * w) as u32)
            };
            let chunk = b.band(down, mask16);
            // Expand to stride-4 positions {0,4,8,…,60}.
            let expanded = expand_low16_to_stride4(&b, chunk);
            // Shift left by bit_idx to place in the correct nibble bit.
            if bit_idx == 0 {
                expanded
            } else {
                b.shl(expanded, bit_idx as u32)
            }
        });
        // The 4 contributions occupy disjoint nibble-bit positions → XOR == OR.
        b.bxor_multi(&bit_contribs)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gf16::scalar;
    use binius_core::verify::verify_constraints;
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    /// Round-trip: packed → bitsliced → packed = identity, in-circuit.
    #[test]
    fn given_random_lanes_when_packed_to_bitsliced_to_packed_then_round_trip() {
        let mut rng = StdRng::seed_from_u64(0x1357_9BDF);
        let builder = CircuitBuilder::new();
        let packed_in: [Wire; 4] = core::array::from_fn(|_| builder.add_witness());
        let bv = packed_to_bitsliced(&builder, &packed_in);
        let packed_out = bitsliced_to_packed(&builder, &bv);
        let expected: [Wire; 4] = core::array::from_fn(|_| builder.add_witness());
        for i in 0..4 {
            builder.assert_eq(format!("rt[{i}]"), packed_out[i], expected[i]);
        }
        let circuit = builder.build();

        for _ in 0..100 {
            let mut w = circuit.new_witness_filler();
            let mut lanes = [0u8; 64];
            for v in lanes.iter_mut() {
                *v = rng.random_range(0..16);
            }
            let pk = scalar::pack_lanes(&lanes);
            for i in 0..4 {
                w[packed_in[i]] = Word(pk[i]);
                w[expected[i]] = Word(pk[i]);
            }
            circuit.populate_wire_witness(&mut w).unwrap();
            verify_constraints(circuit.constraint_system(), &w.into_value_vec()).unwrap();
        }
    }

    /// `packed_to_bitsliced` agrees with the scalar oracle's `lanes_to_bitsliced`.
    #[test]
    fn given_random_lanes_when_packed_to_bitsliced_then_matches_scalar_oracle() {
        let mut rng = StdRng::seed_from_u64(0x2468_ACE0);
        let builder = CircuitBuilder::new();
        let packed_in: [Wire; 4] = core::array::from_fn(|_| builder.add_witness());
        let bv = packed_to_bitsliced(&builder, &packed_in);
        let expected = BitslicedGf16Mvec::new_witness(&builder);
        bv.assert_eq(&builder, &expected);
        let circuit = builder.build();

        for _ in 0..50 {
            let mut w = circuit.new_witness_filler();
            let mut lanes = [0u8; 64];
            for v in lanes.iter_mut() {
                *v = rng.random_range(0..16);
            }
            let pk = scalar::pack_lanes(&lanes);
            for i in 0..4 {
                w[packed_in[i]] = Word(pk[i]);
            }
            expected.populate(&mut w, &lanes);
            circuit.populate_wire_witness(&mut w).unwrap();
            verify_constraints(circuit.constraint_system(), &w.into_value_vec()).unwrap();
        }
    }

    /// Round-trip the other direction: bitsliced → packed → bitsliced = id.
    #[test]
    fn given_random_lanes_when_bitsliced_to_packed_to_bitsliced_then_round_trip() {
        let mut rng = StdRng::seed_from_u64(0xFEDC_BA98);
        let builder = CircuitBuilder::new();
        let bv = BitslicedGf16Mvec::new_witness(&builder);
        let packed = bitsliced_to_packed(&builder, &bv);
        let bv2 = packed_to_bitsliced(&builder, &packed);
        bv2.assert_eq(&builder, &bv);
        let circuit = builder.build();

        for _ in 0..50 {
            let mut w = circuit.new_witness_filler();
            let mut lanes = [0u8; 64];
            for v in lanes.iter_mut() {
                *v = rng.random_range(0..16);
            }
            bv.populate(&mut w, &lanes);
            circuit.populate_wire_witness(&mut w).unwrap();
            verify_constraints(circuit.constraint_system(), &w.into_value_vec()).unwrap();
        }
    }
}

//! Karatsuba bitsliced GF(16) multiplication.
//!
//! GF(16) = GF(2)[x]/(x^4 + x + 1). A nibble `a` is decomposed as
//! `a = a_hi * x^2 + a_lo`, where `a_hi` and `a_lo` are 2-bit polynomials.
//!
//! ## Two-level Karatsuba
//!
//! **Level 1.** Split 4-bit into two 2-bit halves:
//!   z0 = a_lo * b_lo                                    (2-bit poly mul)
//!   z2 = a_hi * b_hi                                    (2-bit poly mul)
//!   z1m = (a_hi + a_lo) * (b_hi + b_lo)                 (2-bit poly mul)
//!   middle = z1m + z2 + z0                              (Karatsuba combine)
//!   a*b = z2 * x^4 + middle * x^2 + z0                  (degree-6 unreduced)
//!
//! **Level 2.** 2-bit Karatsuba `(a1*x + a0)(b1*x + b0)`:
//!   y0 = a0 ∧ b0     (1 AND)
//!   y2 = a1 ∧ b1     (1 AND)
//!   y1 = (a0 ⊕ a1) ∧ (b0 ⊕ b1) ⊕ y0 ⊕ y2     (1 AND)
//!
//! 3 ANDs per 2-bit mul × 3 muls = **9 ANDs per 64-lane Karatsuba**.
//!
//! ## Reduction mod x^4 + x + 1
//!
//! With p the unreduced degree-6 product (coefficients p0..p6, each a Word/plane):
//!   r0 = p0 ⊕ p4
//!   r1 = p1 ⊕ p4 ⊕ p5
//!   r2 = p2 ⊕ p5 ⊕ p6
//!   r3 = p3 ⊕ p6
//!
//! All XORs (linear constraints, near-free in binius64: XORs cost <0.1× an
//! AND constraint and frequently fuse with adjacent gates).

use binius_core::word::Word;
use binius_frontend::{CircuitBuilder, Wire};

use super::BitslicedGf16Mvec;

/// 2-bit polynomial multiply via Karatsuba: 3 ANDs.
///
/// Inputs are 1-bit-per-lane Wires (one bit per of the 64 lanes), representing
/// `(a1·x + a0)` and `(b1·x + b0)`. Returns the 3 coefficients (y2, y1, y0)
/// of `(a1·x + a0)(b1·x + b0) = y2·x^2 + y1·x + y0`.
#[inline]
fn mul2(builder: &CircuitBuilder, a0: Wire, a1: Wire, b0: Wire, b1: Wire) -> (Wire, Wire, Wire) {
    // y0 = a0 & b0
    let y0 = builder.band(a0, b0);
    // y2 = a1 & b1
    let y2 = builder.band(a1, b1);
    // y1 = (a0 ^ a1) & (b0 ^ b1) ^ y0 ^ y2
    //
    // We could do this as (sum_a) & (sum_b) then XOR with y0 and y2 separately;
    // binius64's `fax` gate fuses (x & y) ^ w into a single AND constraint, so
    // we use it once after pre-XORing y0 ⊕ y2.
    let sum_a = builder.bxor(a0, a1);
    let sum_b = builder.bxor(b0, b1);
    let y0_xor_y2 = builder.bxor(y0, y2);
    let y1 = builder.fax(sum_a, sum_b, y0_xor_y2);
    (y2, y1, y0)
}

/// Componentwise GF(16) multiplication of two bitsliced m-vecs.
///
/// Cost: **9 ANDs** total (one fused AND-XOR per 2-bit mul × 3 muls).
pub(crate) fn mul_karatsuba(
    builder: &CircuitBuilder,
    a: &BitslicedGf16Mvec,
    b: &BitslicedGf16Mvec,
) -> BitslicedGf16Mvec {
    let b_ = builder.subcircuit("gf16/mul_karatsuba");

    // Bit indexing inside a nibble (low to high):
    //   a_lo bit 0 = bits[0], a_lo bit 1 = bits[1]
    //   a_hi bit 0 = bits[2], a_hi bit 1 = bits[3]
    let (a_lo0, a_lo1) = (a.bits[0], a.bits[1]);
    let (a_hi0, a_hi1) = (a.bits[2], a.bits[3]);
    let (bb_lo0, bb_lo1) = (b.bits[0], b.bits[1]);
    let (bb_hi0, bb_hi1) = (b.bits[2], b.bits[3]);

    let s_a0 = b_.bxor(a_lo0, a_hi0); // (a_lo + a_hi)_0
    let s_a1 = b_.bxor(a_lo1, a_hi1); // (a_lo + a_hi)_1
    let s_b0 = b_.bxor(bb_lo0, bb_hi0);
    let s_b1 = b_.bxor(bb_lo1, bb_hi1);

    // z0 = a_lo · b_lo
    let (z0_2, z0_1, z0_0) = mul2(&b_, a_lo0, a_lo1, bb_lo0, bb_lo1);
    // z2 = a_hi · b_hi
    let (z2_2, z2_1, z2_0) = mul2(&b_, a_hi0, a_hi1, bb_hi0, bb_hi1);
    // z1m = (a_lo + a_hi) · (b_lo + b_hi)
    let (z1m_2, z1m_1, z1m_0) = mul2(&b_, s_a0, s_a1, s_b0, s_b1);

    // middle(x) = z1m(x) - z2(x) - z0(x)  (in char 2, "minus" = XOR)
    // Then unreduced product p(x) = z2(x)·x^4 + middle(x)·x^2 + z0(x).
    //
    // Coefficients of p (low to high):
    //   p0 = z0_0
    //   p1 = z0_1
    //   p2 = z0_2 ⊕ middle_0 = z0_2 ⊕ z1m_0 ⊕ z2_0 ⊕ z0_0
    //   p3 = middle_1        =          z1m_1 ⊕ z2_1 ⊕ z0_1
    //   p4 = middle_2 ⊕ z2_0 =          z1m_2 ⊕ z2_2 ⊕ z0_2 ⊕ z2_0
    //   p5 = z2_1
    //   p6 = z2_2
    let p0 = z0_0;
    let p1 = z0_1;
    let p2 = b_.bxor_multi(&[z0_2, z1m_0, z2_0, z0_0]);
    let p3 = b_.bxor_multi(&[z1m_1, z2_1, z0_1]);
    let p4 = b_.bxor_multi(&[z1m_2, z2_2, z0_2, z2_0]);
    let p5 = z2_1;
    let p6 = z2_2;

    //   r0 = p0 ⊕ p4
    //   r1 = p1 ⊕ p4 ⊕ p5
    //   r2 = p2 ⊕ p5 ⊕ p6
    //   r3 = p3 ⊕ p6
    let r0 = b_.bxor(p0, p4);
    let r1 = b_.bxor_multi(&[p1, p4, p5]);
    let r2 = b_.bxor_multi(&[p2, p5, p6]);
    let r3 = b_.bxor(p3, p6);

    BitslicedGf16Mvec {
        bits: [r0, r1, r2, r3],
    }
}

/// Broadcast a 4-bit scalar (in the low 4 bits of `nibble_word`, upper bits
/// ignored) into a bitsliced m-vec where every one of the 64 lanes equals
/// that scalar.
///
/// Cost: **8 AND constraints** total. For each of 4 nibble bits we emit one
/// `band(_, 1)` to mask the bit and a `(shl, sar)` splat pair; the shifts
/// are linear gates that the fusion pass materialises as one additional AND
/// each when they cannot fuse with neighbours, giving the empirical 8.
pub(crate) fn broadcast_scalar(builder: &CircuitBuilder, nibble_word: Wire) -> BitslicedGf16Mvec {
    let b = builder.subcircuit("gf16/broadcast_scalar");
    let one = b.add_constant(Word(1));

    let bits = core::array::from_fn(|bit_idx| {
        // Step 1: extract bit `bit_idx` of the scalar into bit position 0.
        //   masked = (nibble_word >> bit_idx) & 1
        // The shift fuses with the band, so this costs 1 AND.
        let shifted = if bit_idx == 0 {
            nibble_word
        } else {
            b.shr(nibble_word, bit_idx as u32)
        };
        let bit0 = b.band(shifted, one);

        // Step 2: broadcast that single bit (bit position 0) to all 64 bits.
        // Trick: shift the bit up to position 63, then arithmetic-right-shift
        // by 63 to splat the sign bit. `sar` produces all-1s if the input MSB
        // is 1, all-0s otherwise.
        let at_msb = b.shl(bit0, 63);
        b.sar(at_msb, 63)
    });

    BitslicedGf16Mvec { bits }
}

/// `acc ^= scalar * vec`, where `scalar` is already broadcast as a bitsliced m-vec.
///
/// This is the bilinear-form hot loop's accumulator step. Equivalent to:
/// `acc = acc.add(builder, &mul_karatsuba(builder, scalar, vec))`.
pub(crate) fn mul_into_acc(
    builder: &CircuitBuilder,
    scalar: &BitslicedGf16Mvec,
    vec: &BitslicedGf16Mvec,
    acc: &mut BitslicedGf16Mvec,
) {
    let prod = mul_karatsuba(builder, scalar, vec);
    *acc = acc.add(builder, &prod);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gf16::scalar;
    use binius_core::verify::verify_constraints;
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    /// 100 random 64-lane pairs: in-circuit Karatsuba == lanewise scalar mul.
    #[test]
    fn given_random_lane_pairs_when_mul_karatsuba_then_matches_scalar_oracle() {
        let mut rng = StdRng::seed_from_u64(0xF00D);
        let builder = CircuitBuilder::new();
        let a = BitslicedGf16Mvec::new_witness(&builder);
        let b = BitslicedGf16Mvec::new_witness(&builder);
        let c = mul_karatsuba(&builder, &a, &b);
        let expected = BitslicedGf16Mvec::new_witness(&builder);
        c.assert_eq(&builder, &expected);
        let circuit = builder.build();

        for _ in 0..100 {
            let mut w = circuit.new_witness_filler();
            let mut a_lanes = [0u8; 64];
            let mut b_lanes = [0u8; 64];
            for i in 0..64 {
                a_lanes[i] = rng.random_range(0..16);
                b_lanes[i] = rng.random_range(0..16);
            }
            let c_lanes: [u8; 64] = core::array::from_fn(|i| scalar::mul(a_lanes[i], b_lanes[i]));
            a.populate(&mut w, &a_lanes);
            b.populate(&mut w, &b_lanes);
            expected.populate(&mut w, &c_lanes);
            circuit.populate_wire_witness(&mut w).unwrap();
            verify_constraints(circuit.constraint_system(), &w.into_value_vec()).unwrap();
        }
    }

    /// 50 random scalars: broadcast, then read back 64 lanes; all must equal scalar.
    #[test]
    fn given_random_scalars_when_broadcast_then_all_lanes_equal_scalar() {
        let mut rng = StdRng::seed_from_u64(0xC0DE);
        let builder = CircuitBuilder::new();
        let scalar_w = builder.add_witness();
        let bvec = broadcast_scalar(&builder, scalar_w);
        let circuit = builder.build();

        for _ in 0..50 {
            let s: u8 = rng.random_range(0..16);
            let mut w = circuit.new_witness_filler();
            w[scalar_w] = Word(s as u64);
            circuit.populate_wire_witness(&mut w).unwrap();
            let lanes = bvec.read(&w);
            for (i, v) in lanes.iter().enumerate() {
                assert_eq!(*v, s, "lane {i} = {v} != broadcast scalar {s}");
            }
            verify_constraints(circuit.constraint_system(), &w.into_value_vec()).unwrap();
        }
    }

    /// `mul_into_acc` must equal `acc + scalar * vec` lanewise.
    #[test]
    fn given_random_inputs_when_mul_into_acc_then_matches_scalar_oracle() {
        let mut rng = StdRng::seed_from_u64(0xACAC);
        let builder = CircuitBuilder::new();
        let s = BitslicedGf16Mvec::new_witness(&builder);
        let v = BitslicedGf16Mvec::new_witness(&builder);
        let mut acc = BitslicedGf16Mvec::new_witness(&builder);
        let acc_in = acc; // copy of starting wires
        mul_into_acc(&builder, &s, &v, &mut acc);
        let expected = BitslicedGf16Mvec::new_witness(&builder);
        acc.assert_eq(&builder, &expected);
        let circuit = builder.build();

        for _ in 0..20 {
            let mut w = circuit.new_witness_filler();
            let s_lanes: [u8; 64] = core::array::from_fn(|_| rng.random_range(0..16));
            let v_lanes: [u8; 64] = core::array::from_fn(|_| rng.random_range(0..16));
            let acc_lanes: [u8; 64] = core::array::from_fn(|_| rng.random_range(0..16));
            let exp_lanes: [u8; 64] = core::array::from_fn(|i| {
                scalar::add(acc_lanes[i], scalar::mul(s_lanes[i], v_lanes[i]))
            });
            s.populate(&mut w, &s_lanes);
            v.populate(&mut w, &v_lanes);
            acc_in.populate(&mut w, &acc_lanes);
            expected.populate(&mut w, &exp_lanes);
            circuit.populate_wire_witness(&mut w).unwrap();
            verify_constraints(circuit.constraint_system(), &w.into_value_vec()).unwrap();
        }
    }

    /// Constraint-count gate: building a circuit with a single `mul_karatsuba`
    /// and nothing else (no assertions, no inputs we can prune) must yield
    /// at most 12 AND constraints (target 9).
    #[test]
    fn given_single_mul_karatsuba_when_built_then_at_most_12_and_constraints() {
        let builder = CircuitBuilder::new();
        let a = BitslicedGf16Mvec::new_witness(&builder);
        let b = BitslicedGf16Mvec::new_witness(&builder);
        let c = mul_karatsuba(&builder, &a, &b);
        // Pin the output by treating it as inout so the optimizer can't prune the gate.
        let out = BitslicedGf16Mvec::new_inout(&builder);
        for i in 0..4 {
            // Use bxor (linear) to keep `c` live without paying for `assert_eq`'s ANDs.
            // assert_eq itself is 1 AND per plane; we'd rather count just the kernel.
            // So we drive `out` via XOR with a constant zero; this still pins `c`.
            let zero = builder.add_constant(Word::ZERO);
            let pin = builder.bxor(c.bits[i], zero);
            builder.assert_eq("pin", pin, out.bits[i]);
        }
        let circuit = builder.build();
        let cs = circuit.constraint_system();
        let n = cs.n_and_constraints();
        eprintln!("mul_karatsuba AND constraint count (with 4 pin asserts) = {n}");
        // Each `assert_eq` adds 1 AND. We add 4 of them. Strip them from the budget.
        let kernel_ands = n.saturating_sub(4);
        eprintln!("mul_karatsuba kernel AND count = {kernel_ands}");
        assert!(
            kernel_ands <= 12,
            "mul_karatsuba should use <=12 ANDs (target 9), got {kernel_ands}"
        );
    }
}

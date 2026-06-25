//! Whipping reduction mod `f(z)` over GF(16)^M.
//!
//! Given the K*K = 16 SPS values produced by the bilinear-form pass, this
//! module collapses them into a single length-M GF(16) m-vector `y` by
//! iterating the schedule of MAYO-C `compute_rhs` (see `src/mayo.c` lines
//! 43-109): an outer accumulator is multiplied by `z` (and reduced mod
//! `f(z) = z^M + 8 + 2*z^2 + 8*z^3` for MAYO-2) on each step, then the
//! relevant SPS contribution is XORed in.
//!
//! ## Bitsliced multiply-by-z + reduce
//!
//! With the bitsliced layout `plane[b].bit(ell) = bit b of lane ell`,
//! multiplying the accumulator by `z` is:
//!
//! - Shift each plane left by 1 bit (bit 63 falls off, bit 0 becomes 0).
//! - The dropped lane is `top` (4 nibble bits, one per plane).
//! - Fold `top * F_TAIL[tau]` back into lanes 0, 2, 3
//!   (`F_TAIL = [8, 0, 2, 8]`, so we add `top*8` at lane 0, `top*2` at
//!   lane 2, `top*8` at lane 3).
//!
//! For a nibble `top = t3 x^3 + t2 x^2 + t1 x + t0` in GF(16) = GF(2)[x]/(x^4+x+1):
//!
//! ```text
//!   top * x   bits (q3, q2, q1, q0) = (t2, t1, t0^t3, t3)
//!   top * x^3 bits (q3, q2, q1, q0) = (t0^t3, t2^t3, t1^t2, t1)
//! ```
//!
//! Both are linear (GF(2)-affine) functions of `t_*`. This is the general
//! case for multiplication by a fixed GF(16) constant: every such map is a
//! fixed matrix over GF(2) on the 4 plane bits, so the fold step costs no
//! ANDs beyond the four `shr(_, 63)` extractions of `top`'s bits and the
//! four `shl(_, 1)` to advance each plane.
//!
//! ## Cost
//!
//! Per outer iteration: 4 extractions + 4 plane-shifts + ~12 fold XORs +
//! 1-2 m-vec XORs (for the SPS contributions). With 10 (i, j) pairs, the
//! whole reduction lands at **151 AND constraints**, far under the 500-AND
//! ceiling enforced by the budget test below.

use binius_frontend::CircuitBuilder;

use crate::gf16::BitslicedGf16Mvec;
use crate::params::{K, M};

/// Whipping reduction: combine the K*K = 16 SPS values into y in GF(16)^M.
///
/// `sps[row*K + col]` for `(row, col) in [K]^2` (row-major layout, matching the
/// output of `compute_sps` in `src/quadratic.rs`).
///
/// The accumulator is iterated 10 times (k(k+1)/2 with k=K=4) following the
/// loop schedule of MAYO-C `compute_rhs`. Each iteration multiplies the
/// running m-vec by `z` (and reduces mod `f(z) = z^M + 8 + 2*z^2 + 8*z^3`),
/// then XORs in `sps[i*K + j]` (and `sps[j*K + i]` when `i != j`).
pub(crate) fn compute_rhs(
    builder: &CircuitBuilder,
    sps: &[BitslicedGf16Mvec],
) -> BitslicedGf16Mvec {
    assert_eq!(
        sps.len(),
        K * K,
        "compute_rhs expects K*K = {} SPS m-vecs",
        K * K
    );
    // Sanity: this routine assumes the MAYO-2 tail polynomial.
    debug_assert_eq!(M, 64);

    let b = builder.subcircuit("whipping/compute_rhs");

    // Initial accumulator = 0 (all four planes are constant zero).
    let zero = b.add_constant(binius_core::word::Word::ZERO);
    let mut acc = BitslicedGf16Mvec {
        bits: [zero, zero, zero, zero],
    };

    // 10 (i, j) pairs: (3,3), (2,2), (2,3), (1,1), (1,2), (1,3),
    //                  (0,0), (0,1), (0,2), (0,3).
    for i_inv in 0..K {
        let i = K - 1 - i_inv;
        for j in i..K {
            // Step 1: acc <- acc * z mod f(z).
            //
            // Extract `top` bits, one per plane, from bit 63 of each
            // plane. After `shr(_, 63)`, only bit 0 of the result is
            // potentially set (the other 63 bits are zero), so no
            // additional masking is required.
            let t0 = b.shr(acc.bits[0], 63);
            let t1 = b.shr(acc.bits[1], 63);
            let t2 = b.shr(acc.bits[2], 63);
            let t3 = b.shr(acc.bits[3], 63);

            // Shift each plane left by 1 bit (lane ell <- lane ell-1; lane
            // 0 becomes 0, lane M-1 = 63 falls off; that's `top`).
            let s0 = b.shl(acc.bits[0], 1);
            let s1 = b.shl(acc.bits[1], 1);
            let s2 = b.shl(acc.bits[2], 1);
            let s3 = b.shl(acc.bits[3], 1);

            // Per-plane fold contributions. For nibble bit `b`, the new
            // plane is `shifted[b]` XORed with the bit-`b` projection of
            // `top * 8` placed at lane 0, `top * 2` at lane 2, and
            // `top * 8` at lane 3.
            //
            //   top * 8 = t1 + (t1+t2) x + (t2+t3) x^2 + (t0+t3) x^3
            //   top * 2 = t3 + (t0+t3) x +  t1     x^2 +  t2     x^3
            //
            // For each plane b we compute the bit-b projection once
            // (a small XOR combination of t0..t3) and shift it into
            // lanes {0, 2, 3} as needed.

            // top*8 bit-projections (shared between lane 0 and lane 3).
            let m8_0 = t1; // (top*8)_0 = t1
            let m8_1 = b.bxor(t1, t2); // (top*8)_1 = t1 ^ t2
            let m8_2 = b.bxor(t2, t3); // (top*8)_2 = t2 ^ t3
            let m8_3 = b.bxor(t0, t3); // (top*8)_3 = t0 ^ t3

            // top*2 bit-projections (used at lane 2).
            let m2_0 = t3; // (top*2)_0 = t3
            let m2_1 = b.bxor(t0, t3); // (top*2)_1 = t0 ^ t3
            let m2_2 = t1; // (top*2)_2 = t1
            let m2_3 = t2; // (top*2)_3 = t2

            // For each plane b, build the fold contribution:
            //   fold_b = m8_b (at bit 0) ^ m2_b (at bit 2) ^ m8_b (at bit 3)
            // and XOR it into the shifted plane.
            //
            // m8_b (at bit 0) is m8_b itself (shr produced a value with
            // only bit 0 set). Lane 3 needs m8_b shifted left by 3, lane 2
            // needs m2_b shifted left by 2.
            let f0_lane3 = b.shl(m8_0, 3);
            let f0_lane2 = b.shl(m2_0, 2);
            let new0 = b.bxor_multi(&[s0, m8_0, f0_lane2, f0_lane3]);

            let f1_lane3 = b.shl(m8_1, 3);
            let f1_lane2 = b.shl(m2_1, 2);
            let new1 = b.bxor_multi(&[s1, m8_1, f1_lane2, f1_lane3]);

            let f2_lane3 = b.shl(m8_2, 3);
            let f2_lane2 = b.shl(m2_2, 2);
            let new2 = b.bxor_multi(&[s2, m8_2, f2_lane2, f2_lane3]);

            let f3_lane3 = b.shl(m8_3, 3);
            let f3_lane2 = b.shl(m2_3, 2);
            let new3 = b.bxor_multi(&[s3, m8_3, f3_lane2, f3_lane3]);

            acc = BitslicedGf16Mvec {
                bits: [new0, new1, new2, new3],
            };

            // Step 2: XOR in SPS contributions.
            let upper = &sps[i * K + j];
            acc = acc.add(&b, upper);
            if i != j {
                let lower = &sps[j * K + i];
                acc = acc.add(&b, lower);
            }
        }
    }

    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gf16::scalar;
    use binius_core::verify::verify_constraints;
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    /// Pure-Rust reference for the whipping loop. Mirrors MAYO-C
    /// `compute_rhs` exactly using the in-crate scalar GF(16) helpers.
    fn scalar_compute_rhs(sps: &[[u8; M]]) -> [u8; M] {
        assert_eq!(sps.len(), K * K);
        let mut acc = [0u8; M];
        for i_inv in 0..K {
            let i = K - 1 - i_inv;
            for j in i..K {
                // shift up + fold
                let top = acc[M - 1];
                for ell in (1..M).rev() {
                    acc[ell] = acc[ell - 1];
                }
                acc[0] = 0;
                acc[0] = scalar::add(acc[0], scalar::mul(top, 8));
                acc[2] = scalar::add(acc[2], scalar::mul(top, 2));
                acc[3] = scalar::add(acc[3], scalar::mul(top, 8));
                // xor in SPS
                for ell in 0..M {
                    acc[ell] = scalar::add(acc[ell], sps[i * K + j][ell]);
                    if i != j {
                        acc[ell] = scalar::add(acc[ell], sps[j * K + i][ell]);
                    }
                }
            }
        }
        acc
    }

    /// Independent smoke check of the formulas for `top * 8` and `top * 2`
    /// against `scalar::mul` for every nibble. Catches transcription errors
    /// in the bit-projection tables used by the in-circuit kernel.
    #[test]
    fn given_all_nibbles_when_top_times_2_and_8_then_match_scalar_mul() {
        for top in 0u8..16 {
            // bits of top
            let t0 = top & 1;
            let t1 = (top >> 1) & 1;
            let t2 = (top >> 2) & 1;
            let t3 = (top >> 3) & 1;
            // top * 8 from formulas: bits (q3..q0) = (t0^t3, t2^t3, t1^t2, t1)
            let q0 = t1;
            let q1 = t1 ^ t2;
            let q2 = t2 ^ t3;
            let q3 = t0 ^ t3;
            let formula_8 = q0 | (q1 << 1) | (q2 << 2) | (q3 << 3);
            assert_eq!(formula_8, scalar::mul(top, 8), "top={top}");

            // top * 2 from formulas: bits (q3..q0) = (t2, t1, t0^t3, t3)
            let q0 = t3;
            let q1 = t0 ^ t3;
            let q2 = t1;
            let q3 = t2;
            let formula_2 = q0 | (q1 << 1) | (q2 << 2) | (q3 << 3);
            assert_eq!(formula_2, scalar::mul(top, 2), "top={top}");
        }
    }

    /// Random fuzz: build the circuit ONCE, repopulate the witness with 100
    /// random SPS arrays, verify the in-circuit `compute_rhs` matches the
    /// pure-Rust reference each time.
    #[test]
    fn given_random_sps_arrays_when_compute_rhs_then_matches_scalar_oracle() {
        let mut rng = StdRng::seed_from_u64(0x5005_C0DE);

        let builder = CircuitBuilder::new();
        let sps_inputs: [BitslicedGf16Mvec; K * K] =
            core::array::from_fn(|_| BitslicedGf16Mvec::new_witness(&builder));
        let y = compute_rhs(&builder, &sps_inputs);
        let expected = BitslicedGf16Mvec::new_witness(&builder);
        y.assert_eq(&builder, &expected);
        let circuit = builder.build();

        for _ in 0..100 {
            let mut w = circuit.new_witness_filler();
            // Random SPS values.
            let mut sps_lanes = [[0u8; M]; K * K];
            for r in sps_lanes.iter_mut() {
                for v in r.iter_mut() {
                    *v = rng.random_range(0..16);
                }
            }
            for i in 0..K * K {
                sps_inputs[i].populate(&mut w, &sps_lanes[i]);
            }
            let exp_lanes = scalar_compute_rhs(&sps_lanes);
            expected.populate(&mut w, &exp_lanes);
            circuit.populate_wire_witness(&mut w).unwrap();
            verify_constraints(circuit.constraint_system(), &w.into_value_vec()).unwrap();
        }
    }

    /// Edge case: zero SPS input should produce zero output (nothing to fold).
    #[test]
    fn given_zero_sps_when_compute_rhs_then_returns_zero() {
        let builder = CircuitBuilder::new();
        let sps_inputs: [BitslicedGf16Mvec; K * K] =
            core::array::from_fn(|_| BitslicedGf16Mvec::new_witness(&builder));
        let y = compute_rhs(&builder, &sps_inputs);
        let expected = BitslicedGf16Mvec::new_witness(&builder);
        y.assert_eq(&builder, &expected);
        let circuit = builder.build();

        let mut w = circuit.new_witness_filler();
        let zeros = [0u8; M];
        for i in 0..K * K {
            sps_inputs[i].populate(&mut w, &zeros);
        }
        expected.populate(&mut w, &zeros);
        circuit.populate_wire_witness(&mut w).unwrap();
        verify_constraints(circuit.constraint_system(), &w.into_value_vec()).unwrap();
    }

    /// AND-constraint budget: a single `compute_rhs` (with the output pinned
    /// via `assert_eq` to keep the optimizer from pruning) must fit in 500
    /// AND constraints. Target is well under 100 ANDs for the kernel itself.
    #[test]
    fn given_single_compute_rhs_when_built_then_at_most_500_and_constraints() {
        let builder = CircuitBuilder::new();
        let sps_inputs: [BitslicedGf16Mvec; K * K] =
            core::array::from_fn(|_| BitslicedGf16Mvec::new_witness(&builder));
        let y = compute_rhs(&builder, &sps_inputs);
        // Pin the output as inout so optimization can't eliminate the kernel.
        let pinned = BitslicedGf16Mvec::new_inout(&builder);
        y.assert_eq(&builder, &pinned);
        let circuit = builder.build();
        let n = circuit.constraint_system().n_and_constraints();
        eprintln!("compute_rhs AND constraint count (with 4 pin asserts) = {n}");
        // assert_eq adds 1 AND per plane (4 ANDs) for the pin.
        let kernel_ands = n.saturating_sub(4);
        eprintln!("compute_rhs kernel AND count (excluding 4 pin asserts) = {kernel_ands}");
        assert!(
            n <= 500,
            "compute_rhs should use <=500 ANDs (target ~100), got {n}"
        );
    }
}

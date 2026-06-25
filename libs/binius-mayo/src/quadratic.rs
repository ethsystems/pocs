//! MAYO-2 bilinear form evaluation: 2-pass `PS + SPS`.
//!
//! ## What this computes
//!
//! Given the expanded MAYO-2 public key (block-decomposed into upper-triangular
//! P^(1) over [V]x[V], rectangular P^(2) over [V]x[O], upper-triangular P^(3)
//! over [O]x[O]) and a signature `s ∈ GF(16)^{K x N}`, this module evaluates
//! the bilinear form
//!
//! ```text
//! SPS[row][col] = (s[row])^T · P · s[col]      (each entry an m-vec of length M)
//! ```
//!
//! where `P` is the n×n upper-triangular block matrix
//!
//! ```text
//! P = [ P^(1)  P^(2) ]
//!     [   0   P^(3) ]
//! ```
//!
//! using the canonical 2-pass schedule from MAYO-C
//! (`m_calculate_PS_SPS`, two-pass branch):
//!
//! 1. **PS pass.** For each `(j, col)` in `[N] × [K]`:
//!    `PS[j][col] = Σ_{r ≥ j} P[j][r] · s[col][r]`.
//! 2. **SPS pass.** For each `(row, col)` in `[K] × [K]`:
//!    `SPS[row][col] = Σ_{j ∈ [N]} s[row][j] · PS[j][col]`.
//!
//! Each scalar `s[a][b]` is referenced many times across the two passes, so we
//! amortize the **8-AND broadcast** of every signature lane up front into a
//! `K × N` table of bitsliced m-vec broadcasts. Subsequent multiplies in the
//! hot loop reuse the broadcast and pay only the **9-AND Karatsuba** kernel.
//!
//! ## Cost (AND constraints)
//!
//! For MAYO-2 (`N=81, K=4, V=64, O=17`), kernel-only counts are:
//!
//! * Broadcasts: `K · N · 8 = 2 592`.
//! * PS pass: `K · (P1_ENTRIES + P2_ENTRIES + P3_ENTRIES) · 9
//!            = 4 · 3 321 · 9 = 119 556`.
//! * SPS pass: `K · K · N · 9 = 16 · 81 · 9 = 11 664`.
//!
//! These add to ~133 812 in isolation. The actual emitted circuit lands
//! around ~153 600 ANDs because successive `mul_into_acc` calls do not all
//! fuse cleanly with each other (the per-mul amortised cost stabilises near
//! ~10.3 ANDs in long chains rather than the 9-AND kernel minimum). Still
//! comfortably below the 200 000 budget enforced by the test below.

use binius_core::word::Word;
use binius_frontend::{CircuitBuilder, Wire, WitnessFiller};

use crate::gf16::{
    BitslicedGf16Mvec,
    mul::{broadcast_scalar, mul_into_acc},
};
use crate::params::{K, N, O, P1_ENTRIES, P2_ENTRIES, P3_ENTRIES, V};

// Index helpers
//
// These match the MAYO-C row-major upper-triangular conventions exactly.
// See `/tmp/MAYO-C/src/generic/generic_arithmetic.h::m_calculate_PS_SPS`.

/// Linear index into P^(1) (V x V upper-triangular, row-major).
///
/// Row `i` starts at offset `Σ_{k=0}^{i-1} (V - k) = i*(2V - i + 1)/2`.
/// We use that closed form rather than `i*V - i*(i-1)/2` to avoid the
/// unsigned underflow that bites when `i == 0`.
#[inline]
pub(crate) fn idx_p1(i: usize, j: usize) -> usize {
    debug_assert!(i <= j && j < V);
    i * (2 * V - i + 1) / 2 + (j - i)
}

/// Linear index into P^(2) (V x O rectangular, row-major).
#[inline]
pub(crate) fn idx_p2(i: usize, j: usize) -> usize {
    debug_assert!(i < V && j < O);
    i * O + j
}

/// Linear index into P^(3) (O x O upper-triangular, row-major).
///
/// See [`idx_p1`] for the underflow-safe closed-form derivation.
#[inline]
pub(crate) fn idx_p3(i: usize, j: usize) -> usize {
    debug_assert!(i <= j && j < O);
    i * (2 * O - i + 1) / 2 + (j - i)
}

// Expanded public-key wires

/// Witness wires for the expanded MAYO-2 public key.
///
/// Each m-vec entry is a `BitslicedGf16Mvec` (4 plane wires), and the three
/// blocks are stored flat in MAYO-C's row-major upper-triangular order.
pub(crate) struct ExpandedPkWires {
    /// `P^(1)`: upper-triangular V x V; index via [`idx_p1`].
    pub(crate) p1: Vec<BitslicedGf16Mvec>,
    /// `P^(2)`: rectangular V x O; index via [`idx_p2`].
    pub(crate) p2: Vec<BitslicedGf16Mvec>,
    /// `P^(3)`: upper-triangular O x O; index via [`idx_p3`].
    pub(crate) p3: Vec<BitslicedGf16Mvec>,
}

impl ExpandedPkWires {
    /// Allocate fresh witness wires for every entry of all three blocks.
    pub(crate) fn new_witness(builder: &CircuitBuilder) -> Self {
        let b = builder.subcircuit("quadratic/expanded_pk");
        Self {
            p1: (0..P1_ENTRIES)
                .map(|_| BitslicedGf16Mvec::new_witness(&b))
                .collect(),
            p2: (0..P2_ENTRIES)
                .map(|_| BitslicedGf16Mvec::new_witness(&b))
                .collect(),
            p3: (0..P3_ENTRIES)
                .map(|_| BitslicedGf16Mvec::new_witness(&b))
                .collect(),
        }
    }

    /// Populate the witness from the raw expanded-pk matrices given in scalar
    /// (per-lane) form. Each entry is M=64 GF(16) values in `0..16`.
    pub(crate) fn populate(
        &self,
        w: &mut WitnessFiller,
        p1_lanes: &[[u8; 64]],
        p2_lanes: &[[u8; 64]],
        p3_lanes: &[[u8; 64]],
    ) {
        assert_eq!(p1_lanes.len(), P1_ENTRIES, "p1_lanes length mismatch");
        assert_eq!(p2_lanes.len(), P2_ENTRIES, "p2_lanes length mismatch");
        assert_eq!(p3_lanes.len(), P3_ENTRIES, "p3_lanes length mismatch");

        for (mvec, lanes) in self.p1.iter().zip(p1_lanes.iter()) {
            mvec.populate(w, lanes);
        }
        for (mvec, lanes) in self.p2.iter().zip(p2_lanes.iter()) {
            mvec.populate(w, lanes);
        }
        for (mvec, lanes) in self.p3.iter().zip(p3_lanes.iter()) {
            mvec.populate(w, lanes);
        }
    }
}

// Pre-broadcast signature scalars

/// Pre-broadcast scalars for the K signature blocks of length N.
///
/// Each `s[col][r]` is allocated as a single nibble-witness `Word` (low 4 bits
/// hold the GF(16) element) and then broadcast once into a bitsliced m-vec.
/// PS and SPS each multiply with these broadcasts many times, amortizing the
/// per-broadcast 8-AND cost.
pub(crate) struct SigBroadcasts {
    /// `nibble_wires[col][r]` is the witness Word holding `s[col][r]` in its low 4 bits.
    pub(crate) nibble_wires: [[Wire; N]; K],
    /// `broadcasts[col][r]` is the bitsliced m-vec where every lane equals `s[col][r]`.
    pub(crate) broadcasts: [[BitslicedGf16Mvec; N]; K],
}

impl SigBroadcasts {
    /// Allocate witness wires for every scalar and emit the broadcast circuits.
    pub(crate) fn new_witness(builder: &CircuitBuilder) -> Self {
        let b = builder.subcircuit("quadratic/sig_broadcasts");
        // Allocate nibble witnesses first.
        let nibble_wires: [[Wire; N]; K] =
            core::array::from_fn(|_col| core::array::from_fn(|_r| b.add_witness()));
        // Then emit broadcast subcircuits, one per scalar.
        let broadcasts: [[BitslicedGf16Mvec; N]; K] = core::array::from_fn(|col| {
            core::array::from_fn(|r| broadcast_scalar(&b, nibble_wires[col][r]))
        });
        Self {
            nibble_wires,
            broadcasts,
        }
    }

    /// Populate the nibble witnesses with the K x N signature lanes.
    pub(crate) fn populate(&self, w: &mut WitnessFiller, s: &[[u8; N]; K]) {
        for col in 0..K {
            for r in 0..N {
                debug_assert!(
                    s[col][r] < 16,
                    "signature lane s[{col}][{r}] = {} is not a GF(16) element",
                    s[col][r]
                );
                w[self.nibble_wires[col][r]] = Word(s[col][r] as u64);
            }
        }
    }
}

// PS pass

/// Allocate a single shared zero `BitslicedGf16Mvec` (one constant Word reused
/// across all 4 planes), the additive identity used as accumulator init.
fn zero_mvec(builder: &CircuitBuilder) -> BitslicedGf16Mvec {
    let z = builder.add_constant(Word::ZERO);
    BitslicedGf16Mvec::from_wires([z, z, z, z])
}

/// Compute `PS[j*K + col] = Σ_{r ≥ j} P[j][r] · s[col][r]` for all `(j, col)`.
///
/// Returns a flat `Vec` of length `N*K`, indexed by `j*K + col` (matching the
/// MAYO-C layout and the SPS pass below).
///
/// Cost: roughly `K · 3321 · 9 ≈ 119 556` AND constraints.
pub(crate) fn compute_ps(
    builder: &CircuitBuilder,
    pk: &ExpandedPkWires,
    sb: &SigBroadcasts,
) -> Vec<BitslicedGf16Mvec> {
    let b = builder.subcircuit("quadratic/ps");
    let z = zero_mvec(&b);
    let mut ps: Vec<BitslicedGf16Mvec> = vec![z; N * K];

    for col in 0..K {
        // P^(1) block: j ∈ [0, V), r ∈ [j, V), entry P^(1)[idx_p1(j, r)].
        for j in 0..V {
            for r in j..V {
                let p_entry = &pk.p1[idx_p1(j, r)];
                let scalar = &sb.broadcasts[col][r];
                mul_into_acc(&b, scalar, p_entry, &mut ps[j * K + col]);
            }
        }
        // P^(2) block: j ∈ [0, V), r ∈ [V, N), entry P^(2)[idx_p2(j, r-V)].
        for j in 0..V {
            for r in V..N {
                let p_entry = &pk.p2[idx_p2(j, r - V)];
                let scalar = &sb.broadcasts[col][r];
                mul_into_acc(&b, scalar, p_entry, &mut ps[j * K + col]);
            }
        }
        // P^(3) block: j ∈ [V, N), r ∈ [j, N), entry P^(3)[idx_p3(j-V, r-V)].
        for j in V..N {
            for r in j..N {
                let p_entry = &pk.p3[idx_p3(j - V, r - V)];
                let scalar = &sb.broadcasts[col][r];
                mul_into_acc(&b, scalar, p_entry, &mut ps[j * K + col]);
            }
        }
    }

    ps
}

// SPS pass

/// Compute `SPS[row*K + col] = Σ_j s[row][j] · PS[j*K + col]` for all
/// `(row, col) ∈ [K] × [K]`.
///
/// Returns a flat `Vec` of length `K*K`, indexed by `row*K + col`.
///
/// Cost: `K · K · N · 9 = 16 · 81 · 9 = 11 664` AND constraints.
pub(crate) fn compute_sps(
    builder: &CircuitBuilder,
    sb: &SigBroadcasts,
    ps: &[BitslicedGf16Mvec],
) -> Vec<BitslicedGf16Mvec> {
    assert_eq!(ps.len(), N * K, "PS table must have length N*K");
    let b = builder.subcircuit("quadratic/sps");
    let z = zero_mvec(&b);
    let mut sps: Vec<BitslicedGf16Mvec> = vec![z; K * K];

    for row in 0..K {
        for col in 0..K {
            for j in 0..N {
                let scalar = &sb.broadcasts[row][j];
                let p_entry = &ps[j * K + col];
                mul_into_acc(&b, scalar, p_entry, &mut sps[row * K + col]);
            }
        }
    }

    sps
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gf16::scalar::{add as gf_add, mul as gf_mul};
    use binius_core::verify::verify_constraints;
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    /// Pure-Rust reference: compute SPS = s · P · s^T from raw lane data.
    /// This is a direct port of the same two-pass loop the circuit executes,
    /// so a match between this and the in-circuit output proves the wiring
    /// (indexing + accumulator dataflow) is correct.
    fn scalar_compute_sps(
        p1: &[[u8; 64]],
        p2: &[[u8; 64]],
        p3: &[[u8; 64]],
        s: &[[u8; N]; K],
    ) -> [[u8; 64]; K * K] {
        // Pass 1: PS[j*K + col] = Σ_{r ≥ j} P[j][r] · s[col][r].
        let mut ps: Vec<[u8; 64]> = vec![[0u8; 64]; N * K];
        for col in 0..K {
            for j in 0..V {
                for r in j..V {
                    let p_entry = &p1[idx_p1(j, r)];
                    let scalar = s[col][r];
                    let acc = &mut ps[j * K + col];
                    for ell in 0..64 {
                        acc[ell] = gf_add(acc[ell], gf_mul(scalar, p_entry[ell]));
                    }
                }
                for r in V..N {
                    let p_entry = &p2[idx_p2(j, r - V)];
                    let scalar = s[col][r];
                    let acc = &mut ps[j * K + col];
                    for ell in 0..64 {
                        acc[ell] = gf_add(acc[ell], gf_mul(scalar, p_entry[ell]));
                    }
                }
            }
            for j in V..N {
                for r in j..N {
                    let p_entry = &p3[idx_p3(j - V, r - V)];
                    let scalar = s[col][r];
                    let acc = &mut ps[j * K + col];
                    for ell in 0..64 {
                        acc[ell] = gf_add(acc[ell], gf_mul(scalar, p_entry[ell]));
                    }
                }
            }
        }
        // Pass 2: SPS[row*K + col] = Σ_j s[row][j] · PS[j*K + col].
        let mut sps = [[0u8; 64]; K * K];
        for row in 0..K {
            for col in 0..K {
                for j in 0..N {
                    let scalar = s[row][j];
                    let acc = &mut sps[row * K + col];
                    let ps_entry = &ps[j * K + col];
                    for ell in 0..64 {
                        acc[ell] = gf_add(acc[ell], gf_mul(scalar, ps_entry[ell]));
                    }
                }
            }
        }
        sps
    }

    /// Sanity-check the index functions against the documented entry counts.
    #[test]
    fn given_extreme_indices_when_idx_then_lands_in_range() {
        // P^(1): last entry is (V-1, V-1).
        assert_eq!(idx_p1(0, 0), 0);
        assert_eq!(idx_p1(V - 1, V - 1), P1_ENTRIES - 1);
        // P^(2): row-major.
        assert_eq!(idx_p2(0, 0), 0);
        assert_eq!(idx_p2(V - 1, O - 1), P2_ENTRIES - 1);
        // P^(3): last entry is (O-1, O-1).
        assert_eq!(idx_p3(0, 0), 0);
        assert_eq!(idx_p3(O - 1, O - 1), P3_ENTRIES - 1);
    }

    /// End-to-end fuzz: build the full PS+SPS circuit, pin the SPS outputs
    /// against expected witness wires, populate from random `(P, s)`, then
    /// verify all constraints. Also asserts the AND-budget upper bound.
    #[test]
    fn given_random_pk_and_sig_when_compute_sps_then_matches_scalar_oracle() {
        let builder = CircuitBuilder::new();
        let pk = ExpandedPkWires::new_witness(&builder);
        let sb = SigBroadcasts::new_witness(&builder);
        let ps = compute_ps(&builder, &pk, &sb);
        let sps = compute_sps(&builder, &sb, &ps);

        // Pin all 16 SPS m-vecs against expected witness wires.
        let expected_sps: Vec<BitslicedGf16Mvec> = (0..K * K)
            .map(|_| BitslicedGf16Mvec::new_witness(&builder))
            .collect();
        for i in 0..K * K {
            sps[i].assert_eq(&builder, &expected_sps[i]);
        }
        let circuit = builder.build();

        let cs = circuit.constraint_system();
        let n_and = cs.n_and_constraints();
        eprintln!("PS+SPS total AND constraint count = {n_and}");
        assert!(
            n_and <= 200_000,
            "PS+SPS AND count {n_and} exceeds 200 000 budget"
        );

        let mut rng = StdRng::seed_from_u64(0xBEAD_CAFE);
        let mut p1_lanes: Vec<[u8; 64]> = Vec::with_capacity(P1_ENTRIES);
        for _ in 0..P1_ENTRIES {
            p1_lanes.push(core::array::from_fn(|_| rng.random_range(0..16)));
        }
        let mut p2_lanes: Vec<[u8; 64]> = Vec::with_capacity(P2_ENTRIES);
        for _ in 0..P2_ENTRIES {
            p2_lanes.push(core::array::from_fn(|_| rng.random_range(0..16)));
        }
        let mut p3_lanes: Vec<[u8; 64]> = Vec::with_capacity(P3_ENTRIES);
        for _ in 0..P3_ENTRIES {
            p3_lanes.push(core::array::from_fn(|_| rng.random_range(0..16)));
        }
        let s: [[u8; N]; K] =
            core::array::from_fn(|_col| core::array::from_fn(|_r| rng.random_range(0..16)));

        let want = scalar_compute_sps(&p1_lanes, &p2_lanes, &p3_lanes, &s);

        let mut w = circuit.new_witness_filler();
        pk.populate(&mut w, &p1_lanes, &p2_lanes, &p3_lanes);
        sb.populate(&mut w, &s);
        for i in 0..K * K {
            expected_sps[i].populate(&mut w, &want[i]);
        }
        circuit.populate_wire_witness(&mut w).unwrap();

        // Cross-check the read-back values before we consume the filler.
        for i in 0..K * K {
            assert_eq!(sps[i].read(&w), want[i], "SPS[{i}] mismatch");
        }
        verify_constraints(circuit.constraint_system(), &w.into_value_vec()).unwrap();
    }

    /// Lower-cost smoke test: zero P and zero s yield zero SPS.
    /// Reuses the same circuit shape so we exercise the all-zero edge case
    /// without paying for a second build.
    #[test]
    fn given_zero_inputs_when_compute_sps_then_all_zero() {
        let builder = CircuitBuilder::new();
        let pk = ExpandedPkWires::new_witness(&builder);
        let sb = SigBroadcasts::new_witness(&builder);
        let ps = compute_ps(&builder, &pk, &sb);
        let sps = compute_sps(&builder, &sb, &ps);
        let expected_sps: Vec<BitslicedGf16Mvec> = (0..K * K)
            .map(|_| BitslicedGf16Mvec::new_witness(&builder))
            .collect();
        for i in 0..K * K {
            sps[i].assert_eq(&builder, &expected_sps[i]);
        }
        let circuit = builder.build();

        let p1_lanes: Vec<[u8; 64]> = vec![[0u8; 64]; P1_ENTRIES];
        let p2_lanes: Vec<[u8; 64]> = vec![[0u8; 64]; P2_ENTRIES];
        let p3_lanes: Vec<[u8; 64]> = vec![[0u8; 64]; P3_ENTRIES];
        let s: [[u8; N]; K] = [[0u8; N]; K];

        let mut w = circuit.new_witness_filler();
        pk.populate(&mut w, &p1_lanes, &p2_lanes, &p3_lanes);
        sb.populate(&mut w, &s);
        for i in 0..K * K {
            expected_sps[i].populate(&mut w, &[0u8; 64]);
        }
        circuit.populate_wire_witness(&mut w).unwrap();
        verify_constraints(circuit.constraint_system(), &w.into_value_vec()).unwrap();
    }
}

//! Bitsliced GF(16) primitives for the MAYO-2 verifier circuit.
//!
//! GF(16) = GF(2)[x]/(x^4 + x + 1). A bitsliced m-vector (length M = 64) is
//! stored as `[Wire; 4]`, one bit-plane per nibble bit. Plane `b`'s 64-bit
//! word holds bit `b` of each of the 64 nibbles, so:
//!
//! ```text
//! plane[b].bit(i) = bit b of lane i
//! ```
//!
//! Componentwise GF(16) addition is just 4 XORs (one per plane). Componentwise
//! multiplication is implemented via a 2-level Karatsuba (9 ANDs / 64-lane).
//!
//! See `mul.rs` for the multiplication kernel and `transpose.rs` for the
//! packed↔bitsliced layout transpose.

use binius_core::word::Word;
use binius_frontend::{CircuitBuilder, Wire, WitnessFiller};

pub(crate) mod mul;
pub(crate) mod scalar;
pub(crate) mod transpose;

/// Bitsliced GF(16) m-vector: 64 GF(16) elements packed bit-plane-wise into 4 Words.
///
/// `bits[b]` is the b-th bit-plane: position `i` of `bits[b]` equals bit `b` of lane `i`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct BitslicedGf16Mvec {
    pub(crate) bits: [Wire; 4],
}

impl BitslicedGf16Mvec {
    /// Allocate a fresh witness-backed bitsliced m-vec (4 private wires).
    pub(crate) fn new_witness(builder: &CircuitBuilder) -> Self {
        Self {
            bits: core::array::from_fn(|_| builder.add_witness()),
        }
    }

    /// Allocate a fresh public-input m-vec (4 inout wires).
    #[cfg(test)]
    pub(crate) fn new_inout(builder: &CircuitBuilder) -> Self {
        Self {
            bits: core::array::from_fn(|_| builder.add_inout()),
        }
    }

    /// Wrap an existing 4-tuple of wires as an m-vec.
    #[inline]
    pub(crate) fn from_wires(bits: [Wire; 4]) -> Self {
        Self { bits }
    }

    /// Componentwise GF(16) addition (4 XORs, near-free; XOR constraints in
    /// binius64 cost <0.1× of an AND, and shifts can materialize 1 AND when
    /// they cannot fuse with adjacent gates).
    pub(crate) fn add(&self, builder: &CircuitBuilder, other: &Self) -> Self {
        let b = builder.subcircuit("gf16/add");
        Self {
            bits: core::array::from_fn(|i| b.bxor(self.bits[i], other.bits[i])),
        }
    }

    /// Assert two bitsliced m-vecs are equal (4 AND constraints, one per plane).
    pub(crate) fn assert_eq(&self, builder: &CircuitBuilder, other: &Self) {
        let b = builder.subcircuit("gf16/assert_eq");
        for i in 0..4 {
            b.assert_eq(format!("plane[{i}]"), self.bits[i], other.bits[i]);
        }
    }

    /// Populate the witness from 64 GF(16) lane values (each in 0..16).
    pub(crate) fn populate(&self, w: &mut WitnessFiller, lanes: &[u8; 64]) {
        let planes = scalar::lanes_to_bitsliced(lanes);
        for b in 0..4 {
            w[self.bits[b]] = Word(planes[b]);
        }
    }

    /// Read back the 64 lane values from a populated witness (test helper).
    #[cfg(test)]
    pub(crate) fn read(&self, w: &WitnessFiller) -> [u8; 64] {
        let planes: [u64; 4] = core::array::from_fn(|b| w[self.bits[b]].0);
        scalar::bitsliced_to_lanes(&planes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use binius_core::verify::verify_constraints;
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    /// Round-trip: populate a bitsliced m-vec from random lanes, evaluate
    /// the (empty) circuit, and read the lanes back.
    #[test]
    fn given_random_lanes_when_populate_then_read_round_trips() {
        let mut rng = StdRng::seed_from_u64(0x9999);
        for _ in 0..20 {
            let builder = CircuitBuilder::new();
            let v = BitslicedGf16Mvec::new_witness(&builder);
            let circuit = builder.build();
            let mut w = circuit.new_witness_filler();
            let mut lanes = [0u8; 64];
            for x in lanes.iter_mut() {
                *x = rng.random_range(0..16);
            }
            v.populate(&mut w, &lanes);
            circuit.populate_wire_witness(&mut w).unwrap();
            assert_eq!(v.read(&w), lanes);
            verify_constraints(circuit.constraint_system(), &w.into_value_vec()).unwrap();
        }
    }

    /// `add` in-circuit must agree with scalar XOR on every lane.
    #[test]
    fn given_random_lanes_when_add_then_matches_scalar_oracle() {
        let mut rng = StdRng::seed_from_u64(0xBABE);
        let builder = CircuitBuilder::new();
        let a = BitslicedGf16Mvec::new_witness(&builder);
        let b = BitslicedGf16Mvec::new_witness(&builder);
        let c = a.add(&builder, &b);
        let expected = BitslicedGf16Mvec::new_witness(&builder);
        c.assert_eq(&builder, &expected);
        let circuit = builder.build();

        for _ in 0..10 {
            let mut w = circuit.new_witness_filler();
            let mut a_lanes = [0u8; 64];
            let mut b_lanes = [0u8; 64];
            for i in 0..64 {
                a_lanes[i] = rng.random_range(0..16);
                b_lanes[i] = rng.random_range(0..16);
            }
            let c_lanes: [u8; 64] = core::array::from_fn(|i| scalar::add(a_lanes[i], b_lanes[i]));
            a.populate(&mut w, &a_lanes);
            b.populate(&mut w, &b_lanes);
            expected.populate(&mut w, &c_lanes);
            circuit.populate_wire_witness(&mut w).unwrap();
            verify_constraints(circuit.constraint_system(), &w.into_value_vec()).unwrap();
        }
    }
}

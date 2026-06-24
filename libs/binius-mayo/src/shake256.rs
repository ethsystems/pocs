//! SHAKE-256 gadget for binius64. Forked from `binius_circuits::keccak::permutation`.
//!
//! SHAKE-256 reuses Keccak-f[1600] (rate = 1088 bits = 17 lanes, capacity = 512 bits)
//! but with the XOF domain separator `0x1F` instead of Keccak-256's `0x01`.
//!
//! For our MAYO call site the input fits within a single rate block and the
//! output is exactly 32 bytes ≤ rate, so a single Keccak-f permutation suffices.
//!
//! Note: the upstream `binius_circuits::keccak::fixed_length::keccak256` uses the
//! original (Ethereum) Keccak padding byte `0x01`, not SHA-3's `0x06`. We follow
//! the same scaffold but substitute `0x1F`.

use binius_circuits::keccak::{
    N_WORDS_PER_BLOCK, N_WORDS_PER_DIGEST, N_WORDS_PER_STATE, permutation::Permutation,
};
use binius_core::word::Word;
use binius_frontend::{CircuitBuilder, Wire};

/// SHAKE-256 XOF domain separator byte.
const SHAKE_DOMAIN_SEP: u64 = 0x1F;

/// Compute SHAKE-256 of an input that fits in a single rate block (≤ 135 bytes)
/// and emit the first 32 output bytes.
///
/// The input occupies `n_input_words` low Words of the rate block, followed by
/// the SHAKE domain separator `0x1F` at byte position `input_byte_len`, then
/// zeros, with `0x80` OR'd into the last byte of the rate block (byte 135).
///
/// `input_byte_len` must equal `n_input_words * 8` (i.e. inputs are word-aligned).
fn shake256_single_block_to_32(
    builder: &CircuitBuilder,
    input: &[Wire],
    input_byte_len: usize,
) -> [Wire; N_WORDS_PER_DIGEST] {
    assert_eq!(
        input.len() * 8,
        input_byte_len,
        "this helper requires word-aligned inputs"
    );
    assert!(
        input_byte_len < N_WORDS_PER_BLOCK * 8,
        "input must be strictly smaller than the rate ({} bytes)",
        N_WORDS_PER_BLOCK * 8
    );

    let zero = builder.add_constant(Word::ZERO);

    let mut block: [Wire; N_WORDS_PER_BLOCK] = [zero; N_WORDS_PER_BLOCK];
    for (i, &w) in input.iter().enumerate() {
        block[i] = w;
    }

    // Place the domain separator `0x1F` in the low byte of the word that
    // immediately follows the input. Since the input is word-aligned, this is
    // word index `input.len()` and the byte sits at bits [0..8).
    let dom_word_idx = input.len();
    assert!(
        dom_word_idx < N_WORDS_PER_BLOCK - 1,
        "domain separator must not fall in the last word for supported sizes \
         (input.len()={dom_word_idx}, N_WORDS_PER_BLOCK={N_WORDS_PER_BLOCK})"
    );
    block[dom_word_idx] = builder.add_constant(Word(SHAKE_DOMAIN_SEP));

    // OR `0x80` into the last byte of the rate block (byte 135 = high byte of
    // word 16). Words 8..16 are still zero, so we can directly assign the
    // constant rather than XOR'ing.
    let last_byte_high = 0x80u64 << 56;
    block[N_WORDS_PER_BLOCK - 1] = builder.add_constant(Word(last_byte_high));

    let mut state: [Wire; N_WORDS_PER_STATE] = [zero; N_WORDS_PER_STATE];
    state[..N_WORDS_PER_BLOCK].copy_from_slice(&block);

    Permutation::keccak_f1600(builder, &mut state);

    [state[0], state[1], state[2], state[3]]
}

/// SHAKE-256 with 56-byte input → 32-byte output.
///
/// `in56`: 7 Words; bytes 0..32 = `digest`, bytes 32..56 = `salt`.
/// Bytes within a word are little-endian (byte i is bits (i%8)*8 .. (i%8)*8+8 of word i/8).
pub(crate) fn shake256_56_to_32(
    builder: &CircuitBuilder,
    in56: &[Wire; 7],
) -> [Wire; N_WORDS_PER_DIGEST] {
    shake256_single_block_to_32(builder, in56, 56)
}

#[cfg(test)]
mod tests {
    use binius_core::verify::verify_constraints;
    use binius_frontend::CircuitBuilder;
    use rand::{Rng, SeedableRng, rngs::StdRng};
    use sha3::{
        Shake256,
        digest::{ExtendableOutput, Update, XofReader},
    };

    use super::*;

    fn shake256_56_oracle(input: &[u8; 56]) -> [u8; 32] {
        let mut hasher = Shake256::default();
        hasher.update(input);
        let mut reader = hasher.finalize_xof();
        let mut out = [0u8; 32];
        reader.read(&mut out);
        out
    }

    fn bytes_to_words<const N_BYTES: usize, const N_WORDS: usize>(
        bytes: &[u8; N_BYTES],
    ) -> [u64; N_WORDS] {
        assert_eq!(N_BYTES, N_WORDS * 8);
        let mut out = [0u64; N_WORDS];
        for (i, chunk) in bytes.chunks_exact(8).enumerate() {
            out[i] = u64::from_le_bytes(chunk.try_into().unwrap());
        }
        out
    }

    #[test]
    fn given_random_56_byte_input_when_shake256_then_matches_reference() {
        let mut rng = StdRng::seed_from_u64(0xFEED_FACE_C0FF_EE00);

        for trial in 0..6 {
            let mut input = [0u8; 56];
            rng.fill_bytes(&mut input);

            let expected = shake256_56_oracle(&input);

            let builder = CircuitBuilder::new();
            let in56: [Wire; 7] = std::array::from_fn(|_| builder.add_witness());
            let out = shake256_56_to_32(&builder, &in56);
            let expected_wires: [Wire; 4] = std::array::from_fn(|_| builder.add_inout());
            for i in 0..4 {
                builder.assert_eq(format!("trial-{trial}-out-{i}"), out[i], expected_wires[i]);
            }
            let circuit = builder.build();

            let mut w = circuit.new_witness_filler();
            let in_words: [u64; 7] = bytes_to_words::<56, 7>(&input);
            for i in 0..7 {
                w[in56[i]] = Word(in_words[i]);
            }
            let exp_words: [u64; 4] = bytes_to_words::<32, 4>(&expected);
            for i in 0..4 {
                w[expected_wires[i]] = Word(exp_words[i]);
            }

            circuit
                .populate_wire_witness(&mut w)
                .expect("circuit should accept valid witness");
            verify_constraints(circuit.constraint_system(), &w.into_value_vec())
                .expect("constraints should be satisfied");
        }
    }
}

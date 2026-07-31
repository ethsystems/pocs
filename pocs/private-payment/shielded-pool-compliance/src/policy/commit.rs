use ark_bn254::Fr;

use super::Policy;
use crate::{
    STATE_DOMAIN,
    poseidon::{
        poseidon3,
        poseidon4,
    },
};

/// `PADDED = 3 * ceil(K / 3)`. Padding is pool-side, so no length crosses the policy
/// interface.
pub const fn padded(k: usize) -> usize {
    3 * k.div_ceil(3)
}

/// Binds the policy identity and `K` into the state commitment. Without it a subject
/// reopens the same leaf under a successor slot layout. Takes no `State`, so unlike
/// `commit` it has nothing to check `K` against.
pub fn state_tag<P: Policy>(policy_source_hash: Fr) -> Fr {
    poseidon3(*STATE_DOMAIN, policy_source_hash, Fr::from(P::K as u64))
}

/// # Panics
///
/// Panics if `state.as_ref().len() != P::K`. `Policy::K` and `Policy::State` are two
/// sources of truth for the same length; a mismatch would otherwise silently commit to
/// the wrong preimage instead of failing visibly.
pub fn commit<P: Policy>(tag: Fr, state: &P::State) -> Fr {
    assert_eq!(
        state.as_ref().len(),
        P::K,
        "policy state length must equal K"
    );
    let mut slots = vec![Fr::from(0u64); padded(P::K)];
    for (i, s) in state.as_ref().iter().enumerate() {
        slots[i] = Fr::from(*s);
    }
    let mut acc = tag;
    for chunk in slots.chunks(3) {
        acc = poseidon4(acc, chunk[0], chunk[1], chunk[2]);
    }
    acc
}

#[cfg(test)]
mod tests {
    use ark_ff::{
        BigInteger,
        PrimeField,
    };
    use num_bigint::BigUint;

    use super::*;
    use crate::{
        error::PolicyError,
        policy::{
            TxFacts,
            reference::ReferencePolicy,
        },
        types::Flags,
    };

    fn assert_fr_eq_decimal(actual: Fr, expected_decimal: &str) {
        let expected = BigUint::parse_bytes(expected_decimal.as_bytes(), 10)
            .expect("valid decimal literal");
        let actual_bytes = actual.into_bigint().to_bytes_be();
        assert_eq!(BigUint::from_bytes_be(&actual_bytes), expected);
    }

    /// Cross-language parity vector: `tag = 7`, `K = 1` state `[42]`. Noir's
    /// `state::commit` on the same inputs, appended as a `#[test]` in
    /// `circuits/lib/src/state.nr`, must produce this same decimal.
    #[test]
    fn commit_parity_vector_tag_7_state_42() {
        let result = commit::<ReferencePolicy>(Fr::from(7u64), &[42u64]);
        assert_fr_eq_decimal(
            result,
            "21596994159255025703084662498772874565058600479438079129086634022518144844191",
        );
    }

    struct TwoSlotPolicy;
    impl Policy for TwoSlotPolicy {
        const K: usize = 2;
        type State = [u64; 2];
        fn zero() -> Self::State {
            [0; 2]
        }
        fn advance(prev: Self::State, _tx: &TxFacts) -> Result<Self::State, PolicyError> {
            Ok(prev)
        }
        fn evaluate(
            _tx: &TxFacts,
            _prev: Self::State,
            _next: Self::State,
        ) -> Result<Flags, PolicyError> {
            Ok(Flags::NONE)
        }
    }

    struct ThreeSlotPolicy;
    impl Policy for ThreeSlotPolicy {
        const K: usize = 3;
        type State = [u64; 3];
        fn zero() -> Self::State {
            [0; 3]
        }
        fn advance(prev: Self::State, _tx: &TxFacts) -> Result<Self::State, PolicyError> {
            Ok(prev)
        }
        fn evaluate(
            _tx: &TxFacts,
            _prev: Self::State,
            _next: Self::State,
        ) -> Result<Flags, PolicyError> {
            Ok(Flags::NONE)
        }
    }

    /// `STATE_TAG` absorbs `K`, so a `K = 2` state `(a, b)` must commit differently from a
    /// `K = 3` state `(a, b, 0)` even though the padded preimage bytes agree past `K`.
    #[test]
    fn commit_distinguishes_k2_from_k3_with_same_leading_values() {
        let tag2 = state_tag::<TwoSlotPolicy>(Fr::from(0u64));
        let tag3 = state_tag::<ThreeSlotPolicy>(Fr::from(0u64));
        let c2 = commit::<TwoSlotPolicy>(tag2, &[7, 9]);
        let c3 = commit::<ThreeSlotPolicy>(tag3, &[7, 9, 0]);
        assert_ne!(c2, c3);
    }

    struct MismatchedPolicy;
    impl Policy for MismatchedPolicy {
        const K: usize = 1;
        type State = [u64; 2];
        fn zero() -> Self::State {
            [0; 2]
        }
        fn advance(prev: Self::State, _tx: &TxFacts) -> Result<Self::State, PolicyError> {
            Ok(prev)
        }
        fn evaluate(
            _tx: &TxFacts,
            _prev: Self::State,
            _next: Self::State,
        ) -> Result<Flags, PolicyError> {
            Ok(Flags::NONE)
        }
    }

    #[test]
    #[should_panic(expected = "policy state length must equal K")]
    fn commit_panics_when_state_length_disagrees_with_declared_k() {
        let _ = commit::<MismatchedPolicy>(Fr::from(0u64), &[1, 2]);
    }
}

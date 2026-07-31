use crate::{
    error::PolicyError,
    types::Flags,
};

use super::{
    Policy,
    TxFacts,
};

/// The demo policy. Mirrors `circuits/lib/src/policy.nr`'s `K = 1`, `TOTAL = 0`, and its
/// two threshold constants.
pub struct ReferencePolicy;

const TOTAL: usize = 0;
pub const SINGLE_TX_THRESHOLD: u64 = 10_000_000_000;
pub const AGGREGATE_THRESHOLD: u64 = 50_000_000_000;

impl Policy for ReferencePolicy {
    const K: usize = 1;
    type State = [u64; 1];

    fn zero() -> Self::State {
        [0; 1]
    }

    /// Traps on overflow via `checked_add`, matching Noir's `+` on `u64`. This is
    /// deliberately different from `tx_facts::sat_add`, which computes `value_out` itself
    /// and saturates so a large transfer cannot make the gadget unsatisfiable: do not
    /// "fix" one to match the other.
    fn advance(prev: Self::State, tx: &TxFacts) -> Result<Self::State, PolicyError> {
        let mut next = prev;
        next[TOTAL] = prev[TOTAL]
            .checked_add(tx.value_out)
            .ok_or(PolicyError::SlotOverflow(TOTAL as u64))?;
        Ok(next)
    }

    fn evaluate(
        tx: &TxFacts,
        _prev: Self::State,
        next: Self::State,
    ) -> Result<Flags, PolicyError> {
        let mut flags = Flags::NONE;
        if tx.value_out > SINGLE_TX_THRESHOLD {
            flags.insert(Flags::FLAG_SINGLE_TX);
        }
        if next[TOTAL] > AGGREGATE_THRESHOLD {
            flags.insert(Flags::FLAG_AGGREGATE);
        }
        Ok(flags)
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;

    use super::*;

    fn tx(value_out: u64) -> TxFacts {
        TxFacts {
            epoch: 0,
            seq: 0,
            token: Fr::from(0u64),
            subject: Fr::from(0u64),
            counterparty: [Fr::from(0u64); 2],
            value_in: 0,
            value_out,
            exit: Fr::from(0u64),
        }
    }

    #[test]
    fn advance_accumulates_value_out_into_total() {
        let state = ReferencePolicy::zero();
        let next = ReferencePolicy::advance(state, &tx(100)).expect("no overflow");
        assert_eq!(next[TOTAL], 100);
    }

    #[test]
    fn advance_overflow_returns_slot_overflow_error() {
        let state = [u64::MAX];
        let err = ReferencePolicy::advance(state, &tx(1)).unwrap_err();
        assert!(matches!(err, PolicyError::SlotOverflow(0)));
    }

    #[test]
    fn evaluate_flags_single_tx_above_threshold() {
        let prev = ReferencePolicy::zero();
        let next = prev;
        let flags = ReferencePolicy::evaluate(&tx(SINGLE_TX_THRESHOLD + 1), prev, next)
            .expect("evaluate never blocks in the reference policy");
        assert!(flags.contains(Flags::FLAG_SINGLE_TX));
        assert!(!flags.contains(Flags::FLAG_AGGREGATE));
    }

    #[test]
    fn evaluate_flags_aggregate_when_total_exceeds_threshold() {
        let prev = ReferencePolicy::zero();
        let next = [AGGREGATE_THRESHOLD + 1];
        let flags = ReferencePolicy::evaluate(&tx(1), prev, next)
            .expect("evaluate never blocks in the reference policy");
        assert!(flags.contains(Flags::FLAG_AGGREGATE));
        assert!(!flags.contains(Flags::FLAG_SINGLE_TX));
    }

    #[test]
    fn evaluate_returns_no_flags_below_both_thresholds() {
        let prev = ReferencePolicy::zero();
        let next = [1];
        let flags = ReferencePolicy::evaluate(&tx(1), prev, next)
            .expect("evaluate never blocks in the reference policy");
        assert_eq!(flags, Flags::NONE);
    }

    /// Cross-language parity vector: prev = [20_000_000_000], value_out =
    /// 35_000_000_001. Noir's `policy::advance`/`policy::evaluate` on the same inputs,
    /// appended as a `#[test]` in `circuits/lib/src/policy.nr`, must produce the same
    /// next state and flags. Pins the Rust mirror's behavior to the circuit the way
    /// `POLICY_SOURCE_HASH` pins the Noir source alone.
    #[test]
    fn advance_evaluate_parity_vector_prev_20e9_value_35_000_000_001() {
        let prev = [20_000_000_000u64];
        let t = tx(35_000_000_001);
        let next = ReferencePolicy::advance(prev, &t).expect("no overflow");
        assert_eq!(next[TOTAL], 55_000_000_001);
        let flags = ReferencePolicy::evaluate(&t, prev, next)
            .expect("evaluate never blocks in the reference policy");
        assert_eq!(flags.as_u64(), 3);
    }
}

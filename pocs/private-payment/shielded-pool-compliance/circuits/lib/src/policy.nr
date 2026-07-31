use crate::tx_facts::TxFacts;

pub global K: u32 = 1;
global TOTAL: u32 = 0;

pub global FLAG_SINGLE_TX: u64 = 1;
pub global FLAG_AGGREGATE: u64 = 2;

// Demo values chosen here for a 6-decimal test token, not fixed by the SPEC.
global SINGLE_TX_THRESHOLD: u64 = 10_000_000_000;
global AGGREGATE_THRESHOLD: u64 = 50_000_000_000;

pub struct State {
    pub s: [u64; K],
}

pub fn zero() -> State {
    State { s: [0; K] }
}

pub fn advance(prev: State, tx: TxFacts) -> State {
    let mut next = prev;
    next.s[TOTAL] = prev.s[TOTAL] + tx.value_out;
    next
}

pub fn evaluate(tx: TxFacts, _prev: State, next: State) -> u64 {
    let mut flags: u64 = 0;
    if tx.value_out > SINGLE_TX_THRESHOLD {
        flags = flags | FLAG_SINGLE_TX;
    }
    if next.s[TOTAL] > AGGREGATE_THRESHOLD {
        flags = flags | FLAG_AGGREGATE;
    }
    flags
}

// Cross-language parity vector: prev = [20_000_000_000], value_out = 35_000_000_001.
// Rust's `ReferencePolicy::advance`/`evaluate` on the same inputs must produce the
// same next state and flags.
#[test]
fn test_advance_evaluate_parity_vector_prev_20e9_value_35_000_000_001() {
    let prev = State { s: [20_000_000_000] };
    let tx = TxFacts {
        epoch: 0,
        seq: 0,
        token: 0,
        subject: 0,
        counterparty: [0, 0],
        value_in: 0,
        value_out: 35_000_000_001,
        exit: 0,
    };
    let next = advance(prev, tx);
    assert(next.s[TOTAL] == 55_000_000_001);
    let flags = evaluate(tx, prev, next);
    assert(flags == 3);
}

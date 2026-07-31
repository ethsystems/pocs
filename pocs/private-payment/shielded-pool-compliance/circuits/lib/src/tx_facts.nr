// Pool-owned. What the pool proves about this transaction, per SPEC "TxFacts
// construction": every field is bound to a constrained value in the gated circuits.
pub struct TxFacts {
    pub epoch: u64,
    pub seq: u64,
    pub token: Field,
    pub subject: Field,
    pub counterparty: [Field; 2],
    pub value_in: u64,
    pub value_out: u64,
    pub exit: Field,
}

// Saturating, not trapping, so a large transfer cannot make the gadget
// unsatisfiable. The policy accumulator in policy.nr still traps on overflow.
pub fn sat_add(a: u64, b: u64) -> u64 {
    let wide = a as u128 + b as u128;
    if wide > 0xffffffffffffffff {
        0xffffffffffffffff
    } else {
        wide as u64
    }
}

#[test]
fn test_sat_add_normal() {
    assert(sat_add(1, 2) == 3);
}

#[test]
fn test_sat_add_overflow_saturates() {
    assert(sat_add(0xffffffffffffffff, 1) == 0xffffffffffffffff);
}

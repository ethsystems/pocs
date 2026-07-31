use std::cell::RefCell;

use ark_bn254::Fr;
use ark_ff::{
    BigInteger,
    PrimeField,
};
use light_poseidon::{
    Poseidon,
    PoseidonHasher,
};

// `Poseidon::hash` takes `&mut self` and each arity rebuilds its round constants and MDS
// matrix from a large literal table on construction, so each width is built once per
// thread rather than once per call.
thread_local! {
    static P1: RefCell<Poseidon<Fr>> =
        RefCell::new(Poseidon::<Fr>::new_circom(1).expect("arity 1 is a valid circom width"));
    static P2: RefCell<Poseidon<Fr>> =
        RefCell::new(Poseidon::<Fr>::new_circom(2).expect("arity 2 is a valid circom width"));
    static P3: RefCell<Poseidon<Fr>> =
        RefCell::new(Poseidon::<Fr>::new_circom(3).expect("arity 3 is a valid circom width"));
    static P4: RefCell<Poseidon<Fr>> =
        RefCell::new(Poseidon::<Fr>::new_circom(4).expect("arity 4 is a valid circom width"));
    static P5: RefCell<Poseidon<Fr>> =
        RefCell::new(Poseidon::<Fr>::new_circom(5).expect("arity 5 is a valid circom width"));
}

// pub(crate), not pub: the SPEC's domain-disjointness argument requires every tag to be
// present in the preimage, so raw Poseidon must never be reachable from outside the
// crate. Tagged derivations in `domain/` are the only public entry points.
pub(crate) fn poseidon1(a: Fr) -> Fr {
    P1.with(|p| p.borrow_mut().hash(&[a]).expect("one input for width 1"))
}

pub(crate) fn poseidon2(a: Fr, b: Fr) -> Fr {
    P2.with(|p| {
        p.borrow_mut()
            .hash(&[a, b])
            .expect("two inputs for width 2")
    })
}

pub(crate) fn poseidon3(a: Fr, b: Fr, c: Fr) -> Fr {
    P3.with(|p| {
        p.borrow_mut()
            .hash(&[a, b, c])
            .expect("three inputs for width 3")
    })
}

pub(crate) fn poseidon4(a: Fr, b: Fr, c: Fr, d: Fr) -> Fr {
    P4.with(|p| {
        p.borrow_mut()
            .hash(&[a, b, c, d])
            .expect("four inputs for width 4")
    })
}

pub(crate) fn poseidon5(a: Fr, b: Fr, c: Fr, d: Fr, e: Fr) -> Fr {
    P5.with(|p| {
        p.borrow_mut()
            .hash(&[a, b, c, d, e])
            .expect("five inputs for width 5")
    })
}

pub(crate) fn fr_to_be_bytes(fr: &Fr) -> [u8; 32] {
    let be = fr.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out.copy_from_slice(&be);
    out
}

/// Precondition: `bytes` is the output of a prior Poseidon call and therefore already
/// canonical. Untrusted bytes must go through `TryFrom<Bytes32> for Fr` in `types.rs`.
pub(crate) fn fr_from_be_bytes(bytes: &[u8; 32]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

#[cfg(test)]
mod tests {
    // Poseidon known-answer vectors, arity 1 through 5, inputs 1..=arity as Fr::from(u64).
    // Rust half of a three-language parity check; Noir and Solidity assert the same values.
    //
    // poseidon1(1) =
    //   18586133768512220936620570745912940619677854269274689475585506675881198879027
    // poseidon2(1, 2) =
    //   7853200120776062878684798364095072458815029376092732009249414926327459813530
    // poseidon3(1, 2, 3) =
    //   6542985608222806190361240322586112750744169038454362455181422643027100751666
    // poseidon4(1, 2, 3, 4) =
    //   18821383157269793795438455681495246036402687001665670618754263018637548127333
    // poseidon5(1, 2, 3, 4, 5) =
    //   6183221330272524995739186171720101788151706631170188140075976616310159254464

    use ark_ff::BigInteger;
    use num_bigint::BigUint;

    use super::*;

    fn fr(n: u64) -> Fr {
        Fr::from(n)
    }

    fn assert_fr_eq_decimal(actual: Fr, expected_decimal: &str) {
        let expected = BigUint::parse_bytes(expected_decimal.as_bytes(), 10)
            .expect("valid decimal literal");
        let actual_bytes = actual.into_bigint().to_bytes_be();
        assert_eq!(BigUint::from_bytes_be(&actual_bytes), expected);
    }

    #[test]
    fn poseidon1_known_answer() {
        assert_fr_eq_decimal(
            poseidon1(fr(1)),
            "18586133768512220936620570745912940619677854269274689475585506675881198879027",
        );
    }

    #[test]
    fn poseidon2_known_answer() {
        assert_fr_eq_decimal(
            poseidon2(fr(1), fr(2)),
            "7853200120776062878684798364095072458815029376092732009249414926327459813530",
        );
    }

    #[test]
    fn poseidon3_known_answer() {
        assert_fr_eq_decimal(
            poseidon3(fr(1), fr(2), fr(3)),
            "6542985608222806190361240322586112750744169038454362455181422643027100751666",
        );
    }

    #[test]
    fn poseidon4_known_answer() {
        assert_fr_eq_decimal(
            poseidon4(fr(1), fr(2), fr(3), fr(4)),
            "18821383157269793795438455681495246036402687001665670618754263018637548127333",
        );
    }

    #[test]
    fn poseidon5_known_answer() {
        assert_fr_eq_decimal(
            poseidon5(fr(1), fr(2), fr(3), fr(4), fr(5)),
            "6183221330272524995739186171720101788151706631170188140075976616310159254464",
        );
    }

    #[test]
    fn fr_be_bytes_round_trip_through_a_prior_poseidon_output() {
        let hash = poseidon2(fr(1), fr(2));
        let bytes = fr_to_be_bytes(&hash);
        assert_eq!(fr_from_be_bytes(&bytes), hash);
    }
}

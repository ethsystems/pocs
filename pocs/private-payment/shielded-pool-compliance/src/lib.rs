pub mod adapters;
pub mod auditor;
pub mod authority;
pub mod crypto;
pub mod domain;
pub mod error;
pub mod policy;
pub mod ports;
pub(crate) mod poseidon;
pub mod types;
pub mod wallet;

use std::sync::LazyLock;

use ark_bn254::Fr;
use num_bigint::BigUint;

pub const MAX_COMMITMENT_TREE_DEPTH: u64 = 32;
pub const MAX_ATTESTATION_TREE_DEPTH: u64 = 20;
pub const ATTESTER_TREE_DEPTH: u64 = 5;
pub const MAX_HISTORICAL_ROOTS: u64 = 300;
pub const EPOCH_SECONDS: u64 = 86400;
pub const MAX_ATTESTATION_EPOCHS: u64 = 7;
pub const OVERLAP_EPOCHS: u64 = 2;

pub(crate) static BN254_MODULUS: LazyLock<BigUint> = LazyLock::new(|| {
    BigUint::parse_bytes(
        b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10,
    )
    .expect("BN254 modulus is a valid decimal literal")
});

fn two_to_160() -> Fr {
    Fr::from(BigUint::from(1u8) << 160u32)
}

/// The five domain tags exceed `u128`, since each is `2^160 + k`. Computing rather than
/// transcribing makes "every tag sits above the address range" self-evident; the test
/// below pins the exact values the SPEC fixes.
pub static CN_TAG: LazyLock<Fr> = LazyLock::new(|| two_to_160() + Fr::from(1u64));
pub static VN_TAG: LazyLock<Fr> = LazyLock::new(|| two_to_160() + Fr::from(2u64));
pub static STATE_DOMAIN: LazyLock<Fr> = LazyLock::new(|| two_to_160() + Fr::from(3u64));
pub static NO_COUNTERPARTY: LazyLock<Fr> =
    LazyLock::new(|| two_to_160() + Fr::from(4u64));
pub static NO_EXIT: LazyLock<Fr> = LazyLock::new(|| two_to_160() + Fr::from(5u64));

// These constants are hardcoded in Noir globals and Solidity constants. Any
// change requires regenerating verifiers and updating both. The arrays force
// a compile error if a value drifts.
const _COMMITMENT_DEPTH_COUPLING: [(); 32] = [(); MAX_COMMITMENT_TREE_DEPTH as usize];
const _ATTESTATION_DEPTH_COUPLING: [(); 20] = [(); MAX_ATTESTATION_TREE_DEPTH as usize];
const _ATTESTER_DEPTH_COUPLING: [(); 5] = [(); ATTESTER_TREE_DEPTH as usize];
const _POLICY_K_COUPLING: [(); 1] =
    [(); <policy::reference::ReferencePolicy as policy::Policy>::K];

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;

    use super::*;

    fn assert_fr_eq_decimal(actual: Fr, expected_decimal: &[u8]) {
        use ark_ff::{
            BigInteger,
            PrimeField,
        };
        let expected =
            BigUint::parse_bytes(expected_decimal, 10).expect("valid decimal literal");
        let actual_bytes = actual.into_bigint().to_bytes_be();
        assert_eq!(BigUint::from_bytes_be(&actual_bytes), expected);
    }

    #[test]
    fn cn_tag_matches_spec() {
        assert_fr_eq_decimal(
            *CN_TAG,
            b"1461501637330902918203684832716283019655932542977",
        );
    }

    #[test]
    fn vn_tag_matches_spec() {
        assert_fr_eq_decimal(
            *VN_TAG,
            b"1461501637330902918203684832716283019655932542978",
        );
    }

    #[test]
    fn state_domain_matches_spec() {
        assert_fr_eq_decimal(
            *STATE_DOMAIN,
            b"1461501637330902918203684832716283019655932542979",
        );
    }

    #[test]
    fn no_counterparty_matches_spec() {
        assert_fr_eq_decimal(
            *NO_COUNTERPARTY,
            b"1461501637330902918203684832716283019655932542980",
        );
    }

    #[test]
    fn no_exit_matches_spec() {
        assert_fr_eq_decimal(
            *NO_EXIT,
            b"1461501637330902918203684832716283019655932542981",
        );
    }

    #[test]
    fn bn254_modulus_matches_spec() {
        let expected = BigUint::parse_bytes(
            b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
            10,
        )
        .expect("valid decimal literal");
        assert_eq!(*BN254_MODULUS, expected);
    }
}

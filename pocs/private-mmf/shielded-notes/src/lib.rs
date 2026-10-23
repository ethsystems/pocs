//! Shielded notes: the Rust side of the private MMF PoC. The transfer agent and
//! investors' wallets, the notes, plans and register feed they build, and the
//! adapters that prove them and submit them to the pool.

pub mod adapters;
pub mod agent;
pub mod chain;
pub mod client;
pub mod crypto;
pub mod domain;
pub mod error;
pub mod ports;
pub(crate) mod poseidon;
pub mod types;
pub mod wallet;

use std::sync::LazyLock;

use ark_bn254::Fr;
use num_bigint::BigUint;

pub const MAX_COMMITMENT_TREE_DEPTH: u64 = 32;
pub const MAX_ATTESTATION_TREE_DEPTH: u64 = 20;
pub const MAX_HISTORICAL_ROOTS: u64 = 300;
pub const EPOCH_SECONDS: u64 = 86400;

/// Multiplier scale: m = S means one unit is worth one share.
pub const S: u128 = 1_000_000_000_000_000_000;

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

/// Domain tags (SPEC, Domain Tags), 2^160 + 16 to 20: above every address and
/// above the base pool's tags. Must match `circuits/lib/src/domain.nr`.
pub static NK_TAG: LazyLock<Fr> = LazyLock::new(|| two_to_160() + Fr::from(16u64));
pub static OWNER_TAG: LazyLock<Fr> = LazyLock::new(|| two_to_160() + Fr::from(17u64));
pub static LOCK_TAG: LazyLock<Fr> = LazyLock::new(|| two_to_160() + Fr::from(18u64));
pub static PLAN_TAG: LazyLock<Fr> = LazyLock::new(|| two_to_160() + Fr::from(19u64));
pub static FEED_TAG: LazyLock<Fr> = LazyLock::new(|| two_to_160() + Fr::from(20u64));

// These constants are hardcoded in Noir globals and Solidity constants. Any
// change requires regenerating verifiers and updating both.
const _COMMITMENT_DEPTH_COUPLING: [(); 32] = [(); MAX_COMMITMENT_TREE_DEPTH as usize];
const _ATTESTATION_DEPTH_COUPLING: [(); 20] = [(); MAX_ATTESTATION_TREE_DEPTH as usize];

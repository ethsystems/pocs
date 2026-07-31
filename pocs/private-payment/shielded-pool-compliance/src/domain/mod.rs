//! The tagged-hash derivation layer. Every SPEC-defined hash (`CN`, `vn`, attestation
//! and revocation leaves, note commitments and nullifiers) is computed exactly once,
//! here, from a domain tag in `crate::` constants; `poseidon.rs`'s raw `poseidon1`
//! through `poseidon5` are `pub(crate)` specifically so this module is the only place
//! a domain tag can be omitted by accident.
//!
//! Struct fields in this module are `Bytes32` (or `u64`/`Address`), never `ark_bn254`'s
//! `Fr`: `Fr` stays inside `poseidon.rs`, `policy/`, and the tree adapter
//! (`adapters::commitment_tree`). `domain::tx_facts::TxFacts` is the one exception,
//! since it is `policy::Policy`'s contract, not a port, and keeps its `Fr` fields fixed.

pub mod attestation;
pub mod compliance_note;
pub mod keys;
pub mod note;
pub mod payload;
pub mod public_inputs;
pub mod tx_facts;
pub mod witness;

use ark_bn254::Fr;
use rand::RngCore;

use crate::types::Bytes32;

/// Rejection-samples 32 random bytes until they encode a canonical `Fr`. Shared by
/// every salt/secret generator in this module so "sample bytes, retry if not below
/// the modulus" is written once.
pub(crate) fn random_canonical_bytes32() -> Bytes32 {
    let mut bytes = [0u8; 32];
    loop {
        rand::thread_rng().fill_bytes(&mut bytes);
        let candidate = Bytes32::from(bytes);
        if Fr::try_from(candidate).is_ok() {
            return candidate;
        }
    }
}

//! Errors live in an `error.rs` owned by the level that owns them. These cross several
//! ports so they sit at crate level and stay qualified; later actor modules (`wallet`,
//! `authority`, `auditor`) each get their own `error.rs` naming the type `Error`, read as
//! `wallet::Error`. One convention, not two.
//!
//! `ProverError`, `MerkleError`, and `ChainError` belong here too, and arrive with the
//! ports that produce them rather than as uninhabited placeholders.

use crate::types::{
    Address,
    Bytes32,
    TxHash,
};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CryptoError {
    #[error("field element bytes are not canonical: {0}")]
    NotCanonical(Bytes32),
    #[error("ciphertext is malformed")]
    MalformedCiphertext,
    #[error("decryption failed: wrong key or tampered ciphertext")]
    DecryptionFailed,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PolicyError {
    #[error("policy accumulator overflowed at slot total {0}")]
    SlotOverflow(u64),
    #[error("policy blocked the transaction")]
    Blocked,
}

/// Produced by `ports::prover::Prover` implementations. `Ok(false)` from `verify`
/// means the proof was rejected; `Err` here means the backend itself failed, which
/// callers must not conflate with rejection.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProverError {
    #[error("proof has {actual} bytes, expected {expected}")]
    MalformedProof { expected: usize, actual: usize },
    #[error("proving backend failed")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

/// Produced by `ports::merkle::MerkleStore` adapters (`adapters::commitment_tree`,
/// `adapters::revocation_tree`).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MerkleError {
    #[error("leaf index {index} is out of range for a tree of size {size}")]
    IndexOutOfRange { index: u64, size: u64 },
    #[error("merkle proof exceeds the tree's maximum depth {max_depth}")]
    DepthExceeded { max_depth: u64 },
    #[error("attester {0} is already registered")]
    AttesterAlreadyExists(Address),
    #[error("attester {0} is not registered")]
    AttesterNotFound(Address),
    #[error("attester revocation tree is at capacity")]
    RevocationTreeFull,
    #[error("merkle tree storage backend failed")]
    Storage(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

/// Produced by `ports::chain::{ChainReader, ChainWriter}` adapters (`adapters::ethereum_rpc`).
/// Declared here with the port, ahead of the adapter that implements it, per the crate's
/// flat error-module convention.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ChainError {
    #[error("chain RPC call failed")]
    Rpc(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("chain returned a non-canonical field element")]
    NonCanonical(#[source] CryptoError),
    #[error("transaction {tx_hash} reverted")]
    Reverted { tx_hash: TxHash },
    #[error("failed to await the transaction receipt")]
    ReceiptUnavailable(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("replaying attester registry events produced an inconsistent revocation tree")]
    ReplayInconsistent(#[source] MerkleError),
}

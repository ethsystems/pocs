//! Where the wallet learns which attestation instance currently covers one of its
//! keys. Separate from `ChainReader`: knowing the registry's current roots
//! (`ChainReader::registry_values`) doesn't say which leaf index and attestation
//! metadata belong to a given subject, and that bookkeeping is naturally async since a
//! real implementation scans registry events or queries an off-chain index.

use std::future::Future;

use crate::{
    domain::{
        attestation::Generation,
        keys::OwnerPubkey,
    },
    error::ChainError,
    ports::merkle::{
        LeafIndex,
        MerklePath,
    },
    types::Address,
};

/// One attestation instance the wallet can present as a witness: enough to
/// reconstruct `attestation_leaf` and its Merkle path via `MerkleStore::get_proof`.
///
/// The attester's revocation status travels with it because the gated circuits verify
/// both instances together, and both come from the same registry. It cannot come from
/// `MerkleStore`: the revocation tree is fixed-depth and keyed by attester rather than
/// append-only, so `adapters::revocation_tree` deliberately does not implement that
/// trait.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationRecord {
    pub attester: Address,
    pub generation: Generation,
    pub issued_at: u64,
    pub expires_at: u64,
    pub leaf_index: LeafIndex,
    /// `u64::MAX` for an attester that has never been revoked, so the circuit's
    /// `epoch < revoked_at` holds for every epoch.
    pub revoked_at: u64,
    /// Inclusion proof for this attester's leaf against
    /// `RegistrySnapshot::attester_revocation_root`.
    pub revocation_proof: MerklePath,
}

pub trait AttestationSource: Send + Sync {
    /// `None` when no instance covers `owner_pubkey` currently, e.g. its attestation
    /// has not been issued yet or every issued instance has expired.
    fn current_attestation(
        &self,
        owner_pubkey: OwnerPubkey,
    ) -> impl Future<Output = Result<Option<AttestationRecord>, ChainError>> + Send;
}

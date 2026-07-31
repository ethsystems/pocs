//! Async, RPITIT, with an explicit `+ Send` on every returned future: the `Send`
//! supertrait bound on the trait does not propagate to the futures its methods
//! return, so each method states it itself.

use std::future::Future;

use crate::{
    error::ChainError,
    ports::prover::CircuitProof,
    types::{
        Address,
        Bytes32,
        Epoch,
        TxHash,
    },
};

/// The three registry values the pool checks against at execution time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistrySnapshot {
    pub attestation_root: Bytes32,
    pub attester_revocation_root: Bytes32,
    pub min_accepted_generation: u64,
}

/// The pool's currently-effective compliance verifier and the policy source it was
/// compiled against, as `ShieldedPool::effectivePolicy()` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyPair {
    pub verifier: Address,
    pub policy_source_hash: Bytes32,
}

pub trait ChainReader: Send + Sync {
    fn current_epoch(&self) -> impl Future<Output = Result<Epoch, ChainError>> + Send;
    fn commitment_root(&self)
    -> impl Future<Output = Result<Bytes32, ChainError>> + Send;
    fn is_known_commitment_root(
        &self,
        root: Bytes32,
    ) -> impl Future<Output = Result<bool, ChainError>> + Send;
    fn registry_values(
        &self,
    ) -> impl Future<Output = Result<RegistrySnapshot, ChainError>> + Send;
    fn effective_policy(
        &self,
    ) -> impl Future<Output = Result<PolicyPair, ChainError>> + Send;
    fn is_nullifier_spent(
        &self,
        nullifier: Bytes32,
    ) -> impl Future<Output = Result<bool, ChainError>> + Send;
}

/// One method per `ShieldedPool` entry point (SPEC "On-Chain State": `deposit`,
/// `transfer`, `withdraw`, `withdrawBlocked`, `claimBlocked`). `submit_withdraw_blocked`
/// takes no encrypted payload: the ungated circuit carries no compliance note to
/// encrypt. Every submission method returns the confirmed transaction hash: the
/// future only resolves once the receipt reports success, so a caller never sees `Ok`
/// for a transaction that reverted.
pub trait ChainWriter: Send + Sync {
    fn submit_deposit(
        &self,
        proof: &CircuitProof,
        encrypted_payload: &[u8],
    ) -> impl Future<Output = Result<TxHash, ChainError>> + Send;

    fn submit_transfer(
        &self,
        proof: &CircuitProof,
        encrypted_payload: &[u8],
    ) -> impl Future<Output = Result<TxHash, ChainError>> + Send;

    fn submit_withdraw(
        &self,
        proof: &CircuitProof,
        encrypted_payload: &[u8],
    ) -> impl Future<Output = Result<TxHash, ChainError>> + Send;

    fn submit_withdraw_blocked(
        &self,
        proof: &CircuitProof,
    ) -> impl Future<Output = Result<TxHash, ChainError>> + Send;

    fn claim_blocked(
        &self,
        nullifier: Bytes32,
    ) -> impl Future<Output = Result<TxHash, ChainError>> + Send;
}

use alloy::primitives::{
    Address,
    B256,
    Bytes,
    U256,
};
use thiserror::Error;

use crate::domain::proof::{
    DepositProof,
    TransferProof,
    WithdrawProof,
};

/// Transaction receipt information.
#[derive(Debug, Clone)]
pub struct TxReceipt {
    /// Transaction hash
    pub tx_hash: B256,
    /// Block number
    pub block_number: u64,
    /// Gas used
    pub gas_used: u64,
    /// Whether the transaction succeeded
    pub success: bool,
}

/// Attestation data returned when adding an attestation.
#[derive(Debug, Clone)]
pub struct AttestationData {
    /// The attestation leaf hash
    pub leaf: B256,
    /// The leaf index in the attestation tree
    pub index: u64,
    /// The attester address
    pub attester: Address,
    /// Timestamp when the attestation was issued
    pub issued_at: u64,
    /// Timestamp when the attestation expires (0 = no expiry)
    pub expires_at: u64,
}

/// Errors that can occur during on-chain interactions.
#[derive(Debug, Error)]
pub enum OnChainError {
    #[error("RPC error: {0}")]
    RpcError(String),

    #[error("Transaction failed: {0}")]
    TransactionFailed(String),

    #[error("Transaction reverted: {0}")]
    TransactionReverted(String),

    #[error("Contract error: {0}")]
    ContractError(String),

    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    #[error("Timeout waiting for transaction")]
    Timeout,

    #[error("Signer error: {0}")]
    SignerError(String),

    #[error("Insufficient funds")]
    InsufficientFunds,
}

/// Trait for interacting with on-chain contracts.
///
/// Abstracts the Ethereum RPC layer for the shielded pool and attestation registry.
pub trait OnChain: Send + Sync {
    // ========== ShieldedPool Reads ==========

    /// Get the current commitment tree root.
    fn get_commitment_root(
        &self,
    ) -> impl core::future::Future<Output = Result<B256, OnChainError>>;

    /// Get the number of commitments in the tree.
    fn get_commitment_count(
        &self,
    ) -> impl core::future::Future<Output = Result<u64, OnChainError>>;

    // Note: getMerkleProof removed from contract - clients maintain local trees
    // using the lean-imt crate and generate proofs locally.

    /// Check if a nullifier has been spent.
    fn is_nullifier_spent(
        &self,
        nullifier: B256,
    ) -> impl core::future::Future<Output = Result<bool, OnChainError>>;

    /// Check if a root is known (current or historical).
    fn is_known_root(
        &self,
        root: B256,
    ) -> impl core::future::Future<Output = Result<bool, OnChainError>>;

    /// Check if a token is supported by the pool.
    fn is_token_supported(
        &self,
        token: Address,
    ) -> impl core::future::Future<Output = Result<bool, OnChainError>>;

    // ========== AttestationRegistry Reads ==========

    /// Get the current attestation tree root.
    fn get_attestation_root(
        &self,
    ) -> impl core::future::Future<Output = Result<B256, OnChainError>>;

    /// Get the number of attestations in the tree.
    fn get_attestation_count(
        &self,
    ) -> impl core::future::Future<Output = Result<u64, OnChainError>>;

    // Note: get_attestation_merkle_proof removed - clients maintain local trees
    // using the lean-imt crate and generate proofs locally.

    /// Get the attestation leaf hash at a given index.
    fn get_attestation_leaf(
        &self,
        index: u64,
    ) -> impl core::future::Future<Output = Result<B256, OnChainError>>;

    /// Check if an address is an authorized attester.
    fn is_authorized_attester(
        &self,
        attester: Address,
    ) -> impl core::future::Future<Output = Result<bool, OnChainError>>;

    // ========== ShieldedPool Writes ==========

    /// Deposit tokens into the shielded pool.
    ///
    /// # Arguments
    /// * `proof` - The deposit ZK proof
    /// * `commitment` - The note commitment
    /// * `token` - The ERC-20 token address
    /// * `amount` - The deposit amount
    /// * `funding_address` - The address the pool pulls tokens from (bound in the proof)
    /// * `encrypted_note` - The encrypted note for viewing key holders
    fn deposit(
        &self,
        proof: &DepositProof,
        commitment: B256,
        token: Address,
        amount: U256,
        funding_address: Address,
        encrypted_note: Bytes,
    ) -> impl core::future::Future<Output = Result<TxReceipt, OnChainError>>;

    /// Transfer notes within the shielded pool.
    ///
    /// # Arguments
    /// * `proof` - The transfer ZK proof
    /// * `nullifiers` - The two input nullifiers
    /// * `commitments` - The two output commitments
    /// * `root` - The commitment tree root used for the proof
    /// * `encrypted_notes` - The encrypted notes for viewing key holders
    fn transfer(
        &self,
        proof: &TransferProof,
        nullifiers: [B256; 2],
        commitments: [B256; 2],
        root: B256,
        encrypted_notes: Bytes,
    ) -> impl core::future::Future<Output = Result<TxReceipt, OnChainError>>;

    /// Withdraw tokens from the shielded pool.
    ///
    /// # Arguments
    /// * `proof` - The withdraw ZK proof
    /// * `nullifier` - The nullifier for the spent note
    /// * `token` - The ERC-20 token address
    /// * `amount` - The withdrawal amount
    /// * `recipient` - The recipient address
    /// * `root` - The commitment tree root used for the proof
    fn withdraw(
        &self,
        proof: &WithdrawProof,
        nullifier: B256,
        token: Address,
        amount: U256,
        recipient: Address,
        root: B256,
    ) -> impl core::future::Future<Output = Result<TxReceipt, OnChainError>>;

    // ========== Admin Operations (for test setup) ==========

    /// Add an authorized attester (owner only).
    fn add_attester(
        &self,
        attester: Address,
    ) -> impl core::future::Future<Output = Result<TxReceipt, OnChainError>>;

    /// Add an attestation for a subject (attester only).
    ///
    /// # Returns
    /// Tuple of (attestation_data, receipt)
    fn add_attestation(
        &self,
        subject_pubkey_hash: B256,
        expires_at: u64,
    ) -> impl core::future::Future<Output = Result<(AttestationData, TxReceipt), OnChainError>>;

    /// Add a supported token to the pool (owner only).
    fn add_supported_token(
        &self,
        token: Address,
    ) -> impl core::future::Future<Output = Result<TxReceipt, OnChainError>>;

    // ========== ERC20 Operations ==========

    /// Approve token spending for the shielded pool.
    fn approve_token(
        &self,
        token: Address,
        amount: U256,
    ) -> impl core::future::Future<Output = Result<TxReceipt, OnChainError>>;

    /// Get token balance for an address.
    fn get_token_balance(
        &self,
        token: Address,
        account: Address,
    ) -> impl core::future::Future<Output = Result<U256, OnChainError>>;

    /// Mint mock tokens (for testing with MockERC20).
    fn mint_mock_token(
        &self,
        token: Address,
        to: Address,
        amount: U256,
    ) -> impl core::future::Future<Output = Result<TxReceipt, OnChainError>>;
}

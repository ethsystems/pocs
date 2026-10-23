//! Crate-level errors, shared across the domain, the prover and the chain adapter.
//! Each keeps its source, and names the failures callers act on.

use alloy::primitives::B256;

use crate::{
    chain::{
        IFundToken::IFundTokenErrors,
        IHonkVerifier::IHonkVerifierErrors,
        IShieldedPool::IShieldedPoolErrors,
    },
    types::{
        Address,
        Bytes32,
    },
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
    #[error("invalid secret key")]
    InvalidKey,
    #[error("the output openings do not match the plan's commitments")]
    PlanMismatch,
    #[error("the registration is for another key")]
    RegistrationKeyMismatch,
    #[error("the signature does not verify")]
    BadSignature,
}

/// `Ok(false)` from `Prover::verify` means the proof was rejected; `Err` here
/// means the backend itself failed, which callers must not conflate with rejection.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProverError {
    #[error("proof has {actual} bytes, expected {expected}")]
    MalformedProof { expected: usize, actual: usize },
    /// The witness breaks one of the circuit's assertions, so no proof exists:
    /// a frozen note, a lapsed attestation, a plan that expired. `assertion` is
    /// the assertion's message; `detail` is the full report.
    #[error("the witness fails the circuit's assertion: {assertion}")]
    Unsatisfied { assertion: String, detail: String },
    /// A Merkle path longer than the circuit's tree depth: the tree outgrew it.
    #[error("a Merkle path of {steps} steps exceeds the circuit's depth of {depth}")]
    PathTooLong { steps: usize, depth: usize },
    #[error("proving backend failed")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

/// Errors of the chain adapter: reading state and events, and submitting.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ChainError {
    #[error("RPC request failed")]
    Rpc(#[from] alloy::transports::TransportError),
    /// The pool refused the operation in simulation, before anything was sent.
    #[error("the pool rejected the operation: {0:?}")]
    PoolRejected(IShieldedPoolErrors),
    /// The verifier refused the proof in simulation: it does not verify against
    /// the public inputs the pool filled in, for example after a register-key
    /// rotation or with a swapped payload.
    #[error("the verifier rejected the proof: {0:?}")]
    ProofRejected(IHonkVerifierErrors),
    /// The public token refused the share movement in simulation: a
    /// withdrawal to an address it does not allowlist, or past a balance limit.
    #[error("the token rejected the transfer: {0:?}")]
    TokenRejected(IFundTokenErrors),
    /// A contract call failed other than with a pool error it declares.
    #[error("contract call failed")]
    Contract(#[source] alloy::contract::Error),
    #[error("waiting for the receipt failed")]
    Receipt(#[from] alloy::providers::PendingTransactionError),
    /// The transaction passed simulation but reverted when mined, because the
    /// state changed in between.
    #[error("transaction {0} reverted on-chain")]
    RevertedOnChain(B256),
    #[error("an event did not decode")]
    Decode(#[from] alloy::sol_types::Error),
    /// A value read from the chain that is not a BN254 field element.
    #[error("not a canonical field element: {0}")]
    NonCanonical(B256),
    #[error("the node returned no latest block")]
    NoLatestBlock,
}

impl From<alloy::contract::Error> for ChainError {
    /// A revert carrying one of the pool's errors becomes `PoolRejected`; one
    /// of the verifier's, `ProofRejected`; one of the token's, `TokenRejected`.
    fn from(e: alloy::contract::Error) -> Self {
        if let Some(reason) = e.as_decoded_interface_error::<IShieldedPoolErrors>() {
            return Self::PoolRejected(reason);
        }
        if let Some(reason) = e.as_decoded_interface_error::<IHonkVerifierErrors>() {
            return Self::ProofRejected(reason);
        }
        if let Some(reason) = e.as_decoded_interface_error::<IFundTokenErrors>() {
            return Self::TokenRejected(reason);
        }
        Self::Contract(e)
    }
}

/// Errors of a client's operations, which prove and then submit.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClientError {
    #[error(transparent)]
    Prover(#[from] ProverError),
    #[error(transparent)]
    Chain(#[from] ChainError),
    #[error("the proving task did not complete")]
    ProvingTask(#[from] tokio::task::JoinError),
}

/// Errors of the wallet and the transfer agent.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ActorError {
    #[error("not enough unspent units: have {have}, need {need}")]
    InsufficientUnits { have: u64, need: u64 },
    #[error("owner {0} has no attestation")]
    NotAttested(Bytes32),
    #[error("note {0} is not known")]
    UnknownNote(Bytes32),
    /// A claim on the seed, the agent's frozen note that keeps `U` above 0.
    #[error("note {0} is the seed, which stays frozen")]
    SeedNote(Bytes32),
    /// A hand-out from a locked note, which the claim path would move.
    #[error("note {0} is locked")]
    LockedNote(Bytes32),
    /// A second seed deposit: the seed is made once, at deployment.
    #[error("the seed is already deposited")]
    SeedExists,
    /// The seed's freeze before its deposit.
    #[error("no seed deposit to freeze")]
    NoSeed,
    /// The seed after an investor's owner value is attested, which the SPEC
    /// forbids: until the seed lands, a lone holder could inflate `m`.
    #[error("investor owner value {0} is attested before the seed")]
    InvestorBeforeSeed(Bytes32),
    /// A hand-out from a note an investor redeemed to the agent, which would
    /// mark the redemption processed with nothing paid.
    #[error("note {0} is a pending redemption")]
    PendingRedemption(Bytes32),
    #[error("owner {0} is not registered with the transfer agent")]
    UnknownOwner(Bytes32),
    /// An investor ID that is empty or one of the agent's reserved names.
    #[error("investor ID {0:?} is empty or reserved for the transfer agent")]
    InvalidInvestorId(String),
    /// An address holding shares publicly that no investor is registered at:
    /// the cap check cannot count it.
    #[error("address {0} holds shares but is registered to no investor")]
    UnknownPublicHolder(Address),
    /// Stopping the agent's own owner value, which hand-outs and seizures pay.
    #[error("the transfer agent's own owner value stays attested")]
    AgentsOwnValue,
    /// A registration whose owner value the agent already holds under another
    /// investor ID: re-attributing a position is a correction, not onboarding.
    #[error("owner {0} is registered to another investor")]
    OwnerOfAnotherInvestor(Bytes32),
    #[error("investor {0} has not been verified")]
    UnverifiedInvestor(String),
    /// A registration for another pool or another investor ID, one its key did
    /// not sign, one whose `nk_hash` the `nk` sent with it does not match, or
    /// a zero `nk`, whose nullifiers anyone could compute.
    #[error("the registration is not signed by its key for this pool")]
    BadRegistration,
    #[error("attesting a new investor in {jurisdiction} would exceed its cap of {cap}")]
    JurisdictionCapReached { jurisdiction: String, cap: usize },
    #[error("attesting a new investor would exceed the cap of {cap}")]
    CapReached { cap: usize },
    #[error("the plan expired at {expiry}, before the end of epoch {epoch}")]
    PlanExpired { expiry: u64, epoch: u64 },
    /// Reconciliation: notes the register feed could not be read for, listed
    /// in `TransferAgent::unreadable_notes`, so the register is incomplete.
    #[error("{0} notes could not be read through the register feed")]
    UnreadableNotes(usize),
    #[error("a transfer spends one or two notes, not {0}")]
    InputCount(usize),
    /// Reconciliation: the register's units total differs from the pool's `U`.
    #[error("the register holds {register} units, the pool {pool}")]
    RegisterMismatch { register: u128, pool: u128 },
    /// Reconciliation: the notes could withdraw more shares than the pool holds.
    #[error("the notes are worth more shares than the pool holds")]
    SharesShort,
    /// A register-key rotation committed out of order, or twice.
    #[error("register key rotation {0} is not the next version")]
    StaleRotation(u64),
    /// A rotation whose key the agent did not prepare, or no longer holds.
    #[error("no prepared register key matches rotation {0}")]
    UnpreparedRotation(u64),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Prover(#[from] ProverError),
}

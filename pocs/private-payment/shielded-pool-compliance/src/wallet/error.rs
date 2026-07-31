use crate::{
    domain::keys::OwnerPubkey,
    error::{
        ChainError,
        CryptoError,
        MerkleError,
        PolicyError,
        ProverError,
    },
    types::{
        Bytes32,
        Epoch,
    },
};

/// A blocked policy check (`PolicyBlocked`) is reached before any chain read, merkle
/// lookup, or prover call, so a caller matching on it is guaranteed the transaction
/// never left the wallet.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("policy rejected the transaction")]
    PolicyBlocked(#[source] PolicyError),
    #[error("no attestation currently covers owner pubkey {0:?}")]
    NoAttestation(OwnerPubkey),
    #[error("selected inputs total {have}, need at least {need}")]
    InsufficientValue { have: u64, need: u64 },
    #[error("local clock epoch {local:?} disagrees with the chain's {chain:?}")]
    EpochMismatch { local: Epoch, chain: Epoch },
    #[error("local commitment root {0} is not one the chain recognizes")]
    UnknownCommitmentRoot(Bytes32),
    #[error("merkle store operation failed")]
    Merkle(#[from] MerkleError),
    #[error("chain read failed")]
    Chain(#[from] ChainError),
    #[error("cryptographic operation failed")]
    Crypto(#[from] CryptoError),
    #[error("audit committee payload encryption failed")]
    Audit(#[source] CryptoError),
    #[error("proving backend failed")]
    Prover(#[from] ProverError),
    #[error("payload element is not a value-note element")]
    WrongElementKind,
}

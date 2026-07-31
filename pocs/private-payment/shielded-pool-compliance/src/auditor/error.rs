use crate::error::CryptoError;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("payload element is not addressed to the audit committee")]
    WrongElementKind,
    #[error("cryptographic operation failed")]
    Crypto(#[from] CryptoError),
    #[error(
        "compliance note at seq {seq} has no matching entry in the observed commitments"
    )]
    UnanchoredNote { seq: u64 },
    #[error("expected seq {expected}, found {found}: the reconstructed chain has a gap")]
    SeqGap { expected: u64, found: u64 },
    #[error("reported flags at seq {seq} disagree with the reference policy")]
    FlagMismatch { seq: u64 },
    #[error(
        "payload element {index} claims the current committee version but does not decrypt"
    )]
    UndecryptableElement { index: usize },
}

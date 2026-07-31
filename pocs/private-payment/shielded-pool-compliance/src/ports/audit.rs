//! SPEC "Audit Channel": encrypts the `0x03` compliance-note payload element to the
//! current audit committee key. `committee_version` is the on-chain counter every
//! `0x03` element MUST carry, so a reader can tell a stale-committee ciphertext from a
//! current one.

use crate::error::CryptoError;

pub trait AuditEncryptor: Send + Sync {
    fn committee_version(&self) -> u64;
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

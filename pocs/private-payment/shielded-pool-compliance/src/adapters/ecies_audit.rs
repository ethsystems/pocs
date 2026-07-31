//! Real `AuditEncryptor` over the existing ECIES keypair. The SPEC asks for Silent
//! Threshold Encryption (a `t`-of-`n` committee); this PoC uses a single keypair
//! (`t = n = 1`) as a documented stand-in, per `domain::keys::AuditViewingKey`'s own
//! doc comment.

use crate::{
    domain::keys::AuditViewingPubkey,
    error::CryptoError,
    ports::audit::AuditEncryptor,
};

pub struct EciesAuditEncryptor {
    pubkey: AuditViewingPubkey,
    committee_version: u64,
}

impl EciesAuditEncryptor {
    pub fn new(pubkey: AuditViewingPubkey, committee_version: u64) -> Self {
        Self {
            pubkey,
            committee_version,
        }
    }
}

impl AuditEncryptor for EciesAuditEncryptor {
    fn committee_version(&self) -> u64 {
        self.committee_version
    }

    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(self.pubkey.encrypt(plaintext, aad))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::keys::AuditViewingKey;

    #[test]
    fn encrypt_round_trips_through_the_matching_secret_key() {
        let sk = AuditViewingKey::random();
        let adapter = EciesAuditEncryptor::new(sk.public_key(), 7);
        let ciphertext = adapter
            .encrypt(b"compliance note", b"aad")
            .expect("encrypt never fails");
        let plaintext = sk
            .decrypt(&ciphertext, b"aad")
            .expect("decrypt with the matching key");
        assert_eq!(plaintext, b"compliance note");
    }

    #[test]
    fn decrypt_with_the_wrong_key_fails() {
        let sk = AuditViewingKey::random();
        let wrong = AuditViewingKey::random();
        let adapter = EciesAuditEncryptor::new(sk.public_key(), 1);
        let ciphertext = adapter
            .encrypt(b"secret", b"aad")
            .expect("encrypt never fails");
        assert!(wrong.decrypt(&ciphertext, b"aad").is_err());
    }

    #[test]
    fn committee_version_reports_the_configured_value() {
        let sk = AuditViewingKey::random();
        let adapter = EciesAuditEncryptor::new(sk.public_key(), 42);
        assert_eq!(adapter.committee_version(), 42);
    }
}

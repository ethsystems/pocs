//! Note encryption over the `sealring` sealed-note envelope.
//!
//! `sealring` owns the suite this PoC used to hand-roll: secp256k1 ECDH, HKDF-SHA256,
//! ChaCha20-Poly1305. It adds two things the hand-rolled version did not have. The
//! recipient public key is mixed into the KDF info, so a crafted ephemeral key cannot
//! make two recipients derive the same key. And every envelope carries a key-commitment
//! tag that `open` checks in constant time before the AEAD runs, which is what makes
//! trial decryption over a batch safe.
//!
//! The wire shape is `sealring`'s: version, kem id, 33-byte SEC1 ephemeral public key,
//! 32-byte commit, ciphertext. [`EncryptedNote`] carries those bytes verbatim.

use sealring::{
    Domain,
    K256,
    OpenError,
    Recipient,
    SealedNote,
};

use crate::domain::{
    encrypted::EncryptedNote,
    keys::{
        ViewingKey,
        ViewingPubkey,
    },
    note::Note,
};

/// Additional authenticated data. Empty: this PoC binds nothing outside the note
/// itself, matching what the previous ECIES did.
const AAD: &[u8] = &[];

/// The note codec and domain tag `sealring` encrypts under. The tag is the same string
/// the hand-rolled HKDF used as its `info`, so envelopes stay separated from any other
/// domain sharing a viewing key.
pub struct NoteDomain;

impl Domain for NoteDomain {
    type Note = Note;
    type Error = serde_json::Error;

    const DOMAIN_TAG: &'static str = "shielded-pool-note-encryption-v1";

    fn encode_note(note: &Self::Note, out: &mut Vec<u8>) -> Result<(), Self::Error> {
        serde_json::to_writer(out, note)
    }

    fn decode_note(bytes: &[u8]) -> Result<Self::Note, Self::Error> {
        serde_json::from_slice(bytes)
    }
}

/// Encrypt a note for a recipient's viewing public key.
pub fn encrypt_note(note: &Note, recipient: &ViewingPubkey) -> EncryptedNote {
    let envelope = sealring::seal::<K256, NoteDomain>(
        recipient.public_key(),
        note,
        AAD,
        &mut rand::rng(),
    )
    .expect("sealing to a valid secp256k1 public key never fails");
    EncryptedNote::new(envelope.as_bytes().to_vec())
}

/// Decrypt a note using the recipient's viewing key.
///
/// A commit mismatch means the envelope was addressed to some other key. `sealring`
/// reports that as `Ok(None)` rather than an error; this PoC's callers only ever try
/// their own envelopes, so it collapses into [`DecryptionError::DecryptionFailed`]
/// alongside a failed AEAD tag.
pub fn decrypt_note(
    encrypted: &EncryptedNote,
    viewing_key: &ViewingKey,
) -> Result<Note, DecryptionError> {
    let envelope = SealedNote::<K256, _>::parse(encrypted.as_bytes())
        .map_err(|_| DecryptionError::MalformedEnvelope)?;
    let recipient = Recipient::<K256>::new(viewing_key.secret_key().clone());

    sealring::open::<K256, NoteDomain, _>(&recipient, &envelope, AAD)
        .map_err(DecryptionError::from)?
        .ok_or(DecryptionError::DecryptionFailed)
}

/// Errors that can occur during decryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecryptionError {
    #[error("Malformed envelope")]
    MalformedEnvelope,
    #[error("Decryption failed (wrong key or corrupted data)")]
    DecryptionFailed,
    #[error("Failed to deserialize note")]
    DeserializationFailed,
}

impl From<OpenError> for DecryptionError {
    fn from(err: OpenError) -> Self {
        match err {
            OpenError::Aead | OpenError::Verify => Self::DecryptionFailed,
            OpenError::NoteDecode => Self::DeserializationFailed,
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::{
        Address,
        U256,
    };

    use super::*;
    use crate::domain::{
        epoch::Epoch,
        keys::SpendingKey,
    };

    fn create_test_note() -> Note {
        let sk = SpendingKey::random();
        let owner = sk.derive_owner_pubkey();
        Note::new(Address::ZERO, U256::from(1000u64), owner, Epoch(7))
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let note = create_test_note();
        let viewing_key = ViewingKey::random();
        let viewing_pubkey = viewing_key.derive_viewing_pubkey();

        let encrypted = encrypt_note(&note, &viewing_pubkey);
        let decrypted = decrypt_note(&encrypted, &viewing_key).unwrap();

        assert_eq!(note.token, decrypted.token);
        assert_eq!(note.amount, decrypted.amount);
        assert_eq!(note.owner_pubkey, decrypted.owner_pubkey);
        assert_eq!(note.salt, decrypted.salt);
        assert_eq!(note.epoch_created, decrypted.epoch_created);
    }

    #[test]
    fn test_decrypt_with_wrong_key_fails() {
        let note = create_test_note();
        let viewing_key = ViewingKey::random();
        let viewing_pubkey = viewing_key.derive_viewing_pubkey();

        let encrypted = encrypt_note(&note, &viewing_pubkey);

        // Try to decrypt with a different key
        let wrong_key = ViewingKey::random();
        let result = decrypt_note(&encrypted, &wrong_key);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), DecryptionError::DecryptionFailed);
    }

    #[test]
    fn test_encrypt_produces_different_ciphertext() {
        let note = create_test_note();
        let viewing_key = ViewingKey::random();
        let viewing_pubkey = viewing_key.derive_viewing_pubkey();

        // Encrypt twice - should produce different envelopes due to random ephemeral keys
        let encrypted1 = encrypt_note(&note, &viewing_pubkey);
        let encrypted2 = encrypt_note(&note, &viewing_pubkey);

        assert_ne!(encrypted1.as_bytes(), encrypted2.as_bytes());

        // But both should decrypt to the same note
        let decrypted1 = decrypt_note(&encrypted1, &viewing_key).unwrap();
        let decrypted2 = decrypt_note(&encrypted2, &viewing_key).unwrap();

        assert_eq!(decrypted1.token, decrypted2.token);
        assert_eq!(decrypted1.amount, decrypted2.amount);
        assert_eq!(decrypted1.salt, decrypted2.salt);
        assert_eq!(decrypted1.epoch_created, decrypted2.epoch_created);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let note = create_test_note();
        let viewing_key = ViewingKey::random();
        let viewing_pubkey = viewing_key.derive_viewing_pubkey();

        let mut encrypted = encrypt_note(&note, &viewing_pubkey);

        // Tamper with the last envelope byte, inside the AEAD tag.
        let last = encrypted.bytes.len() - 1;
        encrypted.bytes[last] ^= 0xFF;

        let result = decrypt_note(&encrypted, &viewing_key);
        assert_eq!(result.unwrap_err(), DecryptionError::DecryptionFailed);
    }

    #[test]
    fn test_tampered_commit_reads_as_addressed_elsewhere() {
        let note = create_test_note();
        let viewing_key = ViewingKey::random();
        let viewing_pubkey = viewing_key.derive_viewing_pubkey();

        let mut encrypted = encrypt_note(&note, &viewing_pubkey);

        // Flip a commit byte: the tag no longer matches, so the envelope reads as
        // addressed to somebody else rather than as a corrupted one of ours, and the
        // AEAD is never reached.
        encrypted.bytes[2 + 33] ^= 0xFF;

        let result = decrypt_note(&encrypted, &viewing_key);
        assert_eq!(result.unwrap_err(), DecryptionError::DecryptionFailed);
    }
}

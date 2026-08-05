//! `sealring`'s suite v1 over secp256k1 (K256 KEM),
//!
//! Callers pass already-serialized bytes, not one fixed note type, so the domain's
//! note codec is a byte-copy passthrough.

use k256::{
    PublicKey,
    SecretKey,
};
use sealring::{
    Domain,
    K256,
    Recipient,
    SealedNote,
};

use crate::error::CryptoError;

const DOMAIN_TAG: &str = "shielded-pool-compliance-ecies-v1";

struct BytesDomain;

impl Domain for BytesDomain {
    type Note = Vec<u8>;
    type Error = core::convert::Infallible;

    const DOMAIN_TAG: &'static str = DOMAIN_TAG;

    fn encode_note(note: &Self::Note, out: &mut Vec<u8>) -> Result<(), Self::Error> {
        out.extend_from_slice(note);
        Ok(())
    }

    fn decode_note(bytes: &[u8]) -> Result<Self::Note, Self::Error> {
        Ok(bytes.to_vec())
    }
}

/// Encrypts `plaintext` to `recipient`, binding `aad` into the AEAD tag.
pub fn encrypt(plaintext: &[u8], recipient: &PublicKey, aad: &[u8]) -> Vec<u8> {
    sealring::seal::<K256, BytesDomain>(recipient, &plaintext.to_vec(), aad, &mut rand::rng())
        .expect("sealing to a valid secp256k1 public key never fails")
        .as_bytes()
        .to_vec()
}

/// Decrypts a payload produced by [`encrypt`] under the identical `aad`. Fails with
/// [`CryptoError::MalformedCiphertext`] if the envelope framing is invalid, and
/// [`CryptoError::DecryptionFailed`] if the key commitment or the AEAD tag does not
/// verify (wrong key, tampered ciphertext, or an `aad` that disagrees with what it was
/// encrypted under).
pub fn decrypt(
    ciphertext: &[u8],
    recipient: &SecretKey,
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let envelope = SealedNote::<K256, _>::parse(ciphertext)
        .map_err(|_| CryptoError::MalformedCiphertext)?;
    let recipient = Recipient::<K256>::new(recipient.clone());

    // Every OpenError variant and a commit-mismatch `Ok(None)` collapse to the same
    // outcome: this crate has no variant finer than "decryption failed".
    sealring::open::<K256, BytesDomain, _>(&recipient, &envelope, aad)
        .map_err(|_| CryptoError::DecryptionFailed)?
        .ok_or(CryptoError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use k256::elliptic_curve::Generate;

    use super::*;

    #[test]
    fn round_trips_through_a_fresh_key_pair() {
        let secret = SecretKey::generate_from_rng(&mut rand::rng());
        let public = secret.public_key();

        let plaintext = b"compliance note payload";
        let ciphertext = encrypt(plaintext, &public, b"aad");
        let decrypted =
            decrypt(&ciphertext, &secret, b"aad").expect("valid ciphertext decrypts");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_fails_with_the_wrong_key() {
        let secret = SecretKey::generate_from_rng(&mut rand::rng());
        let public = secret.public_key();
        let wrong_secret = SecretKey::generate_from_rng(&mut rand::rng());

        let ciphertext = encrypt(b"secret", &public, b"aad");
        assert!(matches!(
            decrypt(&ciphertext, &wrong_secret, b"aad"),
            Err(CryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn decrypt_fails_on_tampered_ciphertext() {
        let secret = SecretKey::generate_from_rng(&mut rand::rng());
        let public = secret.public_key();

        let mut ciphertext = encrypt(b"secret", &public, b"aad");
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0xff;

        assert!(matches!(
            decrypt(&ciphertext, &secret, b"aad"),
            Err(CryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn decrypt_fails_on_truncated_ciphertext() {
        let secret = SecretKey::generate_from_rng(&mut rand::rng());
        assert!(matches!(
            decrypt(&[0u8; 5], &secret, b"aad"),
            Err(CryptoError::MalformedCiphertext)
        ));
    }

    #[test]
    fn repeated_encryptions_use_distinct_ephemeral_keys_and_ciphertexts() {
        let secret = SecretKey::generate_from_rng(&mut rand::rng());
        let public = secret.public_key();

        let a = encrypt(b"same plaintext", &public, b"aad");
        let b = encrypt(b"same plaintext", &public, b"aad");
        assert_ne!(a, b);
    }

    #[test]
    fn decrypt_fails_under_a_different_aad() {
        let secret = SecretKey::generate_from_rng(&mut rand::rng());
        let public = secret.public_key();

        let ciphertext = encrypt(b"secret", &public, b"aad-one");
        assert!(matches!(
            decrypt(&ciphertext, &secret, b"aad-two"),
            Err(CryptoError::DecryptionFailed)
        ));
    }
}

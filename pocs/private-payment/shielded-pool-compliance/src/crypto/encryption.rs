//! ECIES over secp256k1: ephemeral ECDH, HKDF-SHA256 key derivation, ChaCha20-Poly1305
//! AEAD. Used by every key pair in `domain::keys` (`ViewingKey`, `ComplianceViewingKey`,
//! `AuditViewingKey`) to encrypt/decrypt the three payload elements of SPEC "Audit
//! Channel".
//!
//! Output framing: a 33-byte SEC1-compressed ephemeral public key, followed by the
//! ChaCha20-Poly1305 ciphertext (which already carries its own 16-byte tag). The caller
//! supplies additional authenticated data (`domain::payload::PayloadKind::aad`) binding
//! the element's cleartext kind and, for a committee element, its committee version;
//! decryption under a different `aad` fails the Poly1305 tag rather than silently
//! opening a payload addressed to another kind or version.

use chacha20poly1305::{
    ChaCha20Poly1305,
    Nonce,
    aead::{
        Aead,
        KeyInit,
        Payload,
    },
};
use hkdf::Hkdf;
use k256::{
    PublicKey,
    SecretKey,
    ecdh::EphemeralSecret,
    elliptic_curve::sec1::ToEncodedPoint,
};
use sha2::{
    Digest,
    Sha256,
};

use crate::error::CryptoError;

const HKDF_INFO: &[u8] = b"shielded-pool-compliance-ecies-v1";
const EPHEMERAL_PUBKEY_LEN: usize = 33;

/// Encrypts `plaintext` to `recipient`, binding `aad` into the AEAD tag. Generates a
/// fresh ephemeral key pair per call, so the nonce derived from the resulting shared
/// secret (`derive_nonce`) is never reused under the same symmetric key:
/// nonce-derivation-from-shared-secret is safe only as long as every encryption uses
/// its own ephemeral secret, which this function guarantees by construction.
pub fn encrypt(plaintext: &[u8], recipient: &PublicKey, aad: &[u8]) -> Vec<u8> {
    let ephemeral_secret = EphemeralSecret::random(&mut rand::thread_rng());
    let ephemeral_pubkey = ephemeral_secret.public_key();
    let shared_secret = ephemeral_secret.diffie_hellman(recipient);

    let key = derive_key(shared_secret.raw_secret_bytes().as_slice());
    let nonce_bytes = derive_nonce(shared_secret.raw_secret_bytes().as_slice());
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .expect("32-byte HKDF output is a valid key");
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("ChaCha20Poly1305 encryption over a valid key never fails");

    let mut out = ephemeral_pubkey.to_encoded_point(true).as_bytes().to_vec();
    out.extend_from_slice(&ciphertext);
    out
}

/// Decrypts a payload produced by [`encrypt`] under the identical `aad`. Fails with
/// [`CryptoError::MalformedCiphertext`] if the ephemeral public key prefix is missing
/// or invalid, and [`CryptoError::DecryptionFailed`] if the AEAD tag does not verify
/// (wrong key, tampered ciphertext, or an `aad` that disagrees with what it was
/// encrypted under).
pub fn decrypt(
    ciphertext: &[u8],
    recipient: &SecretKey,
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() < EPHEMERAL_PUBKEY_LEN {
        return Err(CryptoError::MalformedCiphertext);
    }
    let (ephemeral_bytes, body) = ciphertext.split_at(EPHEMERAL_PUBKEY_LEN);
    let ephemeral_pubkey = PublicKey::from_sec1_bytes(ephemeral_bytes)
        .map_err(|_| CryptoError::MalformedCiphertext)?;

    let shared_secret = k256::ecdh::diffie_hellman(
        recipient.to_nonzero_scalar(),
        ephemeral_pubkey.as_affine(),
    );
    let key = derive_key(shared_secret.raw_secret_bytes().as_slice());
    let nonce_bytes = derive_nonce(shared_secret.raw_secret_bytes().as_slice());
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .expect("32-byte HKDF output is a valid key");

    cipher
        .decrypt(nonce, Payload { msg: body, aad })
        .map_err(|_| CryptoError::DecryptionFailed)
}

fn derive_key(shared_secret: &[u8]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key = [0u8; 32];
    hkdf.expand(HKDF_INFO, &mut key)
        .expect("32-byte output is within HKDF-SHA256's output limit");
    key
}

fn derive_nonce(shared_secret: &[u8]) -> [u8; 12] {
    let digest = Sha256::digest(shared_secret);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&digest[..12]);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_a_fresh_key_pair() {
        let secret = SecretKey::random(&mut rand::thread_rng());
        let public = secret.public_key();

        let plaintext = b"compliance note payload";
        let ciphertext = encrypt(plaintext, &public, b"aad");
        let decrypted =
            decrypt(&ciphertext, &secret, b"aad").expect("valid ciphertext decrypts");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_fails_with_the_wrong_key() {
        let secret = SecretKey::random(&mut rand::thread_rng());
        let public = secret.public_key();
        let wrong_secret = SecretKey::random(&mut rand::thread_rng());

        let ciphertext = encrypt(b"secret", &public, b"aad");
        assert!(matches!(
            decrypt(&ciphertext, &wrong_secret, b"aad"),
            Err(CryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn decrypt_fails_on_tampered_ciphertext() {
        let secret = SecretKey::random(&mut rand::thread_rng());
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
        let secret = SecretKey::random(&mut rand::thread_rng());
        assert!(matches!(
            decrypt(&[0u8; 5], &secret, b"aad"),
            Err(CryptoError::MalformedCiphertext)
        ));
    }

    #[test]
    fn repeated_encryptions_use_distinct_ephemeral_keys_and_ciphertexts() {
        let secret = SecretKey::random(&mut rand::thread_rng());
        let public = secret.public_key();

        let a = encrypt(b"same plaintext", &public, b"aad");
        let b = encrypt(b"same plaintext", &public, b"aad");
        assert_ne!(a, b);
    }

    #[test]
    fn decrypt_fails_under_a_different_aad() {
        let secret = SecretKey::random(&mut rand::thread_rng());
        let public = secret.public_key();

        let ciphertext = encrypt(b"secret", &public, b"aad-one");
        assert!(matches!(
            decrypt(&ciphertext, &secret, b"aad-two"),
            Err(CryptoError::DecryptionFailed)
        ));
    }
}

//! Voucher AEAD: sealring's X25519 suite for envelopes sent to a relay.

use sealring::{
    Domain,
    OpenError,
    Recipient,
    SealError,
    SealedNote,
    X25519,
};
use thiserror::Error;
use x25519_dalek::{
    PublicKey,
    StaticSecret,
};

use crate::types::{
    Bytes32,
    EncryptedVoucher,
};

#[derive(Debug, Error)]
pub enum AeadError {
    #[error("AEAD decryption failed")]
    DecryptFailed,
    #[error("AEAD encryption failed")]
    EncryptFailed,
}

impl From<SealError> for AeadError {
    fn from(_: SealError) -> Self {
        Self::EncryptFailed
    }
}

impl From<OpenError> for AeadError {
    fn from(_: OpenError) -> Self {
        Self::DecryptFailed
    }
}

/// Note codec and domain tag the voucher is sealed under.
struct VoucherDomain;

impl Domain for VoucherDomain {
    type Note = Vec<u8>;
    type Error = core::convert::Infallible;

    const DOMAIN_TAG: &'static str = "RDR/voucher-aead/v1";

    fn encode_note(note: &Self::Note, out: &mut Vec<u8>) -> Result<(), Self::Error> {
        out.extend_from_slice(note);
        Ok(())
    }

    fn decode_note(bytes: &[u8]) -> Result<Self::Note, Self::Error> {
        Ok(bytes.to_vec())
    }
}

/// Encrypt a serialized voucher to a relay's X25519 static public key.
/// `relay_id` is the AAD, so tampering with routing invalidates the envelope.
pub fn encrypt_to_relay(
    relay_pk: &PublicKey,
    relay_id: Bytes32,
    plaintext: &[u8],
) -> Result<EncryptedVoucher, AeadError> {
    let note = plaintext.to_vec();
    let envelope =
        sealring::seal::<X25519, VoucherDomain>(relay_pk, &note, &relay_id, &mut rand::rng())?;
    Ok(EncryptedVoucher {
        envelope: envelope.as_bytes().to_vec(),
        relay_id,
    })
}

/// Decrypt a voucher envelope with one of the relay's static keys. The
/// relay tries `current`, then `previous`, then errs. This function decrypts
/// against a single key; the `Relay` adapter loops over the archive.
pub fn decrypt_from_companion(
    relay_sk: &StaticSecret,
    env: &EncryptedVoucher,
) -> Result<Vec<u8>, AeadError> {
    let envelope = SealedNote::<X25519, _>::parse(env.envelope.as_slice())
        .map_err(|_| AeadError::DecryptFailed)?;
    // Recipient::new derives the pubkey sealring mixes into the KDF; owned by design.
    let recipient = Recipient::<X25519>::new(relay_sk.clone());
    sealring::open::<X25519, VoucherDomain, _>(&recipient, &envelope, &env.relay_id)?
        .ok_or(AeadError::DecryptFailed)
}

#[cfg(test)]
mod tests {
    use rand::RngExt;
    use x25519_dalek::{
        PublicKey,
        StaticSecret,
    };

    use super::*;

    fn fresh_relay() -> (StaticSecret, PublicKey) {
        let seed: [u8; 32] = rand::rng().random();
        let sk = StaticSecret::from(seed);
        let pk: PublicKey = (&sk).into();
        (sk, pk)
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (sk, pk) = fresh_relay();
        let plaintext = b"voucher-bytes";
        let env = encrypt_to_relay(&pk, [0u8; 32], plaintext).unwrap();
        let plain2 = decrypt_from_companion(&sk, &env).unwrap();
        assert_eq!(plain2, plaintext);
    }

    #[test]
    fn test_decrypt_with_wrong_key_fails() {
        let (_sk, pk) = fresh_relay();
        let (sk2, _pk2) = fresh_relay();
        let env = encrypt_to_relay(&pk, [0u8; 32], b"hello").unwrap();
        assert!(decrypt_from_companion(&sk2, &env).is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let (sk, pk) = fresh_relay();
        let mut env = encrypt_to_relay(&pk, [0u8; 32], b"hello").unwrap();
        let last = env.envelope.len() - 1;
        env.envelope[last] ^= 0xff;
        assert!(decrypt_from_companion(&sk, &env).is_err());
    }

    #[test]
    fn test_two_envelopes_differ() {
        let (_sk, pk) = fresh_relay();
        let e1 = encrypt_to_relay(&pk, [0u8; 32], b"hello").unwrap();
        let e2 = encrypt_to_relay(&pk, [0u8; 32], b"hello").unwrap();
        let p1 = SealedNote::<X25519, _>::parse(e1.envelope.as_slice()).unwrap();
        let p2 = SealedNote::<X25519, _>::parse(e2.envelope.as_slice()).unwrap();
        // Fresh ephemeral key per call.
        assert_ne!(p1.epk(), p2.epk());
        assert_ne!(e1.envelope, e2.envelope);
    }

    #[test]
    fn test_relay_id_is_authenticated() {
        let (sk, pk) = fresh_relay();
        let mut env = encrypt_to_relay(&pk, [0xAA; 32], b"hello").unwrap();
        env.relay_id = [0xBB; 32];
        assert!(decrypt_from_companion(&sk, &env).is_err());
    }
}

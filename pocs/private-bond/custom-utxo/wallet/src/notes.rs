use ff::PrimeField;
use sealring::{Domain, Recipient, SealedNote, X25519};
use poseidon_rs::{Fr, Poseidon};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::keys::ShieldedKeys;

/// Additional authenticated data. Empty: a memo binds nothing outside the note
/// itself, matching what the hand-rolled scheme did.
const AAD: &[u8] = &[];

/// Note codec and domain tag the memo is sealed under.
struct MemoDomain;

impl Domain for MemoDomain {
    type Note = Note;
    type Error = bincode::Error;

    const DOMAIN_TAG: &'static str = "private-bond/custom-utxo/memo-v1";

    fn encode_note(note: &Self::Note, out: &mut Vec<u8>) -> Result<(), Self::Error> {
        let bytes = bincode::serialize(note)?;
        out.extend_from_slice(&bytes);
        Ok(())
    }

    fn decode_note(bytes: &[u8]) -> Result<Self::Note, Self::Error> {
        bincode::deserialize(bytes)
    }
}

/// Encrypted memo: one `sealring` suite v1 envelope.
///
/// The envelope replaces the hand-rolled `[32-byte ephemeral pubkey][ciphertext]`
/// framing. It carries a version byte, a KEM id, the ephemeral public key, a
/// key-commitment tag, and the ciphertext. Two properties are new. The recipient
/// public key is mixed into the KDF, so a crafted ephemeral key cannot make two
/// recipients derive the same memo key. And the AEAD nonce comes out of the KDF
/// rather than being a hardcoded zero, so it changes with every ephemeral key
/// instead of relying on the caller never reusing one.
#[derive(Debug)]
pub struct Memo(SealedNote<X25519, Vec<u8>>);

impl Memo {
    /// Ephemeral public key the sender used for this memo (32 bytes).
    #[cfg(test)]
    pub fn ephemeral_pubkey(&self) -> &[u8] {
        self.0.epk()
    }

    /// Serialize memo to its envelope bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }

    /// Deserialize memo from envelope bytes, rejecting anything that is not a
    /// well-formed X25519 envelope.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        SealedNote::parse(bytes.to_vec())
            .map(Memo)
            .map_err(|e| e.to_string())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Note {
    pub value: u64,
    pub salt: u64,
    pub owner: u64,
    pub asset_id: u64,
    pub maturity_date: u64, // Unix timestamp
}

impl Note {
    pub fn commit(&self) -> Fr {
        let f_val = Fr::from_str(&self.value.to_string()).unwrap();

        let f_owner = Fr::from_str(&self.owner.to_string()).unwrap();

        let f_salt = Fr::from_str(&self.salt.to_string()).expect("Salt too large for field?");

        let f_asset = Fr::from_str(&self.asset_id.to_string()).unwrap();

        let f_maturity_date = Fr::from_str(&self.maturity_date.to_string()).unwrap();

        let hasher = Poseidon::new();
        hasher
            .hash(vec![f_val, f_salt, f_owner, f_asset, f_maturity_date])
            .unwrap()
    }

    pub fn nullifer(&self, private_key: Fr) -> Fr {
        let f_salt = Fr::from_str(&self.salt.to_string()).expect("Salt too large for field?");

        let hasher = Poseidon::new();
        hasher.hash(vec![f_salt, private_key]).unwrap()
    }

    /// Seal a memo to the recipient's X25519 viewing key.
    /// Provides forward secrecy: compromise of static keys doesn't reveal past messages
    pub fn encrypt(
        _sender_keys: &ShieldedKeys, // Unused - we use ephemeral keys for forward secrecy
        recipient_pubkey: &[u8; 32],
        data: &Note,
    ) -> Result<Memo, String> {
        let recipient = PublicKey::from(*recipient_pubkey);
        sealring::seal::<X25519, MemoDomain>(&recipient, data, AAD, &mut rand::rng())
            .map(Memo)
            .map_err(|e| format!("Encryption failed: {}", e))
    }

    /// Open a memo with the recipient's viewing key.
    /// Note: Sender identity is not authenticated - use ZK proofs for ownership verification
    pub fn decrypt(recipient_keys: &ShieldedKeys, memo: &Memo) -> Result<Note, String> {
        let secret = StaticSecret::from(*recipient_keys.seed());
        let recipient = Recipient::<X25519>::new(secret);

        sealring::open::<X25519, MemoDomain, _>(&recipient, &memo.0, AAD)
            .map_err(|e| format!("Decryption failed: {}", e))?
            .ok_or_else(|| "Decryption failed: memo is not addressed to this key".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_note() -> Note {
        Note {
            value: 1_000_000,
            salt: 0xDEADBEEF,
            owner: 12345,
            asset_id: 1,
            maturity_date: 1893456000, // 2030-01-01
        }
    }

    #[test]
    fn test_memo_roundtrip_encryption() {
        // Setup: Alice sends memo to Bob
        let alice_keys = ShieldedKeys::generate();
        let bob_keys = ShieldedKeys::generate();
        let original_note = create_test_note();

        // Alice encrypts memo for Bob
        let memo = Note::encrypt(&alice_keys, bob_keys.public_viewing_key(), &original_note)
            .expect("Encryption should succeed");

        // Bob decrypts memo
        let decrypted_note =
            Note::decrypt(&bob_keys, &memo).expect("Decryption should succeed");

        // Verify note contents match
        assert_eq!(decrypted_note.value, original_note.value);
        assert_eq!(decrypted_note.salt, original_note.salt);
        assert_eq!(decrypted_note.owner, original_note.owner);
        assert_eq!(decrypted_note.asset_id, original_note.asset_id);
        assert_eq!(decrypted_note.maturity_date, original_note.maturity_date);
    }

    #[test]
    fn test_memo_serialization() {
        let alice_keys = ShieldedKeys::generate();
        let bob_keys = ShieldedKeys::generate();
        let note = create_test_note();

        // Encrypt and serialize
        let memo = Note::encrypt(&alice_keys, bob_keys.public_viewing_key(), &note).unwrap();
        let bytes = memo.to_bytes();

        // Deserialize and decrypt
        let restored_memo = Memo::from_bytes(&bytes).expect("Deserialization should succeed");
        let decrypted = Note::decrypt(&bob_keys, &restored_memo).unwrap();

        assert_eq!(decrypted.value, note.value);
        assert_eq!(memo.ephemeral_pubkey(), restored_memo.ephemeral_pubkey());
    }

    #[test]
    fn test_wrong_recipient_cannot_decrypt() {
        let alice_keys = ShieldedKeys::generate();
        let bob_keys = ShieldedKeys::generate();
        let charlie_keys = ShieldedKeys::generate(); // Wrong recipient
        let note = create_test_note();

        // Alice encrypts for Bob
        let memo = Note::encrypt(&alice_keys, bob_keys.public_viewing_key(), &note).unwrap();

        // Charlie tries to decrypt - should fail
        let result = Note::decrypt(&charlie_keys, &memo);
        assert!(result.is_err(), "Wrong recipient should not decrypt");
    }

    #[test]
    fn test_ephemeral_keys_are_unique() {
        let alice_keys = ShieldedKeys::generate();
        let bob_keys = ShieldedKeys::generate();
        let note = create_test_note();

        // Encrypt same note twice
        let memo1 = Note::encrypt(&alice_keys, bob_keys.public_viewing_key(), &note).unwrap();
        let memo2 = Note::encrypt(&alice_keys, bob_keys.public_viewing_key(), &note).unwrap();

        // Ephemeral keys should be different (fresh per message)
        assert_ne!(
            memo1.ephemeral_pubkey(),
            memo2.ephemeral_pubkey(),
            "Each encryption should use a fresh ephemeral key"
        );

        // But both should decrypt correctly
        let decrypted1 = Note::decrypt(&bob_keys, &memo1).unwrap();
        let decrypted2 = Note::decrypt(&bob_keys, &memo2).unwrap();
        assert_eq!(decrypted1.value, decrypted2.value);
    }

    #[test]
    fn test_memo_from_bytes_too_short() {
        let short_bytes = [0u8; 16]; // Shorter than the smallest envelope
        let result = Memo::from_bytes(&short_bytes);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too short"));
    }

    #[test]
    fn test_sender_keys_not_needed_for_decryption() {
        // This test verifies that recipient doesn't need sender's static keys
        let alice_keys = ShieldedKeys::generate();
        let bob_keys = ShieldedKeys::generate();
        let note = create_test_note();

        let memo = Note::encrypt(&alice_keys, bob_keys.public_viewing_key(), &note).unwrap();

        // Bob decrypts without any reference to Alice's keys
        // (the ephemeral pubkey in memo is all that's needed)
        let decrypted = Note::decrypt(&bob_keys, &memo).unwrap();
        assert_eq!(decrypted.value, note.value);
    }
}

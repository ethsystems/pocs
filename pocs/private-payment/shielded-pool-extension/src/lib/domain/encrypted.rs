use serde::{
    Deserialize,
    Serialize,
};

use super::keys::ViewingPubkey;
use crate::domain::commitment::Commitment;

/// An encrypted note payload: one `sealring` suite v1 envelope, carried verbatim.
///
/// The envelope is self-framing (version, kem id, ephemeral public key, commit,
/// ciphertext), so this type adds no framing of its own and stays a dumb byte
/// carrier. `crypto::encryption::decrypt_note` is what parses and validates it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedNote {
    /// The `sealring` envelope bytes.
    pub bytes: Vec<u8>,
}

impl EncryptedNote {
    /// Create from envelope bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Borrow the envelope bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Serialize to bytes for the on-chain event log (the `Deposit`/`Transfer`
    /// event carries the encrypted note; it is not written to contract storage).
    /// Log cost is linear in ciphertext size; a production deployment would use a
    /// compact note format or an off-chain note log with FMD/OMR note-discovery
    /// (SPEC "Off-Chain State-Replica Server").
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.is_empty() {
            return Err("Empty bytes");
        }

        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }
}

/// A P2P message containing an encrypted note and its commitment.
/// Used for off-chain note delivery between transactors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2pMessage {
    /// The encrypted note
    pub encrypted_note: EncryptedNote,
    /// The commitment (for identifying the note on-chain)
    pub commitment: Commitment,
    /// The recipient's viewing public key (for routing)
    pub recipient_viewing_pubkey: ViewingPubkey,
}

impl P2pMessage {
    /// Create a new P2P message.
    pub fn new(
        encrypted_note: EncryptedNote,
        commitment: Commitment,
        recipient_viewing_pubkey: ViewingPubkey,
    ) -> Self {
        Self {
            encrypted_note,
            commitment,
            recipient_viewing_pubkey,
        }
    }
}

/// Encrypted notes payload for on-chain transfer events.
/// Contains two encrypted notes (one for each output).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedTransferNotes {
    /// Encrypted note for output 1
    pub note_1: EncryptedNote,
    /// Encrypted note for output 2
    pub note_2: EncryptedNote,
}

impl EncryptedTransferNotes {
    /// Create from two encrypted notes.
    pub fn new(note_1: EncryptedNote, note_2: EncryptedNote) -> Self {
        Self { note_1, note_2 }
    }

    /// Serialize to bytes for the on-chain `Transfer` event log (see
    /// [`EncryptedNote::to_bytes`] for the calldata-size note).
    pub fn to_bytes(&self) -> Vec<u8> {
        let bytes_1 = self.note_1.to_bytes();
        let bytes_2 = self.note_2.to_bytes();

        let mut bytes = Vec::with_capacity(4 + bytes_1.len() + bytes_2.len());
        bytes.extend_from_slice(&(bytes_1.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&bytes_1);
        bytes.extend_from_slice(&bytes_2);
        bytes
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 4 {
            return Err("Invalid encrypted transfer notes format");
        }

        let len_1 = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        if bytes.len() < 4 + len_1 {
            return Err("Invalid encrypted transfer notes format");
        }

        let note_1 = EncryptedNote::from_bytes(&bytes[4..4 + len_1])?;
        let note_2 = EncryptedNote::from_bytes(&bytes[4 + len_1..])?;

        Ok(Self { note_1, note_2 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypted_note_roundtrip() {
        let note = EncryptedNote::new(vec![0xAB; 133]);
        let bytes = note.to_bytes();
        let recovered = EncryptedNote::from_bytes(&bytes).unwrap();

        assert_eq!(note.bytes, recovered.bytes);
    }

    #[test]
    fn test_encrypted_transfer_notes_roundtrip() {
        let note_1 = EncryptedNote::new(vec![0xAB; 133]);
        let note_2 = EncryptedNote::new(vec![0xCD; 113]);
        let notes = EncryptedTransferNotes::new(note_1, note_2);

        let bytes = notes.to_bytes();
        let recovered = EncryptedTransferNotes::from_bytes(&bytes).unwrap();

        assert_eq!(notes.note_1.bytes, recovered.note_1.bytes);
        assert_eq!(notes.note_2.bytes, recovered.note_2.bytes);
    }
}

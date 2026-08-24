use alloy::primitives::B256;

use super::note::Note;
use crate::crypto::poseidon::swap_id_hash;

/// Terms of a swap agreed upon by both parties during intent matching.
///
/// Both parties compute the same `swap_id` from these terms + a shared nonce.
/// The TEE later verifies that locked notes match these terms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapTerms {
    /// Deterministic swap identifier: H(DOMAIN_SWAP_ID, value_a, asset_id_a, chain_id_a,
    ///   value_b, asset_id_b, chain_id_b, timeout, pk_meta_a, pk_meta_b, nonce)
    pub swap_id: B256,
    /// Chain for Party A's note
    pub chain_id_a: B256,
    /// Chain for Party B's note
    pub chain_id_b: B256,
    /// Value of Party A's note
    pub value_a: u64,
    /// Value of Party B's note
    pub value_b: u64,
    /// Asset identifier for Party A's note
    pub asset_id_a: B256,
    /// Asset identifier for Party B's note
    pub asset_id_b: B256,
    /// Shared timeout (block.timestamp) — both notes use the same timeout
    pub timeout: B256,
    /// Party A's meta public key x-coordinate
    pub pk_meta_a: B256,
    /// Party B's meta public key x-coordinate
    pub pk_meta_b: B256,
    /// Random nonce agreed during intent matching (ensures unique swap_id per deal)
    pub nonce: B256,
}

impl SwapTerms {
    /// Create swap terms and compute the deterministic swap_id.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id_a: B256,
        chain_id_b: B256,
        value_a: u64,
        value_b: u64,
        asset_id_a: B256,
        asset_id_b: B256,
        timeout: B256,
        pk_meta_a: B256,
        pk_meta_b: B256,
        nonce: B256,
    ) -> Self {
        let swap_id = swap_id_hash(
            value_a,
            asset_id_a,
            chain_id_a,
            value_b,
            asset_id_b,
            chain_id_b,
            timeout,
            pk_meta_a,
            pk_meta_b,
            nonce,
        );

        Self {
            swap_id,
            chain_id_a,
            chain_id_b,
            value_a,
            value_b,
            asset_id_a,
            asset_id_b,
            timeout,
            pk_meta_a,
            pk_meta_b,
            nonce,
        }
    }
}

/// What each party sends to the TEE (via RA-TLS) after locking their note.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PartySubmission {
    /// Swap identifier (both parties must submit the same swap_id)
    pub swap_id: B256,
    /// Random nonce (agreed during intent matching)
    pub nonce: B256,
    /// Ephemeral public key R = r·G (x-coordinate)
    pub ephemeral_pubkey: B256,
    /// Salt encrypted with ECDH-derived key: salt XOR H(DOMAIN_SALT_ENC, shared.x)
    pub encrypted_salt: B256,
    /// Plaintext note details (for TEE recomputation of commitment + binding checks)
    pub note_details: Note,
}

/// What the TEE announces on-chain after verifying both submissions.
///
/// A single `announceSwap` transaction reveals both ephemeral keys + encrypted salts
/// atomically, enabling both parties to claim their counterparty's note.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SwapAnnouncement {
    /// Swap identifier
    pub swap_id: B256,
    /// Party A's ephemeral public key (R_A x-coordinate)
    pub ephemeral_key_a: B256,
    /// Party B's ephemeral public key (R_B x-coordinate)
    pub ephemeral_key_b: B256,
    /// Party A's encrypted salt
    pub encrypted_salt_a: B256,
    /// Party B's encrypted salt
    pub encrypted_salt_b: B256,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_swap_terms() -> SwapTerms {
        SwapTerms::new(
            B256::left_padding_from(&[1]),    // chain_id_a
            B256::left_padding_from(&[2]),    // chain_id_b
            1000,                              // value_a
            2000,                              // value_b
            B256::repeat_byte(0x01),           // asset_id_a (USD)
            B256::repeat_byte(0x02),           // asset_id_b (BOND)
            B256::left_padding_from(&[0x01, 0x00]), // timeout
            B256::repeat_byte(0xAA),           // pk_meta_a
            B256::repeat_byte(0xBB),           // pk_meta_b
            B256::repeat_byte(0xFF),           // nonce
        )
    }

    #[test]
    fn test_swap_terms_computes_swap_id() {
        let terms = test_swap_terms();
        assert_ne!(terms.swap_id, B256::ZERO);
    }

    #[test]
    fn test_swap_terms_swap_id_deterministic() {
        let terms1 = test_swap_terms();
        let terms2 = test_swap_terms();
        assert_eq!(terms1.swap_id, terms2.swap_id);
    }

    #[test]
    fn test_swap_terms_nonce_sensitivity() {
        let terms1 = test_swap_terms();
        let terms2 = SwapTerms::new(
            B256::left_padding_from(&[1]),
            B256::left_padding_from(&[2]),
            1000,
            2000,
            B256::repeat_byte(0x01),
            B256::repeat_byte(0x02),
            B256::left_padding_from(&[0x01, 0x00]),
            B256::repeat_byte(0xAA),
            B256::repeat_byte(0xBB),
            B256::repeat_byte(0xEE), // different nonce
        );
        assert_ne!(terms1.swap_id, terms2.swap_id);
    }

    #[test]
    fn test_party_submission_construction() {
        let note = Note::with_salt(
            B256::left_padding_from(&[1]),
            1000,
            B256::repeat_byte(0x01),
            B256::repeat_byte(0xBB),
            B256::repeat_byte(0xCC),
            B256::left_padding_from(&[0x01, 0x00]),
            B256::repeat_byte(0x42),
        );

        let submission = PartySubmission {
            swap_id: B256::repeat_byte(0x10),
            nonce: B256::repeat_byte(0xFF),
            ephemeral_pubkey: B256::repeat_byte(0x20),
            encrypted_salt: B256::repeat_byte(0x30),
            note_details: note.clone(),
        };

        assert_eq!(submission.swap_id, B256::repeat_byte(0x10));
        assert_eq!(submission.note_details, note);
    }

    #[test]
    fn test_swap_announcement_construction() {
        let announcement = SwapAnnouncement {
            swap_id: B256::repeat_byte(0x10),
            ephemeral_key_a: B256::repeat_byte(0x20),
            ephemeral_key_b: B256::repeat_byte(0x30),
            encrypted_salt_a: B256::repeat_byte(0x40),
            encrypted_salt_b: B256::repeat_byte(0x50),
        };

        assert_eq!(announcement.swap_id, B256::repeat_byte(0x10));
    }
}

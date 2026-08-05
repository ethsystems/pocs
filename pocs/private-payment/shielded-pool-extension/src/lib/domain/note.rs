use alloy::primitives::{
    Address,
    B256,
    U256,
};
use rand::RngExt;
use serde::{
    Deserialize,
    Serialize,
};

use super::{
    commitment::Commitment,
    epoch::Epoch,
    keys::{
        OwnerPubkey,
        SpendingKey,
    },
    nullifier::Nullifier,
};
use crate::crypto::poseidon::poseidon5;

/// A note represents a private balance owned by a spending key.
/// Notes are the UTXO primitive in the shielded pool.
///
/// Extended vs parent: carries `epoch_created`, the value of `currentEpoch`
/// when the note was committed, bound into the commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Note {
    /// ERC-20 token contract address
    pub token: Address,
    /// Token amount (raw units, no decimals)
    pub amount: U256,
    /// Spending public key of the owner
    pub owner_pubkey: OwnerPubkey,
    /// Random salt for hiding (prevents commitment collisions)
    pub salt: B256,
    /// Value of `currentEpoch` at the moment this note was committed
    pub epoch_created: Epoch,
}

impl Note {
    /// Create a new note with a random salt.
    pub fn new(
        token: Address,
        amount: U256,
        owner_pubkey: OwnerPubkey,
        epoch_created: Epoch,
    ) -> Self {
        let mut rng = rand::rng();
        let mut salt_bytes = [0u8; 32];
        rng.fill(&mut salt_bytes[5..]); // 27 random bytes (top 5 zeroed) stay < BN254 modulus; no rejection sampling

        Self {
            token,
            amount,
            owner_pubkey,
            salt: B256::from(salt_bytes),
            epoch_created,
        }
    }

    /// Create a note with a specific salt (for testing or reconstruction).
    pub fn with_salt(
        token: Address,
        amount: U256,
        owner_pubkey: OwnerPubkey,
        salt: B256,
        epoch_created: Epoch,
    ) -> Self {
        Self {
            token,
            amount,
            owner_pubkey,
            salt,
            epoch_created,
        }
    }

    /// Create a zero-value note (used for padding 2-in-2-out transfers).
    pub fn zero(token: Address, owner_pubkey: OwnerPubkey, epoch_created: Epoch) -> Self {
        Self::new(token, U256::ZERO, owner_pubkey, epoch_created)
    }

    /// Compute the commitment for this note.
    /// commitment = poseidon5(token, amount, owner_pubkey, salt, epoch_created)
    pub fn commitment(&self) -> Commitment {
        // Convert address to B256 (pad with zeros on the left)
        let token_b256 = B256::left_padding_from(self.token.as_slice());

        // Convert amount to B256
        let amount_b256: B256 = self.amount.into();

        let hash = poseidon5(
            token_b256,
            amount_b256,
            self.owner_pubkey.0,
            self.salt,
            self.epoch_created.as_field(),
        );
        Commitment(hash)
    }

    /// Compute the per-epoch nullifier for this note given the spending key.
    /// η_e = poseidon3(commitment, spending_key, epoch)
    pub fn nullifier(&self, spending_key: &SpendingKey, epoch: Epoch) -> Nullifier {
        self.commitment().nullifier(spending_key, epoch)
    }

    /// Check if this is a zero-value note.
    pub fn is_zero(&self) -> bool {
        self.amount == U256::ZERO
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_note_commitment_deterministic() {
        let sk = SpendingKey::random();
        let pk = sk.derive_owner_pubkey();
        let salt = B256::ZERO;
        let token = Address::ZERO;
        let amount = U256::from(1000u64);

        let note1 = Note::with_salt(token, amount, pk, salt, Epoch(2));
        let note2 = Note::with_salt(token, amount, pk, salt, Epoch(2));

        assert_eq!(note1.commitment(), note2.commitment());
    }

    #[test]
    fn test_note_commitment_different_salts() {
        let sk = SpendingKey::random();
        let pk = sk.derive_owner_pubkey();
        let token = Address::ZERO;
        let amount = U256::from(1000u64);

        let note1 = Note::new(token, amount, pk, Epoch::GENESIS);
        let note2 = Note::new(token, amount, pk, Epoch::GENESIS);

        // Different random salts should produce different commitments
        assert_ne!(note1.commitment(), note2.commitment());
    }

    #[test]
    fn test_note_commitment_binds_epoch() {
        // Identical note fields, different epoch_created => different commitment.
        let sk = SpendingKey::random();
        let pk = sk.derive_owner_pubkey();
        let salt = B256::ZERO;
        let token = Address::ZERO;
        let amount = U256::from(1000u64);

        let note0 = Note::with_salt(token, amount, pk, salt, Epoch(0));
        let note1 = Note::with_salt(token, amount, pk, salt, Epoch(1));

        assert_ne!(note0.commitment(), note1.commitment());
    }

    #[test]
    fn test_note_nullifier_per_epoch() {
        let sk = SpendingKey::random();
        let pk = sk.derive_owner_pubkey();
        let note = Note::new(Address::ZERO, U256::from(1000u64), pk, Epoch(0));

        // Deterministic within an epoch...
        assert_eq!(note.nullifier(&sk, Epoch(0)), note.nullifier(&sk, Epoch(0)));
        // ...and distinct across epochs.
        assert_ne!(note.nullifier(&sk, Epoch(0)), note.nullifier(&sk, Epoch(1)));
    }

    #[test]
    fn test_zero_note() {
        let sk = SpendingKey::random();
        let pk = sk.derive_owner_pubkey();
        let note = Note::zero(Address::ZERO, pk, Epoch::GENESIS);

        assert!(note.is_zero());
        assert_eq!(note.amount, U256::ZERO);
    }
}

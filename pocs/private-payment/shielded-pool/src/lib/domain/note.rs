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
    keys::{
        OwnerPubkey,
        SpendingKey,
    },
    nullifier::Nullifier,
};
use crate::crypto::poseidon::poseidon4;

/// A note represents a private balance owned by a spending key.
/// Notes are the UTXO primitive in the shielded pool.
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
}

impl Note {
    /// Create a new note with a random salt.
    pub fn new(token: Address, amount: U256, owner_pubkey: OwnerPubkey) -> Self {
        let mut rng = rand::rng();
        let mut salt_bytes = [0u8; 32];
        rng.fill(&mut salt_bytes[5..]); // keep within the field

        Self {
            token,
            amount,
            owner_pubkey,
            salt: B256::from(salt_bytes),
        }
    }

    /// Create a note with a specific salt (for testing or reconstruction).
    pub fn with_salt(
        token: Address,
        amount: U256,
        owner_pubkey: OwnerPubkey,
        salt: B256,
    ) -> Self {
        Self {
            token,
            amount,
            owner_pubkey,
            salt,
        }
    }

    /// Create a zero-value note (used for padding 2-in-2-out transfers).
    pub fn zero(token: Address, owner_pubkey: OwnerPubkey) -> Self {
        Self::new(token, U256::ZERO, owner_pubkey)
    }

    /// Compute the commitment for this note.
    /// commitment = poseidon4(token, amount, owner_pubkey, salt)
    pub fn commitment(&self) -> Commitment {
        // Convert address to B256 (pad with zeros on the left)
        let token_b256 = B256::left_padding_from(self.token.as_slice());

        // Convert amount to B256
        let amount_b256: B256 = self.amount.into();

        let hash = poseidon4(token_b256, amount_b256, self.owner_pubkey.0, self.salt);
        Commitment(hash)
    }

    /// Compute the nullifier for this note given the spending key.
    /// nullifier = poseidon2(commitment, spending_key)
    pub fn nullifier(&self, spending_key: &SpendingKey) -> Nullifier {
        self.commitment().nullifier(spending_key)
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

        let note1 = Note::with_salt(token, amount, pk, salt);
        let note2 = Note::with_salt(token, amount, pk, salt);

        assert_eq!(note1.commitment(), note2.commitment());
    }

    #[test]
    fn test_note_commitment_different_salts() {
        let sk = SpendingKey::random();
        let pk = sk.derive_owner_pubkey();
        let token = Address::ZERO;
        let amount = U256::from(1000u64);

        let note1 = Note::new(token, amount, pk);
        let note2 = Note::new(token, amount, pk);

        // Different random salts should produce different commitments
        assert_ne!(note1.commitment(), note2.commitment());
    }

    #[test]
    fn test_note_nullifier() {
        let sk = SpendingKey::random();
        let pk = sk.derive_owner_pubkey();
        let note = Note::new(Address::ZERO, U256::from(1000u64), pk);

        let nullifier1 = note.nullifier(&sk);
        let nullifier2 = note.nullifier(&sk);

        assert_eq!(nullifier1, nullifier2, "Nullifier should be deterministic");
    }

    #[test]
    fn test_zero_note() {
        let sk = SpendingKey::random();
        let pk = sk.derive_owner_pubkey();
        let note = Note::zero(Address::ZERO, pk);

        assert!(note.is_zero());
        assert_eq!(note.amount, U256::ZERO);
    }

    // Regression: ballast (zero-value padding) notes MUST use a fresh random salt, so each
    // single-input transfer publishes a distinct ballast nullifier. A fixed zero salt makes the
    // ballast nullifier deterministic; once spent, every later single-input transfer of the same
    // token collides on it and reverts with NullifierAlreadySpent. `Note::zero` uses a random
    // salt, so two ballasts for the same (token, owner, spending_key) differ.
    #[test]
    fn test_ballast_notes_have_distinct_nullifiers() {
        let sk = SpendingKey::random();
        let pk = sk.derive_owner_pubkey();
        let token = Address::ZERO;

        let ballast1 = Note::zero(token, pk);
        let ballast2 = Note::zero(token, pk);

        assert_ne!(ballast1.salt, ballast2.salt, "ballast salt must be random, not fixed");
        assert_ne!(
            ballast1.nullifier(&sk),
            ballast2.nullifier(&sk),
            "distinct ballast salts must yield distinct nullifiers (no cross-transfer collision)"
        );

        // Contrast: the old fixed-zero-salt construction collides on both salt and nullifier.
        let fixed1 = Note::with_salt(token, U256::ZERO, pk, B256::ZERO);
        let fixed2 = Note::with_salt(token, U256::ZERO, pk, B256::ZERO);
        assert_eq!(
            fixed1.nullifier(&sk),
            fixed2.nullifier(&sk),
            "fixed zero salt reproduces the bug: identical ballast nullifiers"
        );
    }
}

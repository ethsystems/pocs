//! Value notes: the parent PoC's UTXO primitive, unchanged by this extension.
//! `commitment = Poseidon1(token, amount, owner_pubkey, salt)`,
//! `nullifier = Poseidon1(commitment, spending_key)`.

use ark_bn254::Fr;

use crate::{
    error::CryptoError,
    poseidon::{
        poseidon2,
        poseidon4,
    },
    types::{
        Address,
        Bytes32,
    },
};

use super::{
    keys::{
        OwnerPubkey,
        SpendingKey,
    },
    random_canonical_bytes32,
};

/// A private balance owned by a spending key. Mirrors `circuits/deposit/src/main.nr`'s
/// `commitment` binding: `hash_4([token, amount, owner_pubkey, salt])`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Note {
    pub token: Address,
    pub amount: u64,
    pub owner_pubkey: OwnerPubkey,
    pub salt: Bytes32,
}

impl Note {
    pub fn new(token: Address, amount: u64, owner_pubkey: OwnerPubkey) -> Self {
        Self {
            token,
            amount,
            owner_pubkey,
            salt: random_canonical_bytes32(),
        }
    }

    pub fn with_salt(
        token: Address,
        amount: u64,
        owner_pubkey: OwnerPubkey,
        salt: Bytes32,
    ) -> Self {
        Self {
            token,
            amount,
            owner_pubkey,
            salt,
        }
    }

    /// A zero-value padding note. SPEC "TxFacts construction": every minted or padded
    /// note carries a fresh random salt; a zero-value output note sets `owner_out =
    /// subject`, since pubkey `0` has no attestation leaf.
    pub fn zero(token: Address, owner_pubkey: OwnerPubkey) -> Self {
        Self::new(token, 0, owner_pubkey)
    }

    pub fn is_zero(&self) -> bool {
        self.amount == 0
    }

    pub fn commitment(&self) -> Result<Bytes32, CryptoError> {
        let owner = self.owner_pubkey.field()?;
        let salt = Fr::try_from(self.salt)?;
        let hash = poseidon4(Fr::from(self.token), Fr::from(self.amount), owner, salt);
        Ok(Bytes32::from(hash))
    }

    pub fn nullifier(&self, spending_key: &SpendingKey) -> Result<Bytes32, CryptoError> {
        let commitment = Fr::try_from(self.commitment()?)?;
        let hash = poseidon2(commitment, spending_key.field());
        Ok(Bytes32::from(hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subject() -> (SpendingKey, OwnerPubkey) {
        let sk = SpendingKey::random();
        let pk = sk.derive_owner_pubkey();
        (sk, pk)
    }

    #[test]
    fn commitment_is_deterministic_for_the_same_fields() {
        let (_, pk) = subject();
        let salt = Bytes32::from([0u8; 32]);
        let a = Note::with_salt(Address::from([1u8; 20]), 1000, pk, salt);
        let b = Note::with_salt(Address::from([1u8; 20]), 1000, pk, salt);
        assert_eq!(a.commitment().unwrap(), b.commitment().unwrap());
    }

    #[test]
    fn different_salts_produce_different_commitments() {
        let (_, pk) = subject();
        let a = Note::new(Address::from([1u8; 20]), 1000, pk);
        let b = Note::new(Address::from([1u8; 20]), 1000, pk);
        assert_ne!(a.commitment().unwrap(), b.commitment().unwrap());
    }

    #[test]
    fn nullifier_is_deterministic_for_the_same_spending_key() {
        let (sk, pk) = subject();
        let note = Note::new(Address::from([1u8; 20]), 1000, pk);
        assert_eq!(note.nullifier(&sk).unwrap(), note.nullifier(&sk).unwrap());
    }

    #[test]
    fn zero_note_has_zero_amount() {
        let (_, pk) = subject();
        let note = Note::zero(Address::from([1u8; 20]), pk);
        assert!(note.is_zero());
    }
}

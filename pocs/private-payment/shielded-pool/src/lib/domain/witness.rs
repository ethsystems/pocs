use alloy::primitives::{
    Address,
    B256,
    U256,
};
use serde::{
    Deserialize,
    Serialize,
};

use super::{
    commitment::payload_commitment,
    keys::{
        OwnerPubkey,
        SpendingKey,
    },
    merkle::{
        AttestationMerkleProof,
        CommitmentMerkleProof,
    },
    note::Note,
};

/// Witness (public + private inputs) for the deposit circuit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositWitness {
    // === Public Inputs ===
    /// The note commitment being created
    pub commitment: B256,
    /// ERC-20 token address
    pub token: Address,
    /// Deposit amount
    pub amount: U256,
    /// Address the pool pulls the tokens from (bound in the proof)
    pub funding_address: Address,
    /// Current root of attestation tree
    pub attestation_root: B256,
    /// Commitment to the encrypted note payload (keccak256 mod p)
    pub payload_hash: B256,

    // === Private Inputs ===
    /// Depositor's spending key; the circuit derives owner_pubkey = poseidon1(spending_key)
    pub spending_key: SpendingKey,
    /// Depositor's spending public key (derived; must equal the note owner)
    pub owner_pubkey: OwnerPubkey,
    /// Random salt used in commitment
    pub salt: B256,
    /// The attester address that issued the attestation
    pub attester: Address,
    /// Timestamp when the attestation was issued
    pub issued_at: u64,
    /// Timestamp when the attestation expires (0 = no expiry)
    pub expires_at: u64,
    /// Merkle path in attestation tree
    pub attestation_proof: AttestationMerkleProof,
}

impl DepositWitness {
    /// Create a deposit witness from a note, the depositor's spending key, the funding
    /// address, and attestation data.
    pub fn new(
        note: &Note,
        spending_key: SpendingKey,
        funding_address: Address,
        attestation_root: B256,
        attester: Address,
        issued_at: u64,
        expires_at: u64,
        attestation_proof: AttestationMerkleProof,
        encrypted_payload: &[u8],
    ) -> Self {
        Self {
            commitment: note.commitment().0,
            token: note.token,
            amount: note.amount,
            funding_address,
            attestation_root,
            payload_hash: payload_commitment(encrypted_payload),
            owner_pubkey: spending_key.derive_owner_pubkey(),
            spending_key,
            salt: note.salt,
            attester,
            issued_at,
            expires_at,
            attestation_proof,
        }
    }
}

/// Witness (public + private inputs) for the transfer circuit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferWitness {
    // === Public Inputs ===
    /// Nullifiers for the two input notes
    pub nullifiers: [B256; 2],
    /// Commitments for the two output notes
    pub output_commitments: [B256; 2],
    /// Commitment tree root used for the proof
    pub commitment_root: B256,
    /// Commitment to the encrypted notes payload (keccak256 mod p)
    pub payload_hash: B256,

    // === Private Inputs ===
    /// Sender's spending key
    pub spending_key: SpendingKey,
    /// The two input notes being spent
    pub input_notes: [Note; 2],
    /// The two output notes being created
    pub output_notes: [Note; 2],
    /// Merkle proofs for input commitments
    pub input_proofs: [CommitmentMerkleProof; 2],
}

impl TransferWitness {
    /// Create a transfer witness.
    pub fn new(
        spending_key: SpendingKey,
        input_notes: [Note; 2],
        output_notes: [Note; 2],
        input_proofs: [CommitmentMerkleProof; 2],
        commitment_root: B256,
        encrypted_payload: &[u8],
    ) -> Self {
        let nullifiers = [
            input_notes[0].nullifier(&spending_key).0,
            input_notes[1].nullifier(&spending_key).0,
        ];

        let output_commitments = [
            output_notes[0].commitment().0,
            output_notes[1].commitment().0,
        ];

        Self {
            nullifiers,
            output_commitments,
            commitment_root,
            payload_hash: payload_commitment(encrypted_payload),
            spending_key,
            input_notes,
            output_notes,
            input_proofs,
        }
    }

    /// Validate that input amounts equal output amounts (value preservation).
    pub fn validate_amounts(&self) -> bool {
        let input_sum = self.input_notes[0].amount + self.input_notes[1].amount;
        let output_sum = self.output_notes[0].amount + self.output_notes[1].amount;
        input_sum == output_sum
    }

    /// Validate that all notes use the same token.
    pub fn validate_token_consistency(&self) -> bool {
        let token = self.input_notes[0].token;
        self.input_notes[1].token == token
            && self.output_notes[0].token == token
            && self.output_notes[1].token == token
    }
}

/// Witness (public + private inputs) for the withdraw circuit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawWitness {
    // === Public Inputs ===
    /// Nullifier for the note being spent
    pub nullifier: B256,
    /// ERC-20 token address
    pub token: Address,
    /// Withdrawal amount
    pub amount: U256,
    /// Recipient address
    pub recipient: Address,
    /// Commitment tree root used for the proof
    pub commitment_root: B256,

    // === Private Inputs ===
    /// Owner's spending key
    pub spending_key: SpendingKey,
    /// The note being withdrawn
    pub note: Note,
    /// Merkle proof for the commitment
    pub commitment_proof: CommitmentMerkleProof,
}

impl WithdrawWitness {
    /// Create a withdraw witness.
    pub fn new(
        spending_key: SpendingKey,
        note: Note,
        commitment_proof: CommitmentMerkleProof,
        commitment_root: B256,
        recipient: Address,
    ) -> Self {
        let nullifier = note.nullifier(&spending_key).0;

        Self {
            nullifier,
            token: note.token,
            amount: note.amount,
            recipient,
            commitment_root,
            spending_key,
            note,
            commitment_proof,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::keys::SpendingKey;

    #[test]
    fn test_transfer_witness_value_preservation() {
        let sk = SpendingKey::random();
        let pk = sk.derive_owner_pubkey();
        let token = Address::ZERO;

        let input_notes = [
            Note::new(token, U256::from(600u64), pk),
            Note::new(token, U256::from(400u64), pk),
        ];

        let output_notes = [
            Note::new(token, U256::from(700u64), pk),
            Note::new(token, U256::from(300u64), pk),
        ];

        let dummy_proof = CommitmentMerkleProof::new(vec![], vec![], 0);
        let witness = TransferWitness::new(
            sk,
            input_notes,
            output_notes,
            [dummy_proof.clone(), dummy_proof],
            B256::ZERO,
            b"",
        );

        assert!(witness.validate_amounts());
        assert!(witness.validate_token_consistency());
    }

    #[test]
    fn test_transfer_witness_invalid_amounts() {
        let sk = SpendingKey::random();
        let pk = sk.derive_owner_pubkey();
        let token = Address::ZERO;

        let input_notes = [
            Note::new(token, U256::from(600u64), pk),
            Note::new(token, U256::from(400u64), pk),
        ];

        // Output sum != input sum
        let output_notes = [
            Note::new(token, U256::from(800u64), pk),
            Note::new(token, U256::from(300u64), pk),
        ];

        let dummy_proof = CommitmentMerkleProof::new(vec![], vec![], 0);
        let witness = TransferWitness::new(
            sk,
            input_notes,
            output_notes,
            [dummy_proof.clone(), dummy_proof],
            B256::ZERO,
            b"",
        );

        assert!(!witness.validate_amounts());
    }
}

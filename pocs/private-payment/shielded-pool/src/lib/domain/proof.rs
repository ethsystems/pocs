use alloy::primitives::{
    Address,
    B256,
    Bytes,
    U256,
};
use serde::{
    Deserialize,
    Serialize,
};

/// ZK proof output for the deposit circuit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositProof {
    /// The serialized proof bytes
    pub proof: Bytes,
    /// Public inputs: [commitment, token, amount, funding_address, attestation_root, payload_hash]
    pub public_inputs: DepositPublicInputs,
}

/// Public inputs for the deposit circuit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositPublicInputs {
    pub commitment: B256,
    pub token: Address,
    pub amount: U256,
    pub funding_address: Address,
    pub attestation_root: B256,
    pub payload_hash: B256,
}

impl DepositProof {
    /// Create a new deposit proof.
    pub fn new(
        proof: Bytes,
        commitment: B256,
        token: Address,
        amount: U256,
        funding_address: Address,
        attestation_root: B256,
        payload_hash: B256,
    ) -> Self {
        Self {
            proof,
            public_inputs: DepositPublicInputs {
                commitment,
                token,
                amount,
                funding_address,
                attestation_root,
                payload_hash,
            },
        }
    }

    /// Get the public inputs as an array of B256 for contract verification.
    pub fn public_inputs_as_array(&self) -> [B256; 6] {
        [
            self.public_inputs.commitment,
            B256::left_padding_from(self.public_inputs.token.as_slice()),
            self.public_inputs.amount.into(),
            B256::left_padding_from(self.public_inputs.funding_address.as_slice()),
            self.public_inputs.attestation_root,
            self.public_inputs.payload_hash,
        ]
    }
}

/// ZK proof output for the transfer circuit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferProof {
    /// The serialized proof bytes
    pub proof: Bytes,
    /// Public inputs
    pub public_inputs: TransferPublicInputs,
}

/// Public inputs for the transfer circuit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferPublicInputs {
    pub nullifier_0: B256,
    pub nullifier_1: B256,
    pub commitment_out_0: B256,
    pub commitment_out_1: B256,
    pub commitment_root: B256,
    pub payload_hash: B256,
}

impl TransferProof {
    /// Create a new transfer proof.
    pub fn new(
        proof: Bytes,
        nullifiers: [B256; 2],
        output_commitments: [B256; 2],
        commitment_root: B256,
        payload_hash: B256,
    ) -> Self {
        Self {
            proof,
            public_inputs: TransferPublicInputs {
                nullifier_0: nullifiers[0],
                nullifier_1: nullifiers[1],
                commitment_out_0: output_commitments[0],
                commitment_out_1: output_commitments[1],
                commitment_root,
                payload_hash,
            },
        }
    }

    /// Get the public inputs as an array of B256 for contract verification.
    pub fn public_inputs_as_array(&self) -> [B256; 6] {
        [
            self.public_inputs.nullifier_0,
            self.public_inputs.nullifier_1,
            self.public_inputs.commitment_out_0,
            self.public_inputs.commitment_out_1,
            self.public_inputs.commitment_root,
            self.public_inputs.payload_hash,
        ]
    }

    /// Get nullifiers as a fixed-size array.
    pub fn nullifiers(&self) -> [B256; 2] {
        [
            self.public_inputs.nullifier_0,
            self.public_inputs.nullifier_1,
        ]
    }

    /// Get output commitments as a fixed-size array.
    pub fn output_commitments(&self) -> [B256; 2] {
        [
            self.public_inputs.commitment_out_0,
            self.public_inputs.commitment_out_1,
        ]
    }
}

/// ZK proof output for the withdraw circuit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawProof {
    /// The serialized proof bytes
    pub proof: Bytes,
    /// Public inputs
    pub public_inputs: WithdrawPublicInputs,
}

/// Public inputs for the withdraw circuit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawPublicInputs {
    pub nullifier: B256,
    pub token: Address,
    pub amount: U256,
    pub recipient: Address,
    pub commitment_root: B256,
}

impl WithdrawProof {
    /// Create a new withdraw proof.
    pub fn new(
        proof: Bytes,
        nullifier: B256,
        token: Address,
        amount: U256,
        recipient: Address,
        commitment_root: B256,
    ) -> Self {
        Self {
            proof,
            public_inputs: WithdrawPublicInputs {
                nullifier,
                token,
                amount,
                recipient,
                commitment_root,
            },
        }
    }

    /// Get the public inputs as an array of B256 for contract verification.
    pub fn public_inputs_as_array(&self) -> [B256; 5] {
        [
            self.public_inputs.nullifier,
            B256::left_padding_from(self.public_inputs.token.as_slice()),
            self.public_inputs.amount.into(),
            B256::left_padding_from(self.public_inputs.recipient.as_slice()),
            self.public_inputs.commitment_root,
        ]
    }
}

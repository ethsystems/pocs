use std::path::PathBuf;

use alloy::primitives::{
    Address,
    B256,
    Bytes,
    U256,
};
use serde::Serialize;
use tokio::process::Command;

use crate::{
    domain::{
        merkle::{
            MAX_ATTESTATION_TREE_DEPTH,
            MAX_COMMITMENT_TREE_DEPTH,
        },
        proof::{
            DepositProof,
            TransferProof,
            WithdrawProof,
        },
        witness::{
            DepositWitness,
            TransferWitness,
            WithdrawWitness,
        },
    },
    ports,
};

/// Format a B256 as a hex string for Noir.
fn format_field(value: &B256) -> String {
    format!("{}", value)
}

/// Format an Address as a hex field for Noir (left-padded to 32 bytes).
fn format_field_from_address(addr: &Address) -> String {
    let b256 = B256::left_padding_from(addr.as_slice());
    format_field(&b256)
}

/// Format a U256 as a decimal string for Noir.
fn format_u256(value: &U256) -> String {
    value.to_string()
}

/// Pad a B256 path to `max_depth` and convert each element to a hex string.
fn pad_field_array(path: &[B256], max_depth: usize) -> Vec<String> {
    let mut padded = path.to_vec();
    padded.resize(max_depth, B256::ZERO);
    padded.iter().map(|v| format_field(v)).collect()
}

/// Pad an index array to `max_depth`.
fn pad_index_array(indices: &[u8], max_depth: usize) -> Vec<u8> {
    let mut padded = indices.to_vec();
    padded.resize(max_depth, 0);
    padded
}

#[derive(Serialize)]
struct DepositProverInput {
    commitment: String,
    token: String,
    amount: String,
    funding_address: String,
    attestation_root: String,
    payload_hash: String,
    spending_key: String,
    salt: String,
    attester: String,
    issued_at: u64,
    expires_at: u64,
    attestation_proof_length: usize,
    attestation_path: Vec<String>,
    attestation_indices: Vec<u8>,
}

impl From<&DepositWitness> for DepositProverInput {
    fn from(w: &DepositWitness) -> Self {
        Self {
            commitment: format_field(&w.commitment),
            token: format_field_from_address(&w.token),
            amount: format_u256(&w.amount),
            funding_address: format_field_from_address(&w.funding_address),
            attestation_root: format_field(&w.attestation_root),
            payload_hash: format_field(&w.payload_hash),
            spending_key: format_field(&w.spending_key.0),
            salt: format_field(&w.salt),
            attester: format_field_from_address(&w.attester),
            issued_at: w.issued_at,
            expires_at: w.expires_at,
            attestation_proof_length: w.attestation_proof.proof_length,
            attestation_path: pad_field_array(
                &w.attestation_proof.path,
                MAX_ATTESTATION_TREE_DEPTH,
            ),
            attestation_indices: pad_index_array(
                &w.attestation_proof.indices,
                MAX_ATTESTATION_TREE_DEPTH,
            ),
        }
    }
}

#[derive(Serialize)]
struct TransferProverInput {
    nullifier_0: String,
    nullifier_1: String,
    commitment_out_0: String,
    commitment_out_1: String,
    commitment_root: String,
    payload_hash: String,
    spending_key: String,
    token_in_0: String,
    amount_in_0: String,
    salt_in_0: String,
    token_in_1: String,
    amount_in_1: String,
    salt_in_1: String,
    token_out_0: String,
    amount_out_0: String,
    owner_out_0: String,
    salt_out_0: String,
    token_out_1: String,
    amount_out_1: String,
    owner_out_1: String,
    salt_out_1: String,
    proof_length_0: usize,
    path_0: Vec<String>,
    indices_0: Vec<u8>,
    proof_length_1: usize,
    path_1: Vec<String>,
    indices_1: Vec<u8>,
}

impl From<&TransferWitness> for TransferProverInput {
    fn from(w: &TransferWitness) -> Self {
        Self {
            nullifier_0: format_field(&w.nullifiers[0]),
            nullifier_1: format_field(&w.nullifiers[1]),
            commitment_out_0: format_field(&w.output_commitments[0]),
            commitment_out_1: format_field(&w.output_commitments[1]),
            commitment_root: format_field(&w.commitment_root),
            payload_hash: format_field(&w.payload_hash),
            spending_key: format_field(&w.spending_key.0),
            token_in_0: format_field_from_address(&w.input_notes[0].token),
            amount_in_0: format_u256(&w.input_notes[0].amount),
            salt_in_0: format_field(&w.input_notes[0].salt),
            token_in_1: format_field_from_address(&w.input_notes[1].token),
            amount_in_1: format_u256(&w.input_notes[1].amount),
            salt_in_1: format_field(&w.input_notes[1].salt),
            token_out_0: format_field_from_address(&w.output_notes[0].token),
            amount_out_0: format_u256(&w.output_notes[0].amount),
            owner_out_0: format_field(&w.output_notes[0].owner_pubkey.0),
            salt_out_0: format_field(&w.output_notes[0].salt),
            token_out_1: format_field_from_address(&w.output_notes[1].token),
            amount_out_1: format_u256(&w.output_notes[1].amount),
            owner_out_1: format_field(&w.output_notes[1].owner_pubkey.0),
            salt_out_1: format_field(&w.output_notes[1].salt),
            proof_length_0: w.input_proofs[0].proof_length,
            path_0: pad_field_array(&w.input_proofs[0].path, MAX_COMMITMENT_TREE_DEPTH),
            indices_0: pad_index_array(
                &w.input_proofs[0].indices,
                MAX_COMMITMENT_TREE_DEPTH,
            ),
            proof_length_1: w.input_proofs[1].proof_length,
            path_1: pad_field_array(&w.input_proofs[1].path, MAX_COMMITMENT_TREE_DEPTH),
            indices_1: pad_index_array(
                &w.input_proofs[1].indices,
                MAX_COMMITMENT_TREE_DEPTH,
            ),
        }
    }
}

#[derive(Serialize)]
struct WithdrawProverInput {
    nullifier: String,
    token: String,
    amount: String,
    recipient: String,
    commitment_root: String,
    spending_key: String,
    salt: String,
    proof_length: usize,
    path: Vec<String>,
    indices: Vec<u8>,
}

impl From<&WithdrawWitness> for WithdrawProverInput {
    fn from(w: &WithdrawWitness) -> Self {
        Self {
            nullifier: format_field(&w.nullifier),
            token: format_field_from_address(&w.token),
            amount: format_u256(&w.amount),
            recipient: format_field_from_address(&w.recipient),
            commitment_root: format_field(&w.commitment_root),
            spending_key: format_field(&w.spending_key.0),
            salt: format_field(&w.note.salt),
            proof_length: w.commitment_proof.proof_length,
            path: pad_field_array(&w.commitment_proof.path, MAX_COMMITMENT_TREE_DEPTH),
            indices: pad_index_array(
                &w.commitment_proof.indices,
                MAX_COMMITMENT_TREE_DEPTH,
            ),
        }
    }
}

/// BBProver generates ZK proofs by shelling out to nargo and bb (Barretenberg CLI).
///
/// This prover:
/// 1. Writes witness values to Prover.toml in the circuit directory
/// 2. Runs `nargo execute` to generate the witness
/// 3. Runs `bb prove` to generate the proof
/// 4. Reads the proof bytes from the output file
pub struct BBProver {
    /// Path to the circuits directory (containing deposit/, transfer/, withdraw/)
    circuits_dir: PathBuf,
}

impl BBProver {
    /// Create a new BBProver with the given circuits directory.
    pub fn new(circuits_dir: PathBuf) -> Self {
        Self { circuits_dir }
    }

    /// Generate Prover.toml content for the deposit circuit.
    fn format_deposit_prover_toml(witness: &DepositWitness) -> String {
        let input = DepositProverInput::from(witness);
        toml::to_string(&input).expect("failed to serialize deposit prover input")
    }

    /// Generate Prover.toml content for the transfer circuit.
    fn format_transfer_prover_toml(witness: &TransferWitness) -> String {
        let input = TransferProverInput::from(witness);
        toml::to_string(&input).expect("failed to serialize transfer prover input")
    }

    /// Generate Prover.toml content for the withdraw circuit.
    fn format_withdraw_prover_toml(witness: &WithdrawWitness) -> String {
        let input = WithdrawProverInput::from(witness);
        toml::to_string(&input).expect("failed to serialize withdraw prover input")
    }

    /// Execute a circuit and generate a proof.
    async fn prove_circuit(
        &self,
        circuit_name: &str,
        prover_toml: &str,
    ) -> Result<Vec<u8>, ports::prover::ProverError> {
        let circuit_dir = self.circuits_dir.join(circuit_name);

        if !circuit_dir.exists() {
            return Err(ports::prover::ProverError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Circuit directory not found: {}", circuit_dir.display()),
            )));
        }

        let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

        // 1. Write Prover.toml with witness values
        let prover_toml_path = circuit_dir.join("Prover.toml");
        std::fs::write(&prover_toml_path, prover_toml)?;

        // 2. Run nargo execute to generate witness
        let nargo_status = Command::new("nargo")
            .args(["execute", "witness"])
            .current_dir(&circuit_dir)
            .output()
            .await?;

        if !nargo_status.status.success() {
            let stderr = String::from_utf8_lossy(&nargo_status.stderr);
            return Err(ports::prover::ProverError::WitnessError(format!(
                "nargo execute failed: {}",
                stderr
            )));
        }

        // 3. Run bb prove (bb >= 5.0: `-t evm` selects the keccak/ZK EVM target,
        // replacing the removed `--oracle_hash keccak`)
        let bb_binary = std::env::var("BB_BINARY").unwrap_or_else(|_| "bb".to_string());
        let bb_status = Command::new(&bb_binary)
            .args([
                "prove",
                "-b",
                &format!("{}/target/{circuit_name}.json", project_root.display()),
                "-w",
                &format!("{}/target/witness.gz", project_root.display()),
                "--write_vk",
                "-t",
                "evm",
                "-o",
                &format!("{}/target/", project_root.display()),
            ])
            .current_dir(&circuit_dir)
            .output()
            .await?;

        if !bb_status.status.success() {
            let stderr = String::from_utf8_lossy(&bb_status.stderr);
            return Err(ports::prover::ProverError::ProofGenerationError(format!(
                "bb prove failed: {}",
                stderr
            )));
        }

        // 4. Read proof file
        let proof_path =
            circuit_dir.join(&format!("{}/target/proof", project_root.display()));
        let proof = std::fs::read(&proof_path)?;

        Ok(proof)
    }
}

impl ports::prover::Prover for BBProver {
    async fn prove_deposit(
        &self,
        witness: &DepositWitness,
    ) -> Result<DepositProof, ports::prover::ProverError> {
        let prover_toml = Self::format_deposit_prover_toml(witness);
        let proof_bytes = self.prove_circuit("deposit", &prover_toml).await?;

        Ok(DepositProof::new(
            Bytes::from(proof_bytes),
            witness.commitment,
            witness.token,
            witness.amount,
            witness.funding_address,
            witness.attestation_root,
            witness.payload_hash,
        ))
    }

    async fn prove_transfer(
        &self,
        witness: &TransferWitness,
    ) -> Result<TransferProof, ports::prover::ProverError> {
        // Validate witness before proving
        if !witness.validate_amounts() {
            return Err(ports::prover::ProverError::InvalidWitness(
                "Input amounts do not equal output amounts".to_string(),
            ));
        }
        if !witness.validate_token_consistency() {
            return Err(ports::prover::ProverError::InvalidWitness(
                "Token mismatch in notes".to_string(),
            ));
        }

        let prover_toml = Self::format_transfer_prover_toml(witness);
        let proof_bytes = self.prove_circuit("transfer", &prover_toml).await?;

        Ok(TransferProof::new(
            Bytes::from(proof_bytes),
            witness.nullifiers,
            witness.output_commitments,
            witness.commitment_root,
            witness.payload_hash,
        ))
    }

    async fn prove_withdraw(
        &self,
        witness: &WithdrawWitness,
    ) -> Result<WithdrawProof, ports::prover::ProverError> {
        let prover_toml = Self::format_withdraw_prover_toml(witness);
        let proof_bytes = self.prove_circuit("withdraw", &prover_toml).await?;

        Ok(WithdrawProof::new(
            Bytes::from(proof_bytes),
            witness.nullifier,
            witness.token,
            witness.amount,
            witness.recipient,
            witness.commitment_root,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::domain::{
        keys::SpendingKey,
        merkle::{
            AttestationMerkleProof,
            CommitmentMerkleProof,
        },
        note::Note,
        witness::{
            DepositWitness,
            TransferWitness,
            WithdrawWitness,
        },
    };

    #[test]
    fn test_format_deposit_prover_toml() {
        let sk = SpendingKey::random();
        let pk = sk.derive_owner_pubkey();
        let token = Address::ZERO;
        let note = Note::new(token, U256::from(1000u64), pk);

        let attestation_proof = AttestationMerkleProof::new(
            vec![B256::ZERO; MAX_ATTESTATION_TREE_DEPTH],
            vec![0u8; MAX_ATTESTATION_TREE_DEPTH],
            0,
        );

        let witness = DepositWitness::new(
            &note,
            sk,
            Address::ZERO,
            B256::ZERO,
            Address::ZERO,
            0,
            0,
            attestation_proof,
            b"",
        );

        let toml = BBProver::format_deposit_prover_toml(&witness);

        // Verify the TOML contains expected fields
        assert!(toml.contains("commitment = "));
        assert!(toml.contains("token = "));
        assert!(toml.contains("amount = "));
        assert!(toml.contains("funding_address = "));
        assert!(toml.contains("attestation_root = "));
        assert!(toml.contains("payload_hash = "));
        assert!(toml.contains("spending_key = "));
        assert!(toml.contains("salt = "));
        assert!(toml.contains("attestation_path = "));
        assert!(toml.contains("attestation_indices = "));
    }

    #[test]
    fn test_format_transfer_prover_toml() {
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

        let dummy_proof = CommitmentMerkleProof::new(
            vec![B256::ZERO; MAX_COMMITMENT_TREE_DEPTH],
            vec![0u8; MAX_COMMITMENT_TREE_DEPTH],
            0,
        );

        let witness = TransferWitness::new(
            sk,
            input_notes,
            output_notes,
            [dummy_proof.clone(), dummy_proof],
            B256::ZERO,
            b"",
        );

        let toml = BBProver::format_transfer_prover_toml(&witness);

        // Verify the TOML contains expected fields
        assert!(toml.contains("nullifier_0 = "));
        assert!(toml.contains("nullifier_1 = "));
        assert!(toml.contains("commitment_out_0 = "));
        assert!(toml.contains("commitment_out_1 = "));
        assert!(toml.contains("commitment_root = "));
        assert!(toml.contains("payload_hash = "));
        assert!(toml.contains("spending_key = "));
        assert!(toml.contains("token_in_0 = "));
        assert!(toml.contains("amount_in_0 = "));
        assert!(toml.contains("proof_length_0 = "));
        assert!(toml.contains("path_0 = "));
        assert!(toml.contains("proof_length_1 = "));
        assert!(toml.contains("path_1 = "));
    }

    #[test]
    fn test_format_withdraw_prover_toml() {
        let sk = SpendingKey::random();
        let pk = sk.derive_owner_pubkey();
        let token = Address::ZERO;
        let note = Note::new(token, U256::from(1000u64), pk);
        let recipient = Address::repeat_byte(0x42);

        let commitment_proof = CommitmentMerkleProof::new(
            vec![B256::ZERO; MAX_COMMITMENT_TREE_DEPTH],
            vec![0u8; MAX_COMMITMENT_TREE_DEPTH],
            0,
        );

        let witness =
            WithdrawWitness::new(sk, note, commitment_proof, B256::ZERO, recipient);

        let toml = BBProver::format_withdraw_prover_toml(&witness);

        // Verify the TOML contains expected fields
        assert!(toml.contains("nullifier = "));
        assert!(toml.contains("token = "));
        assert!(toml.contains("amount = "));
        assert!(toml.contains("recipient = "));
        assert!(toml.contains("commitment_root = "));
        assert!(toml.contains("spending_key = "));
        assert!(toml.contains("salt = "));
        assert!(toml.contains("path = "));
        assert!(toml.contains("indices = "));
    }
}

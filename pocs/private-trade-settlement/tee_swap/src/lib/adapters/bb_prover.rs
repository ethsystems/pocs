use std::path::PathBuf;

use alloy::primitives::{B256, Bytes};
use serde::Serialize;
use tokio::process::Command;

use crate::ports::{
    self,
    TransferProof,
    TransferPublicInputs,
    TransferWitness,
};

/// Circuit's MAX_DEPTH (must match `circuits/transfer/src/main.nr`).
const CIRCUIT_MAX_DEPTH: usize = 20;

/// Format a B256 as a hex string for Noir (`0x…`).
fn format_field(value: &B256) -> String {
    format!("{}", value)
}

/// Pad a B256 path to `max_depth` and convert each element to a hex string.
fn pad_field_array(path: &[B256], max_depth: usize) -> Vec<String> {
    let mut padded = path.to_vec();
    padded.resize(max_depth, B256::ZERO);
    padded.iter().map(format_field).collect()
}

/// Pad an index array to `max_depth`.
fn pad_index_array(indices: &[u8], max_depth: usize) -> Vec<u8> {
    let mut padded = indices.to_vec();
    padded.resize(max_depth, 0);
    padded
}

/// TOML-serializable input for the unified transfer circuit.
///
/// Field names **must** match the Noir circuit parameter names exactly.
#[derive(Serialize)]
struct TransferProverInput {
    // -- Public inputs (9) --
    nullifier: String,
    root: String,
    new_commitment: String,
    timeout: String,
    pk_stealth: String,
    h_swap: String,
    #[serde(rename = "h_R")]
    h_r: String,
    h_meta: String,
    h_enc: String,

    // -- Private: input note --
    sk_lo: String,
    sk_hi: String,
    in_chain_id: String,
    in_value: u64,
    in_asset_id: String,
    in_owner: String,
    in_fallback_owner: String,
    in_timeout: String,
    in_salt: String,
    proof_length: u32,
    path_elements: Vec<String>,
    path_indices: Vec<u8>,

    // -- Private: output note --
    out_chain_id: String,
    out_value: u64,
    out_asset_id: String,
    out_owner: String,
    out_fallback_owner: String,
    out_timeout: String,
    out_salt: String,

    // -- Private: lock-mode extras --
    swap_id: String,
    r_lo: String,
    r_hi: String,
    pk_meta_x: String,
    pk_meta_y: String,
    encrypted_salt: String,
}

impl From<&TransferWitness> for TransferProverInput {
    fn from(w: &TransferWitness) -> Self {
        Self {
            // Public
            nullifier: format_field(&w.nullifier),
            root: format_field(&w.root),
            new_commitment: format_field(&w.new_commitment),
            timeout: format_field(&w.timeout),
            pk_stealth: format_field(&w.pk_stealth),
            h_swap: format_field(&w.h_swap),
            h_r: format_field(&w.h_r),
            h_meta: format_field(&w.h_meta),
            h_enc: format_field(&w.h_enc),
            // Private: input note
            sk_lo: format_field(&w.sk_lo),
            sk_hi: format_field(&w.sk_hi),
            in_chain_id: format_field(&w.in_chain_id),
            in_value: w.in_value,
            in_asset_id: format_field(&w.in_asset_id),
            in_owner: format_field(&w.in_owner),
            in_fallback_owner: format_field(&w.in_fallback_owner),
            in_timeout: format_field(&w.in_timeout),
            in_salt: format_field(&w.in_salt),
            proof_length: w.proof_length,
            path_elements: pad_field_array(&w.path_elements, CIRCUIT_MAX_DEPTH),
            path_indices: pad_index_array(&w.path_indices, CIRCUIT_MAX_DEPTH),
            // Private: output note
            out_chain_id: format_field(&w.out_chain_id),
            out_value: w.out_value,
            out_asset_id: format_field(&w.out_asset_id),
            out_owner: format_field(&w.out_owner),
            out_fallback_owner: format_field(&w.out_fallback_owner),
            out_timeout: format_field(&w.out_timeout),
            out_salt: format_field(&w.out_salt),
            // Private: lock extras
            swap_id: format_field(&w.swap_id),
            r_lo: format_field(&w.r_lo),
            r_hi: format_field(&w.r_hi),
            pk_meta_x: format_field(&w.pk_meta_x),
            pk_meta_y: format_field(&w.pk_meta_y),
            encrypted_salt: format_field(&w.encrypted_salt),
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
    /// Path to the circuits directory (containing `transfer/`)
    circuits_dir: PathBuf,
}

impl BBProver {
    /// Create a new BBProver with the given circuits directory.
    pub fn new(circuits_dir: PathBuf) -> Self {
        Self { circuits_dir }
    }

    /// Generate Prover.toml content for the transfer circuit.
    fn format_transfer_prover_toml(witness: &TransferWitness) -> String {
        let input = TransferProverInput::from(witness);
        toml::to_string(&input).expect("failed to serialize transfer prover input")
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

        // Symlink circuit sources into a temp dir so concurrent proof generation don't collide
        let tmp = tempfile::tempdir()?;
        let work_dir = tmp.path().join(circuit_name);
        std::fs::create_dir_all(&work_dir)?;
        std::os::unix::fs::symlink(circuit_dir.join("src"), work_dir.join("src"))?;
        std::os::unix::fs::symlink(circuit_dir.join("Nargo.toml"), work_dir.join("Nargo.toml"))?;

        // 1. Write Prover.toml with witness values
        let prover_toml_path = work_dir.join("Prover.toml");
        std::fs::write(&prover_toml_path, prover_toml)?;

        // 2. Run nargo execute to generate witness
        let nargo_status = Command::new("nargo")
            .args(["execute", "witness"])
            .current_dir(&work_dir)
            .output()
            .await?;

        if !nargo_status.status.success() {
            let stderr = String::from_utf8_lossy(&nargo_status.stderr);
            return Err(ports::prover::ProverError::WitnessError(format!(
                "nargo execute failed: {}",
                stderr
            )));
        }

        // 3. Run bb prove (all paths relative to the temp work dir)
        let target_dir = work_dir.join("target");
        let bb_status = Command::new("bb")
            .args([
                "prove",
                "-b",
                &format!("{}/{circuit_name}.json", target_dir.display()),
                "-w",
                &format!("{}/witness.gz", target_dir.display()),
                "--write_vk",
                "-t",
                "evm",
                "-o",
                &format!("{}/", target_dir.display()),
            ])
            .current_dir(&work_dir)
            .output()
            .await?;

        if !bb_status.status.success() {
            let stderr = String::from_utf8_lossy(&bb_status.stderr);
            return Err(ports::prover::ProverError::ProofFailed(format!(
                "bb prove failed: {}",
                stderr
            )));
        }

        // 4. Read proof file
        let proof_path = target_dir.join("proof");
        let proof = std::fs::read(&proof_path)?;

        Ok(proof)
    }
}

impl ports::prover::Prover for BBProver {
    async fn prove_transfer(
        &self,
        witness: &TransferWitness,
    ) -> Result<TransferProof, ports::prover::ProverError> {
        let prover_toml = Self::format_transfer_prover_toml(witness);
        let proof_bytes = self.prove_circuit("transfer", &prover_toml).await?;

        let public_inputs = TransferPublicInputs {
            nullifier: witness.nullifier,
            root: witness.root,
            new_commitment: witness.new_commitment,
            timeout: witness.timeout,
            pk_stealth: witness.pk_stealth,
            h_swap: witness.h_swap,
            h_r: witness.h_r,
            h_meta: witness.h_meta,
            h_enc: witness.h_enc,
        };

        Ok(TransferProof::new(Bytes::from(proof_bytes), public_inputs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::U256;
    use ark_ec::{CurveGroup, PrimeGroup};
    use ark_grumpkin::Projective;

    use crate::crypto::poseidon::{
        poseidon2, poseidon3, poseidon8, DOMAIN_COMMITMENT, DOMAIN_NULLIFIER,
    };
    use crate::crypto::stealth::{affine_x_to_b256, b256_to_grumpkin_scalar, scalar_to_lo_hi};

    fn dummy_witness() -> TransferWitness {
        TransferWitness {
            // Public inputs
            nullifier: B256::repeat_byte(0x01),
            root: B256::repeat_byte(0x02),
            new_commitment: B256::repeat_byte(0x03),
            timeout: B256::ZERO,
            pk_stealth: B256::ZERO,
            h_swap: B256::ZERO,
            h_r: B256::ZERO,
            h_meta: B256::ZERO,
            h_enc: B256::ZERO,
            // Private: input note
            sk_lo: B256::repeat_byte(0x10),
            sk_hi: B256::ZERO,
            in_chain_id: B256::left_padding_from(&[1]),
            in_value: 1000,
            in_asset_id: B256::repeat_byte(0x12),
            in_owner: B256::repeat_byte(0x20),
            in_fallback_owner: B256::ZERO,
            in_timeout: B256::ZERO,
            in_salt: B256::repeat_byte(0xaa),
            proof_length: 1,
            path_elements: vec![B256::ZERO],
            path_indices: vec![0],
            // Private: output note
            out_chain_id: B256::left_padding_from(&[1]),
            out_value: 1000,
            out_asset_id: B256::repeat_byte(0x12),
            out_owner: B256::repeat_byte(0xca),
            out_fallback_owner: B256::ZERO,
            out_timeout: B256::ZERO,
            out_salt: B256::repeat_byte(0xbb),
            // Private: lock extras
            swap_id: B256::ZERO,
            r_lo: B256::ZERO,
            r_hi: B256::ZERO,
            pk_meta_x: B256::ZERO,
            pk_meta_y: B256::ZERO,
            encrypted_salt: B256::ZERO,
        }
    }

    #[test]
    fn test_format_transfer_prover_toml() {
        let witness = dummy_witness();
        let toml = BBProver::format_transfer_prover_toml(&witness);

        // Public inputs
        assert!(toml.contains("nullifier = "));
        assert!(toml.contains("root = "));
        assert!(toml.contains("new_commitment = "));
        assert!(toml.contains("timeout = "));
        assert!(toml.contains("pk_stealth = "));
        assert!(toml.contains("h_swap = "));
        assert!(toml.contains("h_R = "));
        assert!(toml.contains("h_meta = "));
        assert!(toml.contains("h_enc = "));

        // Private: input note
        assert!(toml.contains("sk_lo = "));
        assert!(toml.contains("sk_hi = "));
        assert!(toml.contains("in_chain_id = "));
        assert!(toml.contains("in_value = "));
        assert!(toml.contains("in_asset_id = "));
        assert!(toml.contains("in_owner = "));
        assert!(toml.contains("in_fallback_owner = "));
        assert!(toml.contains("in_timeout = "));
        assert!(toml.contains("in_salt = "));
        assert!(toml.contains("proof_length = "));
        assert!(toml.contains("path_elements = "));
        assert!(toml.contains("path_indices = "));

        // Private: output note
        assert!(toml.contains("out_chain_id = "));
        assert!(toml.contains("out_value = "));
        assert!(toml.contains("out_asset_id = "));
        assert!(toml.contains("out_owner = "));
        assert!(toml.contains("out_fallback_owner = "));
        assert!(toml.contains("out_timeout = "));
        assert!(toml.contains("out_salt = "));

        // Private: lock extras
        assert!(toml.contains("swap_id = "));
        assert!(toml.contains("r_lo = "));
        assert!(toml.contains("r_hi = "));
        assert!(toml.contains("pk_meta_x = "));
        assert!(toml.contains("pk_meta_y = "));
        assert!(toml.contains("encrypted_salt = "));
    }

    #[test]
    fn test_path_padding() {
        let witness = dummy_witness();
        let toml = BBProver::format_transfer_prover_toml(&witness);

        // The path_elements and path_indices should be padded to CIRCUIT_MAX_DEPTH (20)
        let parsed: toml::Value = toml.parse().expect("valid TOML");
        let path_elements = parsed["path_elements"].as_array().unwrap();
        let path_indices = parsed["path_indices"].as_array().unwrap();
        assert_eq!(path_elements.len(), CIRCUIT_MAX_DEPTH);
        assert_eq!(path_indices.len(), CIRCUIT_MAX_DEPTH);
    }

    fn noir_transfer_witness() -> TransferWitness {
        // sk_lo = 0xdeadbeef, sk_hi = 0
        let sk_b256 = B256::left_padding_from(&[0xde, 0xad, 0xbe, 0xef]);
        let sk_scalar = b256_to_grumpkin_scalar(sk_b256);
        let pk = (Projective::generator() * sk_scalar).into_affine();
        let owner = affine_x_to_b256(&pk);
        let (sk_lo, sk_hi) = scalar_to_lo_hi(&sk_scalar);

        let in_chain_id = B256::left_padding_from(&[1]);
        let in_value: u64 = 1000;
        let in_asset_id = B256::left_padding_from(&[0x12, 0x34]);
        let in_fallback_owner = B256::ZERO;
        let in_timeout = B256::ZERO;
        let in_salt = B256::left_padding_from(&[0xaa, 0xaa]);

        // commitment = H(DOMAIN_COMMITMENT, chain_id, value, asset_id, owner, fallback, timeout, salt)
        let in_commitment = poseidon8(
            DOMAIN_COMMITMENT,
            in_chain_id,
            B256::from(U256::from(in_value)),
            in_asset_id,
            owner,
            in_fallback_owner,
            in_timeout,
            in_salt,
        );

        // nullifier = H(DOMAIN_NULLIFIER, commitment, salt)
        let nullifier = poseidon3(DOMAIN_NULLIFIER, in_commitment, in_salt);

        // Single-leaf Merkle tree: root = H(commitment, 0)
        let root = poseidon2(in_commitment, B256::ZERO);

        // Output note
        let out_chain_id = B256::left_padding_from(&[1]);
        let out_value: u64 = 1000;
        let out_asset_id = B256::left_padding_from(&[0x12, 0x34]);
        let out_owner = B256::left_padding_from(&[0xca, 0xfe]);
        let out_fallback_owner = B256::ZERO;
        let out_timeout = B256::ZERO;
        let out_salt = B256::left_padding_from(&[0xbb, 0xbb]);

        let out_commitment = poseidon8(
            DOMAIN_COMMITMENT,
            out_chain_id,
            B256::from(U256::from(out_value)),
            out_asset_id,
            out_owner,
            out_fallback_owner,
            out_timeout,
            out_salt,
        );

        TransferWitness {
            nullifier,
            root,
            new_commitment: out_commitment,
            timeout: B256::ZERO,
            pk_stealth: B256::ZERO,
            h_swap: B256::ZERO,
            h_r: B256::ZERO,
            h_meta: B256::ZERO,
            h_enc: B256::ZERO,
            sk_lo,
            sk_hi,
            in_chain_id,
            in_value,
            in_asset_id,
            in_owner: owner,
            in_fallback_owner,
            in_timeout,
            in_salt,
            proof_length: 1,
            path_elements: vec![B256::ZERO],
            path_indices: vec![0],
            out_chain_id,
            out_value,
            out_asset_id,
            out_owner,
            out_fallback_owner,
            out_timeout,
            out_salt,
            swap_id: B256::ZERO,
            r_lo: B256::ZERO,
            r_hi: B256::ZERO,
            pk_meta_x: B256::ZERO,
            pk_meta_y: B256::ZERO,
            encrypted_salt: B256::ZERO,
        }
    }

    #[tokio::test]
    async fn test_prove_transfer_happy_path() {
        use crate::ports::prover::Prover;

        let witness = noir_transfer_witness();
        let circuits_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("circuits");
        let prover = BBProver::new(circuits_dir);

        let proof = prover
            .prove_transfer(&witness)
            .await
            .expect("prove_transfer failed");

        assert!(!proof.proof.is_empty(), "proof bytes should be non-empty");
        assert_eq!(proof.public_inputs.nullifier, witness.nullifier);
        assert_eq!(proof.public_inputs.root, witness.root);
        assert_eq!(proof.public_inputs.new_commitment, witness.new_commitment);
    }
}

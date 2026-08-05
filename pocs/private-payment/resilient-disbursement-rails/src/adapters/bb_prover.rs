//! `BBProver`: shells to `nargo` + `bb` to generate proofs. Mirrors the
//! reference identity PoC's structure.
//!
//! Per-circuit `*ProverInput` structs match the circuit input field names
//! one-for-one; if the circuit changes, this file must change in lockstep.

use std::{
    path::PathBuf,
    process::Command,
};

use ark_bn254::Fr;
use ark_ff::PrimeField;
use serde::Serialize;

use crate::{
    COHORT_DEPTH,
    POOL_DEPTH,
    error::ProofError,
    ports::proof::ProofBackend,
    poseidon::fr_from_be_bytes,
    types::{
        Bytes32,
        ClaimWitness,
        PoolWithdrawWitness,
    },
};

fn fr_to_decimal(f: Fr) -> String {
    f.into_bigint().to_string()
}

fn bytes_to_decimal_array(b: &[u8; 32]) -> Vec<String> {
    b.iter().map(|x| x.to_string()).collect()
}

#[derive(Serialize)]
struct ClaimProverInput {
    round_id_hi: String,
    round_id_lo: String,
    cohort_root: String,
    chain_id_hi: String,
    chain_id_lo: String,
    destination: String,
    amount: String,
    nullifier: String,
    claim_contract_address: String,
    relay_submitter: String,
    derived_pubkey_x_hi: String,
    derived_pubkey_x_lo: String,
    derived_pubkey_y_hi: String,
    derived_pubkey_y_lo: String,
    m_x_hi: String,
    m_x_lo: String,
    m_y_hi: String,
    m_y_lo: String,
    signature_r: Vec<String>,
    signature_s: Vec<String>,
    proof_length: String,
    leaf_index_bits: Vec<bool>,
    merkle_path: Vec<String>,
}

#[derive(Serialize)]
struct PoolWithdrawProverInput {
    pool_root: String,
    claim_nullifier: String,
    token: String,
    amount: String,
    recipient: String,
    m_x_hi: String,
    m_x_lo: String,
    m_y_hi: String,
    m_y_lo: String,
    derived_pubkey_x_hi: String,
    derived_pubkey_x_lo: String,
    derived_pubkey_y_hi: String,
    derived_pubkey_y_lo: String,
    round_id_hi: String,
    round_id_lo: String,
    chain_id_hi: String,
    chain_id_lo: String,
    claim_contract: String,
    proof_length: String,
    leaf_index_bits: Vec<bool>,
    merkle_path: Vec<String>,
}

pub struct BBProver {
    project_root: PathBuf,
}

impl BBProver {
    pub fn new(project_root: PathBuf) -> Self {
        Self { project_root }
    }

    /// Run nargo + bb. Writes Prover.toml under `circuits/<circuit_name>`,
    /// runs `nargo execute witness`, then `bb write_vk` (-t evm) and `bb
    /// prove` (-t evm), and returns the proof bytes.
    pub fn prove_circuit(
        &self,
        circuit_name: &str,
        prover_toml_content: &str,
    ) -> Result<Vec<u8>, ProofError> {
        let circuit_dir = self.project_root.join("circuits").join(circuit_name);
        if !circuit_dir.exists() {
            return Err(ProofError::Generation(format!(
                "Circuit directory not found: {}",
                circuit_dir.display()
            )));
        }
        let prover_toml_path = circuit_dir.join("Prover.toml");
        std::fs::write(&prover_toml_path, prover_toml_content)
            .map_err(|e| ProofError::Generation(format!("write Prover.toml: {e}")))?;

        // nargo execute witness - runs from the circuit subdir.
        let nargo = Command::new("nargo")
            .args(["execute", "witness"])
            .current_dir(&circuit_dir)
            .output()
            .map_err(|e| ProofError::Generation(format!("spawn nargo: {e}")))?;
        if !nargo.status.success() {
            return Err(ProofError::Generation(format!(
                "nargo execute failed: {}",
                String::from_utf8_lossy(&nargo.stderr)
            )));
        }

        let package_name = match circuit_name {
            "claim" => "rdr_claim",
            "withdraw" => "rdr_withdraw",
            other => {
                return Err(ProofError::Generation(format!("unknown circuit: {other}")));
            }
        };

        let circuit_json = self
            .project_root
            .join("target")
            .join(format!("{package_name}.json"));
        let witness_path = self.project_root.join("target").join("witness.gz");
        let output_dir = self.project_root.join("target");

        // bb write_vk (required by `bb prove -t evm`).
        let vk = Command::new("bb")
            .args([
                "write_vk",
                "-b",
                circuit_json.to_str().unwrap(),
                "-t",
                "evm",
                "-o",
                output_dir.to_str().unwrap(),
            ])
            .output()
            .map_err(|e| ProofError::Generation(format!("spawn bb write_vk: {e}")))?;
        if !vk.status.success() {
            return Err(ProofError::Generation(format!(
                "bb write_vk failed: {}",
                String::from_utf8_lossy(&vk.stderr)
            )));
        }

        // bb prove.
        let bb = Command::new("bb")
            .args([
                "prove",
                "-b",
                circuit_json.to_str().unwrap(),
                "-w",
                witness_path.to_str().unwrap(),
                "-t",
                "evm",
                "-o",
                output_dir.to_str().unwrap(),
            ])
            .output()
            .map_err(|e| ProofError::Generation(format!("spawn bb prove: {e}")))?;
        if !bb.status.success() {
            return Err(ProofError::Generation(format!(
                "bb prove failed: {}",
                String::from_utf8_lossy(&bb.stderr)
            )));
        }

        let proof = std::fs::read(output_dir.join("proof"))
            .map_err(|e| ProofError::Generation(format!("read proof: {e}")))?;
        Ok(proof)
    }
}

fn pad_path<const D: usize>(
    siblings: &[Bytes32],
    indices: &[u8],
) -> (Vec<String>, Vec<bool>, usize) {
    let proof_length = siblings.len();
    let mut padded_siblings: Vec<Fr> =
        siblings.iter().map(|b| fr_from_be_bytes(b)).collect();
    padded_siblings.resize(D, Fr::from(0u64));
    let mut padded_bits: Vec<u8> = indices.to_vec();
    padded_bits.resize(D, 0u8);
    let merkle_path = padded_siblings.into_iter().map(fr_to_decimal).collect();
    // The claim/withdraw circuits take `[bool; D]`, not `[u1; D]`; nargo's
    // TOML reader wants bare `true`/`false`, not "0"/"1" strings.
    let leaf_index_bits = padded_bits.iter().map(|b| *b != 0).collect();
    (merkle_path, leaf_index_bits, proof_length)
}

impl ProofBackend for BBProver {
    fn generate_claim_proof(&self, w: &ClaimWitness) -> Result<Vec<u8>, ProofError> {
        let (merkle_path, leaf_index_bits, proof_length) =
            pad_path::<COHORT_DEPTH>(&w.merkle_path.siblings, &w.merkle_path.indices);
        let input = ClaimProverInput {
            round_id_hi: fr_to_decimal(w.round_id_hi),
            round_id_lo: fr_to_decimal(w.round_id_lo),
            cohort_root: fr_to_decimal(w.cohort_root),
            chain_id_hi: fr_to_decimal(w.chain_id_hi),
            chain_id_lo: fr_to_decimal(w.chain_id_lo),
            destination: fr_to_decimal(w.destination),
            amount: fr_to_decimal(w.amount),
            nullifier: fr_to_decimal(w.nullifier),
            claim_contract_address: fr_to_decimal(w.claim_contract_address),
            relay_submitter: fr_to_decimal(w.relay_submitter),
            derived_pubkey_x_hi: fr_to_decimal(w.derived_pubkey_x_hi),
            derived_pubkey_x_lo: fr_to_decimal(w.derived_pubkey_x_lo),
            derived_pubkey_y_hi: fr_to_decimal(w.derived_pubkey_y_hi),
            derived_pubkey_y_lo: fr_to_decimal(w.derived_pubkey_y_lo),
            m_x_hi: fr_to_decimal(w.m_x_hi),
            m_x_lo: fr_to_decimal(w.m_x_lo),
            m_y_hi: fr_to_decimal(w.m_y_hi),
            m_y_lo: fr_to_decimal(w.m_y_lo),
            signature_r: bytes_to_decimal_array(&w.signature_r),
            signature_s: bytes_to_decimal_array(&w.signature_s),
            proof_length: proof_length.to_string(),
            leaf_index_bits,
            merkle_path,
        };
        let toml_content = toml::to_string(&input)
            .map_err(|e| ProofError::WitnessSerialization(format!("claim toml: {e}")))?;
        self.prove_circuit("claim", &toml_content)
    }

    fn generate_pool_withdraw_proof(
        &self,
        w: &PoolWithdrawWitness,
    ) -> Result<Vec<u8>, ProofError> {
        let (merkle_path, leaf_index_bits, proof_length) =
            pad_path::<POOL_DEPTH>(&w.merkle_path.siblings, &w.merkle_path.indices);
        let input = PoolWithdrawProverInput {
            pool_root: fr_to_decimal(w.pool_root),
            claim_nullifier: fr_to_decimal(w.claim_nullifier),
            token: fr_to_decimal(w.token),
            amount: fr_to_decimal(w.amount),
            recipient: fr_to_decimal(w.recipient),
            m_x_hi: fr_to_decimal(w.m_x_hi),
            m_x_lo: fr_to_decimal(w.m_x_lo),
            m_y_hi: fr_to_decimal(w.m_y_hi),
            m_y_lo: fr_to_decimal(w.m_y_lo),
            derived_pubkey_x_hi: fr_to_decimal(w.derived_pubkey_x_hi),
            derived_pubkey_x_lo: fr_to_decimal(w.derived_pubkey_x_lo),
            derived_pubkey_y_hi: fr_to_decimal(w.derived_pubkey_y_hi),
            derived_pubkey_y_lo: fr_to_decimal(w.derived_pubkey_y_lo),
            round_id_hi: fr_to_decimal(w.round_id_hi),
            round_id_lo: fr_to_decimal(w.round_id_lo),
            chain_id_hi: fr_to_decimal(w.chain_id_hi),
            chain_id_lo: fr_to_decimal(w.chain_id_lo),
            claim_contract: fr_to_decimal(w.claim_contract),
            proof_length: proof_length.to_string(),
            leaf_index_bits,
            merkle_path,
        };
        let toml_content = toml::to_string(&input).map_err(|e| {
            ProofError::WitnessSerialization(format!("pool_withdraw toml: {e}"))
        })?;
        self.prove_circuit("withdraw", &toml_content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fr_to_decimal_smoke() {
        assert_eq!(fr_to_decimal(Fr::from(0u64)), "0");
        assert_eq!(fr_to_decimal(Fr::from(42u64)), "42");
    }

    #[test]
    fn test_claim_toml_round_trip_serializes() {
        let witness = ClaimWitness {
            round_id_hi: Fr::from(0u64),
            round_id_lo: Fr::from(1u64),
            cohort_root: Fr::from(2u64),
            chain_id_hi: Fr::from(0u64),
            chain_id_lo: Fr::from(1u64),
            destination: Fr::from(0x12345u64),
            amount: Fr::from(1_000_000u64),
            nullifier: Fr::from(7u64),
            claim_contract_address: Fr::from(0xcafeu64),
            relay_submitter: Fr::from(0xbeefu64),
            derived_pubkey_x_hi: Fr::from(3u64),
            derived_pubkey_x_lo: Fr::from(4u64),
            derived_pubkey_y_hi: Fr::from(5u64),
            derived_pubkey_y_lo: Fr::from(6u64),
            m_x_hi: Fr::from(8u64),
            m_x_lo: Fr::from(9u64),
            m_y_hi: Fr::from(10u64),
            m_y_lo: Fr::from(11u64),
            signature_r: [0xaa; 32],
            signature_s: [0x11; 32],
            merkle_path: crate::types::CohortMerklePath {
                siblings: vec![],
                indices: vec![],
            },
        };
        let (path_str, bits, plen) = pad_path::<COHORT_DEPTH>(
            &witness.merkle_path.siblings,
            &witness.merkle_path.indices,
        );
        assert_eq!(plen, 0);
        assert_eq!(path_str.len(), COHORT_DEPTH);
        assert_eq!(bits.len(), COHORT_DEPTH);
    }

    #[test]
    fn test_pool_withdraw_toml_pads_to_pool_depth() {
        // Build a 32-byte big-endian sibling whose canonical Fr decimal
        // is 99.
        let mut sibling = [0u8; 32];
        sibling[31] = 99;
        let (path, bits, _) = pad_path::<POOL_DEPTH>(&[sibling], &[1u8]);
        assert_eq!(path.len(), POOL_DEPTH);
        assert_eq!(bits.len(), POOL_DEPTH);
        assert_eq!(path[0], "99");
        assert!(bits[0]);
    }
}

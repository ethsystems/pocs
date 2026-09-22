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
/// Each call builds a throwaway Noir package in a `tempfile::TempDir` and proves there, so the
/// spending key in `Prover.toml` never reaches the tracked `circuits/` tree and concurrent calls
/// cannot collide. On success the directory is removed and a failed removal is an error
/// (`work.close()?`); on an error or a dropped future it goes away on drop, best effort.
/// A kill -9 leaves it in the temp dir.
pub struct BBProver {
    /// Path to the circuits directory (containing deposit/, transfer/, withdraw/)
    circuits_dir: PathBuf,
    /// Parent of the per-call working directories
    work_root: PathBuf,
    /// Barretenberg CLI binary
    bb_binary: String,
    /// Noir CLI binary
    nargo_binary: String,
}

impl BBProver {
    /// Create a new BBProver with the given circuits directory.
    ///
    /// Working directories go under the OS temp dir. The `BB_BINARY` environment variable
    /// selects the Barretenberg binary (default `bb`).
    pub fn new(circuits_dir: PathBuf) -> Self {
        Self {
            circuits_dir,
            work_root: std::env::temp_dir(),
            bb_binary: std::env::var("BB_BINARY").unwrap_or_else(|_| "bb".to_string()),
            nargo_binary: "nargo".to_string(),
        }
    }

    /// Put the per-call working directories under `work_root`.
    pub fn with_work_root(mut self, work_root: PathBuf) -> Self {
        self.work_root = work_root;
        self
    }

    /// Use `bb_binary` as the Barretenberg CLI.
    pub fn with_bb_binary(mut self, bb_binary: impl Into<String>) -> Self {
        self.bb_binary = bb_binary.into();
        self
    }

    /// Use `nargo_binary` as the Noir CLI.
    pub fn with_nargo_binary(mut self, nargo_binary: impl Into<String>) -> Self {
        self.nargo_binary = nargo_binary.into();
        self
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

        // 1. Stand-alone package in a private directory, deleted when `work` drops
        let work = tempfile::Builder::new()
            .prefix("shielded-pool-prove-")
            .tempdir_in(&self.work_root)?;
        let package_dir = work.path().join(circuit_name);
        std::fs::create_dir(&package_dir)?;
        std::fs::copy(circuit_dir.join("Nargo.toml"), package_dir.join("Nargo.toml"))?;
        std::os::unix::fs::symlink(
            std::fs::canonicalize(circuit_dir.join("src"))?,
            package_dir.join("src"),
        )?;
        std::fs::write(package_dir.join("Prover.toml"), prover_toml)?;

        // 2. Run nargo execute to compile and generate the witness
        let nargo_status = Command::new(&self.nargo_binary)
            .args(["execute", "witness"])
            .current_dir(&package_dir)
            .kill_on_drop(true)
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
        let target_dir = package_dir.join("target");
        let bb_status = Command::new(&self.bb_binary)
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
            .current_dir(&package_dir)
            .kill_on_drop(true)
            .output()
            .await?;

        if !bb_status.status.success() {
            let stderr = String::from_utf8_lossy(&bb_status.stderr);
            return Err(ports::prover::ProverError::ProofGenerationError(format!(
                "bb prove failed: {}",
                stderr
            )));
        }

        // 4. Read proof file, then delete the directory and report a failed deletion
        let proof = std::fs::read(target_dir.join("proof"))?;
        work.close()?;

        Ok(proof)
    }
}

impl ports::prover::Prover for BBProver {
    async fn prove_deposit(
        &self,
        witness: &DepositWitness,
    ) -> Result<DepositProof, ports::prover::ProverError> {
        // Validate witness before proving
        if !witness.validate_amount() {
            return Err(ports::prover::ProverError::InvalidWitness(
                "Deposit amount must be non-zero and fit in u128".to_string(),
            ));
        }

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

    // ===== Proving isolation =====
    // Tests with the real toolchain need `nargo` and the Barretenberg CLI in `BB_BINARY`.
    // Tests with stub tools need only `sh`.

    fn circuits_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("circuits")
    }

    fn withdraw_fixture() -> String {
        std::fs::read_to_string(circuits_dir().join("withdraw/Prover.toml")).unwrap()
    }

    /// Content and mtime of the tracked withdraw fixture, to prove no call wrote to it
    fn fixture_state() -> (String, std::time::SystemTime) {
        let path = circuits_dir().join("withdraw/Prover.toml");
        let mtime = std::fs::metadata(&path).unwrap().modified().unwrap();
        (std::fs::read_to_string(&path).unwrap(), mtime)
    }

    fn is_empty(dir: &std::path::Path) -> bool {
        std::fs::read_dir(dir).unwrap().next().is_none()
    }

    /// Write an executable `sh` script and return its path
    fn stub(dir: &std::path::Path, name: &str, body: &str) -> String {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path.to_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn test_prove_leaves_no_files_and_keeps_fixture() {
        let work_root = tempfile::tempdir().unwrap();
        let prover = BBProver::new(circuits_dir()).with_work_root(work_root.path().into());
        let before = fixture_state();

        let proof = prover.prove_circuit("withdraw", &withdraw_fixture()).await.unwrap();

        assert!(!proof.is_empty());
        assert!(is_empty(work_root.path()), "request files left behind");
        // Compare without Debug output: the fixture holds a key
        assert!(fixture_state() == before, "tracked fixture was written");
    }

    #[tokio::test]
    async fn test_prove_cleans_up_when_nargo_fails() {
        let work_root = tempfile::tempdir().unwrap();
        let prover = BBProver::new(circuits_dir()).with_work_root(work_root.path().into());
        let before = fixture_state();
        let bad = withdraw_fixture()
            .lines()
            .map(|l| if l.starts_with("amount =") { "amount = \"1\"" } else { l })
            .collect::<Vec<_>>()
            .join("\n");

        // WitnessError means the request file was written and nargo ran on it
        let err = prover.prove_circuit("withdraw", &bad).await.unwrap_err();

        assert!(matches!(err, ports::prover::ProverError::WitnessError(_)), "{err}");
        assert!(is_empty(work_root.path()), "request files left behind");
        // Compare without Debug output: the fixture holds a key
        assert!(fixture_state() == before, "tracked fixture was written");
    }

    #[tokio::test]
    async fn test_prove_cleans_up_when_bb_fails() {
        let work_root = tempfile::tempdir().unwrap();
        let prover = BBProver::new(circuits_dir())
            .with_work_root(work_root.path().into())
            .with_bb_binary("false");
        let before = fixture_state();

        // ProofGenerationError means nargo succeeded and wrote the witness first
        let err = prover.prove_circuit("withdraw", &withdraw_fixture()).await.unwrap_err();

        assert!(matches!(err, ports::prover::ProverError::ProofGenerationError(_)), "{err}");
        assert!(is_empty(work_root.path()), "request files left behind");
        // Compare without Debug output: the fixture holds a key
        assert!(fixture_state() == before, "tracked fixture was written");
    }

    #[tokio::test]
    async fn test_prove_cancel_kills_child_and_cleans_up() {
        let tools = tempfile::tempdir().unwrap();
        let work_root = tempfile::tempdir().unwrap();
        let pid_file = tools.path().join("nargo.pid");
        let nargo = stub(tools.path(), "nargo", &format!("echo $$ > {}\nexec sleep 30", pid_file.display()));
        let prover = BBProver::new(circuits_dir())
            .with_work_root(work_root.path().into())
            .with_nargo_binary(nargo);

        let fixture = withdraw_fixture();
        let mut call = Box::pin(prover.prove_circuit("withdraw", &fixture));
        // Drive the call until the child is running inside its request directory
        let pid = loop {
            tokio::select! {
                res = &mut call => panic!("call finished early: {res:?}"),
                _ = tokio::time::sleep(std::time::Duration::from_millis(20)) => {}
            }
            if let Ok(pid) = std::fs::read_to_string(&pid_file) {
                if !pid.trim().is_empty() {
                    break pid.trim().to_string();
                }
            }
        };
        assert!(!is_empty(work_root.path()), "no request directory while nargo runs");

        drop(call);

        assert!(is_empty(work_root.path()), "request files left behind");
        // A killed child stays a zombie until Tokio reaps it, so a zombie counts as exited
        let state = || {
            let out = std::process::Command::new("ps").args(["-o", "stat=", "-p", &pid]).output().unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        for _ in 0..100 {
            let s = state();
            if s.is_empty() || s.starts_with('Z') {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("child {pid} still running after the call was dropped (state {})", state());
    }

    #[tokio::test]
    async fn test_concurrent_calls_get_their_own_files() {
        let tools = tempfile::tempdir().unwrap();
        let work_root = tempfile::tempdir().unwrap();
        // Stub nargo waits so both calls overlap; stub bb returns the request as the proof
        let nargo = stub(tools.path(), "nargo", "sleep 1\nmkdir -p target");
        let bb = stub(tools.path(), "bb", "cp Prover.toml target/proof");
        let prover = BBProver::new(circuits_dir())
            .with_work_root(work_root.path().into())
            .with_nargo_binary(nargo)
            .with_bb_binary(bb);
        let before = fixture_state();

        let (a, b) = tokio::join!(
            prover.prove_circuit("withdraw", "request = \"a\""),
            prover.prove_circuit("withdraw", "request = \"b\""),
        );

        assert_eq!(a.unwrap(), b"request = \"a\"");
        assert_eq!(b.unwrap(), b"request = \"b\"");
        assert!(is_empty(work_root.path()), "request files left behind");
        // Compare without Debug output: the fixture holds a key
        assert!(fixture_state() == before, "tracked fixture was written");
    }

    #[tokio::test]
    async fn test_concurrent_real_proofs_succeed() {
        let work_root = tempfile::tempdir().unwrap();
        let prover = BBProver::new(circuits_dir()).with_work_root(work_root.path().into());
        let fixture = withdraw_fixture();

        let (a, b) = tokio::join!(
            prover.prove_circuit("withdraw", &fixture),
            prover.prove_circuit("withdraw", &fixture),
        );

        assert!(!a.unwrap().is_empty());
        assert!(!b.unwrap().is_empty());
        assert!(is_empty(work_root.path()), "request files left behind");
    }

    #[tokio::test]
    async fn test_prove_deposit_rejects_bad_amount_before_proving() {
        // A missing circuits dir proves the guard runs before any file or process work
        let prover = BBProver::new(PathBuf::from("/nonexistent"));
        let sk = SpendingKey::random();
        for amount in [U256::ZERO, U256::from(u128::MAX) + U256::from(1u64)] {
            let note = Note::new(Address::ZERO, amount, sk.derive_owner_pubkey());
            let witness = DepositWitness::new(
                &note,
                sk.clone(),
                Address::ZERO,
                B256::ZERO,
                Address::ZERO,
                0,
                0,
                AttestationMerkleProof::new(vec![], vec![], 0),
                b"",
            );
            let err = ports::prover::Prover::prove_deposit(&prover, &witness)
                .await
                .unwrap_err();
            assert!(matches!(err, ports::prover::ProverError::InvalidWitness(_)), "{err}");
        }
    }
}

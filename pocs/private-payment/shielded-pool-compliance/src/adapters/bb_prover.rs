//! The real `Prover`: `nargo execute` builds the witness, the Barretenberg msgpack
//! API proves and verifies it. `examples/bb_smoke.rs` settled the wire-format
//! questions (decompressed ACIR and witness, `circuit_compute_vk` cached separately
//! from `circuit_prove`, `disable_zk: false`); this adapter only wires that up to the
//! `Prover` port and adds the one piece the spike didn't need: `Prover.toml`.

use std::{
    collections::HashMap,
    io::Read as _,
    path::{
        Path,
        PathBuf,
    },
    process::Command,
    sync::Mutex,
};

use ark_bn254::Fr;
use barretenberg_rs::{
    BarretenbergApi,
    backends::pipe::PipeBackend,
    generated_types::{
        CircuitInput,
        CircuitInputNoVK,
        ProofSystemSettings,
    },
};
use base64::{
    Engine as _,
    engine::general_purpose::STANDARD as BASE64,
};
use flate2::read::GzDecoder;
use toml::Value;

use crate::{
    domain::witness::{
        AttestationWitness,
        BlockedWithdrawWitness,
        ComplianceWitness,
        DepositWitness,
        TransferWitness,
        WithdrawWitness,
    },
    error::ProverError,
    ports::{
        merkle::{
            MerklePath,
            Side,
        },
        prover::{
            Circuit,
            CircuitProof,
            ProofRequest,
            Prover,
        },
    },
    types::{
        Address,
        Bytes32,
    },
};

const COMMITMENT_DEPTH: usize = crate::MAX_COMMITMENT_TREE_DEPTH as usize;
const ATTESTATION_DEPTH: usize = crate::MAX_ATTESTATION_TREE_DEPTH as usize;
const REVOCATION_DEPTH: usize = crate::ATTESTER_TREE_DEPTH as usize;

/// `disable_zk` MUST stay `false`: the non-ZK flavor commits to the witness and
/// voids the SPEC's confidentiality claims, so this is not exposed as a knob.
fn settings() -> ProofSystemSettings {
    ProofSystemSettings {
        ipa_accumulation: false,
        oracle_hash_type: "keccak".to_string(),
        disable_zk: false,
        optimized_solidity_verifier: false,
    }
}

fn circuit_dir(circuit: Circuit) -> &'static str {
    match circuit {
        Circuit::Deposit => "deposit",
        Circuit::Transfer => "transfer",
        Circuit::Withdraw => "withdraw",
        Circuit::WithdrawBlocked => "withdraw_ungated",
    }
}

fn package_name(circuit: Circuit) -> String {
    format!("spc_{}", circuit_dir(circuit))
}

fn backend_err(e: impl std::error::Error + Send + Sync + 'static) -> ProverError {
    ProverError::Backend(Box::new(e))
}

fn backend_msg(msg: impl Into<String>) -> ProverError {
    ProverError::Backend(Box::new(std::io::Error::other(msg.into())))
}

struct Inner {
    api: BarretenbergApi<PipeBackend>,
    vk_cache: HashMap<Circuit, Vec<u8>>,
}

/// One mutex guards the backend handle, the VK cache, and the `nargo execute`/witness
/// file I/O together, so a prove can never observe a VK a concurrent call is still
/// computing while holding a separate lock on the api. The file I/O has to sit inside
/// the same critical section for a reason `examples/bb_smoke.rs` never exercises:
/// `circuits/` is an `nargo` workspace, and `nargo execute witness` run from a member
/// directory still writes to the *workspace root's* shared `circuits/target/witness.gz`,
/// not a per-member `target/`, confirmed empirically (`circuits/target/witness.gz` is
/// the file that appears on disk, never `circuits/<dir>/target/witness.gz`). Two
/// concurrent `prove()` calls for different circuits would otherwise race on that one
/// shared file and could each read the other's witness.
pub struct BbProver {
    inner: Mutex<Inner>,
    project_root: PathBuf,
    nargo_path: PathBuf,
}

impl BbProver {
    pub fn new(
        bb_path: &Path,
        nargo_path: PathBuf,
        project_root: PathBuf,
    ) -> Result<Self, ProverError> {
        let backend = PipeBackend::new(bb_path, None).map_err(backend_err)?;
        let api = BarretenbergApi::new(backend);
        Ok(Self {
            inner: Mutex::new(Inner {
                api,
                vk_cache: HashMap::new(),
            }),
            project_root,
            nargo_path,
        })
    }
}

/// Removes the private `Prover.toml` and `target/witness.gz` on drop, on both the
/// success and failure paths, so witness material never outlives one proving call.
struct WitnessCleanup {
    prover_toml: PathBuf,
    witness_gz: PathBuf,
}

impl Drop for WitnessCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.prover_toml);
        let _ = std::fs::remove_file(&self.witness_gz);
    }
}

fn gunzip(bytes: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    GzDecoder::new(bytes).read_to_end(&mut out)?;
    Ok(out)
}

/// Base64-decodes then gunzip-decompresses the artifact JSON's `bytecode` field.
/// Barretenberg reports the first byte it reads as a format marker; only the fully
/// decompressed ACIR starts with the marker it expects.
fn decode_bytecode(artifact_json: &[u8]) -> std::io::Result<Vec<u8>> {
    let json: serde_json::Value = serde_json::from_slice(artifact_json)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let field = json
        .get("bytecode")
        .and_then(|v| v.as_str())
        .ok_or_else(|| std::io::Error::other("artifact JSON has no bytecode field"))?;
    let gzipped = BASE64
        .decode(field)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    gunzip(&gzipped)
}

/// The one total decode from a backend-returned 32-byte slice to a canonical public
/// input, the Rust twin of the contract's `requireCanonical`: a value at or above the
/// BN254 modulus is rejected, never silently reduced.
fn bytes32_from_backend(raw: &[u8]) -> std::io::Result<Bytes32> {
    let arr: [u8; 32] = raw.try_into().map_err(|_| {
        std::io::Error::other(format!("public input is {} bytes, not 32", raw.len()))
    })?;
    let bytes = Bytes32::from(arr);
    Fr::try_from(bytes).map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok(bytes)
}

/// UltraHonk proof elements are 32-byte BN254 field elements; `circuit_prove` returns
/// them as `Vec<Vec<u8>>` and `circuit_verify` wants them back the same way. The port's
/// `CircuitProof::proof` is a flat `Vec<u8>` (fixed by `ports::prover`), so this chunks
/// it back into 32-byte elements to reverse `Vec<Vec<u8>>::concat()`.
fn chunk_proof(flat: &[u8]) -> Result<Vec<Vec<u8>>, ProverError> {
    if !flat.len().is_multiple_of(32) {
        return Err(ProverError::MalformedProof {
            expected: flat.len().div_ceil(32) * 32,
            actual: flat.len(),
        });
    }
    Ok(flat.chunks_exact(32).map(<[u8]>::to_vec).collect())
}

impl Prover for BbProver {
    fn prove(&self, request: &ProofRequest) -> Result<CircuitProof, ProverError> {
        let circuit = request.circuit();
        let dir = self
            .project_root
            .join("circuits")
            .join(circuit_dir(circuit));
        let prover_toml_path = dir.join("Prover.toml");
        // Workspace-shared, not `dir.join("target/witness.gz")`: see `BbProver`'s doc comment.
        // `_cleanup` drops after `inner`'s guard releases, so a racing `prove()` can see its files deleted mid-run (loud failure, never a wrong proof).
        let witness_path = self.project_root.join("circuits/target/witness.gz");
        let _cleanup = WitnessCleanup {
            prover_toml: prover_toml_path.clone(),
            witness_gz: witness_path.clone(),
        };

        let mut inner = self.inner.lock().expect("bb prover mutex poisoned");

        std::fs::write(&prover_toml_path, render_prover_toml(request)).map_err(|e| {
            backend_msg(format!("write {}: {e}", prover_toml_path.display()))
        })?;

        let output = Command::new(&self.nargo_path)
            .args(["execute", "witness"])
            .current_dir(&dir)
            .output()
            .map_err(|e| {
                backend_msg(format!(
                    "spawn {} in {}: {e}",
                    self.nargo_path.display(),
                    dir.display()
                ))
            })?;
        if !output.status.success() {
            return Err(backend_msg(format!(
                "nargo execute witness failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        let witness_gz = std::fs::read(&witness_path)
            .map_err(|e| backend_msg(format!("read {}: {e}", witness_path.display())))?;
        let witness = gunzip(&witness_gz).map_err(backend_err)?;

        let artifact_path = self
            .project_root
            .join("circuits/target")
            .join(format!("{}.json", package_name(circuit)));
        let artifact_json = std::fs::read(&artifact_path)
            .map_err(|e| backend_msg(format!("read {}: {e}", artifact_path.display())))?;
        let bytecode = decode_bytecode(&artifact_json).map_err(backend_err)?;

        let vk = match inner.vk_cache.get(&circuit) {
            Some(vk) => vk.clone(),
            None => {
                let resp = inner
                    .api
                    .circuit_compute_vk(
                        CircuitInputNoVK {
                            name: package_name(circuit),
                            bytecode: bytecode.clone(),
                        },
                        settings(),
                    )
                    .map_err(backend_err)?;
                inner.vk_cache.insert(circuit, resp.bytes.clone());
                resp.bytes
            }
        };

        let prove_resp = inner
            .api
            .circuit_prove(
                CircuitInput {
                    name: package_name(circuit),
                    bytecode,
                    verification_key: vk,
                },
                &witness,
                settings(),
            )
            .map_err(backend_err)?;
        drop(inner);

        let public_inputs = prove_resp
            .public_inputs
            .iter()
            .map(|raw| bytes32_from_backend(raw))
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(backend_err)?;

        Ok(CircuitProof {
            proof: prove_resp.proof.concat(),
            public_inputs,
        })
    }

    fn verify(
        &self,
        circuit: Circuit,
        proof: &CircuitProof,
    ) -> Result<bool, ProverError> {
        let proof_chunks = chunk_proof(&proof.proof)?;
        let public_inputs: Vec<Vec<u8>> = proof
            .public_inputs
            .iter()
            .map(|b| b.as_ref().to_vec())
            .collect();

        let mut inner = self.inner.lock().expect("bb prover mutex poisoned");
        let vk =
            inner.vk_cache.get(&circuit).cloned().ok_or_else(|| {
                backend_msg("no cached verification key; call prove first")
            })?;

        let resp = inner
            .api
            .circuit_verify(&vk, public_inputs, proof_chunks, settings())
            .map_err(backend_err)?;
        Ok(resp.verified)
    }
}

fn field_hex(bytes: Bytes32) -> String {
    format!("0x{}", hex::encode(bytes.as_ref()))
}

fn address_field_hex(address: Address) -> String {
    field_hex(Bytes32::from(Fr::from(address)))
}

fn u64_str(v: u64) -> String {
    v.to_string()
}

struct PaddedPath {
    length: usize,
    indices: Vec<bool>,
    siblings_hex: Vec<String>,
}

/// Pads a variable-length `MerklePath` to `depth` with zero siblings and `false`
/// indices, recording the real step count separately. `PathStep.side == Side::Right`
/// becomes `true`, matching the vendored Noir `binary_merkle_root` convention.
fn pad_path(path: &MerklePath, depth: usize) -> PaddedPath {
    let steps = path.steps();
    assert!(
        steps.len() <= depth,
        "merkle path has {} steps, exceeds circuit depth {depth}",
        steps.len()
    );
    let mut indices = Vec::with_capacity(depth);
    let mut siblings_hex = Vec::with_capacity(depth);
    for step in steps {
        indices.push(step.side == Side::Right);
        siblings_hex.push(field_hex(step.sibling));
    }
    let zero = field_hex(Bytes32::from([0u8; 32]));
    while indices.len() < depth {
        indices.push(false);
        siblings_hex.push(zero.clone());
    }
    PaddedPath {
        length: steps.len(),
        indices,
        siblings_hex,
    }
}

fn merkle_path_values(pad: &PaddedPath) -> (Value, Value) {
    let indices = Value::Array(pad.indices.iter().map(|b| Value::Boolean(*b)).collect());
    let path = Value::Array(
        pad.siblings_hex
            .iter()
            .cloned()
            .map(Value::String)
            .collect(),
    );
    (indices, path)
}

fn attestation_witness_value(witness: &AttestationWitness) -> Value {
    let att = pad_path(&witness.attestation_proof, ATTESTATION_DEPTH);
    let rev = pad_path(&witness.revocation_proof, REVOCATION_DEPTH);
    let (att_indices, att_path) = merkle_path_values(&att);
    let (rev_indices, rev_path) = merkle_path_values(&rev);

    let mut table = toml::map::Map::new();
    table.insert(
        "attester".into(),
        Value::String(address_field_hex(witness.attester)),
    );
    table.insert(
        "generation".into(),
        Value::String(u64_str(witness.generation.0)),
    );
    table.insert(
        "issued_at".into(),
        Value::String(u64_str(witness.issued_at)),
    );
    table.insert(
        "expires_at".into(),
        Value::String(u64_str(witness.expires_at)),
    );
    table.insert(
        "att_proof_length".into(),
        Value::String(u64_str(att.length as u64)),
    );
    table.insert("att_indices".into(), att_indices);
    table.insert("att_path".into(), att_path);
    table.insert(
        "revoked_at".into(),
        Value::String(u64_str(witness.revoked_at)),
    );
    table.insert("rev_indices".into(), rev_indices);
    table.insert("rev_path".into(), rev_path);
    Value::Table(table)
}

fn prev_state_value(state: crate::domain::witness::PolicyState) -> Value {
    let mut table = toml::map::Map::new();
    let s: Vec<Value> = state
        .as_ref()
        .iter()
        .map(|v| Value::String(u64_str(*v)))
        .collect();
    table.insert("s".into(), Value::Array(s));
    Value::Table(table)
}

fn insert_compliance(table: &mut toml::map::Map<String, Value>, c: &ComplianceWitness) {
    table.insert("seq".into(), Value::String(u64_str(c.seq.0)));
    table.insert("epoch_in".into(), Value::String(u64_str(c.epoch_in.0)));
    table.insert("prev".into(), prev_state_value(c.prev));
    table.insert("flags_in".into(), Value::String(u64_str(c.flags_in)));
    table.insert(
        "cp_in".into(),
        Value::Array(
            c.cp_in
                .iter()
                .map(|b| Value::String(field_hex(*b)))
                .collect(),
        ),
    );
    table.insert(
        "amt_in".into(),
        Value::Array(
            c.amt_in
                .iter()
                .map(|v| Value::String(u64_str(*v)))
                .collect(),
        ),
    );
    table.insert("exit_in".into(), Value::String(field_hex(c.exit_in)));
    table.insert("salt_in".into(), Value::String(field_hex(c.salt_in)));
    table.insert("salt_out".into(), Value::String(field_hex(c.salt_out)));

    let cn = pad_path(&c.cn_proof, COMMITMENT_DEPTH);
    let (cn_indices, cn_path) = merkle_path_values(&cn);
    table.insert(
        "cn_proof_length".into(),
        Value::String(u64_str(cn.length as u64)),
    );
    table.insert("cn_indices".into(), cn_indices);
    table.insert("cn_path".into(), cn_path);
}

fn spending_key_hex(key: &crate::domain::keys::SpendingKey) -> String {
    field_hex(Bytes32::from(key.to_bytes()))
}

fn to_toml(table: toml::map::Map<String, Value>) -> String {
    toml::to_string(&Value::Table(table)).expect("Prover.toml serialization never fails")
}

fn deposit_toml(w: &DepositWitness) -> String {
    let mut t = toml::map::Map::new();
    let f = &w.public;
    t.insert("commitment".into(), Value::String(field_hex(f.commitment)));
    t.insert("token".into(), Value::String(field_hex(f.token)));
    t.insert("amount".into(), Value::String(u64_str(f.amount)));
    t.insert(
        "attestation_root".into(),
        Value::String(field_hex(f.attestation_root)),
    );
    t.insert(
        "velocity_nullifier".into(),
        Value::String(field_hex(f.velocity_nullifier)),
    );
    t.insert(
        "compliance_commitment_out".into(),
        Value::String(field_hex(f.compliance_commitment_out)),
    );
    t.insert("epoch".into(), Value::String(u64_str(f.epoch.0)));
    t.insert(
        "epoch_seconds".into(),
        Value::String(u64_str(f.epoch_seconds)),
    );
    t.insert(
        "policy_source_hash".into(),
        Value::String(field_hex(f.policy_source_hash)),
    );
    t.insert(
        "commitment_root".into(),
        Value::String(field_hex(f.commitment_root)),
    );
    t.insert(
        "attester_revocation_root".into(),
        Value::String(field_hex(f.attester_revocation_root)),
    );
    t.insert(
        "min_accepted_generation".into(),
        Value::String(u64_str(f.min_accepted_generation)),
    );
    t.insert(
        "payload_commitment".into(),
        Value::String(field_hex(f.payload_commitment)),
    );

    t.insert(
        "spending_key".into(),
        Value::String(spending_key_hex(&w.spending_key)),
    );
    t.insert("salt".into(), Value::String(field_hex(w.note_salt)));
    t.insert(
        "attestation_witness".into(),
        attestation_witness_value(&w.attestation),
    );
    insert_compliance(&mut t, &w.compliance);

    to_toml(t)
}

fn transfer_toml(w: &TransferWitness) -> String {
    let mut t = toml::map::Map::new();
    let f = &w.public;
    t.insert(
        "nullifier_0".into(),
        Value::String(field_hex(f.nullifier_0)),
    );
    t.insert(
        "nullifier_1".into(),
        Value::String(field_hex(f.nullifier_1)),
    );
    t.insert(
        "commitment_out_0".into(),
        Value::String(field_hex(f.commitment_out_0)),
    );
    t.insert(
        "commitment_out_1".into(),
        Value::String(field_hex(f.commitment_out_1)),
    );
    t.insert(
        "commitment_root".into(),
        Value::String(field_hex(f.commitment_root)),
    );
    t.insert(
        "velocity_nullifier".into(),
        Value::String(field_hex(f.velocity_nullifier)),
    );
    t.insert(
        "compliance_commitment_out".into(),
        Value::String(field_hex(f.compliance_commitment_out)),
    );
    t.insert("epoch".into(), Value::String(u64_str(f.epoch.0)));
    t.insert(
        "epoch_seconds".into(),
        Value::String(u64_str(f.epoch_seconds)),
    );
    t.insert(
        "policy_source_hash".into(),
        Value::String(field_hex(f.policy_source_hash)),
    );
    t.insert(
        "attestation_root".into(),
        Value::String(field_hex(f.attestation_root)),
    );
    t.insert(
        "attester_revocation_root".into(),
        Value::String(field_hex(f.attester_revocation_root)),
    );
    t.insert(
        "min_accepted_generation".into(),
        Value::String(u64_str(f.min_accepted_generation)),
    );
    t.insert(
        "payload_commitment".into(),
        Value::String(field_hex(f.payload_commitment)),
    );

    t.insert(
        "spending_key".into(),
        Value::String(spending_key_hex(&w.spending_key)),
    );

    let token_hex = address_field_hex(w.token);
    t.insert("token_in_0".into(), Value::String(token_hex.clone()));
    t.insert(
        "amount_in_0".into(),
        Value::String(u64_str(w.inputs[0].amount)),
    );
    t.insert(
        "salt_in_0".into(),
        Value::String(field_hex(w.inputs[0].salt)),
    );
    t.insert("token_in_1".into(), Value::String(token_hex.clone()));
    t.insert(
        "amount_in_1".into(),
        Value::String(u64_str(w.inputs[1].amount)),
    );
    t.insert(
        "salt_in_1".into(),
        Value::String(field_hex(w.inputs[1].salt)),
    );
    t.insert("token_out_0".into(), Value::String(token_hex.clone()));
    t.insert(
        "amount_out_0".into(),
        Value::String(u64_str(w.outputs[0].amount)),
    );
    t.insert(
        "owner_out_0".into(),
        Value::String(field_hex(w.outputs[0].owner.as_bytes32())),
    );
    t.insert(
        "salt_out_0".into(),
        Value::String(field_hex(w.outputs[0].salt)),
    );
    t.insert("token_out_1".into(), Value::String(token_hex));
    t.insert(
        "amount_out_1".into(),
        Value::String(u64_str(w.outputs[1].amount)),
    );
    t.insert(
        "owner_out_1".into(),
        Value::String(field_hex(w.outputs[1].owner.as_bytes32())),
    );
    t.insert(
        "salt_out_1".into(),
        Value::String(field_hex(w.outputs[1].salt)),
    );

    let pad0 = pad_path(&w.inputs[0].proof, COMMITMENT_DEPTH);
    let pad1 = pad_path(&w.inputs[1].proof, COMMITMENT_DEPTH);
    t.insert(
        "proof_length_0".into(),
        Value::String(u64_str(pad0.length as u64)),
    );
    t.insert(
        "proof_length_1".into(),
        Value::String(u64_str(pad1.length as u64)),
    );
    let (indices_0, path_0) = merkle_path_values(&pad0);
    let (indices_1, path_1) = merkle_path_values(&pad1);
    t.insert("path_0".into(), path_0);
    t.insert("indices_0".into(), indices_0);
    t.insert("path_1".into(), path_1);
    t.insert("indices_1".into(), indices_1);

    t.insert(
        "subject_attestation".into(),
        attestation_witness_value(&w.subject_attestation),
    );
    t.insert(
        "out0_attestation".into(),
        attestation_witness_value(&w.output_attestations[0]),
    );
    t.insert(
        "out1_attestation".into(),
        attestation_witness_value(&w.output_attestations[1]),
    );

    insert_compliance(&mut t, &w.compliance);

    to_toml(t)
}

fn withdraw_toml(w: &WithdrawWitness) -> String {
    let mut t = toml::map::Map::new();
    let f = &w.public;
    t.insert("nullifier".into(), Value::String(field_hex(f.nullifier)));
    t.insert("token".into(), Value::String(field_hex(f.token)));
    t.insert("amount".into(), Value::String(u64_str(f.amount)));
    t.insert("recipient".into(), Value::String(field_hex(f.recipient)));
    t.insert(
        "commitment_root".into(),
        Value::String(field_hex(f.commitment_root)),
    );
    t.insert(
        "velocity_nullifier".into(),
        Value::String(field_hex(f.velocity_nullifier)),
    );
    t.insert(
        "compliance_commitment_out".into(),
        Value::String(field_hex(f.compliance_commitment_out)),
    );
    t.insert("epoch".into(), Value::String(u64_str(f.epoch.0)));
    t.insert(
        "epoch_seconds".into(),
        Value::String(u64_str(f.epoch_seconds)),
    );
    t.insert(
        "policy_source_hash".into(),
        Value::String(field_hex(f.policy_source_hash)),
    );
    t.insert(
        "attestation_root".into(),
        Value::String(field_hex(f.attestation_root)),
    );
    t.insert(
        "attester_revocation_root".into(),
        Value::String(field_hex(f.attester_revocation_root)),
    );
    t.insert(
        "min_accepted_generation".into(),
        Value::String(u64_str(f.min_accepted_generation)),
    );
    t.insert(
        "payload_commitment".into(),
        Value::String(field_hex(f.payload_commitment)),
    );

    t.insert(
        "spending_key".into(),
        Value::String(spending_key_hex(&w.spending_key)),
    );
    t.insert("salt".into(), Value::String(field_hex(w.note_salt)));

    let pad = pad_path(&w.note_proof, COMMITMENT_DEPTH);
    t.insert(
        "proof_length".into(),
        Value::String(u64_str(pad.length as u64)),
    );
    let (indices, path) = merkle_path_values(&pad);
    t.insert("path".into(), path);
    t.insert("indices".into(), indices);

    t.insert(
        "subject_attestation".into(),
        attestation_witness_value(&w.attestation),
    );
    insert_compliance(&mut t, &w.compliance);

    to_toml(t)
}

fn withdraw_ungated_toml(w: &BlockedWithdrawWitness) -> String {
    let mut t = toml::map::Map::new();
    let f = &w.public;
    t.insert("nullifier".into(), Value::String(field_hex(f.nullifier)));
    t.insert("token".into(), Value::String(field_hex(f.token)));
    // The parent PoC's circuit, untouched: `amount` stays Field-typed here, unlike
    // the gated circuits' u64 `amount`.
    t.insert("amount".into(), Value::String(field_hex(f.amount)));
    t.insert("recipient".into(), Value::String(field_hex(f.recipient)));
    t.insert(
        "commitment_root".into(),
        Value::String(field_hex(f.commitment_root)),
    );

    t.insert(
        "spending_key".into(),
        Value::String(spending_key_hex(&w.spending_key)),
    );
    t.insert("salt".into(), Value::String(field_hex(w.note_salt)));

    let pad = pad_path(&w.note_proof, COMMITMENT_DEPTH);
    t.insert(
        "proof_length".into(),
        Value::String(u64_str(pad.length as u64)),
    );
    let (indices, path) = merkle_path_values(&pad);
    t.insert("path".into(), path);
    t.insert("indices".into(), indices);

    to_toml(t)
}

fn render_prover_toml(request: &ProofRequest) -> String {
    match request {
        ProofRequest::Deposit(w) => deposit_toml(w),
        ProofRequest::Transfer(w) => transfer_toml(w),
        ProofRequest::Withdraw(w) => withdraw_toml(w),
        ProofRequest::WithdrawBlocked(w) => withdraw_ungated_toml(w),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        domain::{
            attestation::Generation,
            keys::SpendingKey,
            public_inputs::{
                deposit,
                gated_withdraw,
                ungated_withdraw,
            },
        },
        policy::{
            Policy,
            reference::ReferencePolicy,
        },
        ports::merkle::PathStep,
        types::{
            Epoch,
            Seq,
        },
    };

    fn short_path() -> MerklePath {
        MerklePath::new(vec![
            PathStep {
                sibling: Bytes32::from([1u8; 32]),
                side: Side::Left,
            },
            PathStep {
                sibling: Bytes32::from([2u8; 32]),
                side: Side::Right,
            },
        ])
    }

    fn attestation_witness() -> AttestationWitness {
        AttestationWitness {
            attester: Address::from([0xaa; 20]),
            generation: Generation(1),
            issued_at: 10,
            expires_at: 20,
            attestation_proof: short_path(),
            revoked_at: u64::MAX,
            revocation_proof: MerklePath::new(vec![PathStep {
                sibling: Bytes32::from([3u8; 32]),
                side: Side::Right,
            }]),
        }
    }

    fn compliance_witness() -> ComplianceWitness {
        ComplianceWitness {
            seq: Seq(0),
            epoch_in: Epoch(100),
            prev: ReferencePolicy::zero(),
            flags_in: 0,
            cp_in: [Bytes32::from([0u8; 32]); 2],
            amt_in: [0, 0],
            exit_in: Bytes32::from([0u8; 32]),
            salt_in: Bytes32::from([0u8; 32]),
            salt_out: Bytes32::from([0u8; 32]),
            cn_proof: short_path(),
        }
    }

    fn deposit_request() -> ProofRequest {
        ProofRequest::Deposit(Box::new(DepositWitness {
            public: deposit::Fields {
                commitment: Bytes32::from([1u8; 32]),
                token: Bytes32::from([2u8; 32]),
                amount: 1000,
                attestation_root: Bytes32::from([3u8; 32]),
                velocity_nullifier: Bytes32::from([4u8; 32]),
                compliance_commitment_out: Bytes32::from([5u8; 32]),
                epoch: Epoch(100),
                epoch_seconds: 86400,
                policy_source_hash: Bytes32::from([6u8; 32]),
                commitment_root: Bytes32::from([7u8; 32]),
                attester_revocation_root: Bytes32::from([8u8; 32]),
                min_accepted_generation: 1,
                payload_commitment: Bytes32::from([9u8; 32]),
            },
            spending_key: SpendingKey::random(),
            note_salt: Bytes32::from([9u8; 32]),
            attestation: attestation_witness(),
            compliance: compliance_witness(),
        }))
    }

    fn parsed(request: &ProofRequest) -> toml::Table {
        render_prover_toml(request)
            .parse::<toml::Table>()
            .expect("valid toml")
    }

    #[test]
    fn short_merkle_path_pads_to_full_depth_with_real_length_recorded() {
        let table = parsed(&deposit_request());
        let att = table["attestation_witness"].as_table().unwrap();
        assert_eq!(
            att["att_indices"].as_array().unwrap().len(),
            ATTESTATION_DEPTH
        );
        assert_eq!(att["att_path"].as_array().unwrap().len(), ATTESTATION_DEPTH);
        assert_eq!(att["att_proof_length"].as_str().unwrap(), "2");
        assert_eq!(
            att["rev_indices"].as_array().unwrap().len(),
            REVOCATION_DEPTH
        );
        assert_eq!(att["rev_path"].as_array().unwrap().len(), REVOCATION_DEPTH);

        let cn_indices = table["cn_indices"].as_array().unwrap();
        assert_eq!(cn_indices.len(), COMMITMENT_DEPTH);
        assert_eq!(table["cn_proof_length"].as_str().unwrap(), "2");
        // Padded tail entries are false.
        assert!(!cn_indices[2].as_bool().unwrap());
        assert!(!cn_indices[COMMITMENT_DEPTH - 1].as_bool().unwrap());
    }

    #[test]
    fn side_right_step_becomes_true() {
        let table = parsed(&deposit_request());
        let att = table["attestation_witness"].as_table().unwrap();
        let att_indices = att["att_indices"].as_array().unwrap();
        // short_path()'s second step is Side::Right.
        assert!(!att_indices[0].as_bool().unwrap());
        assert!(att_indices[1].as_bool().unwrap());

        let rev_indices = att["rev_indices"].as_array().unwrap();
        assert!(rev_indices[0].as_bool().unwrap());
    }

    #[test]
    fn deposit_toml_contains_every_field_in_the_main_signature() {
        let table = parsed(&deposit_request());
        for key in [
            "commitment",
            "token",
            "amount",
            "attestation_root",
            "velocity_nullifier",
            "compliance_commitment_out",
            "epoch",
            "epoch_seconds",
            "policy_source_hash",
            "commitment_root",
            "attester_revocation_root",
            "min_accepted_generation",
            "payload_commitment",
            "spending_key",
            "salt",
            "attestation_witness",
            "seq",
            "epoch_in",
            "prev",
            "flags_in",
            "cp_in",
            "amt_in",
            "exit_in",
            "salt_in",
            "salt_out",
            "cn_proof_length",
            "cn_indices",
            "cn_path",
        ] {
            assert!(table.contains_key(key), "missing key {key}");
        }
        let prev = table["prev"].as_table().unwrap();
        assert_eq!(prev["s"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn withdraw_toml_contains_every_field_in_the_main_signature() {
        let request = ProofRequest::Withdraw(Box::new(WithdrawWitness {
            public: gated_withdraw::Fields {
                nullifier: Bytes32::from([1u8; 32]),
                token: Bytes32::from([2u8; 32]),
                amount: 500,
                recipient: Bytes32::from([3u8; 32]),
                commitment_root: Bytes32::from([4u8; 32]),
                velocity_nullifier: Bytes32::from([5u8; 32]),
                compliance_commitment_out: Bytes32::from([6u8; 32]),
                epoch: Epoch(1),
                epoch_seconds: 86400,
                policy_source_hash: Bytes32::from([7u8; 32]),
                attestation_root: Bytes32::from([8u8; 32]),
                attester_revocation_root: Bytes32::from([9u8; 32]),
                min_accepted_generation: 1,
                payload_commitment: Bytes32::from([10u8; 32]),
            },
            spending_key: SpendingKey::random(),
            note_salt: Bytes32::from([10u8; 32]),
            note_proof: short_path(),
            attestation: attestation_witness(),
            compliance: compliance_witness(),
        }));
        let table = parsed(&request);
        for key in [
            "nullifier",
            "token",
            "amount",
            "recipient",
            "commitment_root",
            "velocity_nullifier",
            "compliance_commitment_out",
            "epoch",
            "epoch_seconds",
            "policy_source_hash",
            "attestation_root",
            "attester_revocation_root",
            "min_accepted_generation",
            "payload_commitment",
            "spending_key",
            "salt",
            "proof_length",
            "path",
            "indices",
            "subject_attestation",
            "seq",
            "epoch_in",
            "prev",
            "flags_in",
            "cp_in",
            "amt_in",
            "exit_in",
            "salt_in",
            "salt_out",
            "cn_proof_length",
            "cn_indices",
            "cn_path",
        ] {
            assert!(table.contains_key(key), "missing key {key}");
        }
        // gated withdraw's amount is u64: a plain decimal string.
        assert_eq!(table["amount"].as_str().unwrap(), "500");
    }

    #[test]
    fn ungated_withdraw_amount_is_a_field_not_a_u64() {
        let request = ProofRequest::WithdrawBlocked(Box::new(BlockedWithdrawWitness {
            public: ungated_withdraw::Fields {
                nullifier: Bytes32::from([1u8; 32]),
                token: Bytes32::from([2u8; 32]),
                amount: Bytes32::from([0x12u8; 32]),
                recipient: Bytes32::from([3u8; 32]),
                commitment_root: Bytes32::from([4u8; 32]),
            },
            spending_key: SpendingKey::random(),
            note_salt: Bytes32::from([5u8; 32]),
            note_proof: short_path(),
        }));
        let table = parsed(&request);
        for key in [
            "nullifier",
            "token",
            "amount",
            "recipient",
            "commitment_root",
            "spending_key",
            "salt",
            "proof_length",
            "path",
            "indices",
        ] {
            assert!(table.contains_key(key), "missing key {key}");
        }
        // A Field value renders as the full 32-byte hex encoding, not a short decimal
        // integer: this is what distinguishes it from the gated circuits' u64 amount.
        let amount = table["amount"].as_str().unwrap();
        assert_eq!(amount, format!("0x{}", "12".repeat(32)));
        assert!(amount.starts_with("0x"));
        assert_eq!(amount.len(), 2 + 64);
        assert!(amount.parse::<u64>().is_err());
        // No compliance/attestation fields on the ungated path.
        assert!(!table.contains_key("subject_attestation"));
        assert!(!table.contains_key("prev"));
    }

    #[test]
    fn transfer_toml_shares_token_across_all_four_notes() {
        let token = Address::from([0x22; 20]);
        let request = ProofRequest::Transfer(Box::new(TransferWitness {
            public: crate::domain::public_inputs::transfer::Fields {
                nullifier_0: Bytes32::from([1u8; 32]),
                nullifier_1: Bytes32::from([2u8; 32]),
                commitment_out_0: Bytes32::from([3u8; 32]),
                commitment_out_1: Bytes32::from([4u8; 32]),
                commitment_root: Bytes32::from([5u8; 32]),
                velocity_nullifier: Bytes32::from([6u8; 32]),
                compliance_commitment_out: Bytes32::from([7u8; 32]),
                epoch: Epoch(1),
                epoch_seconds: 86400,
                policy_source_hash: Bytes32::from([8u8; 32]),
                attestation_root: Bytes32::from([9u8; 32]),
                attester_revocation_root: Bytes32::from([10u8; 32]),
                min_accepted_generation: 1,
                payload_commitment: Bytes32::from([11u8; 32]),
            },
            spending_key: SpendingKey::random(),
            token,
            inputs: [
                crate::domain::witness::InputNoteWitness {
                    amount: 10,
                    salt: Bytes32::from([11u8; 32]),
                    proof: short_path(),
                },
                crate::domain::witness::InputNoteWitness {
                    amount: 0,
                    salt: Bytes32::from([12u8; 32]),
                    proof: MerklePath::new(vec![]),
                },
            ],
            outputs: [
                crate::domain::witness::OutputNoteWitness {
                    amount: 5,
                    owner: SpendingKey::random().derive_owner_pubkey(),
                    salt: Bytes32::from([13u8; 32]),
                },
                crate::domain::witness::OutputNoteWitness {
                    amount: 5,
                    owner: SpendingKey::random().derive_owner_pubkey(),
                    salt: Bytes32::from([14u8; 32]),
                },
            ],
            subject_attestation: attestation_witness(),
            output_attestations: [attestation_witness(), attestation_witness()],
            compliance: compliance_witness(),
        }));
        let table = parsed(&request);
        let expected_token = address_field_hex(token);
        for key in ["token_in_0", "token_in_1", "token_out_0", "token_out_1"] {
            assert_eq!(table[key].as_str().unwrap(), expected_token);
        }
        // Each input note carries its own proof length: 2 real steps for the
        // first input, 0 for the empty padding note.
        assert_eq!(table["proof_length_0"].as_str().unwrap(), "2");
        assert_eq!(table["proof_length_1"].as_str().unwrap(), "0");
    }

    #[test]
    fn transfer_toml_emits_distinct_lengths_for_unequal_depth_inputs() {
        let token = Address::from([0x22; 20]);
        let request = ProofRequest::Transfer(Box::new(TransferWitness {
            public: crate::domain::public_inputs::transfer::Fields {
                nullifier_0: Bytes32::from([1u8; 32]),
                nullifier_1: Bytes32::from([2u8; 32]),
                commitment_out_0: Bytes32::from([3u8; 32]),
                commitment_out_1: Bytes32::from([4u8; 32]),
                commitment_root: Bytes32::from([5u8; 32]),
                velocity_nullifier: Bytes32::from([6u8; 32]),
                compliance_commitment_out: Bytes32::from([7u8; 32]),
                epoch: Epoch(1),
                epoch_seconds: 86400,
                policy_source_hash: Bytes32::from([8u8; 32]),
                attestation_root: Bytes32::from([9u8; 32]),
                attester_revocation_root: Bytes32::from([10u8; 32]),
                min_accepted_generation: 1,
                payload_commitment: Bytes32::from([11u8; 32]),
            },
            spending_key: SpendingKey::random(),
            token,
            inputs: [
                crate::domain::witness::InputNoteWitness {
                    amount: 10,
                    salt: Bytes32::from([11u8; 32]),
                    proof: short_path(),
                },
                crate::domain::witness::InputNoteWitness {
                    amount: 5,
                    salt: Bytes32::from([12u8; 32]),
                    proof: MerklePath::new(vec![PathStep {
                        sibling: Bytes32::from([13u8; 32]),
                        side: Side::Left,
                    }]),
                },
            ],
            outputs: [
                crate::domain::witness::OutputNoteWitness {
                    amount: 5,
                    owner: SpendingKey::random().derive_owner_pubkey(),
                    salt: Bytes32::from([14u8; 32]),
                },
                crate::domain::witness::OutputNoteWitness {
                    amount: 10,
                    owner: SpendingKey::random().derive_owner_pubkey(),
                    salt: Bytes32::from([15u8; 32]),
                },
            ],
            subject_attestation: attestation_witness(),
            output_attestations: [attestation_witness(), attestation_witness()],
            compliance: compliance_witness(),
        }));
        let table = parsed(&request);
        assert_eq!(table["proof_length_0"].as_str().unwrap(), "2");
        assert_eq!(table["proof_length_1"].as_str().unwrap(), "1");
        assert_ne!(
            table["proof_length_0"].as_str().unwrap(),
            table["proof_length_1"].as_str().unwrap()
        );
    }

    #[test]
    fn decode_bytecode_reverses_base64_then_gzip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let raw_acir = b"\x03fake-acir-bytes-for-testing";
        let mut encoder =
            flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut encoder, raw_acir).unwrap();
        let gzipped = encoder.finish().unwrap();
        let b64 = BASE64.encode(&gzipped);
        let artifact = serde_json::json!({ "bytecode": b64, "noir_version": "1.0.0" });
        let path = dir.path().join("artifact.json");
        std::fs::write(&path, serde_json::to_vec(&artifact).unwrap()).unwrap();

        let bytes = decode_bytecode(&std::fs::read(&path).unwrap()).expect("decode");
        assert_eq!(bytes, raw_acir);
    }

    #[test]
    fn decode_bytecode_rejects_missing_field() {
        let artifact = serde_json::json!({ "not_bytecode": "x" });
        let err = decode_bytecode(&serde_json::to_vec(&artifact).unwrap());
        assert!(err.is_err());
    }

    #[test]
    fn chunk_proof_splits_into_32_byte_elements() {
        let flat = vec![0u8; 96];
        let chunks = chunk_proof(&flat).expect("multiple of 32");
        assert_eq!(chunks.len(), 3);
        assert!(chunks.iter().all(|c| c.len() == 32));
    }

    #[test]
    fn chunk_proof_rejects_a_length_not_a_multiple_of_32() {
        let flat = vec![0u8; 33];
        assert!(chunk_proof(&flat).is_err());
    }

    #[test]
    #[should_panic(expected = "exceeds circuit depth")]
    fn pad_path_panics_when_the_path_exceeds_the_circuit_depth() {
        let steps: Vec<PathStep> = (0..40)
            .map(|_| PathStep {
                sibling: Bytes32::from([0u8; 32]),
                side: Side::Left,
            })
            .collect();
        let _ = pad_path(&MerklePath::new(steps), COMMITMENT_DEPTH);
    }
}

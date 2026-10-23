//! The real `Prover`: `nargo execute` builds the witness, the Barretenberg msgpack
//! API proves and verifies it in-process over the FFI backend. The wire format is
//! decompressed ACIR and witness, `circuit_compute_vk` cached separately from
//! `circuit_prove`, `disable_zk: false`.

use std::{
    collections::HashMap,
    io::Read as _,
    os::unix::fs::PermissionsExt as _,
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
    backends::ffi::FfiBackend,
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
    domain::{
        feed::FeedSecret,
        grumpkin::Point,
        keys::PublicSpendKey,
        note::{
            LockOpening,
            Note,
        },
        tree::MerkleProof,
        witness::{
            AttestationWitness,
            DepositWitness,
            InputWitness,
            TransferWitness,
            WithdrawWitness,
        },
    },
    error::ProverError,
    ports::prover::{
        Circuit,
        CircuitProof,
        ProofRequest,
        Prover,
    },
    types::Bytes32,
};

const COMMITMENT_DEPTH: usize = crate::MAX_COMMITMENT_TREE_DEPTH as usize;
const ATTESTATION_DEPTH: usize = crate::MAX_ATTESTATION_TREE_DEPTH as usize;

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
    }
}

fn package_name(circuit: Circuit) -> String {
    format!("sn_{}", circuit_dir(circuit))
}

fn backend_err(e: impl std::error::Error + Send + Sync + 'static) -> ProverError {
    ProverError::Backend(Box::new(e))
}

fn backend_msg(msg: impl Into<String>) -> ProverError {
    ProverError::Backend(Box::new(std::io::Error::other(msg.into())))
}

struct Inner {
    api: BarretenbergApi<FfiBackend>,
    vk_cache: HashMap<Circuit, Vec<u8>>,
}

/// One mutex guards the backend handle and the VK cache. The witness is built outside
/// it, in a private directory per call (see `prove`).
pub struct BbProver {
    inner: Mutex<Inner>,
    /// Each circuit's compiled program, as `nargo` last wrote it. It holds no witness.
    artifacts: Mutex<HashMap<Circuit, Vec<u8>>>,
    project_root: PathBuf,
    nargo_path: PathBuf,
}

/// The BN254 SRS G2 point of the Aztec ignition ceremony.
const SRS_G2_POINT: &str = "0118c4d5b837bcc2bc89b5b398b5974e9f5944073b32078b7e231fec938883b0\
    260e01b251f6f1c7e7ff4e580791dee8ea51d87a358e038b4efe30fac09383c1\
    22febda3c0c0632a56475b4214e5615e11e6dd3f96e6cea2854a87d4dacc5e55\
    04fc6369f7110fe3d25156c1bb9a72859cf2a04641f99ba4ee413c80da6a5fe4";

const SRS_POINTS: u32 = 1 << 19;

/// `bb`'s own CRS location, same `BB_CRS_PATH` override it honours.
fn crs_g1_path() -> PathBuf {
    match std::env::var("BB_CRS_PATH") {
        Ok(dir) => PathBuf::from(dir),
        Err(_) => {
            PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".bb-crs")
        }
    }
    .join("bn254_g1.dat")
}

/// The CRS mirrors `bb` downloads from, in the order it tries them.
const CRS_G1_URLS: [&str; 2] = [
    "http://crs.aztec-cdn.foundation/g1.dat",
    "http://crs.aztec-labs.com/g1.dat",
];

/// Fetches the leading `len` bytes into `path`, the prefix of the flat file `bb` caches
/// there, so both share one cache. A `.part` sibling holds the download: an interrupted
/// `curl` must not leave a short file where a whole one is expected.
fn fetch_g1(path: &Path, len: u64) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let part = path.with_extension("part");
    eprintln!(
        "downloading {len} bytes of the BN254 CRS to {}",
        path.display()
    );
    for url in CRS_G1_URLS {
        let ok = Command::new("curl")
            .args(["-sfL", "-r", &format!("0-{}", len - 1), "-o"])
            .arg(&part)
            .arg(url)
            .status()?
            .success();
        if ok && std::fs::metadata(&part)?.len() == len {
            return std::fs::rename(&part, path);
        }
    }
    let _ = std::fs::remove_file(&part);
    Err(std::io::Error::other(format!(
        "no CRS mirror served {len} bytes: tried {}",
        CRS_G1_URLS.join(", ")
    )))
}

fn read_g1(path: &Path, len: u64) -> std::io::Result<Vec<u8>> {
    if std::fs::metadata(path).map(|m| m.len()).unwrap_or(0) < len {
        fetch_g1(path, len)?;
    }
    let mut points = vec![0u8; len as usize];
    std::fs::File::open(path)?.read_exact(&mut points)?;
    Ok(points)
}

fn init_srs(api: &mut BarretenbergApi<FfiBackend>) -> Result<(), ProverError> {
    let path = crs_g1_path();
    let points = read_g1(&path, u64::from(SRS_POINTS) * 64).map_err(|e| {
        backend_msg(format!(
            "cannot read {SRS_POINTS} points of the BN254 CRS from {}: {e}",
            path.display()
        ))
    })?;
    let g2 = hex::decode(SRS_G2_POINT).expect("SRS_G2_POINT is hex");
    api.srs_init_srs(&points, SRS_POINTS, &g2)
        .map_err(backend_err)?;
    Ok(())
}

impl BbProver {
    pub fn new(nargo_path: PathBuf, project_root: PathBuf) -> Result<Self, ProverError> {
        let backend = FfiBackend::new().map_err(backend_err)?;
        let mut api = BarretenbergApi::new(backend);
        init_srs(&mut api)?;
        Ok(Self {
            inner: Mutex::new(Inner {
                api,
                vk_cache: HashMap::new(),
            }),
            artifacts: Mutex::new(HashMap::new()),
            project_root,
            nargo_path,
        })
    }
}

/// A temporary directory only its owner can open. The default mode follows the
/// umask, which on a shared `/tmp` lets other users read the witness.
fn private_workdir() -> std::io::Result<tempfile::TempDir> {
    tempfile::Builder::new()
        .prefix("shielded-notes-prove-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
}

/// A stand-alone copy of one circuit's package in `package`: its manifest, with the
/// library's path made absolute, and a link to its sources.
fn write_package(
    circuits: &Path,
    circuit: Circuit,
    package: &Path,
) -> std::io::Result<()> {
    let dir = circuits.join(circuit_dir(circuit));
    let manifest = std::fs::read_to_string(dir.join("Nargo.toml"))?;
    let relative = "path = \"../lib\"";
    if !manifest.contains(relative) {
        return Err(std::io::Error::other(format!(
            "{} does not depend on `{relative}`",
            dir.join("Nargo.toml").display()
        )));
    }
    let lib = std::fs::canonicalize(circuits.join("lib"))?;
    std::fs::create_dir(package)?;
    std::fs::write(
        package.join("Nargo.toml"),
        manifest.replace(relative, &format!("path = \"{}\"", lib.display())),
    )?;
    std::os::unix::fs::symlink(
        std::fs::canonicalize(dir.join("src"))?,
        package.join("src"),
    )
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
        check_path_lengths(request)?;
        let circuit = request.circuit();
        // The witness holds `nk`, the plan signature, the note salts and the feed
        // secret. Each call builds a throwaway package in a private temporary directory
        // and runs `nargo execute` there, so neither `Prover.toml` nor the witness
        // reaches the checkout, and concurrent calls cannot collide. The directory is
        // removed on success, where a failed removal is an error, and on drop
        // otherwise; a process killed by a signal leaves it in the OS temp directory,
        // readable by its owner only.
        let work = private_workdir().map_err(backend_err)?;
        let dir = work.path().join(package_name(circuit));
        write_package(&self.project_root.join("circuits"), circuit, &dir)
            .map_err(backend_err)?;
        // `nargo` reuses a compiled program whose package matches, wherever the
        // package sits, so only each circuit's first proof compiles it.
        let artifact_path = dir
            .join("target")
            .join(format!("{}.json", package_name(circuit)));
        let cached = self
            .artifacts
            .lock()
            .expect("bb prover artifact cache poisoned")
            .get(&circuit)
            .cloned();
        if let Some(artifact) = cached {
            std::fs::create_dir(dir.join("target")).map_err(backend_err)?;
            std::fs::write(&artifact_path, artifact).map_err(backend_err)?;
        }
        let prover_toml_path = dir.join("Prover.toml");
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
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(match failed_assertion(&stderr) {
                Some(assertion) => ProverError::Unsatisfied {
                    assertion,
                    detail: stderr.into_owned(),
                },
                None => backend_msg(format!("nargo execute witness failed: {stderr}")),
            });
        }

        let witness_path = dir.join("target/witness.gz");
        let witness_gz = std::fs::read(&witness_path)
            .map_err(|e| backend_msg(format!("read {}: {e}", witness_path.display())))?;
        let witness = gunzip(&witness_gz).map_err(backend_err)?;

        // The program `nargo execute` compiled or reused with the witness, so the two
        // match.
        let artifact_json = std::fs::read(&artifact_path)
            .map_err(|e| backend_msg(format!("read {}: {e}", artifact_path.display())))?;
        let bytecode = decode_bytecode(&artifact_json).map_err(backend_err)?;
        self.artifacts
            .lock()
            .expect("bb prover artifact cache poisoned")
            .insert(circuit, artifact_json);
        work.close().map_err(backend_err)?;

        let mut inner = self.inner.lock().expect("bb prover mutex poisoned");
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

fn hex_value(fr: Fr) -> Value {
    Value::String(Bytes32::from(fr).to_string())
}

fn u64_value(v: u64) -> Value {
    Value::String(v.to_string())
}

fn u128_value(v: u128) -> Value {
    Value::String(format!("0x{v:x}"))
}

fn bytes_value(bytes: &[u8]) -> Value {
    Value::Array(
        bytes
            .iter()
            .map(|b| Value::Integer(i64::from(*b)))
            .collect(),
    )
}

fn point_value(p: &Point) -> Value {
    Value::Array(vec![hex_value(p.x), hex_value(p.y)])
}

fn fields_value(fields: &[Fr]) -> Value {
    Value::Array(fields.iter().map(|f| hex_value(*f)).collect())
}

fn table(entries: Vec<(&str, Value)>) -> Value {
    Value::Table(
        entries
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
    )
}

/// The message of the circuit assertion `nargo execute` reports failing, from
/// its `error: Assertion failed: <message>` line. `None` for any other failure.
fn failed_assertion(stderr: &str) -> Option<String> {
    let mut plain = String::with_capacity(stderr.len());
    let mut chars = stderr.chars();
    while let Some(c) = chars.next() {
        // Drop terminal colour codes, `ESC [ ... m`.
        if c == '\u{1b}' {
            for c in chars.by_ref() {
                if c == 'm' {
                    break;
                }
            }
            continue;
        }
        plain.push(c);
    }
    plain.lines().find_map(|line| {
        line.trim()
            .strip_prefix("error: Assertion failed")
            .map(|rest| rest.trim_start_matches(':').trim().to_string())
    })
}

/// Every Merkle path in the request fits its circuit's tree depth. A tree that
/// outgrew the circuit is a runtime condition, so it is an error here rather
/// than the assertion in `padded_path`.
fn check_path_lengths(request: &ProofRequest) -> Result<(), ProverError> {
    let check = |path: &MerkleProof, depth: usize| {
        if path.0.len() > depth {
            return Err(ProverError::PathTooLong {
                steps: path.0.len(),
                depth,
            });
        }
        Ok(())
    };
    match request {
        ProofRequest::Deposit(w) => check(&w.attestation.path, ATTESTATION_DEPTH),
        ProofRequest::Transfer(w) => {
            for input in &w.inputs {
                check(&input.path, COMMITMENT_DEPTH)?;
            }
            check(&w.input_attestation.path, ATTESTATION_DEPTH)?;
            for a in &w.output_attestations {
                check(&a.path, ATTESTATION_DEPTH)?;
            }
            Ok(())
        }
        ProofRequest::Withdraw(w) => {
            check(&w.input.path, COMMITMENT_DEPTH)?;
            check(&w.attestation.path, ATTESTATION_DEPTH)
        }
    }
}

/// A proof padded to `depth` with zero siblings and `false` indices, with its
/// real length recorded separately: `(proof_length, indices, path)`. The length
/// is checked by `check_path_lengths` before any rendering.
fn padded_path(proof: &MerkleProof, depth: usize) -> (Value, Value, Value) {
    assert!(
        proof.0.len() <= depth,
        "proof of {} steps exceeds depth {depth}",
        proof.0.len()
    );
    let mut indices = vec![Value::Boolean(false); depth];
    let mut path = vec![hex_value(Fr::from(0u64)); depth];
    for (i, step) in proof.0.iter().enumerate() {
        indices[i] = Value::Boolean(step.is_right);
        path[i] = hex_value(step.sibling);
    }
    (
        u64_value(proof.0.len() as u64),
        Value::Array(indices),
        Value::Array(path),
    )
}

fn spend_key_value(key: &PublicSpendKey) -> Value {
    table(vec![("x", bytes_value(&key.x)), ("y", bytes_value(&key.y))])
}

fn attestation_value(w: &AttestationWitness) -> Value {
    let (length, indices, path) = padded_path(&w.path, ATTESTATION_DEPTH);
    table(vec![
        ("attester", hex_value(Fr::from(w.attester))),
        ("generation", u64_value(w.generation)),
        ("issued_at", u64_value(w.issued_at)),
        ("expires_at", u64_value(w.expires_at)),
        ("proof_length", length),
        ("indices", indices),
        ("path", path),
    ])
}

fn lock_opening_value(o: &LockOpening) -> Value {
    table(vec![
        ("reason", hex_value(Fr::from(o.reason))),
        ("release_after", u64_value(o.release_after)),
        ("claim_party", hex_value(o.claim_party)),
    ])
}

fn input_value(w: &InputWitness) -> Value {
    let (length, indices, path) = padded_path(&w.path, COMMITMENT_DEPTH);
    table(vec![
        ("units", u64_value(w.units)),
        ("salt", hex_value(w.salt)),
        ("lock", hex_value(w.lock)),
        ("lock_opening", lock_opening_value(&w.lock_opening)),
        ("proof_length", length),
        ("indices", indices),
        ("path", path),
    ])
}

fn note_value(n: &Note) -> Value {
    table(vec![
        ("token", hex_value(n.token)),
        ("units", u64_value(n.units)),
        ("owner", hex_value(n.owner)),
        ("salt", hex_value(n.salt)),
        ("lock", hex_value(n.lock)),
    ])
}

fn feed_secret_value(s: &FeedSecret) -> Value {
    table(vec![("lo", u128_value(s.lo)), ("hi", u128_value(s.hi))])
}

fn deposit_table(w: &DepositWitness) -> Value {
    table(vec![
        ("commitment", hex_value(w.commitment)),
        ("token", hex_value(Fr::from(w.token))),
        ("units", u64_value(w.units)),
        ("funding_address", hex_value(Fr::from(w.funding_address))),
        ("attestation_root", hex_value(w.attestation_root)),
        (
            "min_accepted_generation",
            u64_value(w.min_accepted_generation),
        ),
        ("epoch", u64_value(w.epoch)),
        ("chain_id", hex_value(Fr::from(w.chain_id))),
        ("pool", hex_value(Fr::from(w.pool))),
        ("expiry", u64_value(w.expiry)),
        ("register_key", point_value(&w.register_key)),
        ("feed_r", point_value(&w.feed_r)),
        ("feed_ct", fields_value(&w.feed_ct)),
        ("payload_commitment", hex_value(w.payload_commitment)),
        ("owner_key", spend_key_value(&w.owner_key)),
        ("nk", hex_value(w.nk)),
        ("signature", bytes_value(&w.signature)),
        ("salt", hex_value(w.salt)),
        ("attestation_witness", attestation_value(&w.attestation)),
        ("feed_secret", feed_secret_value(&w.feed_secret)),
    ])
}

fn transfer_table(w: &TransferWitness) -> Value {
    table(vec![
        ("nullifier_0", hex_value(w.nullifiers[0])),
        ("nullifier_1", hex_value(w.nullifiers[1])),
        ("commitment_out_0", hex_value(w.commitments_out[0])),
        ("commitment_out_1", hex_value(w.commitments_out[1])),
        ("commitment_root", hex_value(w.commitment_root)),
        ("attestation_root", hex_value(w.attestation_root)),
        (
            "min_accepted_generation",
            u64_value(w.min_accepted_generation),
        ),
        ("epoch", u64_value(w.epoch)),
        ("chain_id", hex_value(Fr::from(w.chain_id))),
        ("pool", hex_value(Fr::from(w.pool))),
        ("expiry", u64_value(w.expiry)),
        ("claim_key_hash", hex_value(w.claim_key_hash)),
        ("register_key", point_value(&w.register_key)),
        ("feed_r", point_value(&w.feed_r)),
        ("feed_ct", fields_value(&w.feed_ct)),
        ("payload_commitment", hex_value(w.payload_commitment)),
        ("claim", Value::Boolean(w.claim)),
        ("token", hex_value(Fr::from(w.token))),
        ("owner_key", spend_key_value(&w.owner_key)),
        ("nk", hex_value(w.nk)),
        ("claim_key", spend_key_value(&w.claim_key)),
        ("signature", bytes_value(&w.signature)),
        (
            "inputs",
            Value::Array(w.inputs.iter().map(input_value).collect()),
        ),
        (
            "outputs",
            Value::Array(w.outputs.iter().map(note_value).collect()),
        ),
        (
            "output_locks",
            Value::Array(w.output_locks.iter().map(lock_opening_value).collect()),
        ),
        ("input_attestation", attestation_value(&w.input_attestation)),
        (
            "output_attestations",
            Value::Array(
                w.output_attestations
                    .iter()
                    .map(attestation_value)
                    .collect(),
            ),
        ),
        ("feed_secret", feed_secret_value(&w.feed_secret)),
    ])
}

fn withdraw_table(w: &WithdrawWitness) -> Value {
    table(vec![
        ("nullifier", hex_value(w.nullifier)),
        ("token", hex_value(Fr::from(w.token))),
        ("units", u64_value(w.units)),
        ("recipient", hex_value(Fr::from(w.recipient))),
        ("commitment_root", hex_value(w.commitment_root)),
        ("attestation_root", hex_value(w.attestation_root)),
        (
            "min_accepted_generation",
            u64_value(w.min_accepted_generation),
        ),
        ("epoch", u64_value(w.epoch)),
        ("chain_id", hex_value(Fr::from(w.chain_id))),
        ("pool", hex_value(Fr::from(w.pool))),
        ("expiry", u64_value(w.expiry)),
        ("owner_key", spend_key_value(&w.owner_key)),
        ("nk", hex_value(w.nk)),
        ("signature", bytes_value(&w.signature)),
        ("input", input_value(&w.input)),
        ("attestation_witness", attestation_value(&w.attestation)),
    ])
}

/// Every key MUST be a parameter name of the circuit's `main`; `nargo execute`
/// rejects a missing one.
fn render_prover_toml(request: &ProofRequest) -> String {
    let value = match request {
        ProofRequest::Deposit(w) => deposit_table(w),
        ProofRequest::Transfer(w) => transfer_table(w),
        ProofRequest::Withdraw(w) => withdraw_table(w),
    };
    toml::to_string(&value).expect("a TOML table always serializes")
}

#[cfg(test)]
mod failed_assertion_tests {
    use super::failed_assertion;

    #[test]
    fn reads_the_assertion_message_through_colour_codes() {
        let stderr = "\u{1b}[1m\u{1b}[31merror\u{1b}[0m\u{1b}[1m: Assertion failed: note is locked\u{1b}[0m\n   \u{250c}\u{2500} src/main.nr:101:9\n\nFailed assertion\n";
        assert_eq!(failed_assertion(stderr).as_deref(), Some("note is locked"));
        assert_eq!(failed_assertion("error: cannot find nargo.toml"), None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The throwaway package stands alone: the library by absolute path, the sources
    /// linked, and nothing written under `circuits/`.
    #[test]
    fn a_proving_package_stands_alone_outside_the_checkout() {
        let circuits = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("circuits");
        let work = tempfile::tempdir().unwrap();
        let package = work.path().join("sn_transfer");
        write_package(&circuits, Circuit::Transfer, &package).unwrap();
        let manifest = std::fs::read_to_string(package.join("Nargo.toml")).unwrap();
        let lib = std::fs::canonicalize(circuits.join("lib")).unwrap();
        assert!(manifest.contains(&format!("path = \"{}\"", lib.display())));
        assert!(!manifest.contains("../lib"));
        assert_eq!(
            std::fs::read_link(package.join("src")).unwrap(),
            std::fs::canonicalize(circuits.join("transfer/src")).unwrap()
        );
        assert!(!circuits.join("transfer/Prover.toml").exists());
    }

    #[test]
    fn the_proving_directory_is_private() {
        let work = private_workdir().unwrap();
        let mode = std::fs::metadata(work.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
    }

    #[test]
    fn padded_path_records_the_real_length() {
        let proof = MerkleProof(vec![crate::domain::tree::Step {
            sibling: Fr::from(5u64),
            is_right: true,
        }]);
        let (length, indices, path) = padded_path(&proof, 4);
        assert_eq!(length, Value::String("1".into()));
        assert_eq!(indices.as_array().unwrap().len(), 4);
        assert_eq!(indices.as_array().unwrap()[0], Value::Boolean(true));
        assert_eq!(path.as_array().unwrap().len(), 4);
    }

    #[test]
    fn decode_bytecode_rejects_missing_field() {
        assert!(decode_bytecode(b"{}").is_err());
    }

    #[test]
    fn chunk_proof_splits_into_32_byte_elements() {
        let chunks = chunk_proof(&[0u8; 64]).unwrap();
        assert_eq!(chunks.len(), 2);
        assert!(chunk_proof(&[0u8; 33]).is_err());
    }
}

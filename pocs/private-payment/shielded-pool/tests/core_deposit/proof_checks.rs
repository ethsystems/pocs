use std::{collections::BTreeMap, io::Read, path::Path, process::Command};

use barretenberg_rs::{
    BarretenbergApi,
    backends::ffi::FfiBackend,
    generated_types::{CircuitInput, CircuitInputNoVK, ProofSystemSettings},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use flate2::read::GzDecoder;
use serde_json::json;
use sha2::{Digest, Sha256};

const CORE_INPUTS: [&str; 5] = [
    "commitment",
    "token",
    "amount",
    "funding_address",
    "payload_hash",
];
const GATED_INPUTS: [&str; 6] = [
    "commitment",
    "token",
    "amount",
    "funding_address",
    "attestation_root",
    "payload_hash",
];

// Same ignition SRS and capacity as the compliance PoC's FFI prover.
const SRS_POINTS: u32 = 1 << 19;
const SRS_G2_POINT: &str = "0118c4d5b837bcc2bc89b5b398b5974e9f5944073b32078b7e231fec938883b0\
    260e01b251f6f1c7e7ff4e580791dee8ea51d87a358e038b4efe30fac09383c1\
    22febda3c0c0632a56475b4214e5615e11e6dd3f96e6cea2854a87d4dacc5e55\
    04fc6369f7110fe3d25156c1bb9a72859cf2a04641f99ba4ee413c80da6a5fe4";

fn settings() -> ProofSystemSettings {
    ProofSystemSettings {
        ipa_accumulation: false,
        oracle_hash_type: "keccak".into(),
        disable_zk: false,
        optimized_solidity_verifier: false,
    }
}

fn backend() -> BarretenbergApi<FfiBackend> {
    let mut api =
        BarretenbergApi::new(FfiBackend::new().expect("initialize FFI backend"));
    let crs_dir = std::env::var_os("BB_CRS_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from(
                std::env::var_os("HOME").expect("HOME or BB_CRS_PATH"),
            )
            .join(".bb-crs")
        });
    let path = crs_dir.join("bn254_g1.dat");
    let mut points = vec![0; SRS_POINTS as usize * 64];
    std::fs::File::open(&path)
        .and_then(|mut file| file.read_exact(&mut points))
        .unwrap_or_else(|e| {
            panic!(
                "read {}: {e}; see tests/core_deposit/README.md",
                path.display()
            )
        });
    api.srs_init_srs(&points, SRS_POINTS, &hex::decode(SRS_G2_POINT).unwrap())
        .expect("initialize BN254 SRS");
    api
}

fn gunzip(bytes: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::new();
    GzDecoder::new(bytes)
        .read_to_end(&mut decoded)
        .expect("decompress Noir data");
    decoded
}

struct Proof {
    vk: Vec<u8>,
    public_inputs: Vec<Vec<u8>>,
    proof: Vec<Vec<u8>>,
}

fn build(
    api: &mut BarretenbergApi<FfiBackend>,
    root: &Path,
    package: &str,
    order: &[&str],
) -> Proof {
    let output = Command::new("nargo")
        .args(["execute", &format!("{package}_check"), "--package", package])
        .current_dir(root)
        .output()
        .expect("run nargo execute");
    assert!(
        output.status.success(),
        "nargo execute {package}:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let artifact: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join(format!("target/{package}.json"))).unwrap(),
    )
    .unwrap();
    let names: Vec<_> = artifact["abi"]["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p["visibility"] == "public")
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, order, "{package} public ABI order");
    let bytecode = gunzip(
        &BASE64
            .decode(artifact["bytecode"].as_str().unwrap())
            .unwrap(),
    );
    let witness =
        gunzip(&std::fs::read(root.join(format!("target/{package}_check.gz"))).unwrap());
    let vk = api
        .circuit_compute_vk(
            CircuitInputNoVK {
                name: package.into(),
                bytecode: bytecode.clone(),
            },
            settings(),
        )
        .expect("compute verification key")
        .bytes;
    let result = api
        .circuit_prove(
            CircuitInput {
                name: package.into(),
                bytecode,
                verification_key: vk.clone(),
            },
            &witness,
            settings(),
        )
        .expect("prove circuit");
    assert_eq!(
        result.public_inputs.len(),
        order.len(),
        "{package} public input count"
    );
    assert!(result.public_inputs.iter().all(|input| input.len() == 32));
    assert!(!result.proof.is_empty());
    assert!(result.proof.iter().all(|element| element.len() == 32));
    Proof {
        vk,
        public_inputs: result.public_inputs,
        proof: result.proof,
    }
}

fn verify(
    api: &mut BarretenbergApi<FfiBackend>,
    proof: &Proof,
    vk: &[u8],
    inputs: &[Vec<u8>],
) -> bool {
    api.circuit_verify(vk, inputs.to_vec(), proof.proof.clone(), settings())
        .expect("verification backend error is not a proof rejection")
        .verified
}

#[test]
fn core_proof_binds_public_inputs_and_deposit_mode() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    std::fs::create_dir_all(root.join("target")).unwrap();
    // Unique output prevents an old success report from surviving a failed run.
    let output = tempfile::Builder::new()
        .prefix("core-deposit-checks-")
        .tempdir_in(root.join("target"))
        .unwrap();
    let mut api = backend();
    let core = build(&mut api, root, "deposit_core", &CORE_INPUTS);
    let gated = build(&mut api, root, "deposit", &GATED_INPUTS);
    for proof in [&core, &gated] {
        assert!(
            verify(&mut api, proof, &proof.vk, &proof.public_inputs),
            "valid-proof control"
        );
    }

    for (index, name) in CORE_INPUTS.iter().enumerate() {
        let mut changed = core.public_inputs.clone();
        changed[index][31] ^= 1;
        assert!(
            !verify(&mut api, &core, &core.vk, &changed),
            "changed {name} must be rejected"
        );
        assert!(
            verify(&mut api, &core, &core.vk, &core.public_inputs),
            "control after {name}"
        );
    }
    for (name, proof, other) in
        [("deposit_core", &core, &gated), ("deposit", &gated, &core)]
    {
        assert!(
            !verify(&mut api, proof, &other.vk, &proof.public_inputs),
            "{name} under wrong key"
        );
        assert!(
            verify(&mut api, proof, &proof.vk, &proof.public_inputs),
            "control after {name} wrong key"
        );
    }

    let mut hashes = BTreeMap::new();
    for (name, proof) in [("deposit_core", &core), ("deposit", &gated)] {
        let artifact = std::fs::read(root.join(format!("target/{name}.json"))).unwrap();
        for (file, bytes) in [
            ("circuit.json", artifact),
            ("vk", proof.vk.clone()),
            ("proof", proof.proof.concat()),
            ("public_inputs", proof.public_inputs.concat()),
        ] {
            let path = format!("{name}.{file}");
            std::fs::write(output.path().join(&path), &bytes).unwrap();
            hashes.insert(path, hex::encode(Sha256::digest(&bytes)));
        }
    }
    std::fs::write(
        output.path().join("results.json"),
        serde_json::to_vec_pretty(&json!({
            "core_public_inputs": CORE_INPUTS,
            "rejected_mutations": CORE_INPUTS,
            "cross_mode_rejections": 2,
            "sha256": hashes,
        }))
        .unwrap(),
    )
    .unwrap();
    println!(
        "Passed: 5 input mutations and 2 cross-mode checks, each with a valid-proof control. Artifacts: {}",
        output.keep().display()
    );
}

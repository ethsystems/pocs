//! Proves that witnesses built by the `Wallet` actor, rather than hand-assembled,
//! satisfy the real circuits. Covers the deposit base case (`seq == 0`) and a following
//! transfer (`seq > 0`), the branch that verifies the predecessor compliance note's
//! Merkle inclusion.
//!
//! `bench_proving` measures the prover on hand-built witnesses, so it cannot catch the
//! wallet and the circuits disagreeing about `seq` numbering, `epoch_in`, or which
//! amount lands in `facts_out`. Each of those three shipped broken and proved fine in
//! isolation. This example is what fails when they drift again.

use std::{
    future::Future,
    path::PathBuf,
    process::ExitCode,
};

use shielded_pool_compliance::{
    adapters::{
        bb_prover::BbProver,
        commitment_tree::RotorMerkleTree,
        revocation_tree::RevocationTree,
    },
    domain::{
        attestation::{
            AttestationLeaf,
            Generation,
        },
        keys::{
            AuditViewingKey,
            AuditViewingPubkey,
            ComplianceViewingKey,
            OwnerPubkey,
            SpendingKey,
            ViewingKey,
        },
    },
    error::{
        ChainError,
        CryptoError,
    },
    policy::{
        commit::state_tag,
        reference::ReferencePolicy,
        source_hash::policy_source_hash,
    },
    ports::{
        audit::AuditEncryptor,
        chain::{
            ChainReader,
            PolicyPair,
            RegistrySnapshot,
        },
        clock::Clock,
        merkle::{
            LeafIndex,
            MerkleStore,
        },
        prover::{
            CircuitProof,
            Prover,
        },
        registry::{
            AttestationRecord,
            AttestationSource,
        },
    },
    types::{
        Address,
        Bytes32,
        Epoch,
    },
    wallet::{
        DepositRequest,
        OwnedNote,
        TransferOutput,
        TransferRequest,
        Wallet,
        WalletKeys,
    },
};

type CommitmentTree = RotorMerkleTree<32>;
type AttestationTree = RotorMerkleTree<20>;

const EPOCH: Epoch = Epoch(100);

struct FixedClock(u64);
impl Clock for FixedClock {
    fn now_unix(&self) -> u64 {
        self.0
    }
}

struct FakeChain {
    registry: RegistrySnapshot,
    policy: PolicyPair,
}

impl ChainReader for FakeChain {
    async fn current_epoch(&self) -> Result<Epoch, ChainError> {
        Ok(EPOCH)
    }
    async fn commitment_root(&self) -> Result<Bytes32, ChainError> {
        Ok(Bytes32::from([0u8; 32]))
    }
    async fn is_known_commitment_root(&self, _r: Bytes32) -> Result<bool, ChainError> {
        Ok(true)
    }
    fn registry_values(
        &self,
    ) -> impl Future<Output = Result<RegistrySnapshot, ChainError>> + Send {
        let registry = self.registry;
        async move { Ok(registry) }
    }
    fn effective_policy(
        &self,
    ) -> impl Future<Output = Result<PolicyPair, ChainError>> + Send {
        let policy = self.policy;
        async move { Ok(policy) }
    }
    async fn is_nullifier_spent(&self, _n: Bytes32) -> Result<bool, ChainError> {
        Ok(false)
    }
}

struct FakeAudit(AuditViewingPubkey);
impl AuditEncryptor for FakeAudit {
    fn committee_version(&self) -> u64 {
        1
    }
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(self.0.encrypt(plaintext, aad))
    }
}

struct FakeAttestations(Vec<(OwnerPubkey, AttestationRecord)>);
impl AttestationSource for FakeAttestations {
    fn current_attestation(
        &self,
        owner: OwnerPubkey,
    ) -> impl Future<Output = Result<Option<AttestationRecord>, ChainError>> + Send {
        let found = self
            .0
            .iter()
            .find(|(o, _)| o.as_bytes32() == owner.as_bytes32())
            .map(|(_, r)| r.clone());
        async move { Ok(found) }
    }
}

fn register(
    attestations: &AttestationTree,
    revocations: &RevocationTree,
    owner: OwnerPubkey,
    attester: Address,
) -> AttestationRecord {
    let generation = Generation(1);
    let leaf = AttestationLeaf {
        owner_pubkey: owner,
        attester,
        generation,
        issued_at: 0,
        expires_at: u64::MAX,
    }
    .hash()
    .expect("canonical owner pubkey");
    let leaf_index: LeafIndex = attestations.insert(leaf).expect("attestation tree room");
    AttestationRecord {
        attester,
        generation,
        issued_at: 0,
        expires_at: u64::MAX,
        leaf_index,
        revoked_at: revocations
            .revoked_at_epoch_of(attester)
            .expect("registered"),
        revocation_proof: revocations.proof(attester).expect("registered"),
    }
}

/// Emits the deposit proof for `contracts/test/RealVerifier.t.sol`. Written here rather
/// than by a separate binary so the bytes Solidity verifies are the same ones Rust just
/// proved. Regenerating verifiers changes the VK, which invalidates this file.
fn write_fixture(path: &std::path::Path, proof: &CircuitProof) -> std::io::Result<()> {
    let public_inputs: Vec<String> = proof
        .public_inputs
        .iter()
        .map(|pi| pi.to_string())
        .collect();
    let json = serde_json::json!({
        "proof": format!("0x{}", hex::encode(&proof.proof)),
        "publicInputs": public_inputs,
    });
    std::fs::create_dir_all(path.parent().expect("fixture path has a parent"))?;
    std::fs::write(path, serde_json::to_string_pretty(&json)?)
}

#[tokio::main]
async fn main() -> ExitCode {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let home = std::env::var("HOME").expect("HOME");
    let commitments_dir = tempfile::tempdir().expect("tempdir");
    let attestations_dir = tempfile::tempdir().expect("tempdir");
    let commitments = CommitmentTree::open(commitments_dir.path()).expect("open");
    let attestations = AttestationTree::open(attestations_dir.path()).expect("open");

    let mut revocations = RevocationTree::new();
    let attester = Address::from([0xaa; 20]);
    revocations.add_attester(attester).expect("room");

    let alice_sk = SpendingKey::random();
    let alice = alice_sk.derive_owner_pubkey();
    let bob = SpendingKey::random().derive_owner_pubkey();

    let alice_rec = register(&attestations, &revocations, alice, attester);
    let bob_rec = register(&attestations, &revocations, bob, attester);
    let attestation_root = attestations.root().expect("nonempty");

    let source_hash_fr = policy_source_hash(&root.join("circuits/lib/src/policy.nr"))
        .expect("read policy.nr");

    let chain = FakeChain {
        registry: RegistrySnapshot {
            attestation_root,
            attester_revocation_root: revocations.root(),
            min_accepted_generation: 1,
        },
        policy: PolicyPair {
            verifier: Address::from([0u8; 20]),
            policy_source_hash: Bytes32::from(source_hash_fr),
        },
    };
    let clock = FixedClock(EPOCH.0 * shielded_pool_compliance::EPOCH_SECONDS);
    let audit = FakeAudit(AuditViewingKey::random().public_key());
    let sources = FakeAttestations(vec![(alice, alice_rec), (bob, bob_rec)]);

    let mut wallet = Wallet::new(
        commitments,
        attestations,
        WalletKeys {
            spending_key: alice_sk,
            compliance_viewing_key: ComplianceViewingKey::random(),
            viewing_key: ViewingKey::random(),
        },
    );

    let prover = match BbProver::new(
        &PathBuf::from(&home).join(".bb/bb"),
        PathBuf::from(&home).join(".nargo/bin/nargo"),
        root.clone(),
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("cannot start bb: {e}");
            return ExitCode::FAILURE;
        }
    };

    let token = Address::from([0x11; 20]);
    let mut ok = true;

    let deposit = wallet
        .build_deposit(
            &chain,
            &clock,
            &audit,
            &sources,
            DepositRequest {
                token,
                amount: 10_000,
            },
        )
        .await
        .expect("wallet builds a deposit");
    match prover.prove(&deposit.request) {
        Ok(proof) => {
            println!(
                "deposit (seq 0 base case): proved, {} bytes",
                proof.proof.len()
            );
            let path = root.join("contracts/test/fixtures/deposit_proof.json");
            write_fixture(&path, &proof).expect("write deposit fixture");
            println!("wrote {}", path.display());
        }
        Err(e) => {
            println!("deposit: FAILED to prove: {e}");
            ok = false;
        }
    }

    // The transfer spends the deposited note and opens the deposit's compliance note as
    // its predecessor, so it exercises the `seq > 0` inclusion branch.
    let transfer = wallet
        .build_transfer(
            &chain,
            &clock,
            &audit,
            &sources,
            TransferRequest {
                token,
                inputs: [
                    OwnedNote {
                        note: deposit.note,
                        leaf_index: deposit.output_index,
                    },
                    OwnedNote {
                        note: shielded_pool_compliance::domain::note::Note::zero(
                            token, alice,
                        ),
                        leaf_index: LeafIndex(0),
                    },
                ],
                outputs: [
                    TransferOutput {
                        owner: bob,
                        amount: 400,
                        viewing_pubkey: ViewingKey::random().public_key(),
                    },
                    TransferOutput {
                        owner: alice,
                        amount: 9_600,
                        viewing_pubkey: ViewingKey::random().public_key(),
                    },
                ],
            },
        )
        .await
        .expect("wallet builds a transfer");
    match prover.prove(&transfer.request) {
        Ok(proof) => println!(
            "transfer (seq 1, predecessor inclusion): proved, {} bytes",
            proof.proof.len()
        ),
        Err(e) => {
            println!("transfer: FAILED to prove: {e}");
            ok = false;
        }
    }

    let _ = state_tag::<ReferencePolicy>(source_hash_fr);
    if ok {
        println!("wallet-built witnesses satisfy the real circuits");
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

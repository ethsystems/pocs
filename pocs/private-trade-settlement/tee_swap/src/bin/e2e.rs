//! E2E harness for the TEE swap protocol.
//!
//! Run with:
//!   cargo run --bin e2e              # happy path (default)
//!   cargo run --bin e2e -- refund    # refund after TEE failure

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use alloy::node_bindings::{Anvil, AnvilInstance};
use alloy::primitives::{Address, B256};

use tee_swap::adapters::bb_prover::BBProver;
use tee_swap::adapters::ethereum::EthereumRpc;
use tee_swap::adapters::memory_store::InMemorySwapStore;
use tee_swap::adapters::merkle_tree::LocalMerkleTree;
use tee_swap::adapters::mock_tee::MockTeeRuntime;
use tee_swap::coordinator::SwapCoordinator;
use tee_swap::domain::note::Note;
use tee_swap::domain::stealth::MetaKeyPair;
use tee_swap::domain::swap::{SwapAnnouncement, SwapTerms};
use tee_swap::party::{prepare_claim, prepare_lock, prepare_refund, PartyRole};
use tee_swap::ports::chain::{ChainError, ChainPort as _};
use tee_swap::ports::prover::Prover;
use tee_swap::ports::tee::AttestationReport;
use tee_swap::server::routes::SwapStatus;
use tee_swap::server::start_server;
use tee_swap::server::verifier::build_ra_tls_client;

#[derive(Debug, Clone, Copy)]
enum Scenario {
    HappyPath,
    Refund,
}

/// First deterministic anvil private key (hex, no 0x prefix).
const ANVIL_KEY_0: &str =
    "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

const CHAIN_ID_A: u64 = 31337;
const CHAIN_ID_B: u64 = 31338;

const VALUE_A: u64 = 1000; // USD
const VALUE_B: u64 = 50; // BOND

#[derive(Debug, thiserror::Error)]
enum E2eError {
    #[error("anvil spawn failed: {0}")]
    AnvilSpawn(String),

    #[error("forge script failed: {0}")]
    ForgeScript(String),

    #[error("deployment config: {0}")]
    Config(String),

    #[error("chain error: {0}")]
    Chain(#[from] ChainError),

    #[error("coordinator error: {0}")]
    Coordinator(#[from] tee_swap::coordinator::CoordinatorError),

    #[error("server error: {0}")]
    Server(#[from] tee_swap::server::ServerError),

    #[error("http request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("prover error: {0}")]
    Prover(#[from] tee_swap::ports::prover::ProverError),

    #[error("json error: {0}")]
    Json(String),
}

struct DeployedChain {
    pub chain_id: B256,
    pub rpc: EthereumRpc,
    pub tree: LocalMerkleTree,
    pub private_utxo: Address,
    pub tee_lock: Address,
}

impl fmt::Debug for DeployedChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeployedChain")
            .field("chain_id", &self.chain_id)
            .field("private_utxo", &self.private_utxo)
            .field("tee_lock", &self.tee_lock)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
struct PartyState {
    pub meta_key: MetaKeyPair,
    pub funded_note: Note,
    pub leaf_index: u64,
}

/// Anvil processes are killed on drop via `AnvilInstance`'s RAII.
struct AnvilHarness {
    pub anvil_a: AnvilInstance,
    pub anvil_b: AnvilInstance,
}

struct E2eHarness {
    pub chain_a: DeployedChain,
    pub chain_b: DeployedChain,
    pub alice: PartyState,
    pub bob: PartyState,
    pub terms: SwapTerms,
    pub prover: BBProver,
    pub server_handle: axum_server::Handle,
    pub base_url: String,
    pub client: reqwest::Client,
    _anvil: AnvilHarness,
}

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

impl AnvilHarness {
    async fn spawn(chain_id_a: u64, chain_id_b: u64) -> Result<Self, E2eError> {
        let (anvil_a, anvil_b) = tokio::try_join!(
            Self::spawn_node(chain_id_a),
            Self::spawn_node(chain_id_b),
        )?;
        Ok(Self { anvil_a, anvil_b })
    }

    async fn spawn_node(chain_id: u64) -> Result<AnvilInstance, E2eError> {
        tokio::task::spawn_blocking(move || {
            Anvil::new()
                .chain_id(chain_id)
                .try_spawn()
                .map_err(|e| E2eError::AnvilSpawn(format!("chain {chain_id}: {e}")))
        })
        .await
        .map_err(|e| E2eError::AnvilSpawn(format!("chain {chain_id} task: {e}")))?
    }

    /// Per-chain config enables concurrent deployment without contention on `deployments.toml`.
    fn write_chain_config(
        chain_id: u64,
        endpoint: &str,
        tee_address: &Address,
    ) -> Result<PathBuf, E2eError> {
        let path = project_root()
            .join("target")
            .join(format!("deploy_{chain_id}.toml"));
        std::fs::create_dir_all(path.parent().unwrap())
            .map_err(|e| E2eError::Config(format!("create target dir: {e}")))?;

        let config = format!(
            "\
[{chain_id}]
endpoint_url = \"{endpoint}\"

[{chain_id}.address]
tee_address = \"{tee_address}\"

[{chain_id}.bool]
use_mock_verifier = false
"
        );
        std::fs::write(&path, config)
            .map_err(|e| E2eError::Config(format!("write {}: {e}", path.display())))?;
        Ok(path)
    }

    async fn deploy_contracts(
        rpc_url: &str,
        sender: &Address,
        config_path: &Path,
    ) -> Result<(), E2eError> {
        let status = tokio::process::Command::new("forge")
            .args([
                "script",
                "contracts/script/Deploy.s.sol",
                "--rpc-url",
                rpc_url,
                "--broadcast",
                "--sender",
                &format!("{sender}"),
                "--unlocked",
                "--slow", // required otherwise the demo fails to avoid nonce issues with --unlocked mode
            ])
            .env("DEPLOY_CONFIG", config_path.to_str().unwrap())
            .current_dir(project_root())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await
            .map_err(|e| E2eError::ForgeScript(format!("failed to execute forge: {e}")))?;

        if !status.success() {
            return Err(E2eError::ForgeScript(format!("exit {status}")));
        }

        Ok(())
    }

    fn parse_chain_addresses(
        config_path: &Path,
        chain_id: u64,
    ) -> Result<(Address, Address), E2eError> {
        let content = std::fs::read_to_string(config_path)
            .map_err(|e| E2eError::Config(format!("read {}: {e}", config_path.display())))?;

        let table: toml::Table = content
            .parse()
            .map_err(|e| E2eError::Config(format!("parse {}: {e}", config_path.display())))?;

        let chain_key = chain_id.to_string();
        let addresses = table
            .get(&chain_key)
            .and_then(|v| v.as_table())
            .and_then(|t| t.get("address"))
            .and_then(|v| v.as_table())
            .ok_or_else(|| {
                E2eError::Config(format!(
                    "missing [{chain_key}.address] in {}",
                    config_path.display()
                ))
            })?;

        let private_utxo: Address = addresses
            .get("private_utxo_address")
            .and_then(|v| v.as_str())
            .ok_or_else(|| E2eError::Config("missing private_utxo_address".into()))?
            .parse()
            .map_err(|e| E2eError::Config(format!("invalid private_utxo_address: {e}")))?;

        let tee_lock: Address = addresses
            .get("tee_lock_address")
            .and_then(|v| v.as_str())
            .ok_or_else(|| E2eError::Config("missing tee_lock_address".into()))?
            .parse()
            .map_err(|e| E2eError::Config(format!("invalid tee_lock_address: {e}")))?;

        Ok((private_utxo, tee_lock))
    }
}

impl E2eHarness {
    async fn start() -> Result<Self, E2eError> {
        println!("[1/10] Spawning anvil nodes...");
        let anvil = AnvilHarness::spawn(CHAIN_ID_A, CHAIN_ID_B).await?;
        let endpoint_a = anvil.anvil_a.endpoint();
        let endpoint_b = anvil.anvil_b.endpoint();
        println!("  Chain A: {endpoint_a} (chain_id: {CHAIN_ID_A})");
        println!("  Chain B: {endpoint_b} (chain_id: {CHAIN_ID_B})");

        let sender = anvil.anvil_a.addresses()[0];
        let config_a = AnvilHarness::write_chain_config(CHAIN_ID_A, &endpoint_a, &sender)?;
        let config_b = AnvilHarness::write_chain_config(CHAIN_ID_B, &endpoint_b, &sender)?;
        println!("[2/10] Deploying contracts...");
        tokio::try_join!(
            AnvilHarness::deploy_contracts(&endpoint_a, &sender, &config_a),
            AnvilHarness::deploy_contracts(&endpoint_b, &sender, &config_b),
        )?;

        println!("[3/10] Creating RPC adapters...");
        let (utxo_a, teelock_a) =
            AnvilHarness::parse_chain_addresses(&config_a, CHAIN_ID_A)?;
        let (utxo_b, teelock_b) =
            AnvilHarness::parse_chain_addresses(&config_b, CHAIN_ID_B)?;
        println!("  Chain A: PrivateUTXO={utxo_a}, TeeLock={teelock_a}");
        println!("  Chain B: PrivateUTXO={utxo_b}, TeeLock={teelock_b}");

        let rpc_a = EthereumRpc::new(&endpoint_a, ANVIL_KEY_0, utxo_a, teelock_a).await?;
        let rpc_b = EthereumRpc::new(&endpoint_b, ANVIL_KEY_0, utxo_b, teelock_b).await?;

        println!("[4/10] Generating identities and funding notes...");
        let mut rng = ark_std::test_rng();
        let alice_key = MetaKeyPair::generate(&mut rng);
        let bob_key = MetaKeyPair::generate(&mut rng);

        let chain_id_a_b256 = B256::left_padding_from(&CHAIN_ID_A.to_be_bytes());
        let chain_id_b_b256 = B256::left_padding_from(&CHAIN_ID_B.to_be_bytes());
        let asset_usd = B256::repeat_byte(0x01);
        let asset_bond = B256::repeat_byte(0x02);
        let timeout_abs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 86400; // now + 24h
        let timeout = B256::left_padding_from(&timeout_abs.to_be_bytes());

        // Alice: USD on chain A
        let alice_note = Note::new(
            chain_id_a_b256,
            VALUE_A,
            asset_usd,
            alice_key.pk_x(),
            B256::ZERO,
            B256::ZERO,
        );
        let mut tree_a = LocalMerkleTree::new();
        rpc_a.fund(alice_note.commitment().0).await?;
        let alice_leaf = tree_a.len() as u64;
        tree_a.insert_commitment(&alice_note.commitment());

        // Bob: BOND on chain B
        let bob_note = Note::new(
            chain_id_b_b256,
            VALUE_B,
            asset_bond,
            bob_key.pk_x(),
            B256::ZERO,
            B256::ZERO,
        );
        let mut tree_b = LocalMerkleTree::new();
        rpc_b.fund(bob_note.commitment().0).await?;
        let bob_leaf = tree_b.len() as u64;
        tree_b.insert_commitment(&bob_note.commitment());

        let terms = SwapTerms::new(
            chain_id_a_b256,
            chain_id_b_b256,
            VALUE_A,
            VALUE_B,
            asset_usd,
            asset_bond,
            timeout,
            alice_key.pk_x(),
            bob_key.pk_x(),
            B256::repeat_byte(0xFF), // nonce
        );

        println!("[5/10] Starting RA-TLS server...");
        let mut chains = HashMap::new();
        chains.insert(chain_id_a_b256, rpc_a.clone());
        chains.insert(chain_id_b_b256, rpc_b.clone());

        let coordinator = Arc::new(SwapCoordinator::new(
            InMemorySwapStore::new(),
            chains,
            chain_id_a_b256,
        ));

        let tee = MockTeeRuntime::new(sender);
        let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (server_handle, bound_addr) =
            start_server(coordinator, &tee, addr).await?;
        let base_url = format!("https://127.0.0.1:{}", bound_addr.port());
        let client = build_ra_tls_client(true);
        println!("  RA-TLS server listening at {base_url}");

        Ok(Self {
            chain_a: DeployedChain {
                chain_id: chain_id_a_b256,
                rpc: rpc_a,
                tree: tree_a,
                private_utxo: utxo_a,
                tee_lock: teelock_a,
            },
            chain_b: DeployedChain {
                chain_id: chain_id_b_b256,
                rpc: rpc_b,
                tree: tree_b,
                private_utxo: utxo_b,
                tee_lock: teelock_b,
            },
            alice: PartyState {
                meta_key: alice_key,
                funded_note: alice_note,
                leaf_index: alice_leaf,
            },
            bob: PartyState {
                meta_key: bob_key,
                funded_note: bob_note,
                leaf_index: bob_leaf,
            },
            terms,
            prover: BBProver::new(project_root().join("circuits")),
            server_handle,
            base_url,
            client,
            _anvil: anvil,
        })
    }
}

/// Warp an Anvil node's clock to the given unix timestamp and mine a block.
async fn anvil_warp_time(endpoint: &str, timestamp: u64) -> Result<(), E2eError> {
    let client = reqwest::Client::new();
    let ts_hex = format!("0x{timestamp:x}");

    // Set the timestamp for the next block
    client
        .post(endpoint)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "evm_setNextBlockTimestamp",
            "params": [ts_hex],
            "id": 1
        }))
        .send()
        .await?;

    // Mine a block so the timestamp takes effect
    client
        .post(endpoint)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "evm_mine",
            "params": [],
            "id": 2
        }))
        .send()
        .await?;

    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), E2eError> {
    let scenario = match std::env::args().nth(1).as_deref() {
        None | Some("happy_path") => Scenario::HappyPath,
        Some("refund") => Scenario::Refund,
        Some(other) => panic!("unknown scenario '{other}'; use 'happy_path' or 'refund'"),
    };

    println!("================== TEE Swap E2E Harness ({scenario:?}) ==================\n");

    let mut harness = E2eHarness::start().await?;

    println!("\n[Ready] Infrastructure scaffolded:");
    println!("  Chain A (chain_id: {}):", harness.chain_a.chain_id);
    println!("    PrivateUTXO: {}", harness.chain_a.private_utxo);
    println!("    TeeLock:     {}", harness.chain_a.tee_lock);
    println!("  Chain B (chain_id: {}):", harness.chain_b.chain_id);
    println!("    PrivateUTXO: {}", harness.chain_b.private_utxo);
    println!("    TeeLock:     {}", harness.chain_b.tee_lock);
    println!();
    println!(
        "  Alice: 0x{}...",
        &hex::encode(harness.alice.meta_key.pk_x().0)[..16]
    );
    println!(
        "    Funded: {VALUE_A} USD on Chain A (leaf #{})",
        harness.alice.leaf_index
    );
    println!(
        "  Bob:   0x{}...",
        &hex::encode(harness.bob.meta_key.pk_x().0)[..16]
    );
    println!(
        "    Funded: {VALUE_B} BOND on Chain B (leaf #{})",
        harness.bob.leaf_index
    );
    println!();
    println!(
        "  swap_id: 0x{}...",
        &hex::encode(harness.terms.swap_id.0)[..16]
    );

    // ── Phase 6: Verify RA-TLS attestation ──
    println!("\n[6/10] Verifying RA-TLS attestation...");

    let attestation: AttestationReport = harness
        .client
        .get(format!("{}/attestation", harness.base_url))
        .send()
        .await?
        .json()
        .await?;
    println!("  tee_type:    {}", attestation.tee_type);
    println!("  pubkey_hash: 0x{}...", &hex::encode(attestation.pubkey_hash.0)[..16]);
    println!("  timestamp:   {}", attestation.timestamp);

    // ── Phase 7: Prepare lock transactions ──
    println!("\n[7/10] Preparing lock transactions...");

    let proof_a = harness
        .chain_a
        .tree
        .generate_proof(harness.alice.leaf_index)
        .expect("proof for alice note");
    let root_a = harness.chain_a.tree.current_root().expect("root a");

    let lock_a = prepare_lock(
        &harness.terms,
        &harness.alice.meta_key,
        &harness.bob.meta_key.pk.into(),
        &harness.alice.funded_note,
        &proof_a,
        root_a,
    );

    let proof_b = harness
        .chain_b
        .tree
        .generate_proof(harness.bob.leaf_index)
        .expect("proof for bob note");
    let root_b = harness.chain_b.tree.current_root().expect("root b");

    let lock_b = prepare_lock(
        &harness.terms,
        &harness.bob.meta_key,
        &harness.alice.meta_key.pk.into(),
        &harness.bob.funded_note,
        &proof_b,
        root_b,
    );

    println!(
        "  Alice locked note: 0x{}...",
        &hex::encode(lock_a.locked_note.commitment().0)[..16]
    );
    println!(
        "  Bob   locked note: 0x{}...",
        &hex::encode(lock_b.locked_note.commitment().0)[..16]
    );

    // ── Phase 8: Prove and send locks on-chain ──
    println!("\n[8/10] Proving and sending lock transactions on-chain...");

    let lock_proof_a = harness.prover.prove_transfer(&lock_a.witness).await?;
    println!("  Alice lock proof generated ({} bytes)", lock_proof_a.proof.len());
    let lock_tx_a = harness
        .chain_a
        .rpc
        .transfer(&lock_proof_a.proof, &lock_proof_a.public_inputs)
        .await?;
    println!("  Alice lock tx: {} (success: {})", lock_tx_a.tx_hash, lock_tx_a.success);

    let lock_proof_b = harness.prover.prove_transfer(&lock_b.witness).await?;
    println!("  Bob   lock proof generated ({} bytes)", lock_proof_b.proof.len());
    let lock_tx_b = harness
        .chain_b
        .rpc
        .transfer(&lock_proof_b.proof, &lock_proof_b.public_inputs)
        .await?;
    println!("  Bob   lock tx: {} (success: {})", lock_tx_b.tx_hash, lock_tx_b.success);

    // Insert locked note commitments into local trees (mirrors on-chain state)
    harness
        .chain_a
        .tree
        .insert_commitment(&lock_a.locked_note.commitment());
    harness
        .chain_b
        .tree
        .insert_commitment(&lock_b.locked_note.commitment());

    match scenario {
        Scenario::HappyPath => {
            // ── Phase 9: Submit to TEE via RA-TLS ──
            println!("\n[9/10] Submitting to TEE via RA-TLS...");

            // Alice submits first → expect "pending"
            let resp = harness
                .client
                .post(format!("{}/submit", harness.base_url))
                .json(&lock_a.submission)
                .send()
                .await?;
            let body: serde_json::Value = resp.json().await?;
            let status = body["status"]
                .as_str()
                .ok_or_else(|| E2eError::Json("missing status field".into()))?;
            println!("  Alice submitted → status: {status}");
            assert_eq!(status, "pending", "first submission should be pending");

            // Bob submits second → expect "verified" with announcement
            let resp = harness
                .client
                .post(format!("{}/submit", harness.base_url))
                .json(&lock_b.submission)
                .send()
                .await?;
            let body: serde_json::Value = resp.json().await?;
            let status = body["status"]
                .as_str()
                .ok_or_else(|| E2eError::Json("missing status field".into()))?;
            println!("  Bob   submitted → status: {status}");
            assert_eq!(status, "verified", "second submission should be verified");

            let announcement: SwapAnnouncement =
                serde_json::from_value(body["announcement"].clone())
                    .map_err(|e| E2eError::Json(format!("parse announcement: {e}")))?;
            println!(
                "  swap_id:         0x{}...",
                &hex::encode(announcement.swap_id.0)[..16]
            );
            println!(
                "  ephemeral_key_a: 0x{}...",
                &hex::encode(announcement.ephemeral_key_a.0)[..16]
            );
            println!(
                "  ephemeral_key_b: 0x{}...",
                &hex::encode(announcement.ephemeral_key_b.0)[..16]
            );

            // Wait for announcement to be confirmed on-chain
            let swap_id_hex = format!("0x{}", hex::encode(harness.terms.swap_id));
            let announced = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                loop {
                    let resp = harness
                        .client
                        .get(format!("{}/status/{swap_id_hex}", harness.base_url))
                        .send()
                        .await
                        .ok();
                    if let Some(resp) = resp
                        && let Ok(status) = resp.json::<SwapStatus>().await
                        && status.announced
                    {
                        return;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            })
            .await;
            assert!(announced.is_ok(), "announcement should be confirmed within 5s");
            println!("  Announcement confirmed on-chain");

            // ── Phase 10: Prove and send claims on-chain ──
            println!("\n[10/10] Proving and sending claim transactions on-chain...");

            // Prepare claim witnesses
            let locked_idx_a = 1u64; // second leaf in tree_a
            let locked_proof_a = harness
                .chain_a
                .tree
                .generate_proof(locked_idx_a)
                .expect("proof for locked note a");
            let locked_root_a = harness.chain_a.tree.current_root().expect("locked root a");

            let locked_idx_b = 1u64; // second leaf in tree_b
            let locked_proof_b = harness
                .chain_b
                .tree
                .generate_proof(locked_idx_b)
                .expect("proof for locked note b");
            let locked_root_b = harness.chain_b.tree.current_root().expect("locked root b");

            // Alice (role A) claims Bob's note on chain B
            let claim_a = prepare_claim(
                &announcement,
                &harness.alice.meta_key,
                &lock_b.ephemeral_keypair.r_pub.into(),
                &harness.terms,
                PartyRole::A,
                &locked_proof_b,
                locked_root_b,
            );

            // Bob (role B) claims Alice's note on chain A
            let claim_b = prepare_claim(
                &announcement,
                &harness.bob.meta_key,
                &lock_a.ephemeral_keypair.r_pub.into(),
                &harness.terms,
                PartyRole::B,
                &locked_proof_a,
                locked_root_a,
            );

            // Generate claim proofs
            let claim_proof_a = harness.prover.prove_transfer(&claim_a.witness).await?;
            println!(
                "  Alice claim proof generated ({} bytes), nullifier: 0x{}...",
                claim_proof_a.proof.len(),
                &hex::encode(claim_a.witness.nullifier.0)[..16]
            );

            let claim_proof_b = harness.prover.prove_transfer(&claim_b.witness).await?;
            println!(
                "  Bob   claim proof generated ({} bytes), nullifier: 0x{}...",
                claim_proof_b.proof.len(),
                &hex::encode(claim_b.witness.nullifier.0)[..16]
            );

            // Alice claims Bob's note on chain B
            let claim_tx_a = harness
                .chain_b
                .rpc
                .transfer(&claim_proof_a.proof, &claim_proof_a.public_inputs)
                .await?;
            println!("  Alice claim tx (chain B): {} (success: {})", claim_tx_a.tx_hash, claim_tx_a.success);

            // Bob claims Alice's note on chain A
            let claim_tx_b = harness
                .chain_a
                .rpc
                .transfer(&claim_proof_b.proof, &claim_proof_b.public_inputs)
                .await?;
            println!("  Bob   claim tx (chain A): {} (success: {})", claim_tx_b.tx_hash, claim_tx_b.success);

            println!(
                "  Alice output: 0x{}...",
                &hex::encode(claim_a.output_note.commitment().0)[..16]
            );
            println!(
                "  Bob   output: 0x{}...",
                &hex::encode(claim_b.output_note.commitment().0)[..16]
            );

            harness.server_handle.shutdown();

            println!("\n================== E2E Complete (Happy Path) ==================");
            println!("  All 10 phases succeeded.");
            println!("  Alice: {VALUE_A} USD (Chain A) → {VALUE_B} BOND (Chain B)");
            println!("  Bob:   {VALUE_B} BOND (Chain B) → {VALUE_A} USD (Chain A)");
        }

        Scenario::Refund => {
            // ── Phase 9: Submit to TEE, then crash ──
            println!("\n[9/10] Alice submits to TEE, then TEE crashes...");

            // Alice submits first → expect "pending"
            let resp = harness
                .client
                .post(format!("{}/submit", harness.base_url))
                .json(&lock_a.submission)
                .send()
                .await?;
            let body: serde_json::Value = resp.json().await?;
            let status = body["status"]
                .as_str()
                .ok_or_else(|| E2eError::Json("missing status field".into()))?;
            println!("  Alice submitted → status: {status}");
            assert_eq!(status, "pending", "first submission should be pending");

            // Simulate TEE crash — shut down the server before Bob can submit
            harness.server_handle.shutdown();
            println!("  TEE server shut down (simulating crash)");
            println!("  Bob cannot submit; swap will not complete");

            // ── Phase 10: Warp time and refund ──
            println!("\n[10/10] Warping time past timeout and submitting refunds...");

            // Extract timeout from swap terms
            let timeout_u64 = u64::from_be_bytes(
                harness.terms.timeout.0[24..32]
                    .try_into()
                    .expect("timeout bytes"),
            );
            let warp_to = timeout_u64 + 1;
            println!("  Timeout: {timeout_u64}, warping to: {warp_to}");

            let endpoint_a = harness._anvil.anvil_a.endpoint();
            let endpoint_b = harness._anvil.anvil_b.endpoint();
            anvil_warp_time(&endpoint_a, warp_to).await?;
            anvil_warp_time(&endpoint_b, warp_to).await?;
            println!("  Both chains warped past timeout");

            // Prepare refund witnesses
            let locked_idx_a = 1u64; // second leaf in tree_a (Alice's locked note)
            let locked_proof_a = harness
                .chain_a
                .tree
                .generate_proof(locked_idx_a)
                .expect("proof for locked note a");
            let locked_root_a = harness.chain_a.tree.current_root().expect("locked root a");

            let locked_idx_b = 1u64; // second leaf in tree_b (Bob's locked note)
            let locked_proof_b = harness
                .chain_b
                .tree
                .generate_proof(locked_idx_b)
                .expect("proof for locked note b");
            let locked_root_b = harness.chain_b.tree.current_root().expect("locked root b");

            // Alice refunds her locked note on chain A
            let refund_a = prepare_refund(
                &lock_a.locked_note,
                &harness.alice.meta_key.sk,
                &locked_proof_a,
                locked_root_a,
            );

            // Bob refunds his locked note on chain B
            let refund_b = prepare_refund(
                &lock_b.locked_note,
                &harness.bob.meta_key.sk,
                &locked_proof_b,
                locked_root_b,
            );

            // Generate refund proofs
            let refund_proof_a = harness.prover.prove_transfer(&refund_a.witness).await?;
            println!(
                "  Alice refund proof generated ({} bytes), nullifier: 0x{}...",
                refund_proof_a.proof.len(),
                &hex::encode(refund_a.witness.nullifier.0)[..16]
            );

            let refund_proof_b = harness.prover.prove_transfer(&refund_b.witness).await?;
            println!(
                "  Bob   refund proof generated ({} bytes), nullifier: 0x{}...",
                refund_proof_b.proof.len(),
                &hex::encode(refund_b.witness.nullifier.0)[..16]
            );

            // Alice refunds on chain A
            let refund_tx_a = harness
                .chain_a
                .rpc
                .transfer(&refund_proof_a.proof, &refund_proof_a.public_inputs)
                .await?;
            println!(
                "  Alice refund tx (chain A): {} (success: {})",
                refund_tx_a.tx_hash, refund_tx_a.success
            );

            // Bob refunds on chain B
            let refund_tx_b = harness
                .chain_b
                .rpc
                .transfer(&refund_proof_b.proof, &refund_proof_b.public_inputs)
                .await?;
            println!(
                "  Bob   refund tx (chain B): {} (success: {})",
                refund_tx_b.tx_hash, refund_tx_b.success
            );

            println!(
                "  Alice refund output: 0x{}...",
                &hex::encode(refund_a.output_note.commitment().0)[..16]
            );
            println!(
                "  Bob   refund output: 0x{}...",
                &hex::encode(refund_b.output_note.commitment().0)[..16]
            );

            println!("\n================== E2E Complete (Refund) ==================");
            println!("  All 10 phases succeeded.");
            println!("  TEE crashed after Alice's submission; swap aborted.");
            println!("  Alice: reclaimed {VALUE_A} USD on Chain A");
            println!("  Bob:   reclaimed {VALUE_B} BOND on Chain B");
        }
    }

    Ok(())
}

//! Testnet binary for the TEE swap protocol.
//!
//! Runs the full swap flow on Sepolia + a Layer 2 (preferably a validium) with separate identities,
//! chain indexing, and on-chain announcement verification.
//!
//! Run with:
//!   cargo run --bin testnet -- --config config.toml

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use alloy::primitives::{Address, B256};
use alloy::providers::Provider;
use alloy::signers::local::PrivateKeySigner;
use clap::Parser;
use tracing::info;

mod config;
mod indexer;

use config::{Chain, ChainConfig, TestnetConfig};
use indexer::ChainIndexer;
use tee_swap::adapters::bb_prover::BBProver;
use tee_swap::adapters::ethereum::EthereumRpc;
use tee_swap::adapters::memory_store::InMemorySwapStore;
use tee_swap::adapters::mock_tee::MockTeeRuntime;
use tee_swap::coordinator::SwapCoordinator;
use tee_swap::domain::note::Note;
use tee_swap::domain::stealth::MetaKeyPair;
use tee_swap::domain::swap::{SwapAnnouncement, SwapTerms};
use tee_swap::party::{prepare_claim, prepare_lock, PartyRole};
use tee_swap::ports::chain::ChainPort as _;
use tee_swap::ports::prover::Prover;
use tee_swap::ports::tee::AttestationReport;
use tee_swap::server::start_server;
use tee_swap::server::verifier::build_ra_tls_client;

#[derive(clap::Parser)]
#[command(name = "testnet", about = "TEE swap testnet demo")]
struct Args {
    /// Path to the TOML configuration file.
    #[arg(long, default_value = "./config.toml")]
    config: PathBuf,
}

#[derive(Debug, thiserror::Error)]
enum TestnetError {
    #[error("config error: {0}")]
    Config(#[from] config::ConfigError),

    #[error("chain error: {0}")]
    Chain(#[from] tee_swap::ports::chain::ChainError),

    #[error("coordinator error: {0}")]
    Coordinator(#[from] tee_swap::coordinator::CoordinatorError),

    #[error("server error: {0}")]
    Server(#[from] tee_swap::server::ServerError),

    #[error("http request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("prover error: {0}")]
    Prover(#[from] tee_swap::ports::prover::ProverError),

    #[error("deploy error: {0}")]
    Deploy(String),

    #[error("indexer error: {0}")]
    Indexer(String),

    #[error("json error: {0}")]
    Json(String),

    #[error("timeout waiting for {0}")]
    Timeout(String),

    #[error("merkle proof unavailable: {0}")]
    MerkleProof(String),

    #[error("RPC error: {0}")]
    Rpc(String),

    #[error("transaction reverted: {0}")]
    TxReverted(String),
}

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Returns a block explorer link for the given transaction hash, or a raw hash if no explorer is configured.
fn tx_link(explorer_url: Option<&str>, tx_hash: B256) -> String {
    match explorer_url {
        Some(base) => format!("{base}/{tx_hash:#x}"),
        None => format!("{tx_hash:#x}"),
    }
}

/// Print a step header — called at the start of each named phase.
fn step(n: u8, total: u8, msg: &str) {
    info!("");
    info!("┌─[{n}/{total}] {msg}");
}

/// Deploy contracts for a chain using forge script.
async fn deploy_contracts(
    chain_config: &ChainConfig,
    deployer_signer: &PrivateKeySigner,
    tee_address: &Address,
    chain_id: u64,
) -> Result<(Address, Address, u64), TestnetError> {
    let config_path = project_root()
        .join("target")
        .join(format!("deploy_testnet_{}.toml", deployer_signer.address()));

    // Write deploy config
    let deployer_hex = hex::encode(deployer_signer.to_bytes());
    let config_content = format!(
        "\
[{chain_id}]
endpoint_url = \"{}\"

[{chain_id}.address]
tee_address = \"{tee_address}\"

[{chain_id}.bool]
use_mock_verifier = false
",
        chain_config.rpc_url
    );
    std::fs::create_dir_all(config_path.parent().unwrap())
        .map_err(|e| TestnetError::Deploy(format!("create dir: {e}")))?;
    std::fs::write(&config_path, &config_content)
        .map_err(|e| TestnetError::Deploy(format!("write config: {e}")))?;

    // Record block number before deployment for conservative indexer start
    let provider = alloy::providers::DynProvider::new(
        alloy::providers::ProviderBuilder::new().connect_http(
            chain_config
                .rpc_url
                .parse()
                .map_err(|e| TestnetError::Deploy(format!("invalid RPC URL: {e}")))?,
        ),
    );
    let block = provider
        .get_block_number()
        .await
        .map_err(|e| TestnetError::Deploy(format!("get block: {e}")))?;

    // Run forge script (private key passed as CLI arg — visible in ps, acceptable for PoC)
    let status = tokio::process::Command::new("forge")
        .args([
            "script",
            "contracts/script/Deploy.s.sol",
            "--rpc-url",
            &chain_config.rpc_url,
            "--broadcast",
            "--private-key",
            &format!("0x{deployer_hex}"),
            "--slow"
        ])
        .env("DEPLOY_CONFIG", config_path.to_str().unwrap())
        .current_dir(project_root())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .status()
        .await
        .map_err(|e| TestnetError::Deploy(format!("forge exec: {e}")))?;

    if !status.success() {
        return Err(TestnetError::Deploy(format!("forge exit: {status}")));
    }

    // Parse addresses from output config
    let content = std::fs::read_to_string(&config_path)
        .map_err(|e| TestnetError::Deploy(format!("read config: {e}")))?;

    let table: toml::Table = content
        .parse()
        .map_err(|e| TestnetError::Deploy(format!("parse config: {e}")))?;

    let addresses = table
        .get(&format!("{chain_id}"))
        .and_then(|inner| inner.as_table())
        .and_then(|inner| inner.get("address"))
        .and_then(|v| v.as_table())
        .ok_or_else(|| TestnetError::Deploy(format!("missing [{chain_id}.address]")))?;

    let private_utxo: Address = addresses
        .get("private_utxo_address")
        .and_then(|v| v.as_str())
        .ok_or_else(|| TestnetError::Deploy("missing private_utxo_address".into()))?
        .parse()
        .map_err(|e| TestnetError::Deploy(format!("invalid private_utxo_address: {e}")))?;

    let tee_lock: Address = addresses
        .get("tee_lock_address")
        .and_then(|v| v.as_str())
        .ok_or_else(|| TestnetError::Deploy("missing tee_lock_address".into()))?
        .parse()
        .map_err(|e| TestnetError::Deploy(format!("invalid tee_lock_address: {e}")))?;

    Ok((private_utxo, tee_lock, block))
}

/// Collected per-chain deployment info.
struct ChainDeployment {
    private_utxo: Address,
    tee_lock: Address,
    deployment_block: u64,
    rpc_url: String,
    explorer_url: Option<String>,
}

/// Resolved per-party references into chain deployments and config.
struct PartyContext<'a> {
    deploy: &'a ChainDeployment,
    deployer_key: &'a str,
    chain_id_b256: B256,
    explorer_url: Option<&'a str>,
}

const COMMITMENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), TestnetError> {
    // Init tracing — no timestamps or level prefix so output is clean for demos.
    tracing_subscriber::fmt()
        .without_time()
        .with_target(false)
        .with_level(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    // ── Step 1: Parse config ──
    step(1, 12, &format!("Loading config from {}", args.config.display()));
    let config = TestnetConfig::load(&args.config)?;

    // ── Step 2: Parse private keys ──
    step(2, 12, "Parsing private keys...");

    let sepolia_deployer: PrivateKeySigner = config.sepolia.deployer_private_key.parse()
        .map_err(|e| TestnetError::Deploy(format!("invalid sepolia deployer key: {e}")))?;
    let layer2_deployer: PrivateKeySigner = config.layer2.deployer_private_key.parse()
        .map_err(|e| TestnetError::Deploy(format!("invalid layer2 deployer key: {e}")))?;
    let alice_signer: PrivateKeySigner = config.alice.private_key.parse()
        .map_err(|e| TestnetError::Deploy(format!("invalid alice key: {e}")))?;
    let bob_signer: PrivateKeySigner = config.bob.private_key.parse()
        .map_err(|e| TestnetError::Deploy(format!("invalid bob key: {e}")))?;

    let is_local_coordinator = match &config.coordinator {
        None => true,
        Some(c) => c.url.is_none(),
    };

    let tee_signer = if is_local_coordinator {
        let tee_config = config
            .tee
            .as_ref()
            .expect("validated: tee private_key required for local coordinator");
        let signer: PrivateKeySigner = tee_config.private_key.parse()
            .map_err(|e| TestnetError::Deploy(format!("invalid tee key: {e}")))?;
        Some(signer)
    } else {
        None
    };

    info!("  Sepolia deployer:  {}", sepolia_deployer.address());
    info!("  Layer 2 deployer:  {}", layer2_deployer.address());
    info!("  Alice:             {}", alice_signer.address());
    info!("  Bob:               {}", bob_signer.address());
    if let Some(ref tee) = tee_signer {
        info!("  TEE:               {}", tee.address());
    }

    // ── Step 3: Query chain IDs ──
    step(3, 12, "Querying chain IDs...");

    let sepolia_provider = alloy::providers::DynProvider::new(
        alloy::providers::ProviderBuilder::new().connect_http(
            config
                .sepolia
                .rpc_url
                .parse()
                .map_err(|e| TestnetError::Rpc(format!("invalid Sepolia RPC URL: {e}")))?,
        ),
    );
    let layer2_provider = alloy::providers::DynProvider::new(
        alloy::providers::ProviderBuilder::new().connect_http(
            config
                .layer2
                .rpc_url
                .parse()
                .map_err(|e| TestnetError::Rpc(format!("invalid Layer 2 RPC URL: {e}")))?,
        ),
    );

    let (sep_id, layer2_id) = tokio::try_join!(
        sepolia_provider.get_chain_id(),
        layer2_provider.get_chain_id(),
    )
    .map_err(|e| TestnetError::Rpc(format!("chain ID query: {e}")))?;

    info!("  Sepolia: chain_id={sep_id}");
    info!("  Layer 2: chain_id={layer2_id}");

    // ── Step 4: Deploy contracts if needed ──
    step(4, 12, "Setting up contracts...");

    // TEE address for TeeLock deployment:
    // - Local coordinator: derived from TEE keystore signer
    // - External coordinator: from coordinator.tee_address config
    // Validation ensures tee_address is available when contracts need deploying.
    let tee_address = if let Some(ref signer) = tee_signer {
        signer.address()
    } else {
        config
            .coordinator
            .as_ref()
            .and_then(|c| c.tee_address)
            .expect("validated: tee_address or local TEE signer must be present")
    };

    let sepolia_deploy = if let Some(private_utxo) = config.sepolia.private_utxo_address {
        let tee_lock = config.sepolia.tee_lock_address.expect("validated: set with private_utxo_address");
        info!("  Sepolia: using pre-deployed contracts");
        info!("    PrivateUTXO: {private_utxo}");
        info!("    TeeLock:     {tee_lock}");
        ChainDeployment {
            private_utxo,
            tee_lock,
            deployment_block: config.sepolia.deployment_block.expect("validated: set with private_utxo_address"),
            rpc_url: config.sepolia.rpc_url.clone(),
            explorer_url: config.sepolia.explorer_url.clone(),
        }
    } else {
        info!("  Sepolia: deploying contracts...");
        let (utxo, tee_lock, block) =
            deploy_contracts(&config.sepolia, &sepolia_deployer, &tee_address, sep_id).await?;
        info!("    PrivateUTXO: {utxo}");
        info!("    TeeLock:     {tee_lock}");
        info!("    Block:       {block}");
        ChainDeployment {
            private_utxo: utxo,
            tee_lock,
            deployment_block: block,
            rpc_url: config.sepolia.rpc_url.clone(),
            explorer_url: config.sepolia.explorer_url.clone(),
        }
    };

    let layer2_deploy = if let Some(private_utxo) = config.layer2.private_utxo_address {
        let tee_lock = config.layer2.tee_lock_address.expect("validated: set with private_utxo_address");
        info!("  Layer 2: using pre-deployed contracts");
        info!("    PrivateUTXO: {private_utxo}");
        info!("    TeeLock:     {tee_lock}");
        ChainDeployment {
            private_utxo,
            tee_lock,
            deployment_block: config.layer2.deployment_block.expect("validated: set with private_utxo_address"),
            rpc_url: config.layer2.rpc_url.clone(),
            explorer_url: config.layer2.explorer_url.clone(),
        }
    } else {
        info!("  Layer 2: deploying contracts...");
        let (utxo, tee_lock, block) =
            deploy_contracts(&config.layer2, &layer2_deployer, &tee_address, layer2_id).await?;
        info!("    PrivateUTXO: {utxo}");
        info!("    TeeLock:     {tee_lock}");
        info!("    Block:       {block}");
        ChainDeployment {
            private_utxo: utxo,
            tee_lock,
            deployment_block: block,
            rpc_url: config.layer2.rpc_url.clone(),
            explorer_url: config.layer2.explorer_url.clone(),
        }
    };

    // ── Step 5: Resolve per-party chain context and create RPC instances ──
    step(5, 12, "Creating RPC adapters...");

    let sepolia_chain_id_b256 = B256::left_padding_from(&sep_id.to_be_bytes());
    let layer2_chain_id_b256 = B256::left_padding_from(&layer2_id.to_be_bytes());

    let resolve_party = |chain: Chain| -> PartyContext<'_> {
        match chain {
            Chain::Sepolia => PartyContext {
                deploy: &sepolia_deploy,
                deployer_key: &config.sepolia.deployer_private_key,
                chain_id_b256: sepolia_chain_id_b256,
                explorer_url: sepolia_deploy.explorer_url.as_deref(),
            },
            Chain::Layer2 => PartyContext {
                deploy: &layer2_deploy,
                deployer_key: &config.layer2.deployer_private_key,
                chain_id_b256: layer2_chain_id_b256,
                explorer_url: layer2_deploy.explorer_url.as_deref(),
            },
        }
    };

    let alice_ctx = resolve_party(config.alice.chain);
    let bob_ctx = resolve_party(config.bob.chain);

    let alice_rpc = EthereumRpc::new(
        &alice_ctx.deploy.rpc_url,
        &config.alice.private_key,
        alice_ctx.deploy.private_utxo,
        alice_ctx.deploy.tee_lock,
    ).await?;

    let bob_rpc = EthereumRpc::new(
        &bob_ctx.deploy.rpc_url,
        &config.bob.private_key,
        bob_ctx.deploy.private_utxo,
        bob_ctx.deploy.tee_lock,
    ).await?;

    // Cross-chain RPCs for claim transactions:
    // Alice claims Bob's note on Bob's chain (signed by Alice)
    // Bob claims Alice's note on Alice's chain (signed by Bob)
    let alice_claim_rpc = EthereumRpc::new(
        &bob_ctx.deploy.rpc_url,
        &config.alice.private_key,
        bob_ctx.deploy.private_utxo,
        bob_ctx.deploy.tee_lock,
    ).await?;

    let bob_claim_rpc = EthereumRpc::new(
        &alice_ctx.deploy.rpc_url,
        &config.bob.private_key,
        alice_ctx.deploy.private_utxo,
        alice_ctx.deploy.tee_lock,
    ).await?;

    // Deployer RPCs for fund() calls (deployer = PrivateUTXO owner)
    let alice_deployer_rpc = EthereumRpc::new(
        &alice_ctx.deploy.rpc_url,
        alice_ctx.deployer_key,
        alice_ctx.deploy.private_utxo,
        alice_ctx.deploy.tee_lock,
    ).await?;

    let bob_deployer_rpc = EthereumRpc::new(
        &bob_ctx.deploy.rpc_url,
        bob_ctx.deployer_key,
        bob_ctx.deploy.private_utxo,
        bob_ctx.deploy.tee_lock,
    ).await?;

    // ── Step 6: Start chain indexers ──
    step(6, 12, "Starting chain indexers...");

    let sepolia_indexer = Arc::new(
        ChainIndexer::spawn(
            &sepolia_deploy.rpc_url,
            sepolia_deploy.private_utxo,
            Some(sepolia_deploy.tee_lock), // Sepolia watches TeeLock too
            sepolia_deploy.deployment_block,
        )
        .map_err(TestnetError::Indexer)?,
    );

    let layer2_indexer = Arc::new(
        ChainIndexer::spawn(
            &layer2_deploy.rpc_url,
            layer2_deploy.private_utxo,
            None, // Layer 2: no TeeLock
            layer2_deploy.deployment_block,
        )
        .map_err(TestnetError::Indexer)?,
    );

    info!("  Waiting for indexers to catch up...");
    tokio::try_join!(
        async {
            sepolia_indexer.wait_until_caught_up().await;
            Ok::<_, TestnetError>(())
        },
        async {
            layer2_indexer.wait_until_caught_up().await;
            Ok::<_, TestnetError>(())
        },
    )?;
    info!("  Indexers caught up");

    // Resolve indexer references per party
    let (alice_indexer, bob_indexer): (&Arc<ChainIndexer>, &Arc<ChainIndexer>) =
        match config.alice.chain {
            Chain::Sepolia => (&sepolia_indexer, &layer2_indexer),
            Chain::Layer2 => (&layer2_indexer, &sepolia_indexer),
        };

    // ── Step 7: Generate identities and fund notes ──
    step(7, 12, "Generating identities and funding notes...");

    let mut rng = ark_std::rand::thread_rng();
    let alice_meta = MetaKeyPair::generate(&mut rng);
    let bob_meta = MetaKeyPair::generate(&mut rng);

    let chain_id_alice = alice_ctx.chain_id_b256;
    let chain_id_bob = bob_ctx.chain_id_b256;

    let value_alice = config.alice.amount;
    let value_bob = config.bob.amount;

    let asset_alice = B256::repeat_byte(0x01); // USD
    let asset_bob = B256::repeat_byte(0x02); // BOND

    let timeout_abs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + config.swap.timeout.as_secs();
    let timeout = B256::left_padding_from(&timeout_abs.to_be_bytes());

    // Create and fund Alice's note (deployer calls fund())
    let alice_note = Note::new(
        chain_id_alice,
        value_alice,
        asset_alice,
        alice_meta.pk_x(),
        B256::ZERO,
        B256::ZERO,
    );
    // Create Bob's note
    let bob_note = Note::new(
        chain_id_bob,
        value_bob,
        asset_bob,
        bob_meta.pk_x(),
        B256::ZERO,
        B256::ZERO,
    );

    info!(
        "  Funding Alice on {} and Bob on {} concurrently...",
        config.alice.chain, config.bob.chain
    );
    let (fund_tx_alice, fund_tx_bob) = tokio::try_join!(
        alice_deployer_rpc.fund(alice_note.commitment().0),
        bob_deployer_rpc.fund(bob_note.commitment().0),
    )?;
    info!("  Alice fund tx:  {}", tx_link(alice_ctx.explorer_url, fund_tx_alice.tx_hash));
    info!("  Bob fund tx:    {}", tx_link(bob_ctx.explorer_url, fund_tx_bob.tx_hash));

    // ── Step 8: Wait for indexer to see funded commitments ──
    step(8, 12, "Waiting for funded commitments to be indexed...");

    let alice_leaf = tokio::time::timeout(
        COMMITMENT_TIMEOUT,
        alice_indexer.wait_for_commitment(alice_note.commitment().0),
    )
    .await
    .map_err(|_| TestnetError::Timeout("alice funded commitment".into()))?;
    info!("  Alice note indexed at leaf #{alice_leaf}");

    let bob_leaf = tokio::time::timeout(
        COMMITMENT_TIMEOUT,
        bob_indexer.wait_for_commitment(bob_note.commitment().0),
    )
    .await
    .map_err(|_| TestnetError::Timeout("bob funded commitment".into()))?;
    info!("  Bob note indexed at leaf #{bob_leaf}");

    // ── Step 9: Create swap terms and start coordinator ──
    step(9, 12, "Creating swap terms and connecting to coordinator...");

    let terms = SwapTerms::new(
        chain_id_alice,
        chain_id_bob,
        value_alice,
        value_bob,
        asset_alice,
        asset_bob,
        timeout,
        alice_meta.pk_x(),
        bob_meta.pk_x(),
        B256::repeat_byte(0xFF), // nonce
    );
    info!("  swap_id:  0x{}", &hex::encode(terms.swap_id.0)[..16]);

    let external_coordinator_url = config
        .coordinator
        .as_ref()
        .and_then(|c| c.url.clone());

    // server_handle is kept alive to prevent the local server from shutting down
    let (base_url, client, server_handle): (String, reqwest::Client, Option<axum_server::Handle>) =
        if let Some(ref url) = external_coordinator_url {
            info!("  Coordinator:  {url}");
            let client = build_ra_tls_client(true);
            (url.clone(), client, None)
        } else {
            let tee_private_key = &config.tee.as_ref().unwrap().private_key;
            let tee_rpc_sepolia = EthereumRpc::new(
                &sepolia_deploy.rpc_url,
                tee_private_key,
                sepolia_deploy.private_utxo,
                sepolia_deploy.tee_lock,
            ).await?;
            let tee_rpc_layer2 = EthereumRpc::new(
                &layer2_deploy.rpc_url,
                tee_private_key,
                layer2_deploy.private_utxo,
                layer2_deploy.tee_lock,
            ).await?;

            let mut chains = HashMap::new();
            chains.insert(sepolia_chain_id_b256, tee_rpc_sepolia);
            chains.insert(layer2_chain_id_b256, tee_rpc_layer2);

            let coordinator = Arc::new(
                SwapCoordinator::new(InMemorySwapStore::new(), chains, sepolia_chain_id_b256)
                    .with_min_timeout(60),
            );

            let tee = MockTeeRuntime::new(tee_signer.as_ref().unwrap().address());
            let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
            let (server_handle, bound_addr) = start_server(coordinator, &tee, addr).await?;
            let base_url = format!("https://127.0.0.1:{}", bound_addr.port());
            let client = build_ra_tls_client(true);
            info!("  Coordinator:  {base_url} (local)");

            (base_url, client, Some(server_handle))
        };

    // Fetch and display attestation report
    let attestation: AttestationReport = client
        .get(format!("{base_url}/attestation"))
        .send()
        .await?
        .json()
        .await?;
    info!("  ┌─ TEE Attestation ──────────────────────────────────────────────┐");
    info!("  │  type:        {}", attestation.tee_type);
    info!("  │  pubkey_hash: {:#x}", attestation.pubkey_hash);
    info!("  │  timestamp:   {}", attestation.timestamp);
    if let Some(ref doc) = attestation.raw_document {
        info!("  │  nsm_doc:     {} bytes (AWS Nitro COSE_Sign1)", doc.len());
    }
    info!("  └────────────────────────────────────────────────────────────────┘");

    // ── Step 10: Prepare and send lock transactions ──
    step(10, 12, "Proving and sending lock transactions...");

    let proof_alice = alice_indexer
        .generate_proof(alice_leaf)
        .await
        .ok_or_else(|| TestnetError::MerkleProof(format!("alice note at leaf #{alice_leaf}")))?;
    let root_alice = alice_indexer
        .current_root()
        .await
        .ok_or_else(|| TestnetError::MerkleProof("alice chain root".into()))?;

    let lock_alice = prepare_lock(
        &terms,
        &alice_meta,
        &bob_meta.pk.into(),
        &alice_note,
        &proof_alice,
        root_alice,
    );

    let proof_bob = bob_indexer
        .generate_proof(bob_leaf)
        .await
        .ok_or_else(|| TestnetError::MerkleProof(format!("bob note at leaf #{bob_leaf}")))?;
    let root_bob = bob_indexer
        .current_root()
        .await
        .ok_or_else(|| TestnetError::MerkleProof("bob chain root".into()))?;

    let lock_bob = prepare_lock(
        &terms,
        &bob_meta,
        &alice_meta.pk.into(),
        &bob_note,
        &proof_bob,
        root_bob,
    );

    let prover = BBProver::new(project_root().join("circuits"));

    let (lock_proof_alice, lock_proof_bob) = tokio::try_join!(
        prover.prove_transfer(&lock_alice.witness),
        prover.prove_transfer(&lock_bob.witness),
    )?;
    info!("  Alice ZK proof: {} bytes", lock_proof_alice.proof.len());
    info!("  Bob ZK proof:   {} bytes", lock_proof_bob.proof.len());

    let (lock_tx_alice, lock_tx_bob) = tokio::try_join!(
        alice_rpc.transfer(&lock_proof_alice.proof, &lock_proof_alice.public_inputs),
        bob_rpc.transfer(&lock_proof_bob.proof, &lock_proof_bob.public_inputs),
    )?;
    info!("  Alice lock tx:  {}", tx_link(alice_ctx.explorer_url, lock_tx_alice.tx_hash));
    info!("  Bob lock tx:    {}", tx_link(bob_ctx.explorer_url, lock_tx_bob.tx_hash));

    if !lock_tx_alice.success {
        return Err(TestnetError::TxReverted(format!("alice lock tx {}", lock_tx_alice.tx_hash)));
    }
    if !lock_tx_bob.success {
        return Err(TestnetError::TxReverted(format!("bob lock tx {}", lock_tx_bob.tx_hash)));
    }

    info!("  Waiting for locked notes to be indexed...");
    let locked_leaf_alice = tokio::time::timeout(
        COMMITMENT_TIMEOUT,
        alice_indexer.wait_for_commitment(lock_alice.locked_note.commitment().0),
    )
    .await
    .map_err(|_| TestnetError::Timeout("alice locked commitment".into()))?;
    let locked_leaf_bob = tokio::time::timeout(
        COMMITMENT_TIMEOUT,
        bob_indexer.wait_for_commitment(lock_bob.locked_note.commitment().0),
    )
    .await
    .map_err(|_| TestnetError::Timeout("bob locked commitment".into()))?;
    info!("  Alice locked note: leaf #{locked_leaf_alice}");
    info!("  Bob locked note:   leaf #{locked_leaf_bob}");

    // ── Step 11: Submit to TEE ──
    step(11, 12, "Submitting to TEE coordinator via RA-TLS...");

    // Alice submits first
    let resp = client
        .post(format!("{base_url}/submit"))
        .json(&lock_alice.submission)
        .send()
        .await?;
    let body: serde_json::Value = resp.json().await?;
    let status = body["status"]
        .as_str()
        .ok_or_else(|| TestnetError::Json(format!("alice submit: server responded: {body}")))?;
    info!("  Alice submitted  -> status: {status}");

    if status != "pending" {
        return Err(TestnetError::Json(format!(
            "expected 'pending', got '{status}'"
        )));
    }

    // Bob submits second — coordinator verifies both and announces
    let resp = client
        .post(format!("{base_url}/submit"))
        .json(&lock_bob.submission)
        .send()
        .await?;
    let body: serde_json::Value = resp.json().await?;
    let status = body["status"]
        .as_str()
        .ok_or_else(|| TestnetError::Json(format!("bob submit: server responded: {body}")))?;
    info!("  Bob submitted    -> status: {status}");

    if status != "verified" {
        return Err(TestnetError::Json(format!(
            "expected 'verified', got '{status}'"
        )));
    }

    let announcement: SwapAnnouncement =
        serde_json::from_value(body["announcement"].clone())
            .map_err(|e| TestnetError::Json(format!("parse announcement: {e}")))?;

    let announce_tx_hash: B256 = body["tx_receipt"]["tx_hash"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| TestnetError::Json("missing tx_receipt.tx_hash".into()))?;
    info!("  TEE announce tx: {}", tx_link(sepolia_deploy.explorer_url.as_deref(), announce_tx_hash));

    // Wait for on-chain announcement (via indexer)
    info!("  Waiting for on-chain confirmation...");
    tokio::time::timeout(
        std::time::Duration::from_secs(120),
        sepolia_indexer.wait_for_swap_revealed(terms.swap_id),
    )
    .await
    .map_err(|_| TestnetError::Timeout("swap revealed on-chain".into()))?;
    info!("  Announcement confirmed on-chain");

    // Read announcement directly from chain for independent verification.
    let sepolia_verifier_rpc = match config.alice.chain {
        Chain::Sepolia => &alice_deployer_rpc,
        Chain::Layer2 => &bob_deployer_rpc,
    };
    let on_chain_announcement = tee_swap::ports::chain::ChainPort::get_announcement(
        sepolia_verifier_rpc,
        terms.swap_id,
    )
    .await?;
    if on_chain_announcement.swap_id != terms.swap_id {
        return Err(TestnetError::Json(format!(
            "announcement swap_id mismatch: expected {}, got {}",
            terms.swap_id, on_chain_announcement.swap_id
        )));
    }
    info!("  On-chain announcement verified independently");

    // ── Step 12: Claim ──
    step(12, 12, "Proving and sending claim transactions...");

    // Get updated Merkle proofs for locked notes
    let locked_proof_alice = alice_indexer
        .generate_proof(locked_leaf_alice)
        .await
        .ok_or_else(|| TestnetError::MerkleProof(format!("locked alice at leaf #{locked_leaf_alice}")))?;
    let locked_root_alice = alice_indexer
        .current_root()
        .await
        .ok_or_else(|| TestnetError::MerkleProof("alice chain root (locked)".into()))?;

    let locked_proof_bob = bob_indexer
        .generate_proof(locked_leaf_bob)
        .await
        .ok_or_else(|| TestnetError::MerkleProof(format!("locked bob at leaf #{locked_leaf_bob}")))?;
    let locked_root_bob = bob_indexer
        .current_root()
        .await
        .ok_or_else(|| TestnetError::MerkleProof("bob chain root (locked)".into()))?;

    // Alice (role A) claims Bob's note on Bob's chain
    let claim_alice = prepare_claim(
        &announcement,
        &alice_meta,
        &lock_bob.ephemeral_keypair.r_pub.into(),
        &terms,
        PartyRole::A,
        &locked_proof_bob,
        locked_root_bob,
    );

    // Bob (role B) claims Alice's note on Alice's chain
    let claim_bob = prepare_claim(
        &announcement,
        &bob_meta,
        &lock_alice.ephemeral_keypair.r_pub.into(),
        &terms,
        PartyRole::B,
        &locked_proof_alice,
        locked_root_alice,
    );

    let (claim_proof_alice, claim_proof_bob) = tokio::try_join!(
        prover.prove_transfer(&claim_alice.witness),
        prover.prove_transfer(&claim_bob.witness),
    )?;
    info!("  Alice ZK proof: {} bytes", claim_proof_alice.proof.len());
    info!("  Bob ZK proof:   {} bytes", claim_proof_bob.proof.len());

    // Alice claims Bob's note on Bob's chain; Bob claims Alice's note on Alice's chain
    let (claim_tx_alice, claim_tx_bob) = tokio::try_join!(
        alice_claim_rpc.transfer(&claim_proof_alice.proof, &claim_proof_alice.public_inputs),
        bob_claim_rpc.transfer(&claim_proof_bob.proof, &claim_proof_bob.public_inputs),
    )?;
    info!("  Alice claim tx: {}", tx_link(bob_ctx.explorer_url, claim_tx_alice.tx_hash));
    info!("  Bob claim tx:   {}", tx_link(alice_ctx.explorer_url, claim_tx_bob.tx_hash));

    if !claim_tx_alice.success {
        return Err(TestnetError::TxReverted(format!("alice claim tx {}", claim_tx_alice.tx_hash)));
    }
    if !claim_tx_bob.success {
        return Err(TestnetError::TxReverted(format!("bob claim tx {}", claim_tx_bob.tx_hash)));
    }

    // ── Summary ──
    if let Some(handle) = server_handle {
        handle.shutdown();
    }

    info!("");
    info!("╔══════════════════════════════════════════════════════════════════════════════╗");
    info!("║                         TESTNET DEMO COMPLETE                               ║");
    info!("╠══════════════════════════════════════════════════════════════════════════════╣");
    info!("║  Fund Alice    {}", tx_link(alice_ctx.explorer_url, fund_tx_alice.tx_hash));
    info!("║  Fund Bob      {}", tx_link(bob_ctx.explorer_url,   fund_tx_bob.tx_hash));
    info!("║  Lock Alice    {}", tx_link(alice_ctx.explorer_url, lock_tx_alice.tx_hash));
    info!("║  Lock Bob      {}", tx_link(bob_ctx.explorer_url,   lock_tx_bob.tx_hash));
    info!("║  TEE Announce  {}", tx_link(sepolia_deploy.explorer_url.as_deref(),     announce_tx_hash));
    info!("║  Claim Alice   {}", tx_link(bob_ctx.explorer_url,   claim_tx_alice.tx_hash));
    info!("║  Claim Bob     {}", tx_link(alice_ctx.explorer_url, claim_tx_bob.tx_hash));
    info!("╚══════════════════════════════════════════════════════════════════════════════╝");

    Ok(())
}

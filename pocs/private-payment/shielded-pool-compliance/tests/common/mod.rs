//! Shared end-to-end harness. Each test owns an anvil node it spawned itself, deploys
//! the stack into it with `forge script`, and drives the production actors (`Authority`,
//! `Wallet`, `Auditor`) against it through `adapters::ethereum_rpc::EthereumRpc`.
//!
//! The pool submission helpers below carry their own `sol!` bindings rather than going
//! through `ChainWriter`, so that a scenario can assert on the decoded revert of a
//! rejected submission and on the events of an accepted one.

#![allow(dead_code)]

use std::{
    borrow::Cow,
    path::PathBuf,
    process::Command,
    sync::{
        Arc,
        Mutex,
        atomic::{
            AtomicU64,
            Ordering,
        },
    },
};

use alloy::{
    network::EthereumWallet,
    primitives::{
        Address as AlloyAddress,
        B256,
        Bytes as AlloyBytes,
        U256,
    },
    providers::{
        DynProvider,
        Provider,
        ProviderBuilder,
    },
    rpc::types::{
        Log,
        TransactionReceipt,
    },
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolError,
};
use ark_bn254::Fr;
use tempfile::TempDir;

use shielded_pool_compliance::{
    adapters::{
        commitment_tree::RotorMerkleTree,
        ecies_audit::EciesAuditEncryptor,
        ethereum_rpc::EthereumRpc,
    },
    authority::{
        Authority,
        MinCohortSize,
    },
    domain::{
        attestation::{
            Cohort,
            Generation,
        },
        keys::{
            AuditViewingKey,
            AuditViewingPubkey,
            ComplianceViewingKey,
            OwnerPubkey,
            SpendingKey,
            ViewingKey,
            ViewingPubkey,
        },
        note::Note,
        payload::{
            Payload,
            PayloadElement,
        },
        public_inputs::{
            deposit as deposit_idx,
            gated_withdraw as withdraw_idx,
            transfer as transfer_idx,
            ungated_withdraw as ungated_idx,
        },
    },
    policy::{
        commit::state_tag,
        reference::ReferencePolicy,
    },
    ports::{
        clock::Clock,
        merkle::LeafIndex,
        prover::{
            CircuitProof,
            Prover,
        },
    },
    types::{
        Address,
        Bytes32,
        Epoch,
    },
    wallet::{
        DepositRequest,
        TransferRequest,
        Wallet,
        WalletKeys,
        WithdrawRequest,
    },
};

pub mod proof_backend;

use proof_backend::{
    prover,
    use_mock_proofs,
};

/// Anvil's default prefunded accounts. 0 is the deployer and holds every registry and
/// pool role the tests exercise; 1 is `blockedFundsAccount`.
pub const ANVIL_KEYS: [&str; 4] = [
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
];

pub const DEPLOYER: usize = 0;
pub const BLOCKED_FUNDS: usize = 1;
pub const PAYEE: usize = 2;
pub const SANCTIONED: usize = 3;

sol! {
    #[sol(rpc)]
    #[derive(Debug)]
    interface IShieldedPool {
        struct DepositParams {
            bytes proof;
            bytes32 commitment;
            uint256 token;
            uint256 amount;
            bytes32 attestationRoot;
            bytes32 velocityNullifier;
            bytes32 complianceCommitmentOut;
            uint256 epoch;
            uint256 epochSeconds;
            bytes32 policySourceHash;
            bytes32 commitmentRoot;
            bytes32 attesterRevocationRoot;
            uint256 minAcceptedGeneration;
            bytes32 payloadCommitment;
            bytes encryptedNotes;
        }

        struct TransferParams {
            bytes proof;
            bytes32 nullifier0;
            bytes32 nullifier1;
            bytes32 commitmentOut0;
            bytes32 commitmentOut1;
            bytes32 commitmentRoot;
            bytes32 velocityNullifier;
            bytes32 complianceCommitmentOut;
            uint256 epoch;
            uint256 epochSeconds;
            bytes32 policySourceHash;
            bytes32 attestationRoot;
            bytes32 attesterRevocationRoot;
            uint256 minAcceptedGeneration;
            bytes32 payloadCommitment;
            bytes encryptedNotes;
        }

        struct WithdrawParams {
            bytes proof;
            bytes32 nullifier;
            uint256 token;
            uint256 amount;
            address recipient;
            bytes32 commitmentRoot;
            bytes32 velocityNullifier;
            bytes32 complianceCommitmentOut;
            uint256 epoch;
            uint256 epochSeconds;
            bytes32 policySourceHash;
            bytes32 attestationRoot;
            bytes32 attesterRevocationRoot;
            uint256 minAcceptedGeneration;
            bytes32 payloadCommitment;
            bytes encryptedNotes;
        }

        struct WithdrawBlockedParams {
            bytes proof;
            bytes32 nullifier;
            uint256 token;
            uint256 amount;
            address recipient;
            bytes32 commitmentRoot;
        }

        function deposit(DepositParams calldata p) external;
        function transfer(TransferParams calldata p) external;
        function withdraw(WithdrawParams calldata p) external;
        function withdrawBlocked(WithdrawBlockedParams calldata p) external;
        function claimBlocked(bytes32 nullifier) external;
        function setBlockedDestination(address destination, bool blocked) external;

        function currentEpoch() external view returns (uint256);
        function commitmentRoot() external view returns (bytes32);
        function getCommitmentCount() external view returns (uint256);
        function isKnownRoot(bytes32 root) external view returns (bool);
        function nullifiers(bytes32 nullifier) external view returns (bool);
        function blockedBalance(bytes32 nullifier) external view returns (uint256);
        function blockedDestination(address destination) external view returns (bool);
        function singleTxThreshold() external view returns (uint256);
        function committeeVersion() external view returns (uint64);
        function effectivePolicy() external view returns (address verifier, bytes32 sourceHash);

        event Deposit(
            bytes32 indexed commitment,
            uint256 amount,
            bytes32 indexed velocityNullifier,
            bytes32 complianceCommitment,
            bytes encryptedNotes
        );
        event Transfer(
            bytes32 indexed nullifier0,
            bytes32 indexed nullifier1,
            bytes32 commitmentOut0,
            bytes32 commitmentOut1,
            bytes32 velocityNullifier,
            bytes32 complianceCommitment,
            bytes encryptedNotes
        );
        event Withdraw(
            bytes32 indexed nullifier,
            address indexed recipient,
            uint256 amount,
            bytes32 velocityNullifier,
            bytes32 complianceCommitment,
            bytes encryptedNotes
        );
        event WithdrawBlocked(bytes32 indexed nullifier, uint256 amount);
        event BlockedFundsClaimed(bytes32 indexed nullifier, uint256 amount);

        error BlockedDestination();
        error WrongEpoch();
        error UnknownRoot();
        error NullifierSpent();
        error NotBlockedFundsAccount();
        error InvalidProof();
        error PayloadMismatch();
    }

    #[sol(rpc)]
    interface IAttestationRegistry {
        function addAttester(address attester) external;
        function addAttestations(bytes32[] calldata subjectPubkeyHashes, uint64 expiresAt, uint64 generation) external;
        function attestationRoot() external view returns (bytes32);
        function attesterRevocationRoot() external view returns (bytes32);
        function minAcceptedGeneration() external view returns (uint256);
        function isAttester(address attester) external view returns (bool);
        function currentEpoch() external view returns (uint256);
        function MIN_COHORT_SIZE() external view returns (uint256);

        event AttestationAdded(
            bytes32 indexed leaf,
            bytes32 indexed subjectPubkeyHash,
            address indexed attester,
            uint64 generation,
            uint64 issuedAt,
            uint64 expiresAt
        );

        error CohortTooSmall();
    }

    #[sol(rpc)]
    interface IMockERC20 {
        function mint(address to, uint256 amount) external;
        function approve(address spender, uint256 amount) external returns (bool);
        function balanceOf(address account) external view returns (uint256);
    }
}

/// `forge` shares `contracts/out` and `contracts/cache` across invocations, so
/// concurrent test threads must not drive it at the same time.
static FORGE: Mutex<()> = Mutex::new(());

pub fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

pub struct AnvilHarness {
    /// Owned so the node dies with the test, including on a panicking unwind.
    _anvil: alloy::node_bindings::AnvilInstance,
    pub endpoint: String,
    pub deployer_pk: String,
    providers: Vec<DynProvider>,
    accounts: Vec<AlloyAddress>,
    pub use_mock: bool,
    now: Arc<AtomicU64>,
}

impl AnvilHarness {
    /// Alloy picks a free port and reports it through `endpoint_url()`, so several test
    /// binaries can hold their own node at once.
    pub fn start() -> Self {
        let anvil = alloy::node_bindings::Anvil::new().chain_id(31337).spawn();
        let endpoint = anvil.endpoint();

        let mut providers = Vec::with_capacity(ANVIL_KEYS.len());
        let mut accounts = Vec::with_capacity(ANVIL_KEYS.len());
        for key in ANVIL_KEYS {
            let signer: PrivateKeySigner = key.parse().expect("anvil key");
            accounts.push(signer.address());
            providers.push(
                ProviderBuilder::new()
                    .with_simple_nonce_management()
                    .wallet(EthereumWallet::from(signer))
                    .connect_http(anvil.endpoint_url())
                    .erased(),
            );
        }

        Self {
            _anvil: anvil,
            endpoint,
            deployer_pk: ANVIL_KEYS[DEPLOYER].to_string(),
            providers,
            accounts,
            use_mock: use_mock_proofs(),
            now: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn provider(&self, index: usize) -> DynProvider {
        self.providers[index].clone()
    }

    pub fn account(&self, index: usize) -> AlloyAddress {
        self.accounts[index]
    }

    pub fn deployer(&self) -> AlloyAddress {
        self.accounts[DEPLOYER]
    }

    /// A `Clock` the harness keeps pinned to the node's latest block timestamp, so the
    /// wallet's `local_epoch` and the pool's `currentEpoch()` never disagree.
    pub fn clock(&self) -> HarnessClock {
        HarnessClock(Arc::clone(&self.now))
    }

    pub async fn sync_clock(&self) {
        let block = self.providers[DEPLOYER]
            .get_block(alloy::eips::BlockId::latest())
            .await
            .expect("get latest block")
            .expect("latest block exists");
        self.now.store(block.header.timestamp, Ordering::SeqCst);
    }

    /// Mines one block an hour into `epoch`. An hour of slack keeps the several
    /// one-second block bumps that follow inside the same epoch.
    pub async fn warp_to_epoch(&self, epoch: u64) {
        let target = epoch * shielded_pool_compliance::EPOCH_SECONDS + 3600;
        let provider = &self.providers[DEPLOYER];
        let _: serde_json::Value = provider
            .raw_request(Cow::Borrowed("evm_setNextBlockTimestamp"), (target,))
            .await
            .expect("evm_setNextBlockTimestamp");
        let _: serde_json::Value = provider
            .raw_request(Cow::Borrowed("evm_mine"), ())
            .await
            .expect("evm_mine");
        self.sync_clock().await;
    }

    pub fn current_epoch(&self) -> Epoch {
        self.clock()
            .current_epoch(shielded_pool_compliance::EPOCH_SECONDS)
    }

    /// Runs the deploy script against this node and parses the addresses out of its
    /// `console.log` labels. `FOUNDRY_PROFILE=deploy` is required: `forge script`
    /// simulates all of `run()` in one call frame and the stack sums past the default
    /// profile's honest 30M block limit.
    pub fn deploy_all(&self) -> Deployment {
        let _guard = FORGE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let root = project_root();
        let deployments = root.join("deployments.toml");
        let original =
            std::fs::read_to_string(&deployments).expect("read deployments.toml");

        let deployer = self.deployer().to_string();
        let zero = AlloyAddress::ZERO.to_string();
        let output = Command::new("forge")
            .args([
                "script",
                "contracts/script/Deploy.s.sol:Deploy",
                "--rpc-url",
                &self.endpoint,
                "--private-key",
                &self.deployer_pk,
                "--broadcast",
            ])
            .env("FOUNDRY_PROFILE", "deploy")
            .env("USE_MOCK_VERIFIER", if self.use_mock { "true" } else { "false" })
            .env("GOVERNANCE", &deployer)
            .env("TIMELOCK_CONTROLLER", &deployer)
            .env("GUARDIAN", &deployer)
            .env("CURATOR", &deployer)
            .env("COMMITTEE", &deployer)
            .env("BLOCKED_FUNDS_ACCOUNT", self.account(BLOCKED_FUNDS).to_string())
            // `forge-std/Config` resolves every `${ENV}` in every chain block at load
            // time, so the unused sepolia block still has to resolve.
            .env("SEPOLIA_RPC_URL", &self.endpoint)
            .env("DEPOSIT_VERIFIER_ADDRESS", &zero)
            .env("TRANSFER_VERIFIER_ADDRESS", &zero)
            .env("WITHDRAW_VERIFIER_ADDRESS", &zero)
            .env("WITHDRAW_UNGATED_VERIFIER_ADDRESS", &zero)
            .current_dir(&root)
            .output()
            .expect("forge on PATH");

        // `config.set` rewrites deployments.toml, so restore it before the exit status
        // can short-circuit this function.
        std::fs::write(&deployments, &original).expect("restore deployments.toml");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "forge script failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );

        let blob = format!("{stdout}\n{stderr}");
        Deployment {
            token: parse_addr(&blob, "MockERC20:"),
            registry: parse_addr(&blob, "AttestationRegistry:"),
            deposit_verifier: parse_addr(&blob, "DepositVerifier:"),
            transfer_verifier: parse_addr(&blob, "TransferVerifier:"),
            withdraw_verifier: parse_addr(&blob, "WithdrawVerifier:"),
            withdraw_ungated_verifier: parse_addr(&blob, "WithdrawUngatedVerifier:"),
            composite_verifier: parse_addr(&blob, "CompositeVerifier:"),
            pool: parse_addr(&blob, "ShieldedPool:"),
        }
    }
}

#[track_caller]
fn parse_addr(blob: &str, label: &str) -> AlloyAddress {
    for line in blob.lines() {
        if let Some(rest) = line.trim().strip_prefix(label)
            && let Ok(address) = rest.trim().parse::<AlloyAddress>()
        {
            return address;
        }
    }
    panic!("no `{label}` line in forge output:\n{blob}")
}

#[derive(Debug, Clone, Copy)]
pub struct Deployment {
    pub token: AlloyAddress,
    pub registry: AlloyAddress,
    pub deposit_verifier: AlloyAddress,
    pub transfer_verifier: AlloyAddress,
    pub withdraw_verifier: AlloyAddress,
    pub withdraw_ungated_verifier: AlloyAddress,
    pub composite_verifier: AlloyAddress,
    pub pool: AlloyAddress,
}

#[derive(Clone)]
pub struct HarnessClock(Arc<AtomicU64>);

impl Clock for HarnessClock {
    fn now_unix(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// Everything a `Wallet::build_*` call needs besides the wallet itself. `EthereumRpc`
/// serves as both `ChainReader` and `AttestationSource`.
pub struct Ctx {
    pub rpc: EthereumRpc<DynProvider>,
    pub audit: EciesAuditEncryptor,
    pub clock: HarnessClock,
    pub committee_version: u64,
    pub state_tag: Bytes32,
}

impl Ctx {
    pub async fn new(
        harness: &AnvilHarness,
        deployment: &Deployment,
        audit_pubkey: AuditViewingPubkey,
    ) -> Self {
        let provider = harness.provider(DEPLOYER);
        let pool = IShieldedPool::new(deployment.pool, &provider);
        let committee_version = pool
            .committeeVersion()
            .call()
            .await
            .expect("committeeVersion");
        let source_hash = pool
            .effectivePolicy()
            .call()
            .await
            .expect("effectivePolicy")
            .sourceHash;
        let source_hash = Bytes32::from(source_hash.0);
        let tag = Bytes32::from(state_tag::<ReferencePolicy>(
            Fr::try_from(source_hash).expect("policy source hash is canonical"),
        ));

        Self {
            rpc: EthereumRpc::new(provider, deployment.pool, deployment.registry),
            audit: EciesAuditEncryptor::new(audit_pubkey, committee_version),
            clock: harness.clock(),
            committee_version,
            state_tag: tag,
        }
    }
}

pub type CommitmentTree = RotorMerkleTree<32>;
pub type AttestationTree = RotorMerkleTree<20>;

/// A wallet plus the key material a test needs to make assertions the wallet does not
/// expose: the spending key recomputes velocity nullifiers, the owner pubkey addresses
/// the subject in a cohort and in the auditor's reconstruction.
pub struct TestWallet {
    _commitments_dir: TempDir,
    _attestations_dir: TempDir,
    pub wallet: Wallet<CommitmentTree, AttestationTree>,
    pub spending_key: SpendingKey,
    pub owner: OwnerPubkey,
    pub viewing_pubkey: ViewingPubkey,
}

impl TestWallet {
    pub fn new() -> Self {
        let commitments_dir = tempfile::tempdir().expect("tempdir");
        let attestations_dir = tempfile::tempdir().expect("tempdir");
        let commitments =
            CommitmentTree::open(commitments_dir.path()).expect("open commitment tree");
        let attestations = AttestationTree::open(attestations_dir.path())
            .expect("open attestation tree");
        let spending_key = SpendingKey::random();
        let owner = spending_key.derive_owner_pubkey();
        let viewing_key = ViewingKey::random();
        let viewing_pubkey = viewing_key.public_key();

        Self {
            _commitments_dir: commitments_dir,
            _attestations_dir: attestations_dir,
            wallet: Wallet::new(
                commitments,
                attestations,
                WalletKeys {
                    spending_key: spending_key.clone(),
                    compliance_viewing_key: ComplianceViewingKey::random(),
                    viewing_key,
                },
            ),
            spending_key,
            owner,
            viewing_pubkey,
        }
    }

    /// Folds leaves another party's transaction inserted into this wallet's mirror.
    /// LeanIMT is positional, so every wallet must see the same leaves in the same order
    /// the pool inserted them.
    pub fn observe_commitments(&self, leaves: &[Bytes32]) {
        for leaf in leaves {
            self.wallet
                .observe_commitment(*leaf)
                .expect("observe commitment");
        }
    }

    pub fn observe_attestations(&self, leaves: &[Bytes32]) {
        for leaf in leaves {
            self.wallet
                .observe_attestation(*leaf)
                .expect("observe attestation");
        }
    }
}

impl Default for TestWallet {
    fn default() -> Self {
        Self::new()
    }
}

/// Grants the deployer `ATTESTER_ROLE`, then issues one cohort through `Authority`,
/// which reads the registry's own `MIN_COHORT_SIZE` and computes `expiresAt` off the
/// calendar function the registry checks against.
pub async fn issue_cohort(
    harness: &AnvilHarness,
    deployment: &Deployment,
    subjects: Vec<OwnerPubkey>,
    generation: Generation,
) -> Cohort {
    let provider = harness.provider(DEPLOYER);
    let registry = IAttestationRegistry::new(deployment.registry, &provider);

    if !registry
        .isAttester(harness.deployer())
        .call()
        .await
        .expect("isAttester")
    {
        registry
            .addAttester(harness.deployer())
            .send()
            .await
            .expect("addAttester send")
            .get_receipt()
            .await
            .expect("addAttester receipt");
    }

    let cohort = build_cohort(harness, deployment, subjects, generation).await;
    submit_cohort(harness, deployment, &cohort)
        .await
        .expect("addAttestations");
    harness.sync_clock().await;
    cohort
}

pub async fn build_cohort(
    harness: &AnvilHarness,
    deployment: &Deployment,
    subjects: Vec<OwnerPubkey>,
    generation: Generation,
) -> Cohort {
    let authority = Authority::new(min_cohort_size(harness, deployment).await);
    authority
        .build_cohort(&harness.clock(), subjects, generation)
        .expect("cohort meets the registry minimum")
}

pub async fn min_cohort_size(
    harness: &AnvilHarness,
    deployment: &Deployment,
) -> MinCohortSize {
    let provider = harness.provider(DEPLOYER);
    let value = IAttestationRegistry::new(deployment.registry, &provider)
        .MIN_COHORT_SIZE()
        .call()
        .await
        .expect("MIN_COHORT_SIZE");
    MinCohortSize(u64::try_from(value).expect("min cohort size fits u64"))
}

pub async fn submit_cohort(
    harness: &AnvilHarness,
    deployment: &Deployment,
    cohort: &Cohort,
) -> Result<TransactionReceipt, alloy::contract::Error> {
    let provider = harness.provider(DEPLOYER);
    let hashes: Vec<B256> = cohort
        .subjects
        .iter()
        .map(|subject| b256(subject.as_bytes32()))
        .collect();
    let pending = IAttestationRegistry::new(deployment.registry, &provider)
        .addAttestations(hashes, cohort.expires_at, cohort.generation.0)
        .send()
        .await?;
    Ok(pending
        .get_receipt()
        .await
        .expect("addAttestations receipt"))
}

/// The registry's attestation leaves in insertion order, which is also the leaf index
/// order `AttestationSource` derives from the event stream.
pub async fn attestation_leaves(
    harness: &AnvilHarness,
    deployment: &Deployment,
) -> Vec<Bytes32> {
    let provider = harness.provider(DEPLOYER);
    let mut events = IAttestationRegistry::new(deployment.registry, &provider)
        .event_filter::<IAttestationRegistry::AttestationAdded>()
        .from_block(0u64)
        .query()
        .await
        .expect("AttestationAdded query");
    events.sort_by_key(|(_, log)| log_key(log));
    events
        .into_iter()
        .map(|(event, _)| Bytes32::from(event.leaf.0))
        .collect()
}

fn log_key(log: &Log) -> (u64, u64) {
    (log.block_number.unwrap_or(0), log.log_index.unwrap_or(0))
}

pub async fn mint_and_approve(
    harness: &AnvilHarness,
    deployment: &Deployment,
    holder: usize,
    amount: u64,
) {
    let provider = harness.provider(holder);
    let token = IMockERC20::new(deployment.token, &provider);
    token
        .mint(harness.account(holder), U256::from(amount))
        .send()
        .await
        .expect("mint send")
        .get_receipt()
        .await
        .expect("mint receipt");
    token
        .approve(deployment.pool, U256::from(amount))
        .send()
        .await
        .expect("approve send")
        .get_receipt()
        .await
        .expect("approve receipt");
    harness.sync_clock().await;
}

pub async fn token_balance(
    harness: &AnvilHarness,
    deployment: &Deployment,
    account: AlloyAddress,
) -> U256 {
    IMockERC20::new(deployment.token, harness.provider(DEPLOYER))
        .balanceOf(account)
        .call()
        .await
        .expect("balanceOf")
}

pub async fn commitment_count(harness: &AnvilHarness, deployment: &Deployment) -> u64 {
    let count = IShieldedPool::new(deployment.pool, harness.provider(DEPLOYER))
        .getCommitmentCount()
        .call()
        .await
        .expect("getCommitmentCount");
    u64::try_from(count).expect("commitment count fits u64")
}

pub async fn pool_commitment_root(stage: &Stage) -> Bytes32 {
    let root = pool_of(&stage.harness, &stage.deployment)
        .commitmentRoot()
        .call()
        .await
        .expect("commitmentRoot");
    Bytes32::from(root.0)
}

pub async fn is_known_root(stage: &Stage, root: Bytes32) -> bool {
    pool_of(&stage.harness, &stage.deployment)
        .isKnownRoot(b256(root))
        .call()
        .await
        .expect("isKnownRoot")
}

pub async fn nullifier_spent(
    harness: &AnvilHarness,
    deployment: &Deployment,
    nullifier: Bytes32,
) -> bool {
    IShieldedPool::new(deployment.pool, harness.provider(DEPLOYER))
        .nullifiers(b256(nullifier))
        .call()
        .await
        .expect("nullifiers")
}

pub async fn blocked_balance(
    harness: &AnvilHarness,
    deployment: &Deployment,
    nullifier: Bytes32,
) -> U256 {
    IShieldedPool::new(deployment.pool, harness.provider(DEPLOYER))
        .blockedBalance(b256(nullifier))
        .call()
        .await
        .expect("blockedBalance")
}

pub async fn block_destination(
    harness: &AnvilHarness,
    deployment: &Deployment,
    destination: AlloyAddress,
) {
    IShieldedPool::new(deployment.pool, harness.provider(DEPLOYER))
        .setBlockedDestination(destination, true)
        .send()
        .await
        .expect("setBlockedDestination send")
        .get_receipt()
        .await
        .expect("setBlockedDestination receipt");
    harness.sync_clock().await;
}

pub struct ProvedDeposit {
    pub proof: CircuitProof,
    pub payload: Payload,
    pub note: Note,
    pub output_index: LeafIndex,
}

pub struct ProvedTransfer {
    pub proof: CircuitProof,
    pub payload: Payload,
    pub outputs: [Note; 2],
    pub output_indices: [LeafIndex; 2],
}

pub struct ProvedWithdraw {
    pub proof: CircuitProof,
    pub payload: Payload,
}

pub async fn prove_deposit(
    subject: &mut TestWallet,
    ctx: &Ctx,
    request: DepositRequest,
) -> Result<ProvedDeposit, shielded_pool_compliance::wallet::Error> {
    let built = subject
        .wallet
        .build_deposit(&ctx.rpc, &ctx.clock, &ctx.audit, &ctx.rpc, request)
        .await?;
    Ok(ProvedDeposit {
        proof: prover().prove(&built.request)?,
        payload: built.payload,
        note: built.note,
        output_index: built.output_index,
    })
}

pub async fn prove_transfer(
    subject: &mut TestWallet,
    ctx: &Ctx,
    request: TransferRequest,
) -> Result<ProvedTransfer, shielded_pool_compliance::wallet::Error> {
    let built = subject
        .wallet
        .build_transfer(&ctx.rpc, &ctx.clock, &ctx.audit, &ctx.rpc, request)
        .await?;
    Ok(ProvedTransfer {
        proof: prover().prove(&built.request)?,
        payload: built.payload,
        outputs: built.outputs,
        output_indices: built.output_indices,
    })
}

pub async fn prove_withdraw(
    subject: &mut TestWallet,
    ctx: &Ctx,
    request: WithdrawRequest,
) -> Result<ProvedWithdraw, shielded_pool_compliance::wallet::Error> {
    let built = subject
        .wallet
        .build_withdraw(&ctx.rpc, &ctx.clock, &ctx.audit, &ctx.rpc, request)
        .await?;
    Ok(ProvedWithdraw {
        proof: prover().prove(&built.request)?,
        payload: built.payload,
    })
}

pub async fn prove_withdraw_blocked(
    subject: &TestWallet,
    ctx: &Ctx,
    request: WithdrawRequest,
) -> Result<CircuitProof, shielded_pool_compliance::wallet::Error> {
    let built = subject
        .wallet
        .build_withdraw_blocked(&ctx.rpc, request)
        .await?;
    Ok(prover().prove(&built.request)?)
}

/// The leaves a deposit inserts, in the order `ShieldedPool.deposit` inserts them.
pub fn deposit_leaves(proof: &CircuitProof) -> [Bytes32; 2] {
    [
        proof.public_inputs[deposit_idx::COMMITMENT],
        proof.public_inputs[deposit_idx::COMPLIANCE_COMMITMENT_OUT],
    ]
}

pub fn transfer_leaves(proof: &CircuitProof) -> [Bytes32; 3] {
    [
        proof.public_inputs[transfer_idx::COMMITMENT_OUT_0],
        proof.public_inputs[transfer_idx::COMMITMENT_OUT_1],
        proof.public_inputs[transfer_idx::COMPLIANCE_COMMITMENT_OUT],
    ]
}

pub fn withdraw_leaves(proof: &CircuitProof) -> [Bytes32; 1] {
    [proof.public_inputs[withdraw_idx::COMPLIANCE_COMMITMENT_OUT]]
}

/// Every `0x01` value-note element in `payload` that `wallet`'s own `viewing_key`
/// decrypts, in payload order. The practical way a recipient recovers a note it was
/// never handed directly: scan the payload, keep whatever your own key opens.
pub fn owned_value_notes(
    wallet: &Wallet<CommitmentTree, AttestationTree>,
    payload: &Payload,
) -> Vec<Note> {
    payload
        .elements()
        .iter()
        .filter_map(|element| wallet.accept_value_note(element).ok())
        .collect()
}

pub fn deposit_params(proved: &ProvedDeposit) -> IShieldedPool::DepositParams {
    let pi = &proved.proof.public_inputs;
    IShieldedPool::DepositParams {
        proof: AlloyBytes::from(proved.proof.proof.clone()),
        commitment: b256(pi[deposit_idx::COMMITMENT]),
        token: u256(pi[deposit_idx::TOKEN]),
        amount: u256(pi[deposit_idx::AMOUNT]),
        attestationRoot: b256(pi[deposit_idx::ATTESTATION_ROOT]),
        velocityNullifier: b256(pi[deposit_idx::VELOCITY_NULLIFIER]),
        complianceCommitmentOut: b256(pi[deposit_idx::COMPLIANCE_COMMITMENT_OUT]),
        epoch: u256(pi[deposit_idx::EPOCH]),
        epochSeconds: u256(pi[deposit_idx::EPOCH_SECONDS]),
        policySourceHash: b256(pi[deposit_idx::POLICY_SOURCE_HASH]),
        commitmentRoot: b256(pi[deposit_idx::COMMITMENT_ROOT]),
        attesterRevocationRoot: b256(pi[deposit_idx::ATTESTER_REVOCATION_ROOT]),
        minAcceptedGeneration: u256(pi[deposit_idx::MIN_ACCEPTED_GENERATION]),
        payloadCommitment: b256(pi[deposit_idx::PAYLOAD_COMMITMENT]),
        encryptedNotes: AlloyBytes::from(proved.payload.encode()),
    }
}

pub async fn submit_deposit(
    harness: &AnvilHarness,
    deployment: &Deployment,
    proved: &ProvedDeposit,
) -> Result<TransactionReceipt, alloy::contract::Error> {
    let params = deposit_params(proved);
    let receipt = {
        let pool = pool_of(harness, deployment);
        send_pool_call(pool.deposit(params)).await
    };
    harness.sync_clock().await;
    receipt
}

pub async fn submit_transfer(
    harness: &AnvilHarness,
    deployment: &Deployment,
    proved: &ProvedTransfer,
) -> Result<TransactionReceipt, alloy::contract::Error> {
    submit_transfer_with_encrypted_notes(
        harness,
        deployment,
        proved,
        proved.payload.encode(),
    )
    .await
}

/// Submits a transfer with `encrypted_notes` substituted for whatever the proof
/// actually committed to, every other public input left alone. `payloadCommitment`
/// is bound to the honest payload, so a swapped `encryptedNotes` blob must fail the
/// contract's own recomputation even though the proof and the rest of the calldata
/// are unchanged.
pub async fn submit_transfer_with_encrypted_notes(
    harness: &AnvilHarness,
    deployment: &Deployment,
    proved: &ProvedTransfer,
    encrypted_notes: Vec<u8>,
) -> Result<TransactionReceipt, alloy::contract::Error> {
    let pi = &proved.proof.public_inputs;
    let params = IShieldedPool::TransferParams {
        proof: AlloyBytes::from(proved.proof.proof.clone()),
        nullifier0: b256(pi[transfer_idx::NULLIFIER_0]),
        nullifier1: b256(pi[transfer_idx::NULLIFIER_1]),
        commitmentOut0: b256(pi[transfer_idx::COMMITMENT_OUT_0]),
        commitmentOut1: b256(pi[transfer_idx::COMMITMENT_OUT_1]),
        commitmentRoot: b256(pi[transfer_idx::COMMITMENT_ROOT]),
        velocityNullifier: b256(pi[transfer_idx::VELOCITY_NULLIFIER]),
        complianceCommitmentOut: b256(pi[transfer_idx::COMPLIANCE_COMMITMENT_OUT]),
        epoch: u256(pi[transfer_idx::EPOCH]),
        epochSeconds: u256(pi[transfer_idx::EPOCH_SECONDS]),
        policySourceHash: b256(pi[transfer_idx::POLICY_SOURCE_HASH]),
        attestationRoot: b256(pi[transfer_idx::ATTESTATION_ROOT]),
        attesterRevocationRoot: b256(pi[transfer_idx::ATTESTER_REVOCATION_ROOT]),
        minAcceptedGeneration: u256(pi[transfer_idx::MIN_ACCEPTED_GENERATION]),
        payloadCommitment: b256(pi[transfer_idx::PAYLOAD_COMMITMENT]),
        encryptedNotes: AlloyBytes::from(encrypted_notes),
    };
    let receipt = {
        let pool = pool_of(harness, deployment);
        send_pool_call(pool.transfer(params)).await
    };
    harness.sync_clock().await;
    receipt
}

pub async fn submit_withdraw(
    harness: &AnvilHarness,
    deployment: &Deployment,
    proved: &ProvedWithdraw,
) -> Result<TransactionReceipt, alloy::contract::Error> {
    let pi = &proved.proof.public_inputs;
    let params = IShieldedPool::WithdrawParams {
        proof: AlloyBytes::from(proved.proof.proof.clone()),
        nullifier: b256(pi[withdraw_idx::NULLIFIER]),
        token: u256(pi[withdraw_idx::TOKEN]),
        amount: u256(pi[withdraw_idx::AMOUNT]),
        recipient: address_input(pi[withdraw_idx::RECIPIENT]),
        commitmentRoot: b256(pi[withdraw_idx::COMMITMENT_ROOT]),
        velocityNullifier: b256(pi[withdraw_idx::VELOCITY_NULLIFIER]),
        complianceCommitmentOut: b256(pi[withdraw_idx::COMPLIANCE_COMMITMENT_OUT]),
        epoch: u256(pi[withdraw_idx::EPOCH]),
        epochSeconds: u256(pi[withdraw_idx::EPOCH_SECONDS]),
        policySourceHash: b256(pi[withdraw_idx::POLICY_SOURCE_HASH]),
        attestationRoot: b256(pi[withdraw_idx::ATTESTATION_ROOT]),
        attesterRevocationRoot: b256(pi[withdraw_idx::ATTESTER_REVOCATION_ROOT]),
        minAcceptedGeneration: u256(pi[withdraw_idx::MIN_ACCEPTED_GENERATION]),
        payloadCommitment: b256(pi[withdraw_idx::PAYLOAD_COMMITMENT]),
        encryptedNotes: AlloyBytes::from(proved.payload.encode()),
    };
    let receipt = {
        let pool = pool_of(harness, deployment);
        send_pool_call(pool.withdraw(params)).await
    };
    harness.sync_clock().await;
    receipt
}

pub async fn submit_withdraw_blocked(
    harness: &AnvilHarness,
    deployment: &Deployment,
    proof: &CircuitProof,
) -> Result<TransactionReceipt, alloy::contract::Error> {
    let pi = &proof.public_inputs;
    let params = IShieldedPool::WithdrawBlockedParams {
        proof: AlloyBytes::from(proof.proof.clone()),
        nullifier: b256(pi[ungated_idx::NULLIFIER]),
        token: u256(pi[ungated_idx::TOKEN]),
        amount: u256(pi[ungated_idx::AMOUNT]),
        recipient: address_input(pi[ungated_idx::RECIPIENT]),
        commitmentRoot: b256(pi[ungated_idx::COMMITMENT_ROOT]),
    };
    let receipt = {
        let pool = pool_of(harness, deployment);
        send_pool_call(pool.withdrawBlocked(params)).await
    };
    harness.sync_clock().await;
    receipt
}

/// `claimBlocked` only ever pays `blockedFundsAccount`, and only that account may call
/// it, so this submits from that account rather than the deployer.
pub async fn claim_blocked(
    harness: &AnvilHarness,
    deployment: &Deployment,
    nullifier: Bytes32,
) -> Result<TransactionReceipt, alloy::contract::Error> {
    claim_blocked_from(harness, deployment, BLOCKED_FUNDS, nullifier).await
}

pub async fn claim_blocked_from(
    harness: &AnvilHarness,
    deployment: &Deployment,
    caller: usize,
    nullifier: Bytes32,
) -> Result<TransactionReceipt, alloy::contract::Error> {
    let provider = harness.provider(caller);
    let pending = IShieldedPool::new(deployment.pool, &provider)
        .claimBlocked(b256(nullifier))
        .send()
        .await?;
    let receipt = pending.get_receipt().await.expect("claimBlocked receipt");
    harness.sync_clock().await;
    Ok(receipt)
}

fn pool_of(
    harness: &AnvilHarness,
    deployment: &Deployment,
) -> IShieldedPool::IShieldedPoolInstance<DynProvider> {
    IShieldedPool::new(deployment.pool, harness.provider(DEPLOYER))
}

/// Gas estimation runs before the transaction is sent, so a reverting entry point
/// surfaces its custom error here rather than as a failed receipt with no reason.
async fn send_pool_call<P: Provider + Clone, D: alloy::contract::CallDecoder>(
    call: alloy::contract::CallBuilder<P, D>,
) -> Result<TransactionReceipt, alloy::contract::Error> {
    let pending = call.send().await?;
    Ok(pending.get_receipt().await.expect("pool receipt"))
}

/// Every `encryptedNotes` blob the pool has emitted, in chain order, flattened into the
/// payload elements the auditor consumes.
pub async fn observed_payload_elements(
    harness: &AnvilHarness,
    deployment: &Deployment,
) -> Vec<PayloadElement> {
    let provider = harness.provider(DEPLOYER);
    let pool = IShieldedPool::new(deployment.pool, &provider);

    let mut blobs: Vec<((u64, u64), AlloyBytes)> = Vec::new();
    for (event, log) in pool
        .event_filter::<IShieldedPool::Deposit>()
        .from_block(0u64)
        .query()
        .await
        .expect("Deposit query")
    {
        blobs.push((log_key(&log), event.encryptedNotes));
    }
    for (event, log) in pool
        .event_filter::<IShieldedPool::Transfer>()
        .from_block(0u64)
        .query()
        .await
        .expect("Transfer query")
    {
        blobs.push((log_key(&log), event.encryptedNotes));
    }
    for (event, log) in pool
        .event_filter::<IShieldedPool::Withdraw>()
        .from_block(0u64)
        .query()
        .await
        .expect("Withdraw query")
    {
        blobs.push((log_key(&log), event.encryptedNotes));
    }
    blobs.sort_by_key(|(key, _)| *key);

    blobs
        .into_iter()
        .flat_map(|(_, bytes)| {
            Payload::decode(&bytes)
                .expect("pool emitted a well-formed payload")
                .elements()
                .to_vec()
        })
        .collect()
}

/// Every compliance commitment the pool has recorded, read back from its events rather
/// than from the wallet that produced it.
pub async fn observed_compliance_commitments(
    harness: &AnvilHarness,
    deployment: &Deployment,
) -> Vec<Bytes32> {
    let provider = harness.provider(DEPLOYER);
    let pool = IShieldedPool::new(deployment.pool, &provider);

    let mut out: Vec<((u64, u64), Bytes32)> = Vec::new();
    for (event, log) in pool
        .event_filter::<IShieldedPool::Deposit>()
        .from_block(0u64)
        .query()
        .await
        .expect("Deposit query")
    {
        out.push((log_key(&log), Bytes32::from(event.complianceCommitment.0)));
    }
    for (event, log) in pool
        .event_filter::<IShieldedPool::Transfer>()
        .from_block(0u64)
        .query()
        .await
        .expect("Transfer query")
    {
        out.push((log_key(&log), Bytes32::from(event.complianceCommitment.0)));
    }
    for (event, log) in pool
        .event_filter::<IShieldedPool::Withdraw>()
        .from_block(0u64)
        .query()
        .await
        .expect("Withdraw query")
    {
        out.push((log_key(&log), Bytes32::from(event.complianceCommitment.0)));
    }
    out.sort_by_key(|(key, _)| *key);
    out.into_iter().map(|(_, commitment)| commitment).collect()
}

#[track_caller]
pub fn assert_reverts_with<E: SolError>(error: &alloy::contract::Error) {
    assert!(
        error.as_decoded_error::<E>().is_some(),
        "expected revert {}, got: {error}",
        E::SIGNATURE
    );
}

/// The first epoch of a fresh attestation period at or after the host clock, so the
/// cohort issued in it covers exactly `MAX_ATTESTATION_EPOCHS` epochs and the rollover
/// test can name the lapse epoch without guessing.
pub fn base_epoch() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after the unix epoch")
        .as_secs();
    let epoch = now / shielded_pool_compliance::EPOCH_SECONDS;
    let period = epoch / shielded_pool_compliance::MAX_ATTESTATION_EPOCHS;
    (period + 1) * shielded_pool_compliance::MAX_ATTESTATION_EPOCHS
}

pub fn to_crate_address(address: AlloyAddress) -> Address {
    Address::from(address.into_array())
}

pub fn b256(value: Bytes32) -> B256 {
    B256::from_slice(value.as_ref())
}

pub fn u256(value: Bytes32) -> U256 {
    U256::from_be_slice(value.as_ref())
}

fn address_input(value: Bytes32) -> AlloyAddress {
    let raw = value.as_ref();
    assert!(
        raw[..12].iter().all(|byte| *byte == 0),
        "address-typed public input exceeds 160 bits: {value}"
    );
    AlloyAddress::from_slice(&raw[12..])
}

/// A cohort of `size` subjects with `members` among them. The cohort is the anonymity
/// set, so padding it out to the registry's minimum with unrelated keys is the faithful
/// shape rather than a formality.
pub fn cohort_with(members: &[OwnerPubkey], size: usize) -> Vec<OwnerPubkey> {
    let mut subjects: Vec<OwnerPubkey> = members.to_vec();
    while subjects.len() < size {
        subjects.push(SpendingKey::random().derive_owner_pubkey());
    }
    subjects
}

/// A node, a deployment into it, and the off-chain wiring every scenario needs.
pub struct Stage {
    pub harness: AnvilHarness,
    pub deployment: Deployment,
    pub ctx: Ctx,
    pub audit_key: AuditViewingKey,
}

impl Stage {
    pub async fn open(epoch: u64) -> Self {
        let harness = AnvilHarness::start();
        harness.warp_to_epoch(epoch).await;
        let deployment = harness.deploy_all();
        harness.sync_clock().await;

        let audit_key = AuditViewingKey::random();
        let ctx = Ctx::new(&harness, &deployment, audit_key.public_key()).await;
        Self {
            harness,
            deployment,
            ctx,
            audit_key,
        }
    }

    pub fn epoch(&self) -> Epoch {
        self.harness.current_epoch()
    }

    pub fn token(&self) -> Address {
        to_crate_address(self.deployment.token)
    }
}

/// Issues one cohort covering `wallets`, padded to the registry's own minimum, and
/// mirrors every issued leaf into each wallet's attestation tree in registry order.
pub async fn enroll(stage: &Stage, wallets: &[&TestWallet]) -> Cohort {
    let minimum = min_cohort_size(&stage.harness, &stage.deployment).await;
    let members: Vec<OwnerPubkey> = wallets.iter().map(|w| w.owner).collect();
    let subjects = cohort_with(&members, minimum.0 as usize);
    let cohort =
        issue_cohort(&stage.harness, &stage.deployment, subjects, Generation(1)).await;

    let leaves = attestation_leaves(&stage.harness, &stage.deployment).await;
    for wallet in wallets {
        wallet.observe_attestations(&leaves);
    }
    cohort
}

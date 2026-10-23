//! Shared end-to-end harness. Each test spawns its own anvil node, deploys the
//! stack with `forge script`, and drives the transfer agent and the investors'
//! wallets against it. `SN_USE_MOCK_PROOFS=1` swaps the in-process prover for
//! `MockProver` and deploys accepting verifiers, so the flows run in seconds;
//! without it every operation carries a real UltraHonk proof, checked by the
//! generated verifiers.

#![allow(dead_code)]

use std::{
    io::Read,
    path::PathBuf,
    process::{
        Command,
        Output as ProcessOutput,
        Stdio,
    },
    sync::{
        Arc,
        Mutex,
        OnceLock,
    },
    time::{
        Duration,
        Instant,
    },
};

use alloy::{
    network::EthereumWallet,
    primitives::{
        Address as AlloyAddress,
        U256,
    },
    providers::{
        DynProvider,
        Provider,
        ProviderBuilder,
    },
    rpc::types::TransactionReceipt,
    signers::local::PrivateKeySigner,
};
use ark_bn254::Fr;
use shielded_notes::{
    adapters::bb_prover::BbProver,
    agent::{
        HandOutOrder,
        HandOutSource,
        TransferAgent,
    },
    chain::{
        self,
        Deployment,
        IFundToken,
        PoolEnv,
        to_address,
    },
    client::{
        self,
        Client,
    },
    domain::{
        keys::{
            OwnerKeys,
            PlanSigner,
            SpendKey,
            ViewingPubkey,
        },
        witness::{
            DepositWitness,
            WithdrawWitness,
        },
    },
    error::ClientError,
    ports::prover::Prover,
    types::Address,
    wallet::{
        BuiltTransfer,
        Wallet,
    },
};

/// Anvil's default prefunded accounts: 0 is the deployer, the token issuer and
/// the transfer agent's address; 1 is the relayer; 2 and 3 are public holders.
pub const ANVIL_KEYS: [&str; 4] = [
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
];
pub const AGENT: usize = 0;
pub const RELAYER: usize = 1;
pub const HOLDER: usize = 2;
pub const OTHER_HOLDER: usize = 3;

/// Shares and units have 6 decimals: one share is 1_000_000.
pub const SHARE: u64 = 1_000_000;

/// One basis point as a reinvestment rate: `MockFundToken.reinvest` counts 1e18
/// as 100%.
pub const BASIS_POINT: u64 = 100_000_000_000_000;

pub fn use_mock_proofs() -> bool {
    matches!(
        std::env::var("SN_USE_MOCK_PROOFS").as_deref(),
        Ok("1") | Ok("true")
    )
}

/// One prover per test process: `BbProver` sets up the Barretenberg backend and
/// its reference string once, and caches each circuit's verification key.
pub fn prover() -> Arc<dyn Prover> {
    static PROVER: OnceLock<Arc<dyn Prover>> = OnceLock::new();
    PROVER
        .get_or_init(|| {
            if use_mock_proofs() {
                #[cfg(feature = "test-mocks")]
                return Arc::new(shielded_notes::adapters::mock_prover::MockProver);
                #[cfg(not(feature = "test-mocks"))]
                panic!("SN_USE_MOCK_PROOFS needs --features test-mocks");
            }
            let nargo = std::env::var("NARGO_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| {
                    PathBuf::from(std::env::var("HOME").unwrap()).join(".nargo/bin/nargo")
                });
            Arc::new(
                BbProver::new(nargo, project_root())
                    .expect("start the barretenberg backend"),
            )
        })
        .clone()
}

/// `forge` shares `contracts/out` and `contracts/cache` across invocations.
static FORGE: Mutex<()> = Mutex::new(());

pub fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

pub struct Harness {
    _anvil: alloy::node_bindings::AnvilInstance,
    pub endpoint: String,
    providers: Vec<DynProvider>,
    accounts: Vec<AlloyAddress>,
    pub deployment: Deployment,
}

impl Harness {
    /// Spawns anvil and deploys the stack for `agent`: its claim key hash and
    /// register key go into the pool, and account 0 becomes the agent's address.
    /// The pool is exempt from the token's administrative powers.
    pub fn start(agent: &TransferAgent) -> Self {
        Self::start_with(agent, true)
    }

    /// As `start`; `pool_admin_exempt = false` models the policy fallback, where
    /// the issuer keeps its administrative powers over the pool.
    pub fn start_with(agent: &TransferAgent, pool_admin_exempt: bool) -> Self {
        let anvil = alloy::node_bindings::Anvil::new().chain_id(31337).spawn();
        let mut providers = Vec::new();
        let mut accounts = Vec::new();
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
        let endpoint = anvil.endpoint();
        let deployment = deploy(&endpoint, accounts[AGENT], agent, pool_admin_exempt);
        Self {
            _anvil: anvil,
            endpoint,
            providers,
            accounts,
            deployment,
        }
    }

    pub fn provider(&self, i: usize) -> DynProvider {
        self.providers[i].clone()
    }

    pub fn account(&self, i: usize) -> AlloyAddress {
        self.accounts[i]
    }

    pub fn client(&self, i: usize) -> Client {
        Client {
            provider: self.provider(i),
            deployment: self.deployment,
        }
    }

    pub fn token(&self, i: usize) -> IFundToken::IFundTokenInstance<DynProvider> {
        IFundToken::new(self.deployment.token, self.provider(i))
    }

    pub async fn balance(&self, who: AlloyAddress) -> u128 {
        self.token(AGENT)
            .balanceOf(who)
            .call()
            .await
            .expect("balanceOf")
            .to::<u128>()
    }

    pub async fn mine(&self) {
        let _: serde_json::Value = self
            .provider(AGENT)
            .raw_request("evm_mine".into(), ())
            .await
            .expect("evm_mine");
    }

    /// Moves the chain's clock `epochs` days ahead and mines a block there.
    pub async fn advance_epochs(&self, epochs: u64) {
        let _: serde_json::Value = self
            .provider(AGENT)
            .raw_request(
                "evm_increaseTime".into(),
                (epochs * shielded_notes::EPOCH_SECONDS,),
            )
            .await
            .expect("evm_increaseTime");
        self.mine().await;
    }
}

fn deploy(
    endpoint: &str,
    agent_address: AlloyAddress,
    agent: &TransferAgent,
    pool_admin_exempt: bool,
) -> Deployment {
    let _guard = FORGE.lock().unwrap_or_else(|p| p.into_inner());
    let root = project_root();
    let deployments = root.join("deployments.toml");
    let original = std::fs::read_to_string(&deployments).expect("read deployments.toml");
    let tpk = agent.register_public_key();
    let zero = AlloyAddress::ZERO.to_string();
    let agent_hex = agent_address.to_string();
    let mut command = Command::new("forge");
    command
        .args([
            "script",
            "contracts/script/DeployLocal.s.sol:DeployLocal",
            "--rpc-url",
            endpoint,
            "--private-key",
            ANVIL_KEYS[AGENT],
            "--broadcast",
            // One transaction at a time: anvil can leave a burst's later
            // transactions queued behind one it was mining, for good.
            "--slow",
        ])
        .env("FOUNDRY_PROFILE", "deploy")
        .env(
            "USE_MOCK_VERIFIER",
            if use_mock_proofs() { "true" } else { "false" },
        )
        .env(
            "POOL_ADMIN_EXEMPT",
            if pool_admin_exempt { "true" } else { "false" },
        )
        .env("TOKEN", &zero)
        .env("TIMELOCK_CONTROLLER", &agent_hex)
        .env("GUARDIAN", &agent_hex)
        .env("TRANSFER_AGENT", &agent_hex)
        .env(
            "CLAIM_KEY_HASH",
            chain::b256(agent.claim_key_hash()).to_string(),
        )
        .env("REGISTER_KEY_X", chain::u256(tpk.x).to_string())
        .env("REGISTER_KEY_Y", chain::u256(tpk.y).to_string())
        .env("DEPOSIT_VERIFIER_ADDRESS", &zero)
        .env("TRANSFER_VERIFIER_ADDRESS", &zero)
        .env("WITHDRAW_VERIFIER_ADDRESS", &zero)
        .current_dir(&root);
    let output = output_within(command, Duration::from_secs(600));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "forge script failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(&deployments).expect("read deployments.toml"),
        original,
        "the deploy writes nothing back to deployments.toml"
    );
    let blob = format!("{stdout}\n{stderr}");
    Deployment {
        pool: parse_addr(&blob, "ShieldedPool:"),
        registry: parse_addr(&blob, "AttestationRegistry:"),
        token: parse_addr(&blob, "MockFundToken:"),
        chain_id: 31337,
    }
}

/// Runs `command` to the end, or kills it after `limit` and fails: under heavy
/// load a `forge script` can wait without end on transactions anvil keeps
/// queued (the deploy's `--slow` avoids the one case seen), and a test should
/// fail rather than hang.
fn output_within(mut command: Command, limit: Duration) -> ProcessOutput {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("forge on PATH");
    let drain = |mut pipe: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            pipe.read_to_end(&mut bytes).expect("read forge's output");
            bytes
        })
    };
    let stdout = drain(Box::new(child.stdout.take().expect("piped stdout")));
    let stderr = drain(Box::new(child.stderr.take().expect("piped stderr")));
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait for forge") {
            break status;
        }
        if start.elapsed() > limit {
            child.kill().expect("kill forge");
            panic!("forge script did not finish within {limit:?}");
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    ProcessOutput {
        status,
        stdout: stdout.join().expect("stdout reader"),
        stderr: stderr.join().expect("stderr reader"),
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

// ========== Proving and submitting ==========

// The owner of an operation proves it with its own prover and hands the
// submitting account only the `Submission`; the witness never reaches it.

pub async fn relay_transfer(
    relayer: &Client,
    built: &BuiltTransfer,
) -> Result<TransactionReceipt, ClientError> {
    let submission = client::prove_transfer(&prover(), built).await?;
    Ok(relayer.submit(&submission).await?)
}

pub async fn relay_withdraw(
    relayer: &Client,
    witness: &WithdrawWitness,
) -> Result<TransactionReceipt, ClientError> {
    let submission = client::prove_withdraw(&prover(), witness).await?;
    Ok(relayer.submit(&submission).await?)
}

/// A deposit is sent by its funding address, which pays the shares.
pub async fn submit_deposit(
    funder: &Client,
    witness: &DepositWitness,
    payload: &[u8],
) -> Result<TransactionReceipt, ClientError> {
    let submission = client::prove_deposit(&prover(), witness, payload).await?;
    Ok(funder.submit(&submission).await?)
}

// ========== Flows shared by the scenarios ==========

/// An investor: its pseudonymous ID and jurisdiction, its custody signer,
/// which alone holds `sk`, and its wallet.
pub struct Investor {
    pub id: String,
    pub jurisdiction: String,
    pub signer: SpendKey,
    pub wallet: Wallet,
}

impl Investor {
    pub fn new(id: &str) -> Self {
        let (signer, keys) = OwnerKeys::random().split();
        Self {
            id: id.to_string(),
            jurisdiction: "J1".to_string(),
            signer,
            wallet: Wallet::new(keys),
        }
    }

    /// Verification and a signed registration (SPEC, Onboarding, steps 1
    /// and 2): the investor sends `pk`, `nk` and `vpk`, its custody signer
    /// having signed them with `nk`'s hash in place of `nk`; `sk` and `vk`
    /// stay with it.
    pub fn register_with(&self, agent: &mut TransferAgent, env: &PoolEnv) -> Fr {
        // All off-chain; `onboard_and_attest` attests the owner value afterwards.
        // The agent's KYC (step 1). The harness only records the investor's
        // jurisdiction under its pseudonymous ID: the agent refuses a
        // registration from an ID not recorded, and the per-jurisdiction caps
        // count investors by it.
        agent
            .verify_investor(&self.id, &self.jurisdiction)
            .expect("a valid investor ID");
        // The wallet, which holds `pk`, `nk` and `vk` but not `sk`, builds the
        // registration: chain ID, pool, the investor ID the agent assigned,
        // `pk`, `nk`'s hash and `vpk`.
        let registration = self.wallet.registration(env, &self.id);
        // The custody signer rebuilds the registration's digest from its fields
        // and signs it, refusing one for any `pk` but its own. The signature shows
        // the investor controls `sk`, and binds the `nk` and `vpk` it registers,
        // for this investor ID, chain and pool only. The signer never sees `nk`.
        let signature = self
            .signer
            .sign_registration(&registration)
            .expect("a registration of its own key");
        // The wallet sends `nk` to the agent alongside. The agent checks the
        // registration and that `nk` hashes to what was signed, then computes
        // the owner value itself and records it against the investor ID (step 2).
        agent
            .onboard(
                &self.id,
                env,
                &registration,
                &signature,
                &self.wallet.keys.nk,
            )
            .expect("a registration signed for this pool")
    }

    pub fn owner(&self) -> Fr {
        self.wallet.owner()
    }

    pub fn vpk(&self) -> ViewingPubkey {
        self.wallet.vpk()
    }
}

/// The agent's registered public holders that hold shares now.
pub async fn holding_publicly(h: &Harness, agent: &TransferAgent) -> Vec<Address> {
    let mut out = Vec::new();
    for address in agent.public_holders.keys() {
        if h.balance(AlloyAddress::from_slice(address.as_ref())).await > 0 {
            out.push(*address);
        }
    }
    out
}

/// Onboarding (SPEC, Onboarding): each investor sends its keys, the agent
/// computes the owner values, and its next attestation batch attests them,
/// with whatever else is due (`attest_due`). Every investor here must fit the
/// cap. The leaf includes the block timestamp, so re-attesting an owner value
/// in a block with the same timestamp would repeat a leaf, which the tree
/// rejects.
pub async fn onboard_and_attest(
    h: &Harness,
    agent: &mut TransferAgent,
    investors: &[&Investor],
) {
    let env = h.client(AGENT).env().await.expect("read the pool");
    // `TransferAgent::onboard`, inside `register_with`, verifies each
    // registration's signature against its own `pk`, off-chain: the chain sees
    // only the attested owner value, never `pk`, `nk` or the signature. It then
    // computes the owner value from `pk` and `nk` instead of taking one from the
    // investor, so every value it attests has a `pk` the investor controls and an
    // `nk` the agent holds, which it needs to see the notes' spends. The assertion
    // checks that the agent's value matches the wallet's.
    for inv in investors {
        let owner = inv.register_with(agent, &env);
        assert_eq!(owner, inv.owner());
    }
    let over_cap = attest_due(h, agent).await;
    assert!(over_cap.is_empty(), "within the investor cap");
}

/// The agent's next attestation batch, sent (`TransferAgent::attestation_batch`):
/// every value due, the caps checked, padded, shuffled, in parts of 16 under
/// the period's expiry. Returns the owner values the caps left out.
pub async fn attest_due(h: &Harness, agent: &mut TransferAgent) -> Vec<Fr> {
    let client = h.client(AGENT);
    let env = client.env().await.expect("read the pool");
    let view = client.view().await.expect("read the chain");
    let public = holding_publicly(h, agent).await;
    let round = agent
        .attestation_batch(&view, &env, &public, 0)
        .expect("build the attestation batch");
    chain::add_attestations(&h.provider(AGENT), &h.deployment, &round.batch)
        .await
        .expect("attest");
    round.over_cap
}

/// The seed (SPEC, Deployment Parameters): before any investor's owner value
/// is attested, the agent attests its own, padded with owner values whose keys
/// it holds, deposits one share (`TransferAgent::seed_deposit`) and freezes it
/// through the claim path (`freeze_seed`). It keeps `U > 0` for good, so no
/// holder can inflate `m` by depositing, donating shares and withdrawing
/// everything.
pub async fn seed(h: &Harness, agent: &mut TransferAgent) {
    onboard_and_attest(h, agent, &[]).await;
    mint_for_deposit(h, SHARE).await;
    let client = h.client(AGENT);
    let view = client.view().await.expect("read the chain");
    let env = client.env().await.expect("read the pool");
    agent.read_feed(&view).expect("read the feed");
    let (w, payload) = agent
        .seed_deposit(&view, &env, SHARE, to_address(h.account(AGENT)))
        .expect("build the seed's deposit");
    submit_deposit(&client, &w, &payload)
        .await
        .expect("the seed's deposit");
    let relayer = h.client(RELAYER);
    let view = relayer.view().await.expect("read the chain");
    let env = relayer.env().await.expect("read the pool");
    agent.read_feed(&view).expect("read the feed");
    let built = agent
        .freeze_seed(&view, &env)
        .expect("build the seed's freeze");
    relay_transfer(&relayer, &built)
        .await
        .expect("freeze the seed");
    agent
        .read_feed(&relayer.view().await.expect("read the chain"))
        .expect("read the feed");
}

/// The issuer's side of a deposit of `units` by the agent: it allowlists the
/// agent, mints exactly the shares the deposit pulls, ceil(units * m / S) at
/// the pool's current multiplier, and the agent approves the pool.
pub async fn mint_for_deposit(h: &Harness, units: u64) {
    let token = h.token(AGENT);
    let agent_address = h.account(AGENT);
    token
        .setAllowlisted(agent_address, true)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    let m = chain::pool_totals(&h.provider(AGENT), &h.deployment)
        .await
        .expect("read the pool's totals")
        .multiplier;
    let s = U256::from(shielded_notes::S);
    let shares = (U256::from(units) * m).div_ceil(s);
    token
        .mint(agent_address, shares)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    token
        .approve(h.deployment.pool, U256::MAX)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
}

/// The day's issuance (SPEC, Subscription): the issuer mints the day's shares
/// on the public side once cash is confirmed, and the agent deposits them into
/// its own owner value, one public aggregate.
pub async fn aggregate_deposit(h: &Harness, agent: &mut TransferAgent, units: u64) {
    mint_for_deposit(h, units).await;
    let agent_address = h.account(AGENT);
    let client = h.client(AGENT);
    let view = client.view().await.expect("read the chain");
    let env = client.env().await.expect("read the pool");
    agent.read_feed(&view).expect("read the feed");
    let (w, payload) = agent
        .wallet
        .deposit(&agent.signer, &view, &env, units, to_address(agent_address))
        .expect("build deposit");
    submit_deposit(&client, &w, &payload)
        .await
        .expect("aggregate deposit");
}

/// The hand-out tree (SPEC, Subscription, step 3): each transfer spends one of
/// the agent's notes and creates two, each either an investor's note or an
/// agent note for several orders, which a later round splits again. Submitted
/// through the relayer, like any transfer.
pub async fn hand_out(
    h: &Harness,
    agent: &mut TransferAgent,
    orders: &[(&Investor, u64)],
) {
    let orders: Vec<_> = orders
        .iter()
        .map(|(inv, units)| (*inv, *units, None))
        .collect();
    hand_out_held(h, agent, &orders).await;
}

/// A hand-out where an order may carry a holding period, the epoch it ends: its
/// note is created locked, so the transfer that creates it goes through the
/// claim path (`TransferAgent::hand_out_transfer`). The tree is the agent's
/// (`TransferAgent::plan_hand_out`); this sends it, a transfer at a time.
pub async fn hand_out_held(
    h: &Harness,
    agent: &mut TransferAgent,
    orders: &[(&Investor, u64, Option<u64>)],
) {
    let orders: Vec<HandOutOrder> = orders
        .iter()
        .map(|(inv, units, hold_until)| HandOutOrder {
            owner: inv.owner(),
            vpk: inv.vpk(),
            units: *units,
            hold_until: *hold_until,
        })
        .collect();
    let total: u64 = orders.iter().map(|o| o.units).sum();
    let plan = agent.plan_hand_out(&orders);
    let relayer = h.client(RELAYER);
    let mut sent: Vec<BuiltTransfer> = Vec::with_capacity(plan.len());
    for step in plan {
        let view = relayer.view().await.expect("read the chain");
        let env = relayer.env().await.expect("read the pool");
        agent.read_feed(&view).expect("read the feed");
        let source = match step.source {
            HandOutSource::Aggregate => agent
                .wallet
                .spendable(env.epoch)
                .into_iter()
                .find(|n| n.note.units == total)
                .expect("an agent note carrying the day's total"),
            HandOutSource::Output { transfer, index } => {
                let c = sent[transfer].outputs[index].commitment();
                *agent
                    .wallet
                    .notes
                    .iter()
                    .find(|n| n.commitment == c)
                    .expect("an earlier transfer's output")
            }
        };
        let built = agent
            .hand_out_transfer(&view, &env, source, step.outputs)
            .expect("build hand-out");
        relay_transfer(&relayer, &built)
            .await
            .expect("hand-out transfer");
        sent.push(built);
    }
    agent
        .read_feed(&relayer.view().await.expect("read the chain"))
        .expect("read the feed");
}

/// The agent's register must account for every unit in the pool, and the
/// actors' local trees must match the pool's. Returns the rounding remainder,
/// which the agent reports at reconciliation; it is at least the pool-level
/// bound `B - floor(U*m/S)`, since each note rounds down on its own.
pub async fn assert_register_reconciles(h: &Harness, agent: &mut TransferAgent) -> U256 {
    let view = h.client(AGENT).view().await.expect("read the chain");
    let pool = chain::pool_totals(&h.provider(AGENT), &h.deployment)
        .await
        .expect("read the pool's totals");
    let found = agent
        .reconcile(&view, pool)
        .expect("the register accounts for U, and the notes for no more than B");
    assert!(
        found.remainder
            >= pool.balance
                - U256::from(pool.units) * pool.multiplier
                    / U256::from(shielded_notes::S),
        "the remainder is at least the pool-level bound"
    );
    let (_, _, root) = chain::pool_state(&h.provider(AGENT), &h.deployment)
        .await
        .unwrap();
    assert_eq!(
        view.commitments.root(),
        root,
        "local commitment tree matches the pool"
    );
    let attestation_root =
        chain::IAttestationRegistry::new(h.deployment.registry, h.provider(AGENT))
            .attestationRoot()
            .call()
            .await
            .expect("attestationRoot");
    assert_eq!(
        chain::b256(view.attestations.root()),
        attestation_root,
        "local attestation tree matches the registry"
    );
    found.remainder
}

/// The pool's share balance `B`, in the token's base units, and its units `U`.
pub async fn assert_pool(h: &Harness, balance: u128, units: u128) {
    let pool = chain::pool_totals(&h.provider(AGENT), &h.deployment)
        .await
        .expect("read the pool's totals");
    assert_eq!(pool.balance, U256::from(balance), "the pool's shares, B");
    assert_eq!(pool.units, units, "the pool's units, U");
}

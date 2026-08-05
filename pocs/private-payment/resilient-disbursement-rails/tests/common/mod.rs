//! Shared test harness for resilient-disbursement-rails integration tests.
//!
//! Wires the production-shaped flow end-to-end:
//!   Funder.sign_round_header / sign_roster
//!     -> RoundFactory.publishRound (funder_sig recorded on-chain)
//!     -> Companion.build_voucher (verifies funder + roster sigs, drives card)
//!     -> Relay.submit_voucher (decrypts, builds witnesses, generates proofs)
//!     -> ClaimContract.claim
//!
//! - `AnvilHarness` spins up anvil and deploys the contract stack via
//!   `forge script` (subprocess).
//! - `Deployment` carries the resolved contract addresses.
//! - `make_cohort` returns `(cards, m_pubs, pre_keys)` with auth-token
//!   verification ON (production default).
//! - `publish_round` builds + signs a header via `Funder::with_multisig`,
//!   computes the per-recipient commitments, and drives the funder multisig
//!   to call `RoundFactory.publishRound`. Returns the funder sig bytes so
//!   downstream Companion builds can verify the on-chain header.
//! - `build_claim_for_card` runs Companion + Relay end-to-end and returns
//!   the on-chain ClaimBundle.
//!
//! Real / mock proof-backend selection happens via the `RDR_USE_MOCK_PROOFS`
//! env var (see `proof_backend.rs`). The same env var controls the
//! `USE_MOCK_VERIFIER` flag passed to the deploy script so the on-chain
//! verifier matches the in-process backend.

#![allow(dead_code)]

use std::{
    path::PathBuf,
    process::Command,
    sync::Arc,
    time::{
        Duration,
        Instant,
        SystemTime,
        UNIX_EPOCH,
    },
};

use alloy::{
    eips::Encodable2718,
    network::{
        EthereumWallet,
        TransactionBuilder,
    },
    node_bindings::{
        Anvil,
        AnvilInstance,
    },
    primitives::{
        Address as AlloyAddress,
        B256,
        Bytes,
        U256,
        keccak256,
    },
    providers::{
        DynProvider,
        Provider,
        ProviderBuilder,
    },
    signers::local::PrivateKeySigner,
    sol,
};
use ark_bn254::Fr;
use ark_ff::{
    BigInteger,
    PrimeField,
};
use k256::ecdsa::SigningKey;
use rand::{
    RngExt,
    SeedableRng,
    rngs::StdRng,
};
use x25519_dalek::{
    PublicKey as X25519PublicKey,
    StaticSecret as X25519StaticSecret,
};

use resilient_disbursement_rails::{
    adapters::{
        direct_anon_transport::DirectAnonymousTransport,
        direct_submission::DirectSubmission,
        lean_imt_merkle::LeanImtMerkleStore,
        software_smartcard::SoftwareSmartcard,
    },
    clock::MockClock,
    companion::{
        Companion,
        types::{
            HeaderBundle,
            RelayDescriptor,
            RelayRoster,
        },
    },
    crypto::multisig::address_from_verifying_key,
    error::{
        CardError,
        PoolError,
    },
    funder::Funder,
    ports::{
        anon_transport::AnonymousTransport,
        merkle::MerkleStore,
        proof::ProofBackend,
        smartcard::Smartcard,
        submission::Submission,
    },
    poseidon::{
        fr_from_be_bytes,
        pack_round_id,
    },
    registry::OperatorRegistry,
    relay::{
        Relay,
        core::{
            OnChainCohort,
            OnChainPool,
        },
        types::KeyArchive,
    },
    smartcard::apdu::{
        decode_export_key_response,
        encode_export_key,
        encode_generate_key,
    },
    types::{
        Address as RdrAddress,
        Bytes32,
        ClaimWitness,
        CohortMerklePath,
        EcdsaSignature,
        PoolMerklePath,
        PoolWithdrawWitness,
        RoundHeader,
        SecpPubkey,
        SignedHeader,
        U256Be,
    },
};

pub mod proof_backend;

// alloy bindings for the deployed contracts.
sol! {
    #[sol(rpc)]
    interface IRegistry {
        function publishCohort(uint256 root, uint256 size) external;
        function currentVersion() external view returns (uint64);
        function cohortRoot(uint64 version) external view returns (uint256);
        function cohortSize(uint64 version) external view returns (uint256);
    }

    #[sol(rpc)]
    #[derive(Debug)]
    interface IRoundFactory {
        struct RoundHeader {
            uint256 roundId;
            uint64 cohortVersion;
            uint256 cohortRoot;
            uint256 perRecipientAmount;
            uint256 cohortSize;
            address token;
            uint64 closeTime;
            address claimContractAddress;
            uint256 chainId;
        }
        function publishRound(RoundHeader calldata header, uint256[] calldata commitments) external;
        event RoundPublished(
            uint256 indexed roundId,
            uint64 cohortVersion,
            uint256 cohortRoot,
            uint256 perRecipientAmount,
            uint256 cohortSize,
            address token,
            uint64 closeTime,
            address claimContractAddress,
            uint256 chainId,
            uint64 firstPoolLeafIndex,
            bytes32 hHeader
        );
    }

    #[sol(rpc)]
    interface IClaimContract {
        function claim(
            bytes calldata claimProof,
            uint256[10] calldata claimPublicInputs,
            bytes calldata poolWithdrawProof,
            uint256[5] calldata poolPublicInputs
        ) external;
        function funderUnshieldResidual(uint256 roundId) external;
        function nullifierConsumed(uint256 nullifier) external view returns (bool);
        function nullifiersConsumedCount(uint256 roundId) external view returns (uint256);
        function residualPaid(uint256 roundId) external view returns (bool);
        event Claimed(
            uint256 indexed roundId,
            uint256 indexed claimNullifier,
            address indexed destination,
            uint256 amount,
            address relaySubmitter
        );
    }

    #[sol(rpc)]
    interface IShieldedPool {
        function balance(address claimContract) external view returns (uint256);
        function spentClaimNullifiers(uint256 nullifier) external view returns (bool);
        function commitmentIndex(address claimContract, uint256 commitment) external view returns (uint256);
        function subTreeRoot(address claimContract) external view returns (uint256);
        function subTreeSize(address claimContract) external view returns (uint256);
        function isKnownRoot(address claimContract, uint256 root) external view returns (bool);
        function roundDeposit(address claimContract, uint256 roundId) external view returns (uint256);
        function roundClaimed(address claimContract, uint256 roundId) external view returns (uint256);
    }

    #[sol(rpc)]
    interface IMockERC20 {
        function mint(address to, uint256 amount) external;
        function approve(address spender, uint256 amount) external returns (bool);
        function balanceOf(address account) external view returns (uint256);
    }

    #[sol(rpc)]
    interface IMultisig {
        function propose(address target, bytes calldata data) external returns (uint256);
        function confirm(uint256 proposalId) external;
        function execute(uint256 proposalId) external;
        function proposalCount() external view returns (uint256);
    }
}

/// Anvil's default-prefunded test private keys (first 7 accounts). The
/// derived addresses are exactly what `Multisig.sol` is constructed with by
/// `Deploy.s.sol::_funderOwnersForChain()`.
pub const ANVIL_OWNER_PKS: [&str; 7] = [
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
    "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
    "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",
    "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e",
];

/// Funder multisig threshold (matches `Multisig.sol::THRESHOLD`).
pub const FUNDER_THRESHOLD: usize = 4;

/// Anvil instance with the deployer wallet wired through alloy.
pub struct AnvilHarness {
    pub anvil: AnvilInstance,
    pub endpoint: String,
    pub deployer_pk: String,
    pub deployer_addr: AlloyAddress,
    pub provider: DynProvider,
    /// Per-owner cached providers (one per anvil prefunded account).
    /// Built once and reused so the alloy nonce filler remains
    /// consistent across multiple txns from the same EOA.
    pub owners: Vec<DynProvider>,
    pub use_mock: bool,
    pub chain_id: u64,
}

impl AnvilHarness {
    /// Spawn anvil with default chain id 31337.
    pub fn start(use_mock: bool) -> Self {
        Self::start_with_chain_id(use_mock, 31337)
    }

    /// Spawn anvil with an explicit chain id (for cross-chain replay tests).
    pub fn start_with_chain_id(use_mock: bool, chain_id: u64) -> Self {
        let anvil = Anvil::new().chain_id(chain_id).spawn();
        let endpoint = anvil.endpoint();

        let deployer_pk = ANVIL_OWNER_PKS[0].to_string();
        let signer: PrivateKeySigner = deployer_pk.parse().unwrap();
        let deployer_addr = signer.address();
        let wallet = EthereumWallet::from(signer);

        let provider = ProviderBuilder::new()
            .with_simple_nonce_management()
            .wallet(wallet)
            .connect_http(anvil.endpoint_url())
            .erased();

        // Per-owner providers query nonces from chain each tx so the
        // typed-`.send()` path and `submit_claim_from_owner`'s raw-tx
        // submission stay in sync on shared EOAs.
        let owners: Vec<DynProvider> = ANVIL_OWNER_PKS
            .iter()
            .map(|pk| {
                let signer: PrivateKeySigner = pk.parse().unwrap();
                let wallet = EthereumWallet::from(signer);
                ProviderBuilder::new()
                    .with_simple_nonce_management()
                    .wallet(wallet)
                    .connect_http(anvil.endpoint_url())
                    .erased()
            })
            .collect();

        Self {
            anvil,
            endpoint,
            deployer_pk,
            deployer_addr,
            provider,
            owners,
            use_mock,
            chain_id,
        }
    }

    /// Get a provider for one of the seven anvil owner accounts.
    pub fn owner_provider(&self, idx: usize) -> DynProvider {
        self.owners[idx].clone()
    }

    /// Run `forge script Deploy.s.sol --broadcast` and parse the resulting
    /// addresses out of the script's stdout. The script also writes
    /// addresses back into `deployments.toml`; we restore the original file
    /// after running so we don't perturb the developer's working copy.
    pub fn deploy_all(&self) -> Deployment {
        let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let deployments_path = project_root.join("deployments.toml");
        let original =
            std::fs::read_to_string(&deployments_path).expect("read deployments.toml");

        let use_mock = if self.use_mock { "true" } else { "false" };

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
            // Config-resolved env vars: deployer is governance for tests.
            .env("USE_MOCK_VERIFIER", use_mock)
            .env("GOVERNANCE", self.deployer_addr.to_string())
            .env("OPERATOR_KEY", self.deployer_addr.to_string())
            .env(
                "FUNDER_RESIDUAL_DESTINATION",
                self.deployer_addr.to_string(),
            )
            // Stub-out unused chains so Config's eager env resolution doesn't
            // error.
            .env("SEPOLIA_RPC_URL", "http://localhost:8545")
            .env("CLAIM_VERIFIER_ADDRESS", AlloyAddress::ZERO.to_string())
            .env(
                "WITHDRAW_VERIFIER_ADDRESS",
                AlloyAddress::ZERO.to_string(),
            )
            .current_dir(&project_root)
            .output()
            .expect("spawn forge script");

        // Always restore the file before unwrapping the result.
        std::fs::write(&deployments_path, &original).expect("restore deployments.toml");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !output.status.success() {
            panic!("forge script failed:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}");
        }

        let blob = format!("{stdout}\n{stderr}");

        Deployment {
            mock_token: parse_addr(&blob, "MockERC20:"),
            multisig: parse_addr(&blob, "Multisig (funder):"),
            composite_verifier: parse_addr(&blob, "CompositeVerifier:"),
            registry: parse_addr(&blob, "Registry:"),
            claim_contract: parse_addr(&blob, "ClaimContract:"),
            pool: parse_addr(&blob, "ShieldedPool:"),
            factory: parse_addr(&blob, "RoundFactory:"),
        }
    }
}

fn parse_addr(blob: &str, label: &str) -> AlloyAddress {
    for line in blob.lines() {
        if let Some(rest) = line.trim().strip_prefix(label) {
            if let Ok(a) = rest.trim().parse::<AlloyAddress>() {
                return a;
            }
        }
    }
    panic!("Could not parse address `{label}` from forge output:\n{blob}");
}

/// Resolved on-chain addresses.
#[derive(Debug, Clone, Copy)]
pub struct Deployment {
    pub registry: AlloyAddress,
    pub multisig: AlloyAddress,
    pub composite_verifier: AlloyAddress,
    pub pool: AlloyAddress,
    pub claim_contract: AlloyAddress,
    pub factory: AlloyAddress,
    pub mock_token: AlloyAddress,
}

/// Generate `n` `SoftwareSmartcard` instances with auth-token verification
/// ENABLED (production default) and a deterministic per-card pre-key.
/// Returns `(cards, m_pubs, pre_keys)` in cohort-position order.
pub fn make_cohort(n: usize) -> (Vec<SoftwareSmartcard>, Vec<SecpPubkey>, Vec<Bytes32>) {
    let mut cards = Vec::with_capacity(n);
    let mut m_pubs = Vec::with_capacity(n);
    let mut pre_keys = Vec::with_capacity(n);
    for i in 0..n {
        // Deterministic pre-key per card: zero-padded big-endian u64 in the
        // low 8 bytes. Reproducible across runs.
        let mut pk = [0u8; 32];
        pk[24..].copy_from_slice(&(i as u64).to_be_bytes());
        let mut card = SoftwareSmartcard::new(Some(pk), true);
        card.transmit(&encode_generate_key()).unwrap();
        let m = decode_export_key_response(&card.transmit(&encode_export_key()).unwrap())
            .unwrap();
        cards.push(card);
        m_pubs.push(m);
        pre_keys.push(pk);
    }
    (cards, m_pubs, pre_keys)
}

/// Off-chain side: enroll all `m_pubs` into a fresh OperatorRegistry, build
/// the cohort tree, return `(reg, cohort_root_be, cohort_root_fr)`.
pub fn build_cohort_tree(
    m_pubs: &[SecpPubkey],
) -> (OperatorRegistry<LeanImtMerkleStore>, Bytes32, Fr) {
    let mut reg = OperatorRegistry::new(LeanImtMerkleStore::new());
    for (i, m) in m_pubs.iter().enumerate() {
        let mut id = [0u8; 32];
        id[24..32].copy_from_slice(&(i as u64).to_be_bytes());
        reg.enroll(id, *m).unwrap();
    }
    reg.rebuild_tree();
    let root_fr = reg.tree.root().expect("cohort root");
    let root_be = fr_to_be_bytes(&root_fr);
    (reg, root_be, root_fr)
}

/// On-chain side: register the cohort with the deployed Registry contract.
pub async fn publish_cohort_on_chain(
    provider: &DynProvider,
    registry_addr: AlloyAddress,
    cohort_root_fr: Fr,
    m_pubs: &[SecpPubkey],
) -> u64 {
    let registry = IRegistry::new(registry_addr, provider);

    let root_u256 = fr_to_u256(cohort_root_fr);
    let size_u256 = U256::from(m_pubs.len() as u64);
    registry
        .publishCohort(root_u256, size_u256)
        .send()
        .await
        .expect("publishCohort send")
        .get_receipt()
        .await
        .expect("publishCohort receipt");

    registry
        .currentVersion()
        .call()
        .await
        .expect("currentVersion call")
}

/// Mint `amount` of MockERC20 to `to`.
pub async fn mint_token(
    provider: &DynProvider,
    token: AlloyAddress,
    to: AlloyAddress,
    amount: U256,
) {
    IMockERC20::new(token, provider)
        .mint(to, amount)
        .send()
        .await
        .expect("mint send")
        .get_receipt()
        .await
        .expect("mint receipt");
}

/// Approve `spender` to draw `amount` of `token` from the `provider`'s
/// signer.
pub async fn approve_token(
    provider: &DynProvider,
    token: AlloyAddress,
    spender: AlloyAddress,
    amount: U256,
) {
    IMockERC20::new(token, provider)
        .approve(spender, amount)
        .send()
        .await
        .expect("approve send")
        .get_receipt()
        .await
        .expect("approve receipt");
}

/// Build `SigningKey`s for the first `FUNDER_THRESHOLD` (= 4) anvil owners.
/// These are the four signers used to drive the funder multisig.
pub fn build_funder_multisig_signers() -> Vec<SigningKey> {
    ANVIL_OWNER_PKS
        .iter()
        .take(FUNDER_THRESHOLD)
        .map(|pk| {
            let bytes = hex::decode(&pk[2..]).expect("decode anvil pk hex");
            SigningKey::from_bytes(bytes.as_slice().into())
                .expect("anvil pk -> SigningKey")
        })
        .collect()
}

/// Derive RDR addresses from each of the seven anvil owner private keys.
/// Matches the on-chain `Multisig.sol` owner set deployed by
/// `Deploy.s.sol::_funderOwnersForChain()`.
pub fn build_funder_owners() -> Vec<RdrAddress> {
    ANVIL_OWNER_PKS
        .iter()
        .map(|pk| {
            let bytes = hex::decode(&pk[2..]).expect("decode anvil pk hex");
            let sk = SigningKey::from_bytes(bytes.as_slice().into())
                .expect("anvil pk -> SigningKey");
            address_from_verifying_key(sk.verifying_key())
        })
        .collect()
}

/// Construct a production-shaped Funder bound to the deployed Multisig
/// (4-of-7) and ClaimContract.
pub fn build_funder_with_multisig(
    deployment: &Deployment,
    harness: &AnvilHarness,
) -> Funder {
    Funder::with_multisig(
        build_funder_multisig_signers(),
        build_funder_owners(),
        FUNDER_THRESHOLD,
        address_to_rdr(deployment.multisig),
        address_to_rdr(deployment.claim_contract),
        address_to_rdr(harness.deployer_addr),
    )
    .expect("Funder::with_multisig")
}

/// Build a single-relay roster signed by the funder multisig.
pub fn build_signed_relay_roster(
    funder: &Funder,
    relay_pubkey: &X25519PublicKey,
    signed_at_unix: u64,
) -> RelayRoster {
    let mut roster = RelayRoster {
        relays: vec![RelayDescriptor {
            relay_id: [0x77; 32],
            static_pub_x25519: *relay_pubkey.as_bytes(),
            rotation_epoch: 0,
        }],
        signed_at_unix,
        signature: Vec::new(),
    };
    roster.signature = funder.sign_roster(&roster).expect("Funder::sign_roster");
    roster
}

/// Wall-clock unix-seconds. Anvil's block.timestamp tracks the host clock,
/// so harness state and tests share this notion of "now".
pub fn harness_now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_secs()
}

/// Build a round header, compute per-recipient commitments, mint and
/// approve the funder multisig to draw, then drive the multisig
/// propose/confirm/execute calling `RoundFactory.publishRound` with a real
/// 4-of-7 funder signature on `H_header`.
///
/// Returns `(header, commitments, funder_sig)`. `funder_sig` is the
/// multisig wire-format bytes that the on-chain factory recorded into the
/// `RoundPublished` event; the Companion verifies it off-chain when
/// building a voucher.
pub async fn publish_round(
    harness: &AnvilHarness,
    deployment: &Deployment,
    cohort_version: u64,
    cohort_root_be: Bytes32,
    cohort_size: u64,
    per_recipient_amount: U256Be,
    close_time: u64,
    chain_id: U256Be,
    round_id: Bytes32,
    m_pubs: &[SecpPubkey],
) -> (RoundHeader, Vec<Bytes32>, Vec<u8>) {
    let token_rdr = address_to_rdr(deployment.mock_token);
    let funder = build_funder_with_multisig(deployment, harness);

    let header = funder.build_round_header(
        round_id,
        cohort_version,
        cohort_root_be,
        per_recipient_amount,
        cohort_size,
        token_rdr,
        close_time,
        chain_id,
    );

    let commitments = funder
        .compute_round_commitments(&header, m_pubs)
        .expect("compute commitments");

    let funder_sig = funder
        .sign_round_header(&header)
        .expect("Funder::sign_round_header");

    let total = u256_be_to_alloy(&per_recipient_amount) * U256::from(cohort_size);

    // Mint to the multisig (which acts as the funder) and have the multisig
    // approve the factory.
    mint_token(
        &harness.provider,
        deployment.mock_token,
        deployment.multisig,
        total,
    )
    .await;
    multisig_call_token_approve(harness, deployment, total).await;

    publish_round_via_multisig(harness, deployment, &header, &commitments).await;

    (header, commitments, funder_sig)
}

/// 4-of-7 multisig: propose `MockERC20.approve(factory, amount)`, confirm
/// from 4 owners, execute.
async fn multisig_call_token_approve(
    harness: &AnvilHarness,
    deployment: &Deployment,
    amount: U256,
) {
    let owner0 = harness.owner_provider(0);
    let token = IMockERC20::new(deployment.mock_token, &owner0);
    let approve_calldata = token.approve(deployment.factory, amount).calldata().clone();

    multisig_propose_confirm_execute(
        harness,
        deployment.multisig,
        deployment.mock_token,
        approve_calldata,
    )
    .await;
}

/// Drive the funder multisig: propose + 4 confirmations + execute calling
/// `RoundFactory.publishRound`. The factory authorizes via
/// `msg.sender == funderMultisig`; the funder ECDSA signature on `H_header`
/// is delivered out-of-band to companion devices, not threaded through the
/// factory.
async fn publish_round_via_multisig(
    harness: &AnvilHarness,
    deployment: &Deployment,
    header: &RoundHeader,
    commitments: &[Bytes32],
) {
    let header_sol = round_header_sol(header);
    let commitments_u256: Vec<U256> =
        commitments.iter().map(|c| u256_be_from_bytes(c)).collect();

    let owner0 = harness.owner_provider(0);
    let factory = IRoundFactory::new(deployment.factory, &owner0);
    let publish_calldata = factory
        .publishRound(header_sol, commitments_u256)
        .calldata()
        .clone();

    multisig_propose_confirm_execute(
        harness,
        deployment.multisig,
        deployment.factory,
        publish_calldata,
    )
    .await;
}

/// Propose, gather 4 confirmations, then execute and return the
/// post-execute receipt without asserting status. Caller decides what to
/// do with success vs. revert. Useful for negative tests that expect
/// `Multisig.execute` to revert because the inner call reverts.
pub async fn multisig_propose_confirm_try_execute(
    harness: &AnvilHarness,
    multisig: AlloyAddress,
    target: AlloyAddress,
    calldata: Bytes,
) -> Result<alloy::rpc::types::TransactionReceipt, alloy::contract::Error> {
    let owner0 = harness.owner_provider(0);

    let proposal_id = IMultisig::new(multisig, &owner0)
        .proposalCount()
        .call()
        .await
        .expect("proposalCount call");

    let r = IMultisig::new(multisig, &owner0)
        .propose(target, calldata)
        .send()
        .await
        .expect("propose send")
        .get_receipt()
        .await
        .expect("propose receipt");
    assert!(r.status(), "Multisig.propose reverted");

    for i in 0..4 {
        let p = harness.owner_provider(i);
        let cr = IMultisig::new(multisig, &p)
            .confirm(proposal_id)
            .send()
            .await
            .expect("confirm send")
            .get_receipt()
            .await
            .expect("confirm receipt");
        assert!(cr.status(), "Multisig.confirm reverted (owner {i})");
    }

    let exec = IMultisig::new(multisig, &owner0)
        .execute(proposal_id)
        .send()
        .await?;
    Ok(exec.get_receipt().await.expect("execute receipt"))
}

/// Propose, gather 4 confirmations from owners 0..4, execute.
pub async fn multisig_propose_confirm_execute(
    harness: &AnvilHarness,
    multisig: AlloyAddress,
    target: AlloyAddress,
    calldata: Bytes,
) {
    let owner0 = harness.owner_provider(0);

    // Get the next proposal id BEFORE proposing.
    let proposal_id = IMultisig::new(multisig, &owner0)
        .proposalCount()
        .call()
        .await
        .expect("proposalCount call");

    let r = IMultisig::new(multisig, &owner0)
        .propose(target, calldata)
        .send()
        .await
        .expect("propose send")
        .get_receipt()
        .await
        .expect("propose receipt");
    assert!(r.status(), "Multisig.propose reverted");

    for i in 0..4 {
        let p = harness.owner_provider(i);
        let cr = IMultisig::new(multisig, &p)
            .confirm(proposal_id)
            .send()
            .await
            .expect("confirm send")
            .get_receipt()
            .await
            .expect("confirm receipt");
        assert!(cr.status(), "Multisig.confirm reverted (owner {i})");
    }

    let er = IMultisig::new(multisig, &owner0)
        .execute(proposal_id)
        .send()
        .await
        .expect("execute send")
        .get_receipt()
        .await
        .expect("execute receipt");
    assert!(er.status(), "Multisig.execute reverted");
}

pub fn address_to_rdr(a: AlloyAddress) -> RdrAddress {
    let mut out = [0u8; 20];
    out.copy_from_slice(a.as_slice());
    out
}

pub fn address_from_rdr(a: RdrAddress) -> AlloyAddress {
    AlloyAddress::from_slice(&a)
}

pub fn fr_to_be_bytes(fr: &Fr) -> Bytes32 {
    let bigint = fr.into_bigint();
    let le = bigint.to_bytes_le();
    let mut be = [0u8; 32];
    for i in 0..32 {
        be[i] = le[31 - i];
    }
    be
}

pub fn fr_to_u256(fr: Fr) -> U256 {
    let bigint = fr.into_bigint();
    let le = bigint.to_bytes_le();
    U256::from_le_slice(&le)
}

pub fn u256_be_to_alloy(v: &U256Be) -> U256 {
    U256::from_be_slice(v.as_bytes())
}

pub fn u256_be_from_bytes(b: &Bytes32) -> U256 {
    U256::from_be_slice(b)
}

pub fn round_header_sol(h: &RoundHeader) -> IRoundFactory::RoundHeader {
    IRoundFactory::RoundHeader {
        roundId: U256::from_be_slice(&h.round_id),
        cohortVersion: h.cohort_version,
        cohortRoot: U256::from_be_slice(&h.cohort_root),
        perRecipientAmount: U256::from_be_slice(h.per_recipient_amount.as_bytes()),
        cohortSize: U256::from(h.cohort_size),
        token: address_from_rdr(h.token),
        closeTime: h.close_time,
        claimContractAddress: address_from_rdr(h.claim_contract_address),
        chainId: U256::from_be_slice(h.chain_id.as_bytes()),
    }
}

pub fn round_id_from_u64(v: u64) -> Bytes32 {
    let mut id = [0u8; 32];
    id[24..32].copy_from_slice(&v.to_be_bytes());
    id
}

pub fn destination_from_dpk(dpk: &SecpPubkey) -> AlloyAddress {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&dpk.x);
    buf[32..].copy_from_slice(&dpk.y);
    let h: B256 = keccak256(buf);
    let mut a = [0u8; 20];
    a.copy_from_slice(&h.as_slice()[12..]);
    AlloyAddress::from_slice(&a)
}

pub fn random_round_id(seed: u64) -> Bytes32 {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut id = [0u8; 32];
    rng.fill(&mut id);
    id
}

/// Build the off-chain pool sub-tree for the given commitments (in
/// cohort-position order). Returns the populated tree.
pub fn build_pool_tree(commitments: &[Bytes32]) -> LeanImtMerkleStore {
    let mut tree = LeanImtMerkleStore::new();
    for c in commitments {
        tree.insert(fr_from_be_bytes(c));
    }
    tree
}

// -----------------------------------------------------------------------
// Companion <-> Card ownership glue.
//
// `Companion::new(card, ...)` consumes the smartcard by value because in
// production the card is opened/closed for the lifetime of a voucher build.
// In tests we want to reuse the same `SoftwareSmartcard` across multiple
// `build_voucher` calls (e.g. `double_claim_rejected` builds two bundles
// from card 0). `SoftwareSmartcard` does not derive Clone, so we wrap a
// mutable borrow in a thin newtype that itself implements `Smartcard`.
// `Companion<CardRefMut<'_>>` then owns the wrapper, and the underlying
// card is borrowed only for the duration of `build_voucher`.
// -----------------------------------------------------------------------
struct CardRefMut<'a>(&'a mut SoftwareSmartcard);

impl Smartcard for CardRefMut<'_> {
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, CardError> {
        self.0.transmit(apdu)
    }
}

/// Borrowing wrapper that lets `Relay::new` accept a shared `ProofBackend`
/// reference. `Relay` owns the prover by value but never needs to mutate
/// it, so a thin `Send + Sync` newtype delegating to the borrowed backend
/// is sufficient for tests.
struct BackendRef<'a, P: ProofBackend>(&'a P);

impl<P: ProofBackend> ProofBackend for BackendRef<'_, P> {
    fn generate_claim_proof(
        &self,
        witness: &ClaimWitness,
    ) -> Result<Vec<u8>, resilient_disbursement_rails::error::ProofError> {
        self.0.generate_claim_proof(witness)
    }
    fn generate_pool_withdraw_proof(
        &self,
        witness: &PoolWithdrawWitness,
    ) -> Result<Vec<u8>, resilient_disbursement_rails::error::ProofError> {
        self.0.generate_pool_withdraw_proof(witness)
    }
}

// -----------------------------------------------------------------------
// Snapshot adapters: trivial OnChainPool / OnChainCohort backed by
// pre-built LeanIMT trees + the pre-built commitment list. Since
// `LeanImtMerkleStore` is not `Clone`, snapshots are constructed by
// rebuilding the tree from the leaves the caller already has.
// -----------------------------------------------------------------------

/// In-memory `OnChainPool` snapshot. Mirrors the post-publishRound state
/// of the deployed `ShieldedPool` for a single claim contract.
pub struct SnapshotPool {
    commitments: Vec<Bytes32>,
    tree: LeanImtMerkleStore,
    claim_contract: RdrAddress,
}

impl SnapshotPool {
    pub fn new(commitments: Vec<Bytes32>, claim_contract: RdrAddress) -> Self {
        let tree = build_pool_tree(&commitments);
        Self {
            commitments,
            tree,
            claim_contract,
        }
    }
}

impl OnChainPool for SnapshotPool {
    fn commitment_index(
        &self,
        claim_contract: &RdrAddress,
        commitment: &Bytes32,
    ) -> Result<Option<u64>, PoolError> {
        if claim_contract != &self.claim_contract {
            return Ok(None);
        }
        Ok(self
            .commitments
            .iter()
            .position(|c| c == commitment)
            .map(|i| i as u64))
    }

    fn sub_tree_root(&self, _claim_contract: &RdrAddress) -> Result<Bytes32, PoolError> {
        let root = self
            .tree
            .root()
            .ok_or_else(|| PoolError::Rpc("empty pool tree".to_string()))?;
        Ok(fr_to_be_bytes(&root))
    }

    fn pool_merkle_path(
        &self,
        _claim_contract: &RdrAddress,
        leaf_index: u64,
    ) -> Result<PoolMerklePath, PoolError> {
        let p = self
            .tree
            .get_proof(leaf_index as usize)
            .map_err(|e| PoolError::Rpc(format!("get_proof: {e:?}")))?;
        Ok(PoolMerklePath {
            siblings: p.siblings.iter().map(fr_to_be_bytes).collect(),
            indices: p.indices.clone(),
        })
    }
}

/// In-memory `OnChainCohort` snapshot for a single registered cohort
/// version. The version parameter is ignored on lookup because tests work
/// with a single version per scenario.
pub struct SnapshotCohort {
    tree: LeanImtMerkleStore,
    cohort_root_be: Bytes32,
}

impl SnapshotCohort {
    /// Rebuild the cohort tree from `m_pubs` to mirror the
    /// `OperatorRegistry` state. `cohort_root_be` is captured separately
    /// so callers can serve the published header's root regardless of
    /// what the rebuilt tree's root computes to (they should agree, but
    /// asserting that is a registry concern, not a snapshot concern).
    pub fn new(m_pubs: &[SecpPubkey], cohort_root_be: Bytes32) -> Self {
        let (reg, _, _) = build_cohort_tree(m_pubs);
        Self {
            tree: reg.tree,
            cohort_root_be,
        }
    }

    /// Construct from raw `m_packed` field-element leaves. Used by
    /// negative tests that synthesize attacker cohorts (a single rogue
    /// `M`).
    pub fn from_m_packed(m_packed_leaves: &[Fr], cohort_root_be: Bytes32) -> Self {
        let mut tree = LeanImtMerkleStore::new();
        for leaf in m_packed_leaves {
            tree.insert(*leaf);
        }
        Self {
            tree,
            cohort_root_be,
        }
    }
}

impl OnChainCohort for SnapshotCohort {
    fn cohort_root(&self, _cohort_version: u64) -> Result<Bytes32, PoolError> {
        Ok(self.cohort_root_be)
    }

    fn cohort_merkle_path(
        &self,
        _cohort_version: u64,
        cohort_position: u64,
    ) -> Result<CohortMerklePath, PoolError> {
        let p = self
            .tree
            .get_proof(cohort_position as usize)
            .map_err(|e| PoolError::Rpc(format!("get_proof: {e:?}")))?;
        Ok(CohortMerklePath {
            siblings: p.siblings.iter().map(fr_to_be_bytes).collect(),
            indices: p.indices.clone(),
        })
    }
}

/// Bundle of artifacts produced by the in-test "relay": signed voucher
/// data + proofs + the public-input arrays expected by the claim contract.
pub struct ClaimBundle {
    pub claim_proof: Vec<u8>,
    pub pool_proof: Vec<u8>,
    pub claim_public_inputs: [U256; 10],
    pub pool_public_inputs: [U256; 5],
    pub claim_witness: ClaimWitness,
    pub pool_witness: PoolWithdrawWitness,
    pub destination: AlloyAddress,
    pub claim_nullifier: U256,
    pub m_pub: SecpPubkey,
    pub derived_pub: SecpPubkey,
    pub signature: EcdsaSignature,
}

/// Per-claim assembly through the production-shaped path:
///   1. Companion verifies the funder's `H_header` + roster signatures,
///      drives the card's SIGN_VOUCHER, encrypts the voucher.
///   2. Relay decrypts, looks up `commitmentIndex` via `SnapshotPool`,
///      builds witnesses, and generates both proofs.
/// The relay's EOA address (`relay_submitter`) MUST equal `msg.sender`
/// when the test submits the resulting `claim()` tx.
#[allow(clippy::too_many_arguments)]
pub fn build_claim_for_card<P: ProofBackend>(
    backend: &P,
    card: &mut SoftwareSmartcard,
    pre_key: Bytes32,
    cohort_version: u64,
    m_pubs: &[SecpPubkey],
    cohort_position: u64,
    pool_leaf_index: u64,
    commitments: &[Bytes32],
    header: &RoundHeader,
    funder_sig: &[u8],
    signed_roster: &RelayRoster,
    relay_secret: &X25519StaticSecret,
    relay_submitter: AlloyAddress,
    funder_owners: &[RdrAddress],
    funder_threshold: usize,
) -> ClaimBundle {
    let snapshot_pool =
        SnapshotPool::new(commitments.to_vec(), header.claim_contract_address);
    let snapshot_cohort = SnapshotCohort::new(m_pubs, header.cohort_root);
    build_claim_with_snapshots(
        backend,
        card,
        pre_key,
        cohort_version,
        snapshot_cohort,
        cohort_position,
        snapshot_pool,
        pool_leaf_index,
        header,
        funder_sig,
        signed_roster,
        relay_secret,
        relay_submitter,
        funder_owners,
        funder_threshold,
    )
}

/// Lower-level variant of `build_claim_for_card` that accepts pre-built
/// snapshots. Negative tests use this to inject doctored cohort or pool
/// state (e.g. the non-cohort-member scenario synthesizes a single-leaf
/// attacker cohort).
#[allow(clippy::too_many_arguments)]
pub fn build_claim_with_snapshots<P: ProofBackend>(
    backend: &P,
    card: &mut SoftwareSmartcard,
    pre_key: Bytes32,
    cohort_version: u64,
    snapshot_cohort: SnapshotCohort,
    cohort_position: u64,
    snapshot_pool: SnapshotPool,
    pool_leaf_index: u64,
    header: &RoundHeader,
    funder_sig: &[u8],
    signed_roster: &RelayRoster,
    relay_secret: &X25519StaticSecret,
    relay_submitter: AlloyAddress,
    funder_owners: &[RdrAddress],
    funder_threshold: usize,
) -> ClaimBundle {
    // 1. Companion: verify funder + roster sigs, drive card SIGN_VOUCHER,
    //    encrypt voucher to the relay.
    let card_ref = CardRefMut(card);
    // Pin the clock at the same instant the roster was signed; the
    // 48h-staleness window matches.
    let clock = Arc::new(MockClock::new(signed_roster.signed_at_unix));
    let mut companion = Companion::new(
        card_ref,
        pre_key,
        signed_roster.clone(),
        funder_owners.to_vec(),
        funder_threshold,
        clock,
    );
    let bundle = HeaderBundle {
        signed: SignedHeader {
            header: header.clone(),
            signature: funder_sig.to_vec(),
        },
        first_pool_leaf_index: pool_leaf_index,
    };
    let env = companion
        .build_voucher(&bundle)
        .expect("Companion::build_voucher");
    drop(companion); // releases the &mut borrow on the card

    // ISubmission: recipient hands the envelope to the channel, the relay
    // pulls it on the other side. DirectSubmission is an in-process queue;
    // production deployments wire mesh transport.
    let relay_id = signed_roster.relays[0].relay_id;
    let submission = DirectSubmission::new([relay_id]);
    submission
        .submit_voucher(env, &relay_id)
        .expect("Submission::submit_voucher");
    let env = submission
        .pull_voucher(&relay_id)
        .expect("envelope queued for relay");

    let current_pk = X25519PublicKey::from(relay_secret);
    let keys = KeyArchive {
        current_sk: relay_secret.clone(),
        current_pk,
        previous_sk: None,
        previous_pk: None,
        rotated_at: Instant::now(),
        rotation_interval: Duration::from_secs(86_400),
    };
    let mut relay = Relay::new(
        BackendRef(backend),
        keys,
        snapshot_pool,
        snapshot_cohort,
        header.claim_contract_address,
        address_to_rdr(relay_submitter),
    );

    let artifacts = relay
        .submit_voucher(&env, header.token, cohort_version, cohort_position)
        .expect("Relay::submit_voucher");

    let claim_witness = artifacts.claim_witness;
    let pool_witness = artifacts.pool_witness;

    // Public-input arrays in the order the claim contract's library
    // expects.
    let claim_public_inputs: [U256; 10] = [
        fr_to_u256(claim_witness.round_id_hi),
        fr_to_u256(claim_witness.round_id_lo),
        fr_to_u256(claim_witness.cohort_root),
        fr_to_u256(claim_witness.chain_id_hi),
        fr_to_u256(claim_witness.chain_id_lo),
        fr_to_u256(claim_witness.destination),
        fr_to_u256(claim_witness.amount),
        fr_to_u256(claim_witness.nullifier),
        fr_to_u256(claim_witness.claim_contract_address),
        fr_to_u256(claim_witness.relay_submitter),
    ];
    let pool_public_inputs: [U256; 5] = [
        fr_to_u256(pool_witness.pool_root),
        fr_to_u256(pool_witness.claim_nullifier),
        fr_to_u256(pool_witness.token),
        fr_to_u256(pool_witness.amount),
        fr_to_u256(pool_witness.recipient),
    ];

    let voucher = artifacts.voucher;
    let _ = pack_round_id; // keep import live

    ClaimBundle {
        claim_proof: artifacts.claim_proof,
        pool_proof: artifacts.pool_proof,
        claim_public_inputs,
        pool_public_inputs,
        claim_witness,
        pool_witness,
        destination: address_from_rdr(voucher.destination),
        claim_nullifier: fr_to_u256(claim_witness_nullifier_fr_from_be(
            &voucher.claim_nullifier,
        )),
        m_pub: voucher.m,
        derived_pub: voucher.derived_pubkey,
        signature: voucher.signature,
    }
}

/// Helper: convert a 32-byte big-endian `claim_nullifier` from the voucher
/// into an `Fr`. The field-side value is the canonical nullifier; we
/// re-export it as `U256` for the on-chain assertions.
fn claim_witness_nullifier_fr_from_be(be: &Bytes32) -> Fr {
    fr_from_be_bytes(be)
}

/// Submit a `ClaimBundle` to the deployed claim contract from the given
/// `relay_signer_idx` (anvil prefunded account).
///
/// Routes the signed claim through `IAnonymousTransport`. The relay builds
/// the typed call, fills + signs via the provider's wallet (the rotated
/// EOA in production), then hands opaque EIP-2718 bytes to
/// `DirectAnonymousTransport`. Receipt polling stays on the caller.
pub async fn submit_claim_from_owner(
    harness: &AnvilHarness,
    deployment: &Deployment,
    bundle: &ClaimBundle,
    relay_signer_idx: usize,
) -> Result<alloy::rpc::types::TransactionReceipt, Box<dyn std::error::Error + Send + Sync>>
{
    let p = harness.owner_provider(relay_signer_idx);
    let signer: PrivateKeySigner = ANVIL_OWNER_PKS[relay_signer_idx].parse()?;
    let from = signer.address();
    let wallet = EthereumWallet::from(signer);

    let cc = IClaimContract::new(deployment.claim_contract, &p);
    let tx_request = cc
        .claim(
            Bytes::from(bundle.claim_proof.clone()),
            bundle.claim_public_inputs,
            Bytes::from(bundle.pool_proof.clone()),
            bundle.pool_public_inputs,
        )
        .into_transaction_request()
        .with_from(from);

    let nonce = p.get_transaction_count(from).await?;
    let chain_id = p.get_chain_id().await?;
    let gas_price = p.get_gas_price().await?;
    let gas_limit = p.estimate_gas(tx_request.clone()).await?;
    let tx_request = tx_request
        .with_nonce(nonce)
        .with_chain_id(chain_id)
        .with_gas_limit(gas_limit)
        .with_max_fee_per_gas(gas_price * 2)
        .with_max_priority_fee_per_gas(gas_price);

    let tx_envelope = tx_request.build(&wallet).await?;
    let raw = tx_envelope.encoded_2718();

    let transport = DirectAnonymousTransport::new(p.clone());
    let tx_hash = B256::from(transport.submit(&raw).await?);

    let mut attempts = 0;
    loop {
        if let Some(r) = p.get_transaction_receipt(tx_hash).await? {
            return Ok(r);
        }
        attempts += 1;
        if attempts > 200 {
            return Err("timed out waiting for tx receipt".into());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Build a deterministic X25519 secret from a 32-byte seed. Tests pass
/// distinct seeds for reproducibility.
pub fn relay_secret_from_seed(seed: [u8; 32]) -> X25519StaticSecret {
    X25519StaticSecret::from(seed)
}

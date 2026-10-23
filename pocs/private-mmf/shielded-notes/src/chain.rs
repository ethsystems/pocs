//! The chain adapter: bindings to the pool, the registry and the fund token,
//! a snapshot of what the actors read from chain (`ChainView`), and submission
//! of proved operations.

use std::collections::HashSet;

use alloy::{
    primitives::{
        Address as AlloyAddress,
        B256,
        Bytes as AlloyBytes,
        U256,
    },
    providers::{
        DynProvider,
        Provider,
    },
    rpc::types::{
        Filter,
        TransactionReceipt,
    },
    sol,
    sol_types::SolEvent,
};
use ark_bn254::Fr;
use num_bigint::BigUint;

use crate::{
    domain::{
        feed::FEED_FIELDS,
        grumpkin::Point,
        tree::LeanTree,
        witness::{
            DepositWitness,
            TransferWitness,
            WithdrawWitness,
        },
    },
    error::ChainError,
    ports::prover::CircuitProof,
    poseidon::fr_to_be_bytes,
    types::{
        Address,
        Bytes32,
    },
};

sol! {
    #[sol(rpc, all_derives)]
    interface IShieldedPool {
        struct DepositParams {
            bytes proof;
            bytes32 commitment;
            uint64 units;
            bytes32 attestationRoot;
            uint256 epoch;
            uint256[2] feedR;
            uint256[8] feedCt;
            bytes recipientPayload;
        }

        struct TransferParams {
            bytes proof;
            bytes32 nullifier0;
            bytes32 nullifier1;
            bytes32 commitmentOut0;
            bytes32 commitmentOut1;
            bytes32 commitmentRoot;
            bytes32 attestationRoot;
            uint256 epoch;
            uint256[2] feedR;
            uint256[16] feedCt;
            bytes recipientPayload;
        }

        struct WithdrawParams {
            bytes proof;
            bytes32 nullifier;
            uint64 units;
            address recipient;
            bytes32 commitmentRoot;
            bytes32 attestationRoot;
            uint256 epoch;
        }

        function deposit(DepositParams calldata p) external;
        function transfer(TransferParams calldata p) external;
        function withdraw(WithdrawParams calldata p) external;
        function checkpoint(bytes32 registerHash, uint256 expectedUnits) external;
        function clearHalt() external;
        function recordGrant(bytes32 scopeCommitment) external;
        function setRegisterKey(uint256 x, uint256 y, uint64 version) external;

        function commitmentRoot() external view returns (bytes32);
        function totalUnits() external view returns (uint256);
        function multiplier() external view returns (uint256);
        function lastMultiplier() external view returns (uint256);
        function halted() external view returns (bool);
        function claimKeyHash() external view returns (bytes32);
        function registerKeyX() external view returns (uint256);
        function registerKeyY() external view returns (uint256);
        function registerKeyVersion() external view returns (uint64);
        function currentEpoch() external view returns (uint256);
        function nullifiers(bytes32 nullifier) external view returns (bool);

        event Deposit(bytes32 indexed commitment, uint64 units, uint256 shares, uint256[2] feedR, uint256[8] feedCt, bytes recipientPayload);
        event Transfer(bytes32 indexed nullifier0, bytes32 indexed nullifier1, bytes32 commitment0, bytes32 commitment1, uint256[2] feedR, uint256[16] feedCt, bytes recipientPayload);
        event Withdraw(bytes32 indexed nullifier, address indexed recipient, uint64 units, uint256 shares);
        event Checkpoint(uint256 epoch, uint256 balance, uint256 totalUnits, uint256 multiplier, bytes32 registerHash);
        event Halted(uint256 multiplier, uint256 lastMultiplier);
        event HaltCleared(uint256 multiplier);
        event RegisterKeyRotated(uint64 version, uint256 x, uint256 y);

        error ContractPaused();
        error WrongEpoch();
        error InvalidFeedPoint();
        error UnknownRoot();
        error NullifierSpent();
        error DuplicateNullifier();
        error InvalidProof();
        error ZeroUnits();
        error EmptyPool();
        error ZeroAddress();
        error MultiplierDecreased();
        error MultiplierNotRestored();
        error UnitsChanged();
        error PoolHalted();
        error NotHalted();
        error NotTransferAgent();
        error InvalidRegisterKey();
        error WrongRegisterKeyVersion();
        error NonCanonicalInput();
    }

    #[sol(rpc)]
    interface IAttestationRegistry {
        function addAttestations(bytes32[] calldata owners, uint64 expiresAt, uint64 generation) external;
        function attestationRoot() external view returns (bytes32);
        function minAcceptedGeneration() external view returns (uint256);
        function MIN_BATCH_SIZE() external view returns (uint256);

        event AttestationAdded(bytes32 indexed leaf, bytes32 indexed owner, address indexed attester, uint64 generation, uint64 issuedAt, uint64 expiresAt);
    }

    #[sol(rpc, all_derives)]
    interface IFundToken {
        function mint(address to, uint256 amount) external;
        function burn(address from, uint256 amount) external;
        function approve(address spender, uint256 amount) external returns (bool);
        function transfer(address to, uint256 amount) external returns (bool);
        function balanceOf(address account) external view returns (uint256);
        function setAllowlisted(address holder, bool value) external;
        function reinvest(address[] calldata holders, uint256 rateWad) external;
        function forceTransfer(address from, address to, uint256 amount) external;

        event Transfer(address indexed from, address indexed to, uint256 value);

        error NotIssuer();
        error NotAllowlisted(address holder);
        error BalanceLimitExceeded(address holder);
        error AdminExempt(address holder);
    }

    /// The generated UltraHonk verifiers revert with one of these on a proof
    /// that does not verify, instead of returning false, so the pool's own
    /// `InvalidProof` is not reached.
    #[sol(all_derives)]
    interface IHonkVerifier {
        error ConsistencyCheckFailed();
        error GeminiChallengeInSubgroup();
        error InvertOfZero();
        error ModExpFailed();
        error NotPowerOfTwo();
        error PointAtInfinity();
        error ProofLengthWrong();
        error ProofLengthWrongWithLogN(uint256 logN, uint256 actualLength, uint256 expectedLength);
        error PublicInputsLengthWrong();
        error ShpleminiFailed();
        error SumcheckFailed();
        error ValueGeFieldOrder();
        error ValueGeGroupOrder();
        error ValueGeLimbMax();
    }
}

/// A fixed limit on every submission. Each one is simulated first, with this
/// same limit, which reports a rejection with the pool's reason and fails a
/// call that needs more gas before anything is sent; the limit saves a
/// second, redundant estimation.
const SUBMIT_GAS_LIMIT: u64 = 12_000_000;

/// The owners one `addAttestations` call carries: exactly the registry's
/// minimum batch. An owner costs from about 0.35M to about 0.8M gas, depending
/// on where its leaf falls in the tree, since LeanIMT hashes at every level
/// where the leaf's index has a 1 bit; 16 owners stay under EIP-7825's
/// per-transaction cap of 2^24 gas even at the tree's last leaves (about
/// 12.8M), where 32 would not.
pub const ATTESTATION_PART: usize = 16;

/// EIP-7825's per-transaction gas cap.
const MAX_TRANSACTION_GAS: u64 = 1 << 24;

/// An attestation batch as the transfer agent builds it
/// (`TransferAgent::attestation_batch`): owner values the cap check admitted,
/// with the period's renewals and padding, shuffled, in parts of exactly
/// `ATTESTATION_PART`, under the period's uniform expiry. Only the crate
/// builds one, so `add_attestations` cannot attest a list that skipped those
/// rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationBatch {
    parts: Vec<Vec<Fr>>,
    expires_at: u64,
    generation: u64,
}

impl AttestationBatch {
    pub(crate) fn new(parts: Vec<Vec<Fr>>, expires_at: u64, generation: u64) -> Self {
        debug_assert!(parts.iter().all(|p| p.len() == ATTESTATION_PART));
        Self {
            parts,
            expires_at,
            generation,
        }
    }

    /// One `addAttestations` call each.
    pub fn parts(&self) -> &[Vec<Fr>] {
        &self.parts
    }

    pub fn owners(&self) -> impl Iterator<Item = &Fr> {
        self.parts.iter().flatten()
    }

    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Nothing was due: no transaction to send.
    pub fn is_empty(&self) -> bool {
        self.parts.is_empty()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Deployment {
    pub pool: AlloyAddress,
    pub registry: AlloyAddress,
    pub token: AlloyAddress,
    pub chain_id: u64,
}

// ========== Conversions ==========

pub fn to_address(a: AlloyAddress) -> Address {
    Address::from(a.into_array())
}

pub fn to_alloy(a: Address) -> AlloyAddress {
    AlloyAddress::from_slice(a.as_ref())
}

pub fn b256(f: Fr) -> B256 {
    B256::from(fr_to_be_bytes(&f))
}

pub fn u256(f: Fr) -> U256 {
    U256::from_be_bytes(fr_to_be_bytes(&f))
}

/// A field element read from the chain. The pool canonicalizes its own public
/// inputs, but values such as attested owners come from other parties.
pub fn fr_of_b256(b: B256) -> Result<Fr, ChainError> {
    Fr::try_from(Bytes32::from(b.0)).map_err(|_| ChainError::NonCanonical(b))
}

pub fn fr_of_u256(u: U256) -> Result<Fr, ChainError> {
    fr_of_b256(B256::from(u.to_be_bytes::<32>()))
}

fn point_of(r: &[U256; 2]) -> Result<Point, ChainError> {
    Ok(Point::new(fr_of_u256(r[0])?, fr_of_u256(r[1])?))
}

// ========== Reading ==========

/// The values every proof is built against, read fresh before each operation.
#[derive(Debug, Clone, Copy)]
pub struct PoolEnv {
    pub chain_id: u64,
    pub pool: Address,
    pub token: Address,
    pub register_key: Point,
    pub claim_key_hash: Fr,
    pub min_accepted_generation: u64,
    pub epoch: u64,
    pub timestamp: u64,
}

impl PoolEnv {
    /// A plan expiry at a midnight UTC, as the SPEC recommends: the end of the
    /// next epoch, so a signature stays usable today and tomorrow, generous
    /// for an MPC approval in tests.
    pub fn expiry(&self) -> u64 {
        (self.epoch + 2) * crate::EPOCH_SECONDS
    }

    pub async fn fetch(
        provider: &DynProvider,
        d: &Deployment,
    ) -> Result<Self, ChainError> {
        let pool = IShieldedPool::new(d.pool, provider.clone());
        let registry = IAttestationRegistry::new(d.registry, provider.clone());
        let block = provider
            .get_block(alloy::eips::BlockId::latest())
            .await?
            .ok_or(ChainError::NoLatestBlock)?;
        let x = pool.registerKeyX().call().await?;
        let y = pool.registerKeyY().call().await?;
        Ok(Self {
            chain_id: d.chain_id,
            pool: to_address(d.pool),
            token: to_address(d.token),
            register_key: Point::new(fr_of_u256(x)?, fr_of_u256(y)?),
            claim_key_hash: fr_of_b256(pool.claimKeyHash().call().await?)?,
            min_accepted_generation: registry
                .minAcceptedGeneration()
                .call()
                .await?
                .to::<u64>(),
            epoch: block.header.timestamp / crate::EPOCH_SECONDS,
            timestamp: block.header.timestamp,
        })
    }
}

/// One note the pool created: its leaf, its slice of the register feed, and the
/// recipient payload of the operation that created it.
#[derive(Debug, Clone)]
pub struct NoteRecord {
    pub commitment: Fr,
    pub leaf_index: usize,
    /// Output position in its operation, which selects the keystream and the payload element.
    pub output: usize,
    pub feed_r: Point,
    pub feed_ct: [Fr; FEED_FIELDS],
    pub payload: Vec<u8>,
    /// The pool's register-key version when the note was created, which picks
    /// the agent's `tk` (0 is the key set at deployment).
    pub key_version: u64,
}

/// Shares the public token moved out of the pool.
#[derive(Debug, Clone)]
pub struct Outflow {
    pub to: Address,
    pub shares: U256,
    pub tx: B256,
    /// Whether a withdrawal paid exactly this transfer: same transaction,
    /// recipient and amount, one transfer per withdrawal. Any other outflow is
    /// a forced transfer, burn or recovery the pool cannot tell from yield
    /// (SPEC, Multiplier Rules), which the agent flags at reconciliation, even
    /// in a transaction that also withdrew.
    pub by_withdrawal: bool,
}

/// Marks the outflows a withdrawal paid: each `Withdraw` (transaction,
/// recipient, shares) pays one token transfer out of the pool, and every
/// transfer left over stays unexplained.
fn match_withdrawals(outflows: &mut [Outflow], withdrawals: &[(B256, Address, U256)]) {
    let mut unpaid = withdrawals.to_vec();
    for o in outflows.iter_mut() {
        if let Some(i) = unpaid.iter().position(|w| *w == (o.tx, o.to, o.shares)) {
            unpaid.swap_remove(i);
            o.by_withdrawal = true;
        }
    }
}

/// One attestation leaf, as the registry built it.
#[derive(Debug, Clone)]
pub struct AttestationRecord {
    pub owner: Fr,
    pub attester: Address,
    pub generation: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub leaf_index: usize,
}

/// A spend the pool recorded: one transfer's or withdrawal's nullifiers.
#[derive(Debug, Clone)]
pub struct SpendRecord {
    pub nullifiers: Vec<Fr>,
    /// The commitments the same transfer created; empty for a withdrawal.
    pub outputs: Vec<Fr>,
    pub withdrawn_units: Option<u64>,
}

/// Everything the wallet and the agent read from chain, rebuilt from events.
#[derive(Debug, Clone, Default)]
pub struct ChainView {
    pub commitments: LeanTree,
    pub notes: Vec<NoteRecord>,
    pub nullifiers: HashSet<Fr>,
    pub spends: Vec<SpendRecord>,
    pub attestations: LeanTree,
    pub attestation_records: Vec<AttestationRecord>,
    /// Leaves whose owner value is not a canonical field element. The registry
    /// refuses such owners, so only an older registry produces one. The leaf
    /// stays in `attestations`, which must match the registry's tree, but it
    /// attests nobody a wallet can name.
    pub unreadable_attestations: Vec<B256>,
    pub outflows: Vec<Outflow>,
}

fn ct_slice<const N: usize>(
    ct: &[U256; N],
    j: usize,
) -> Result<[Fr; FEED_FIELDS], ChainError> {
    let mut out = [Fr::from(0u64); FEED_FIELDS];
    for i in 0..FEED_FIELDS {
        out[i] = fr_of_u256(ct[FEED_FIELDS * j + i])?;
    }
    Ok(out)
}

impl ChainView {
    /// Rebuilds the view from every event up to the latest block. The three
    /// log queries are pinned to that block, so a withdrawal mined between
    /// them cannot show up as a token transfer without its `Withdraw`.
    pub async fn sync(
        provider: &DynProvider,
        d: &Deployment,
    ) -> Result<Self, ChainError> {
        let mut view = Self::default();
        // The trees are built once, in one batch, from all their leaves.
        let mut commitments = Vec::new();
        let mut attestations = Vec::new();
        let mut key_version = 0u64;
        let mut withdrawals = Vec::new();
        let to_block = provider.get_block_number().await?;

        let pool_logs = provider
            .get_logs(
                &Filter::new()
                    .address(d.pool)
                    .from_block(0)
                    .to_block(to_block),
            )
            .await?;
        for log in pool_logs {
            let Some(topic) = log.topic0() else { continue };
            if *topic == IShieldedPool::Deposit::SIGNATURE_HASH {
                let e = log.log_decode::<IShieldedPool::Deposit>()?.inner.data;
                let commitment = fr_of_b256(e.commitment)?;
                commitments.push(commitment);
                let leaf_index = commitments.len() - 1;
                view.notes.push(NoteRecord {
                    commitment,
                    leaf_index,
                    output: 0,
                    feed_r: point_of(&e.feedR)?,
                    feed_ct: ct_slice(&e.feedCt, 0)?,
                    payload: e.recipientPayload.to_vec(),
                    key_version,
                });
            } else if *topic == IShieldedPool::Transfer::SIGNATURE_HASH {
                let e = log.log_decode::<IShieldedPool::Transfer>()?.inner.data;
                let nullifiers =
                    vec![fr_of_b256(e.nullifier0)?, fr_of_b256(e.nullifier1)?];
                view.nullifiers.extend(nullifiers.iter().copied());
                let outputs =
                    vec![fr_of_b256(e.commitment0)?, fr_of_b256(e.commitment1)?];
                for (j, commitment) in outputs.iter().enumerate() {
                    commitments.push(*commitment);
                    let leaf_index = commitments.len() - 1;
                    view.notes.push(NoteRecord {
                        commitment: *commitment,
                        leaf_index,
                        output: j,
                        feed_r: point_of(&e.feedR)?,
                        feed_ct: ct_slice(&e.feedCt, j)?,
                        payload: e.recipientPayload.to_vec(),
                        key_version,
                    });
                }
                view.spends.push(SpendRecord {
                    nullifiers,
                    outputs,
                    withdrawn_units: None,
                });
            } else if *topic == IShieldedPool::Withdraw::SIGNATURE_HASH {
                let e = log.log_decode::<IShieldedPool::Withdraw>()?.inner.data;
                let nullifier = fr_of_b256(e.nullifier)?;
                view.nullifiers.insert(nullifier);
                withdrawals.push((
                    log.transaction_hash.unwrap_or_default(),
                    to_address(e.recipient),
                    e.shares,
                ));
                view.spends.push(SpendRecord {
                    nullifiers: vec![nullifier],
                    outputs: vec![],
                    withdrawn_units: Some(e.units),
                });
            } else if *topic == IShieldedPool::RegisterKeyRotated::SIGNATURE_HASH {
                key_version = log
                    .log_decode::<IShieldedPool::RegisterKeyRotated>()?
                    .inner
                    .data
                    .version;
            }
        }

        let outflow_logs = provider
            .get_logs(
                &Filter::new()
                    .address(d.token)
                    .event_signature(IFundToken::Transfer::SIGNATURE_HASH)
                    .topic1(d.pool.into_word())
                    .from_block(0)
                    .to_block(to_block),
            )
            .await?;
        for log in outflow_logs {
            let e = log.log_decode::<IFundToken::Transfer>()?.inner.data;
            view.outflows.push(Outflow {
                to: to_address(e.to),
                shares: e.value,
                tx: log.transaction_hash.unwrap_or_default(),
                by_withdrawal: false,
            });
        }
        match_withdrawals(&mut view.outflows, &withdrawals);

        let registry_logs = provider
            .get_logs(
                &Filter::new()
                    .address(d.registry)
                    .event_signature(
                        IAttestationRegistry::AttestationAdded::SIGNATURE_HASH,
                    )
                    .from_block(0)
                    .to_block(to_block),
            )
            .await?;
        for log in registry_logs {
            let e = log
                .log_decode::<IAttestationRegistry::AttestationAdded>()?
                .inner
                .data;
            attestations.push(fr_of_b256(e.leaf)?);
            let leaf_index = attestations.len() - 1;
            let Ok(owner) = fr_of_b256(e.owner) else {
                view.unreadable_attestations.push(e.leaf);
                continue;
            };
            view.attestation_records.push(AttestationRecord {
                owner,
                attester: to_address(e.attester),
                generation: e.generation,
                issued_at: e.issuedAt,
                expires_at: e.expiresAt,
                leaf_index,
            });
        }
        view.commitments = LeanTree::from_leaves(&commitments);
        view.attestations = LeanTree::from_leaves(&attestations);
        Ok(view)
    }

    /// The newest attestation of `owner` that is still current at `epoch`.
    pub fn attestation_of(
        &self,
        owner: Fr,
        epoch: u64,
        min_generation: u64,
    ) -> Option<&AttestationRecord> {
        self.attestation_records.iter().rev().find(|r| {
            r.owner == owner
                && (epoch + 1) * crate::EPOCH_SECONDS <= r.expires_at
                && r.generation >= min_generation
        })
    }
}

/// What the agent reconciles against (SPEC, Reconciliation): `U`, the pool's
/// share balance `B`, and `m`.
#[derive(Debug, Clone, Copy)]
pub struct PoolTotals {
    pub units: u128,
    pub balance: U256,
    pub multiplier: U256,
}

pub async fn pool_totals(
    provider: &DynProvider,
    d: &Deployment,
) -> Result<PoolTotals, ChainError> {
    let pool = IShieldedPool::new(d.pool, provider.clone());
    let token = IFundToken::new(d.token, provider.clone());
    Ok(PoolTotals {
        units: pool.totalUnits().call().await?.to::<u128>(),
        balance: token.balanceOf(d.pool).call().await?,
        multiplier: pool.multiplier().call().await?,
    })
}

pub async fn pool_state(
    provider: &DynProvider,
    d: &Deployment,
) -> Result<(u128, u128, Fr), ChainError> {
    let pool = IShieldedPool::new(d.pool, provider.clone());
    let units = pool.totalUnits().call().await?;
    let m = pool.multiplier().call().await?;
    let root = pool.commitmentRoot().call().await?;
    Ok((units.to::<u128>(), m.to::<u128>(), fr_of_b256(root)?))
}

// ========== Submitting ==========

/// Waits for the receipt of a sent transaction. One that passed simulation
/// but reverted when mined, because the state changed in between, is reported
/// with its hash.
async fn confirm(
    pending: alloy::providers::PendingTransactionBuilder<alloy::network::Ethereum>,
) -> Result<TransactionReceipt, ChainError> {
    let receipt = pending.get_receipt().await?;
    if !receipt.status() {
        return Err(ChainError::RevertedOnChain(receipt.transaction_hash));
    }
    Ok(receipt)
}

/// The prover port's contract: a proof's public inputs are the witness's.
/// A mismatch is a bug in the prover adapter, not a runtime condition.
fn checked_public_inputs(proof: &CircuitProof, expected: &[Bytes32]) {
    assert!(
        proof.public_inputs.len() >= expected.len()
            && proof.public_inputs[..expected.len()] == *expected,
        "the proof's public inputs disagree with the witness"
    );
}

fn feed_r(p: &Point) -> [U256; 2] {
    [u256(p.x), u256(p.y)]
}

fn u256_array<const N: usize>(fields: &[Fr; N]) -> [U256; N] {
    fields.map(u256)
}

/// A proved operation as a relayer receives it: the pool call's parameters,
/// which go on-chain anyway. The owner proves and builds it; the witness, with
/// `nk`, the plan signature, the openings, the Merkle paths and the feed
/// secret, never leaves the owner's side (SPEC, Participants and Roles,
/// Relayer). A deposit must be sent by its funding address, which the pool
/// fills in as a public input.
#[derive(Debug, Clone)]
pub enum Submission {
    Deposit(Box<IShieldedPool::DepositParams>),
    Transfer(Box<IShieldedPool::TransferParams>),
    Withdraw(Box<IShieldedPool::WithdrawParams>),
}

impl Submission {
    pub fn deposit(w: &DepositWitness, proof: &CircuitProof, payload: &[u8]) -> Self {
        checked_public_inputs(proof, &w.public_inputs());
        Self::Deposit(Box::new(IShieldedPool::DepositParams {
            proof: AlloyBytes::from(proof.proof.clone()),
            commitment: b256(w.commitment),
            units: w.units,
            attestationRoot: b256(w.attestation_root),
            epoch: U256::from(w.epoch),
            feedR: feed_r(&w.feed_r),
            feedCt: u256_array(&w.feed_ct),
            recipientPayload: AlloyBytes::from(payload.to_vec()),
        }))
    }

    pub fn transfer(w: &TransferWitness, proof: &CircuitProof, payload: &[u8]) -> Self {
        checked_public_inputs(proof, &w.public_inputs());
        Self::Transfer(Box::new(IShieldedPool::TransferParams {
            proof: AlloyBytes::from(proof.proof.clone()),
            nullifier0: b256(w.nullifiers[0]),
            nullifier1: b256(w.nullifiers[1]),
            commitmentOut0: b256(w.commitments_out[0]),
            commitmentOut1: b256(w.commitments_out[1]),
            commitmentRoot: b256(w.commitment_root),
            attestationRoot: b256(w.attestation_root),
            epoch: U256::from(w.epoch),
            feedR: feed_r(&w.feed_r),
            feedCt: u256_array(&w.feed_ct),
            recipientPayload: AlloyBytes::from(payload.to_vec()),
        }))
    }

    pub fn withdraw(w: &WithdrawWitness, proof: &CircuitProof) -> Self {
        checked_public_inputs(proof, &w.public_inputs());
        Self::Withdraw(Box::new(IShieldedPool::WithdrawParams {
            proof: AlloyBytes::from(proof.proof.clone()),
            nullifier: b256(w.nullifier),
            units: w.units,
            recipient: to_alloy(w.recipient),
            commitmentRoot: b256(w.commitment_root),
            attestationRoot: b256(w.attestation_root),
            epoch: U256::from(w.epoch),
        }))
    }
}

/// Simulates the submission, then sends it, both through `provider`. A claim
/// SHOULD go through the agent's own node or a private channel to a builder
/// (SPEC, Claims): a simulation on a public RPC would show the claim's
/// nullifier before it is sent. The PoC sends claims like any transfer.
pub async fn submit(
    provider: &DynProvider,
    d: &Deployment,
    submission: &Submission,
) -> Result<TransactionReceipt, ChainError> {
    let pool = IShieldedPool::new(d.pool, provider.clone());
    match submission {
        Submission::Deposit(params) => {
            let call = pool.deposit(params.as_ref().clone());
            let call = call.gas(SUBMIT_GAS_LIMIT);
            call.call().await?;
            confirm(call.send().await?).await
        }
        Submission::Transfer(params) => {
            let call = pool.transfer(params.as_ref().clone());
            let call = call.gas(SUBMIT_GAS_LIMIT);
            call.call().await?;
            confirm(call.send().await?).await
        }
        Submission::Withdraw(params) => {
            let call = pool.withdraw(params.as_ref().clone());
            let call = call.gas(SUBMIT_GAS_LIMIT);
            call.call().await?;
            confirm(call.send().await?).await
        }
    }
}

/// Sends an attestation batch, one transaction per part. Returns each part's
/// receipt; none for an empty batch.
pub async fn add_attestations(
    provider: &DynProvider,
    d: &Deployment,
    batch: &AttestationBatch,
) -> Result<Vec<TransactionReceipt>, ChainError> {
    let registry = IAttestationRegistry::new(d.registry, provider.clone());
    let mut receipts = Vec::new();
    for part in batch.parts() {
        let part: Vec<B256> = part.iter().map(|o| b256(*o)).collect();
        let call = registry.addAttestations(part, batch.expires_at(), batch.generation());
        // A part's cost varies too much for `SUBMIT_GAS_LIMIT`: estimate it,
        // with a margin, within the per-transaction cap.
        let gas = (call.estimate_gas().await? * 6 / 5).min(MAX_TRANSACTION_GAS);
        let call = call.gas(gas);
        call.call().await?;
        receipts.push(confirm(call.send().await?).await?);
    }
    Ok(receipts)
}

/// The daily checkpoint, with `U` as the agent's snapshot counted it: the pool
/// refuses it (`UnitsChanged`) if a deposit or withdrawal landed in between.
pub async fn checkpoint(
    provider: &DynProvider,
    d: &Deployment,
    register_hash: B256,
    units: u128,
) -> Result<TransactionReceipt, ChainError> {
    let pool = IShieldedPool::new(d.pool, provider.clone());
    let call = pool.checkpoint(register_hash, U256::from(units));
    let call = call.gas(SUBMIT_GAS_LIMIT);
    call.call().await?;
    confirm(call.send().await?).await
}

pub async fn set_register_key(
    provider: &DynProvider,
    d: &Deployment,
    key: &Point,
    version: u64,
) -> Result<TransactionReceipt, ChainError> {
    let pool = IShieldedPool::new(d.pool, provider.clone());
    let call = pool.setRegisterKey(u256(key.x), u256(key.y), version);
    let call = call.gas(SUBMIT_GAS_LIMIT);
    call.call().await?;
    confirm(call.send().await?).await
}

/// Governance lifts a halt (timelocked in production; the PoC's timelock
/// controller is an account).
pub async fn clear_halt(
    provider: &DynProvider,
    d: &Deployment,
) -> Result<TransactionReceipt, ChainError> {
    let pool = IShieldedPool::new(d.pool, provider.clone());
    let call = pool.clearHalt();
    let call = call.gas(SUBMIT_GAS_LIMIT);
    call.call().await?;
    confirm(call.send().await?).await
}

pub async fn halted(provider: &DynProvider, d: &Deployment) -> Result<bool, ChainError> {
    Ok(IShieldedPool::new(d.pool, provider.clone())
        .halted()
        .call()
        .await?)
}

pub fn big(u: U256) -> BigUint {
    BigUint::from_bytes_be(&u.to_be_bytes::<32>())
}

#[cfg(test)]
mod tests {
    use alloy::{
        primitives::{
            Log as PrimitiveLog,
            LogData,
        },
        providers::ProviderBuilder,
        rpc::types::Log,
        transports::mock::Asserter,
    };

    use super::*;

    fn deployment() -> Deployment {
        Deployment {
            pool: AlloyAddress::repeat_byte(0x11),
            registry: AlloyAddress::repeat_byte(0x22),
            token: AlloyAddress::repeat_byte(0x33),
            chain_id: 31337,
        }
    }

    fn rpc_log(address: AlloyAddress, data: LogData, tx: B256, index: u64) -> Log {
        Log {
            inner: PrimitiveLog { address, data },
            block_hash: Some(B256::repeat_byte(1)),
            block_number: Some(1),
            block_timestamp: None,
            transaction_hash: Some(tx),
            transaction_index: Some(0),
            log_index: Some(index),
            removed: false,
        }
    }

    /// A node that answers `sync`'s four requests in order: the latest block
    /// number, then the pool's, the token's and the registry's logs.
    async fn sync_against(
        pool: Vec<Log>,
        token: Vec<Log>,
        registry: Vec<Log>,
    ) -> ChainView {
        let asserter = Asserter::new();
        asserter.push_success(&"0x10");
        asserter.push_success(&pool);
        asserter.push_success(&token);
        asserter.push_success(&registry);
        let provider = ProviderBuilder::new()
            .connect_mocked_client(asserter)
            .erased();
        ChainView::sync(&provider, &deployment())
            .await
            .expect("sync")
    }

    fn withdraw(recipient: AlloyAddress, shares: u64) -> LogData {
        IShieldedPool::Withdraw {
            nullifier: B256::repeat_byte(7),
            recipient,
            units: shares,
            shares: U256::from(shares),
        }
        .encode_log_data()
    }

    fn transfer_out(to: AlloyAddress, value: u64) -> LogData {
        IFundToken::Transfer {
            from: deployment().pool,
            to,
            value: U256::from(value),
        }
        .encode_log_data()
    }

    /// Council 2, C25: a withdrawal no longer explains every other transfer
    /// out of the pool in its transaction. Each `Withdraw` pays exactly one
    /// transfer, with its recipient and amount.
    #[tokio::test]
    async fn a_withdrawal_explains_only_its_own_transfer() {
        let d = deployment();
        let (alice, issuer) = (
            AlloyAddress::repeat_byte(0x44),
            AlloyAddress::repeat_byte(0x55),
        );
        let tx = B256::repeat_byte(0xaa);
        let view = sync_against(
            vec![rpc_log(d.pool, withdraw(alice, 100), tx, 0)],
            vec![
                rpc_log(d.token, transfer_out(alice, 100), tx, 1),
                rpc_log(d.token, transfer_out(issuer, 5), tx, 2),
                // The same recipient and amount again: one withdrawal pays one.
                rpc_log(d.token, transfer_out(alice, 100), tx, 3),
                // A transfer in another transaction than its withdrawal.
                rpc_log(
                    d.token,
                    transfer_out(alice, 100),
                    B256::repeat_byte(0xbb),
                    0,
                ),
            ],
            vec![],
        )
        .await;
        let explained: Vec<bool> =
            view.outflows.iter().map(|o| o.by_withdrawal).collect();
        assert_eq!(explained, [true, false, false, false]);
    }

    /// Council 2, C35: an attestation of an owner value outside the field does
    /// not stop the sync. Its leaf stays in the tree, which must match the
    /// registry's, and it is reported.
    #[tokio::test]
    async fn an_unreadable_attestation_is_reported_not_fatal() {
        let d = deployment();
        let attestation = |owner: B256, leaf: u8| {
            IAttestationRegistry::AttestationAdded {
                leaf: B256::repeat_byte(leaf),
                owner,
                attester: AlloyAddress::repeat_byte(9),
                generation: 0,
                issuedAt: 1,
                expiresAt: 2,
            }
            .encode_log_data()
        };
        let tx = B256::repeat_byte(0xcc);
        let view = sync_against(
            vec![],
            vec![],
            vec![
                rpc_log(d.registry, attestation(B256::repeat_byte(0xff), 1), tx, 0),
                rpc_log(d.registry, attestation(B256::with_last_byte(5), 2), tx, 1),
            ],
        )
        .await;
        assert_eq!(view.attestations.len(), 2);
        assert_eq!(view.unreadable_attestations, [B256::repeat_byte(1)]);
        assert_eq!(view.attestation_records.len(), 1);
        assert_eq!(view.attestation_records[0].leaf_index, 1);
    }
}

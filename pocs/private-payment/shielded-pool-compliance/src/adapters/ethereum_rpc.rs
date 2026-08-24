//! The real `ChainReader`/`ChainWriter`/`AttestationSource` over `alloy`. One adapter
//! holds both contract addresses: `ChainReader::registry_values` reads the registry,
//! everything else reads or writes the pool.
//!
//! The four write methods' calldata structs mirror `contracts/src/PublicInputs.sol` in
//! ABI order, proof bytes first, and each write entry point takes exactly one struct.
//! `ChainWriter`'s `encrypted_payload` argument lands in the trailing `encryptedNotes`
//! field of the three gated structs; `withdrawBlocked` carries none.
//!
//! The event ABIs below are reconciled against `contracts/src/AttestationRegistry.sol`:
//! `AttestationAdded`, `AttesterAdded`, `AttesterRemoved`, `AttesterRevocationLowered`.
//! `AttestationAdded` carries no leaf index, so `AttestationSource::current_attestation`
//! derives one, per the rule stated at `latest_attestation_for_subject`. The attester
//! set (for the revocation Merkle proof) is rebuilt locally by replaying
//! `AttesterAdded`/`AttesterRemoved`/`AttesterRevocationLowered` logs in block order
//! into a fresh `adapters::revocation_tree::RevocationTree`, mirroring the contract's
//! fixed-depth, at-most-32-attester tree exactly, since that tree cannot be queried
//! for a Merkle proof any other way.
//!
//! Both replays are folded incrementally through a `chainfold::Engine`, held on
//! `EthereumRpc` and synced from its cursor on every read instead of rescanning from
//! block 0 each time.

use std::{
    future::Future,
    sync::Mutex,
};

use alloy::{
    contract::Error as ContractError,
    primitives::{
        Address as AlloyAddress,
        B256,
        Bytes as AlloyBytes,
        U256,
    },
    providers::Provider,
    rpc::types::{
        Filter,
        Log,
    },
    sol,
    sol_types::SolEvent,
};
use ark_bn254::Fr;
use chainfold::{
    ApplyError,
    Batch,
    BlockRef,
    Engine,
    EngineConfig,
    EngineStatus,
    Fold,
    FoldError,
    Position,
};

use crate::{
    adapters::revocation_tree::RevocationTree,
    domain::{
        attestation::Generation,
        keys::OwnerPubkey,
    },
    error::{
        ChainError,
        MerkleError,
    },
    ports::{
        chain::{
            ChainReader,
            ChainWriter,
            PolicyPair,
            RegistrySnapshot,
        },
        merkle::LeafIndex,
        prover::CircuitProof,
        registry::{
            AttestationRecord,
            AttestationSource,
        },
    },
    types::{
        Address,
        Bytes32,
        Epoch,
        TxHash,
    },
};

sol! {
    #[sol(rpc)]
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

        function currentEpoch() external view returns (uint256);
        function commitmentRoot() external view returns (bytes32);
        function isKnownRoot(bytes32 root) external view returns (bool);
        function effectivePolicy() external view returns (address verifier, bytes32 sourceHash);
        function nullifiers(bytes32 nullifier) external view returns (bool);
        function deposit(DepositParams calldata params) external;
        function transfer(TransferParams calldata params) external;
        function withdraw(WithdrawParams calldata params) external;
        function withdrawBlocked(WithdrawBlockedParams calldata params) external;
        function claimBlocked(bytes32 nullifier) external;
    }

    #[sol(rpc)]
    interface IAttestationRegistry {
        event AttesterAdded(address indexed attester);
        event AttesterRemoved(address indexed attester);
        event AttesterRevocationLowered(address indexed attester, uint64 revokedAtEpoch);
        event AttestationAdded(
            bytes32 indexed leaf,
            bytes32 indexed subjectPubkeyHash,
            address indexed attester,
            uint64 generation,
            uint64 issuedAt,
            uint64 expiresAt
        );

        function attestationRoot() external view returns (bytes32);
        function attesterRevocationRoot() external view returns (bytes32);
        function minAcceptedGeneration() external view returns (uint256);
        function revokedAtEpoch(address attester) external view returns (uint64);
        function isAttester(address attester) external view returns (bool);
        function currentEpoch() external view returns (uint256);
    }
}

/// One replayed registry event, in the order `fetch_registry_batch` observed it on
/// chain.
#[derive(Clone)]
enum RegistryEvent {
    AttesterAdded(AlloyAddress),
    AttesterRemoved(AlloyAddress),
    RevocationLowered(AlloyAddress, u64),
    AttestationAdded(IAttestationRegistry::AttestationAdded),
}

/// Folded registry state: the attester revocation tree, plus every `AttestationAdded`
/// seen so far in chain order. `addAttestations` calls `_issueOne` once per subject in
/// calldata order, and `_issueOne` inserts into the append-only LeanIMT at `size` and
/// then emits, one event per insert, with no removal or update of the attestation tree
/// anywhere in the registry. So the ordinal of an `AttestationAdded` in (block, log
/// index) order is its leaf position, and `attestations`'s index IS that leaf index.
/// Reordering, filtering, or batching that loop away breaks this.
#[derive(Default)]
struct RegistryFold {
    tree: RevocationTree,
    attestations: Vec<IAttestationRegistry::AttestationAdded>,
}

impl Fold for RegistryFold {
    type Event = RegistryEvent;
    type Error = MerkleError;

    fn apply(
        &mut self,
        _pos: Position,
        event: &RegistryEvent,
    ) -> Result<(), FoldError<MerkleError>> {
        // A write rejected here means the replayed event log is inconsistent with the
        // tree's write rules (e.g. a duplicate add, or a revoke/remove of an unknown
        // attester), which can only mean corrupt or missing history: the state is
        // untrusted until a full resync, so it poisons rather than halts.
        match event {
            RegistryEvent::AttesterAdded(a) => {
                self.tree
                    .add_attester(address_from_alloy(*a))
                    .map_err(FoldError::Poison)?;
            }
            RegistryEvent::AttesterRemoved(a) => {
                self.tree
                    .remove_attester(address_from_alloy(*a))
                    .map_err(FoldError::Poison)?;
            }
            RegistryEvent::RevocationLowered(a, epoch) => {
                self.tree
                    .lower_revocation(address_from_alloy(*a), *epoch)
                    .map_err(FoldError::Poison)?;
            }
            RegistryEvent::AttestationAdded(ev) => {
                self.attestations.push(ev.clone());
            }
        }
        Ok(())
    }
}

/// Wraps a not-fold status (already Halted or Poisoned from a prior call) into a
/// `MerkleError` so it can travel through `ChainError::ReplayInconsistent` alongside
/// fold-originated failures.
fn engine_not_active_error(status: EngineStatus) -> MerkleError {
    MerkleError::Storage(Box::new(std::io::Error::other(status.to_string())))
}

/// Classifies an `apply_batch` failure: `Some` is a fold-originated inconsistency with
/// no retry, `None` means the batch or boundary itself was rejected and a full resync
/// from block 0 is worth trying.
fn classify_registry_apply_error(error: ApplyError<MerkleError>) -> Option<ChainError> {
    match error {
        ApplyError::Halted { error, .. } | ApplyError::Poisoned { error, .. } => {
            Some(ChainError::ReplayInconsistent(error))
        }
        ApplyError::NotActive { status } => {
            Some(ChainError::ReplayInconsistent(engine_not_active_error(status)))
        }
        _ => None,
    }
}

const REGISTRY_ENGINE_CONFIG: EngineConfig = EngineConfig {
    ring_capacity: 1024,
    checkpoint_slots: 0,
};

pub struct EthereumRpc<P> {
    provider: P,
    pool: AlloyAddress,
    registry: AlloyAddress,
    registry_engine: Mutex<Engine<RegistryFold>>,
}

impl<P> EthereumRpc<P> {
    pub fn new(provider: P, pool: AlloyAddress, registry: AlloyAddress) -> Self {
        let engine = Engine::new(RegistryFold::default(), REGISTRY_ENGINE_CONFIG)
            .expect("registry engine config is a fixed, valid power of two");
        Self {
            provider,
            pool,
            registry,
            registry_engine: Mutex::new(engine),
        }
    }
}

fn rpc_err(e: ContractError) -> ChainError {
    ChainError::Rpc(Box::new(e))
}

/// The one checked conversion every `Bytes32 <-> B256/U256/Address` helper below
/// funnels through: a value at or above the BN254 modulus is rejected, the Rust twin
/// of the contract's `requireCanonical`, never silently reduced.
fn checked_bytes32(raw: [u8; 32]) -> Result<Bytes32, ChainError> {
    let bytes = Bytes32::from(raw);
    Fr::try_from(bytes).map_err(ChainError::NonCanonical)?;
    Ok(bytes)
}

fn bytes32_to_b256(value: Bytes32) -> Result<B256, ChainError> {
    let raw: [u8; 32] = value.as_ref().try_into().expect("Bytes32 is 32 bytes");
    checked_bytes32(raw)?;
    Ok(B256::from(raw))
}

fn b256_to_bytes32(value: B256) -> Result<Bytes32, ChainError> {
    checked_bytes32(value.0)
}

fn bytes32_to_u256(value: Bytes32) -> Result<U256, ChainError> {
    Ok(U256::from_be_bytes(bytes32_to_b256(value)?.0))
}

/// The reverse of `bytes32_to_u256`. No production call site needs it yet (every
/// `U256` this adapter reads back from the chain is an epoch or generation counter
/// converted through `u256_to_u64`, not a field element), so it is `cfg(test)`-only,
/// kept for the round-trip test the port's canonicality contract calls for.
#[cfg(test)]
fn u256_to_bytes32(value: U256) -> Result<Bytes32, ChainError> {
    checked_bytes32(value.to_be_bytes::<32>())
}

fn u256_to_u64(value: U256) -> Result<u64, ChainError> {
    u64::try_from(value)
        .map_err(|e| ChainError::Rpc(Box::new(std::io::Error::other(e.to_string()))))
}

/// `recipient` is `address`-typed on-chain, unlike `token`, which stays `uint256`
/// even though both public inputs originate as a 160-bit value under `Fr`.
fn bytes32_to_recipient(value: Bytes32) -> Result<AlloyAddress, ChainError> {
    let raw = value.as_ref();
    if raw[..12].iter().any(|&b| b != 0) {
        return Err(ChainError::Rpc(Box::new(std::io::Error::other(
            "recipient public input exceeds 160 bits",
        ))));
    }
    Ok(AlloyAddress::from_slice(&raw[12..]))
}

/// No production call site: every outgoing `Address` this adapter sends is already a
/// `Bytes32` public input converted through `bytes32_to_recipient`. Kept `cfg(test)`
/// for the `address_from_alloy` round-trip test.
#[cfg(test)]
fn address_to_alloy(address: Address) -> AlloyAddress {
    AlloyAddress::from_slice(address.as_ref())
}

fn address_from_alloy(address: AlloyAddress) -> Address {
    Address::from(address.into_array())
}

fn deposit_params(
    proof: &CircuitProof,
    encrypted_notes: AlloyBytes,
) -> Result<IShieldedPool::DepositParams, ChainError> {
    use crate::domain::public_inputs::deposit as idx;
    debug_assert_eq!(proof.public_inputs.len(), idx::LENGTH);
    let pi = &proof.public_inputs;
    Ok(IShieldedPool::DepositParams {
        proof: AlloyBytes::from(proof.proof.clone()),
        commitment: bytes32_to_b256(pi[idx::COMMITMENT])?,
        token: bytes32_to_u256(pi[idx::TOKEN])?,
        amount: bytes32_to_u256(pi[idx::AMOUNT])?,
        attestationRoot: bytes32_to_b256(pi[idx::ATTESTATION_ROOT])?,
        velocityNullifier: bytes32_to_b256(pi[idx::VELOCITY_NULLIFIER])?,
        complianceCommitmentOut: bytes32_to_b256(pi[idx::COMPLIANCE_COMMITMENT_OUT])?,
        epoch: bytes32_to_u256(pi[idx::EPOCH])?,
        epochSeconds: bytes32_to_u256(pi[idx::EPOCH_SECONDS])?,
        policySourceHash: bytes32_to_b256(pi[idx::POLICY_SOURCE_HASH])?,
        commitmentRoot: bytes32_to_b256(pi[idx::COMMITMENT_ROOT])?,
        attesterRevocationRoot: bytes32_to_b256(pi[idx::ATTESTER_REVOCATION_ROOT])?,
        minAcceptedGeneration: bytes32_to_u256(pi[idx::MIN_ACCEPTED_GENERATION])?,
        payloadCommitment: bytes32_to_b256(pi[idx::PAYLOAD_COMMITMENT])?,
        encryptedNotes: encrypted_notes,
    })
}

fn transfer_params(
    proof: &CircuitProof,
    encrypted_notes: AlloyBytes,
) -> Result<IShieldedPool::TransferParams, ChainError> {
    use crate::domain::public_inputs::transfer as idx;
    debug_assert_eq!(proof.public_inputs.len(), idx::LENGTH);
    let pi = &proof.public_inputs;
    Ok(IShieldedPool::TransferParams {
        proof: AlloyBytes::from(proof.proof.clone()),
        nullifier0: bytes32_to_b256(pi[idx::NULLIFIER_0])?,
        nullifier1: bytes32_to_b256(pi[idx::NULLIFIER_1])?,
        commitmentOut0: bytes32_to_b256(pi[idx::COMMITMENT_OUT_0])?,
        commitmentOut1: bytes32_to_b256(pi[idx::COMMITMENT_OUT_1])?,
        commitmentRoot: bytes32_to_b256(pi[idx::COMMITMENT_ROOT])?,
        velocityNullifier: bytes32_to_b256(pi[idx::VELOCITY_NULLIFIER])?,
        complianceCommitmentOut: bytes32_to_b256(pi[idx::COMPLIANCE_COMMITMENT_OUT])?,
        epoch: bytes32_to_u256(pi[idx::EPOCH])?,
        epochSeconds: bytes32_to_u256(pi[idx::EPOCH_SECONDS])?,
        policySourceHash: bytes32_to_b256(pi[idx::POLICY_SOURCE_HASH])?,
        attestationRoot: bytes32_to_b256(pi[idx::ATTESTATION_ROOT])?,
        attesterRevocationRoot: bytes32_to_b256(pi[idx::ATTESTER_REVOCATION_ROOT])?,
        minAcceptedGeneration: bytes32_to_u256(pi[idx::MIN_ACCEPTED_GENERATION])?,
        payloadCommitment: bytes32_to_b256(pi[idx::PAYLOAD_COMMITMENT])?,
        encryptedNotes: encrypted_notes,
    })
}

fn withdraw_params(
    proof: &CircuitProof,
    encrypted_notes: AlloyBytes,
) -> Result<IShieldedPool::WithdrawParams, ChainError> {
    use crate::domain::public_inputs::gated_withdraw as idx;
    debug_assert_eq!(proof.public_inputs.len(), idx::LENGTH);
    let pi = &proof.public_inputs;
    Ok(IShieldedPool::WithdrawParams {
        proof: AlloyBytes::from(proof.proof.clone()),
        nullifier: bytes32_to_b256(pi[idx::NULLIFIER])?,
        token: bytes32_to_u256(pi[idx::TOKEN])?,
        amount: bytes32_to_u256(pi[idx::AMOUNT])?,
        recipient: bytes32_to_recipient(pi[idx::RECIPIENT])?,
        commitmentRoot: bytes32_to_b256(pi[idx::COMMITMENT_ROOT])?,
        velocityNullifier: bytes32_to_b256(pi[idx::VELOCITY_NULLIFIER])?,
        complianceCommitmentOut: bytes32_to_b256(pi[idx::COMPLIANCE_COMMITMENT_OUT])?,
        epoch: bytes32_to_u256(pi[idx::EPOCH])?,
        epochSeconds: bytes32_to_u256(pi[idx::EPOCH_SECONDS])?,
        policySourceHash: bytes32_to_b256(pi[idx::POLICY_SOURCE_HASH])?,
        attestationRoot: bytes32_to_b256(pi[idx::ATTESTATION_ROOT])?,
        attesterRevocationRoot: bytes32_to_b256(pi[idx::ATTESTER_REVOCATION_ROOT])?,
        minAcceptedGeneration: bytes32_to_u256(pi[idx::MIN_ACCEPTED_GENERATION])?,
        payloadCommitment: bytes32_to_b256(pi[idx::PAYLOAD_COMMITMENT])?,
        encryptedNotes: encrypted_notes,
    })
}

fn withdraw_blocked_params(
    proof: &CircuitProof,
) -> Result<IShieldedPool::WithdrawBlockedParams, ChainError> {
    use crate::domain::public_inputs::ungated_withdraw as idx;
    debug_assert_eq!(proof.public_inputs.len(), idx::LENGTH);
    let pi = &proof.public_inputs;
    Ok(IShieldedPool::WithdrawBlockedParams {
        proof: AlloyBytes::from(proof.proof.clone()),
        nullifier: bytes32_to_b256(pi[idx::NULLIFIER])?,
        token: bytes32_to_u256(pi[idx::TOKEN])?,
        amount: bytes32_to_u256(pi[idx::AMOUNT])?,
        recipient: bytes32_to_recipient(pi[idx::RECIPIENT])?,
        commitmentRoot: bytes32_to_b256(pi[idx::COMMITMENT_ROOT])?,
    })
}

impl<P: Provider + Clone + Send + Sync + 'static> ChainReader for EthereumRpc<P> {
    fn current_epoch(&self) -> impl Future<Output = Result<Epoch, ChainError>> + Send {
        let pool = IShieldedPool::new(self.pool, self.provider.clone());
        async move {
            let epoch = pool.currentEpoch().call().await.map_err(rpc_err)?;
            Ok(Epoch(u256_to_u64(epoch)?))
        }
    }

    fn commitment_root(
        &self,
    ) -> impl Future<Output = Result<Bytes32, ChainError>> + Send {
        let pool = IShieldedPool::new(self.pool, self.provider.clone());
        async move {
            let root = pool.commitmentRoot().call().await.map_err(rpc_err)?;
            b256_to_bytes32(root)
        }
    }

    fn is_known_commitment_root(
        &self,
        root: Bytes32,
    ) -> impl Future<Output = Result<bool, ChainError>> + Send {
        let pool = IShieldedPool::new(self.pool, self.provider.clone());
        async move {
            let root = bytes32_to_b256(root)?;
            pool.isKnownRoot(root).call().await.map_err(rpc_err)
        }
    }

    fn registry_values(
        &self,
    ) -> impl Future<Output = Result<RegistrySnapshot, ChainError>> + Send {
        let registry = IAttestationRegistry::new(self.registry, self.provider.clone());
        async move {
            let attestation_root =
                registry.attestationRoot().call().await.map_err(rpc_err)?;
            let attester_revocation_root = registry
                .attesterRevocationRoot()
                .call()
                .await
                .map_err(rpc_err)?;
            let min_accepted_generation = registry
                .minAcceptedGeneration()
                .call()
                .await
                .map_err(rpc_err)?;
            Ok(RegistrySnapshot {
                attestation_root: b256_to_bytes32(attestation_root)?,
                attester_revocation_root: b256_to_bytes32(attester_revocation_root)?,
                min_accepted_generation: u256_to_u64(min_accepted_generation)?,
            })
        }
    }

    fn effective_policy(
        &self,
    ) -> impl Future<Output = Result<PolicyPair, ChainError>> + Send {
        let pool = IShieldedPool::new(self.pool, self.provider.clone());
        async move {
            let result = pool.effectivePolicy().call().await.map_err(rpc_err)?;
            Ok(PolicyPair {
                verifier: address_from_alloy(result.verifier),
                policy_source_hash: b256_to_bytes32(result.sourceHash)?,
            })
        }
    }

    fn is_nullifier_spent(
        &self,
        nullifier: Bytes32,
    ) -> impl Future<Output = Result<bool, ChainError>> + Send {
        let pool = IShieldedPool::new(self.pool, self.provider.clone());
        async move {
            let n = bytes32_to_b256(nullifier)?;
            pool.nullifiers(n).call().await.map_err(rpc_err)
        }
    }
}

/// A generous fixed limit, set on every submission below so the fill pipeline never
/// calls `eth_estimateGas`. Estimating first would simulate the call and turn a
/// revert into a `.send()`-time error, which defeats the point of confirming through
/// the mined receipt: the one case this adapter exists to catch is a transaction that
/// looked valid when signed and reverted anyway.
const SUBMIT_GAS_LIMIT: u64 = 5_000_000;

/// Awaits the mined receipt and turns a failed one into `ChainError::Reverted`, so a
/// caller's `Ok` always means the transaction actually took effect on chain.
async fn confirm<N: alloy::network::Network>(
    pending: alloy::providers::PendingTransactionBuilder<N>,
) -> Result<TxHash, ChainError> {
    use alloy::network::ReceiptResponse;

    let receipt = pending
        .get_receipt()
        .await
        .map_err(|e| ChainError::ReceiptUnavailable(Box::new(e)))?;
    let tx_hash = TxHash(receipt.transaction_hash().0);
    if !receipt.status() {
        return Err(ChainError::Reverted { tx_hash });
    }
    Ok(tx_hash)
}

impl<P: Provider + Clone + Send + Sync + 'static> ChainWriter for EthereumRpc<P> {
    fn submit_deposit(
        &self,
        proof: &CircuitProof,
        encrypted_payload: &[u8],
    ) -> impl Future<Output = Result<TxHash, ChainError>> + Send {
        let provider = self.provider.clone();
        let pool_addr = self.pool;
        let params = deposit_params(proof, AlloyBytes::from(encrypted_payload.to_vec()));
        async move {
            let pool = IShieldedPool::new(pool_addr, provider);
            let pending = pool
                .deposit(params?)
                .gas(SUBMIT_GAS_LIMIT)
                .send()
                .await
                .map_err(rpc_err)?;
            confirm(pending).await
        }
    }

    fn submit_transfer(
        &self,
        proof: &CircuitProof,
        encrypted_payload: &[u8],
    ) -> impl Future<Output = Result<TxHash, ChainError>> + Send {
        let provider = self.provider.clone();
        let pool_addr = self.pool;
        let params = transfer_params(proof, AlloyBytes::from(encrypted_payload.to_vec()));
        async move {
            let pool = IShieldedPool::new(pool_addr, provider);
            let pending = pool
                .transfer(params?)
                .gas(SUBMIT_GAS_LIMIT)
                .send()
                .await
                .map_err(rpc_err)?;
            confirm(pending).await
        }
    }

    fn submit_withdraw(
        &self,
        proof: &CircuitProof,
        encrypted_payload: &[u8],
    ) -> impl Future<Output = Result<TxHash, ChainError>> + Send {
        let provider = self.provider.clone();
        let pool_addr = self.pool;
        let params = withdraw_params(proof, AlloyBytes::from(encrypted_payload.to_vec()));
        async move {
            let pool = IShieldedPool::new(pool_addr, provider);
            let pending = pool
                .withdraw(params?)
                .gas(SUBMIT_GAS_LIMIT)
                .send()
                .await
                .map_err(rpc_err)?;
            confirm(pending).await
        }
    }

    fn submit_withdraw_blocked(
        &self,
        proof: &CircuitProof,
    ) -> impl Future<Output = Result<TxHash, ChainError>> + Send {
        let provider = self.provider.clone();
        let pool_addr = self.pool;
        let params = withdraw_blocked_params(proof);
        async move {
            let pool = IShieldedPool::new(pool_addr, provider);
            let pending = pool
                .withdrawBlocked(params?)
                .gas(SUBMIT_GAS_LIMIT)
                .send()
                .await
                .map_err(rpc_err)?;
            confirm(pending).await
        }
    }

    fn claim_blocked(
        &self,
        nullifier: Bytes32,
    ) -> impl Future<Output = Result<TxHash, ChainError>> + Send {
        let provider = self.provider.clone();
        let pool_addr = self.pool;
        async move {
            let n = bytes32_to_b256(nullifier)?;
            let pool = IShieldedPool::new(pool_addr, provider);
            let pending = pool
                .claimBlocked(n)
                .gas(SUBMIT_GAS_LIMIT)
                .send()
                .await
                .map_err(rpc_err)?;
            confirm(pending).await
        }
    }
}

/// Topic0 of every registry event the fold tracks, in one list so the query and the
/// dispatch below cannot drift apart.
const REGISTRY_TOPICS: [B256; 4] = [
    IAttestationRegistry::AttesterAdded::SIGNATURE_HASH,
    IAttestationRegistry::AttesterRemoved::SIGNATURE_HASH,
    IAttestationRegistry::AttesterRevocationLowered::SIGNATURE_HASH,
    IAttestationRegistry::AttestationAdded::SIGNATURE_HASH,
];

/// One query over `from..=to` for every tracked registry event.
fn registry_filter(registry: AlloyAddress, from: u64, to: u64) -> Filter {
    Filter::new()
        .address(registry)
        .event_signature(REGISTRY_TOPICS.to_vec())
        .from_block(from)
        .to_block(to)
}

/// Dispatches one log on its topic0; anything else the node admitted decodes to none.
fn decode_registry_event(log: &Log) -> Option<RegistryEvent> {
    let topic = *log.topic0()?;
    if topic == IAttestationRegistry::AttesterAdded::SIGNATURE_HASH {
        let event = log
            .log_decode::<IAttestationRegistry::AttesterAdded>()
            .ok()?;
        return Some(RegistryEvent::AttesterAdded(event.inner.attester));
    }
    if topic == IAttestationRegistry::AttesterRemoved::SIGNATURE_HASH {
        let event = log
            .log_decode::<IAttestationRegistry::AttesterRemoved>()
            .ok()?;
        return Some(RegistryEvent::AttesterRemoved(event.inner.attester));
    }
    if topic == IAttestationRegistry::AttesterRevocationLowered::SIGNATURE_HASH {
        let event = log
            .log_decode::<IAttestationRegistry::AttesterRevocationLowered>()
            .ok()?;
        return Some(RegistryEvent::RevocationLowered(
            event.inner.attester,
            event.inner.revokedAtEpoch,
        ));
    }
    if topic == IAttestationRegistry::AttestationAdded::SIGNATURE_HASH {
        let event = log
            .log_decode::<IAttestationRegistry::AttestationAdded>()
            .ok()?;
        return Some(RegistryEvent::AttestationAdded(event.inner.data));
    }
    None
}

/// Fetches the header of one block as the batch boundary the engine rechecks.
async fn header_at<P: Provider>(
    provider: &P,
    number: u64,
) -> Result<Option<BlockRef>, ChainError> {
    let block = provider
        .get_block_by_number(number.into())
        .await
        .map_err(|e| ChainError::Rpc(Box::new(e)))?;
    Ok(block.map(|block| BlockRef {
        number,
        hash: block.header.hash.0,
    }))
}

/// Groups decoded logs into one batch, oldest block first and ascending log index
/// within a block, which is the ordering `apply_batch` validates. A block whose logs
/// all fail to decode contributes no span.
fn batch_from_logs(logs: &[Log]) -> Result<Batch<RegistryEvent>, ChainError> {
    let mut entries: Vec<(BlockRef, u32, RegistryEvent)> = Vec::with_capacity(logs.len());
    for log in logs {
        let (Some(number), Some(hash), Some(index)) =
            (log.block_number, log.block_hash, log.log_index)
        else {
            continue
        };
        let Some(event) = decode_registry_event(log) else {
            continue
        };
        let index = u32::try_from(index).map_err(|_| {
            ChainError::Rpc(Box::new(std::io::Error::other(format!(
                "log index {index} in block {number} exceeds u32"
            ))))
        })?;
        entries.push((
            BlockRef {
                number,
                hash: hash.0,
            },
            index,
            event,
        ));
    }
    entries.sort_by_key(|(block, index, _)| (block.number, *index));

    let mut batch = Batch::new();
    for span in entries.chunk_by(|a, b| a.0.number == b.0.number) {
        batch.push_block(span[0].0, span.iter().map(|(_, i, e)| (*i, e.clone())));
    }
    Ok(batch)
}

/// Among a subject's several attestations the last in `events`, the most recent, wins.
/// `events` must already be in fold order (chain order); its index at that position is
/// the leaf index, per the ordinal rule documented on `RegistryFold`.
fn latest_attestation_for_subject(
    events: &[IAttestationRegistry::AttestationAdded],
    subject: B256,
) -> Option<(LeafIndex, IAttestationRegistry::AttestationAdded)> {
    events
        .iter()
        .enumerate()
        .rfind(|(_, ev)| ev.subjectPubkeyHash == subject)
        .map(|(index, ev)| (LeafIndex(index as u64), ev.clone()))
}

impl<P: Provider + Clone + Send + Sync + 'static> EthereumRpc<P> {
    /// Fetches every registry event since `cursor` (all of them, from block 0, when
    /// `None`), pinning `to_block` to one head fetch so a new block cannot straddle and
    /// split across two batches. When `cursor` is set, also refetches that block's
    /// header as the batch's boundary, the reorg check `apply_batch` performs even on
    /// an empty batch.
    async fn fetch_registry_batch(
        &self,
        cursor: Option<Position>,
    ) -> Result<Batch<RegistryEvent>, ChainError> {
        let head = self
            .provider
            .get_block_number()
            .await
            .map_err(|e| ChainError::Rpc(Box::new(e)))?;

        let boundary = match cursor {
            Some(c) => header_at(&self.provider, c.block).await?,
            None => None,
        };

        let from = cursor.map_or(0u64, |c| c.block + 1);
        let logs = self
            .provider
            .get_logs(&registry_filter(self.registry, from, head))
            .await
            .map_err(|e| ChainError::Rpc(Box::new(e)))?;

        let mut batch = batch_from_logs(&logs)?;
        batch.boundary = boundary;
        Ok(batch)
    }

    /// Syncs `registry_engine` to the chain tip. Fetches complete before the engine is
    /// locked; the lock is never held across an `.await`.
    ///
    /// A fold-originated inconsistency (or an engine already halted/poisoned from a
    /// prior call) fails immediately, since corrupt history is deterministic and
    /// retrying reproduces it. Any other rejection (a boundary mismatch, a suspected
    /// fork, an unobserved cursor block) resets the engine and retries once with a full
    /// refetch from block 0; a second failure is a plain RPC error.
    async fn sync_registry(&self) -> Result<(), ChainError> {
        let cursor = {
            let engine = self.registry_engine.lock().expect("registry engine lock poisoned");
            engine.cursor()
        };
        let batch = self.fetch_registry_batch(cursor).await?;

        let result = {
            let mut engine = self.registry_engine.lock().expect("registry engine lock poisoned");
            engine.apply_batch(&batch)
        };

        let Err(error) = result else {
            return Ok(());
        };
        if let Some(chain_error) = classify_registry_apply_error(error) {
            return Err(chain_error);
        }

        {
            let mut engine = self.registry_engine.lock().expect("registry engine lock poisoned");
            engine.reset(RegistryFold::default());
        }
        let batch = self.fetch_registry_batch(None).await?;
        let mut engine = self.registry_engine.lock().expect("registry engine lock poisoned");
        engine
            .apply_batch(&batch)
            .map(|_| ())
            .map_err(|e| ChainError::Rpc(Box::new(e)))
    }
}

impl<P: Provider + Clone + Send + Sync + 'static> AttestationSource for EthereumRpc<P> {
    async fn current_attestation(
        &self,
        owner_pubkey: OwnerPubkey,
    ) -> Result<Option<AttestationRecord>, ChainError> {
        // `subjectPubkeyHash` is `owner_pubkey` itself, not a further hash of it: the
        // contract's leaf is `PoseidonT6(subjectPubkeyHash, msg.sender, ...)`, matching
        // `domain::attestation::AttestationLeaf::hash`.
        let subject = bytes32_to_b256(owner_pubkey.as_bytes32())?;
        self.sync_registry().await?;

        let engine = self.registry_engine.lock().expect("registry engine lock poisoned");
        let fold = engine.fold();
        let Some((leaf_index, ev)) = latest_attestation_for_subject(&fold.attestations, subject)
        else {
            return Ok(None);
        };

        let attester = address_from_alloy(ev.attester);
        let revoked_at = fold.tree.revoked_at_epoch_of(attester).unwrap_or(u64::MAX);
        let revocation_proof = fold.tree.proof(attester).unwrap_or_default();

        Ok(Some(AttestationRecord {
            attester,
            generation: Generation(ev.generation),
            issued_at: ev.issuedAt,
            expires_at: ev.expiresAt,
            leaf_index,
            revoked_at,
            revocation_proof,
        }))
    }
}

#[cfg(test)]
mod tests {
    use chainfold::BlockRef;

    use super::*;

    /// One `AttesterAdded` log, sited at `(block, log_index)`.
    fn attester_added_log(
        block: u64,
        log_index: u64,
        attester: AlloyAddress,
        hash_byte: u8,
    ) -> Log {
        raw_log(
            block,
            log_index,
            hash_byte,
            vec![
                IAttestationRegistry::AttesterAdded::SIGNATURE_HASH,
                attester.into_word(),
            ],
        )
    }

    fn raw_log(block: u64, log_index: u64, hash_byte: u8, topics: Vec<B256>) -> Log {
        Log {
            inner: alloy::primitives::Log::new(
                AlloyAddress::ZERO,
                topics,
                AlloyBytes::new(),
            )
            .expect("topic count fits a log"),
            block_number: Some(block),
            block_hash: Some(B256::repeat_byte(hash_byte)),
            log_index: Some(log_index),
            ..Default::default()
        }
    }

    #[test]
    fn batch_from_logs_orders_spans_by_block_then_log_index() {
        // given four attester events supplied out of (block, log index) order
        let first = AlloyAddress::from_slice(&[0x01; 20]);
        let second = AlloyAddress::from_slice(&[0x02; 20]);
        let logs = vec![
            attester_added_log(2, 1, second, 0x02),
            attester_added_log(1, 5, first, 0x01),
            attester_added_log(2, 0, first, 0x02),
            attester_added_log(1, 1, second, 0x01),
        ];

        // when they are grouped into one batch
        let batch = batch_from_logs(&logs).expect("logs group");

        // then the batch passes the shape the engine validates, one ascending span per block
        batch.validate().expect("batch shape is valid");
        let spans: Vec<(u64, Vec<u32>)> = batch
            .spans()
            .map(|span| (span.number, span.log_indices.to_vec()))
            .collect();
        assert_eq!(spans, vec![(1, vec![1, 5]), (2, vec![0, 1])])
    }

    #[test]
    fn batch_from_logs_drops_a_block_whose_logs_all_fail_to_decode() {
        // given a single log in block 3 carrying an unrecognised topic0
        let logs = vec![raw_log(3, 0, 0x03, vec![B256::repeat_byte(0xff)])];

        // when it is grouped into a batch
        let batch = batch_from_logs(&logs).expect("logs group");

        // then the batch carries no span, rather than an empty one the engine rejects
        assert!(batch.is_empty())
    }

    #[test]
    fn bytes32_to_u256_round_trips_below_the_modulus() {
        let bytes = Bytes32::from([7u8; 32]);
        let value = bytes32_to_u256(bytes).expect("below modulus");
        let back = u256_to_bytes32(value).expect("round trip");
        assert_eq!(back, bytes);
    }

    #[test]
    fn bytes32_to_u256_rejects_a_value_at_the_modulus() {
        let modulus_bytes: [u8; 32] = crate::BN254_MODULUS
            .to_bytes_be()
            .try_into()
            .expect("32 bytes");
        let at_modulus = Bytes32::from(modulus_bytes);
        assert!(matches!(
            bytes32_to_u256(at_modulus),
            Err(ChainError::NonCanonical(_))
        ));
    }

    #[test]
    fn bytes32_to_u256_does_not_silently_reduce_a_value_above_the_modulus() {
        let mut above = crate::BN254_MODULUS.to_bytes_be();
        *above.last_mut().unwrap() += 1;
        let bytes = Bytes32::from(<[u8; 32]>::try_from(above).unwrap());
        assert!(bytes32_to_u256(bytes).is_err());
    }

    #[test]
    fn deposit_params_maps_public_inputs_by_abi_index() {
        let public_inputs =
            distinguishable_inputs(crate::domain::public_inputs::deposit::LENGTH);
        let proof = CircuitProof {
            proof: vec![0xab; 64],
            public_inputs: public_inputs.clone(),
        };
        let params =
            deposit_params(&proof, AlloyBytes::new()).expect("all inputs canonical");
        use crate::domain::public_inputs::deposit as idx;
        assert_eq!(
            params.commitment,
            bytes32_to_b256(public_inputs[idx::COMMITMENT]).unwrap()
        );
        assert_eq!(
            params.token,
            bytes32_to_u256(public_inputs[idx::TOKEN]).unwrap()
        );
        assert_eq!(
            params.amount,
            bytes32_to_u256(public_inputs[idx::AMOUNT]).unwrap()
        );
        assert_eq!(
            params.minAcceptedGeneration,
            bytes32_to_u256(public_inputs[idx::MIN_ACCEPTED_GENERATION]).unwrap()
        );
        assert_eq!(
            params.payloadCommitment,
            bytes32_to_b256(public_inputs[idx::PAYLOAD_COMMITMENT]).unwrap()
        );
        assert_eq!(params.proof.as_ref(), proof.proof.as_slice());
    }

    #[test]
    fn transfer_params_maps_public_inputs_by_abi_index() {
        let public_inputs =
            distinguishable_inputs(crate::domain::public_inputs::transfer::LENGTH);
        let proof = CircuitProof {
            proof: vec![],
            public_inputs: public_inputs.clone(),
        };
        let params =
            transfer_params(&proof, AlloyBytes::new()).expect("all inputs canonical");
        use crate::domain::public_inputs::transfer as idx;
        assert_eq!(
            params.nullifier0,
            bytes32_to_b256(public_inputs[idx::NULLIFIER_0]).unwrap()
        );
        assert_eq!(
            params.nullifier1,
            bytes32_to_b256(public_inputs[idx::NULLIFIER_1]).unwrap()
        );
        assert_eq!(
            params.commitmentOut1,
            bytes32_to_b256(public_inputs[idx::COMMITMENT_OUT_1]).unwrap()
        );
        assert_eq!(
            params.attesterRevocationRoot,
            bytes32_to_b256(public_inputs[idx::ATTESTER_REVOCATION_ROOT]).unwrap()
        );
        assert_eq!(
            params.payloadCommitment,
            bytes32_to_b256(public_inputs[idx::PAYLOAD_COMMITMENT]).unwrap()
        );
    }

    #[test]
    fn withdraw_params_maps_recipient_to_an_address_and_token_to_a_u256() {
        use crate::domain::public_inputs::gated_withdraw as idx;
        let mut public_inputs = distinguishable_inputs(idx::LENGTH);
        // A canonical value whose top 12 bytes are zero, so it converts to an address.
        let mut recipient_bytes = [0u8; 32];
        recipient_bytes[12..].copy_from_slice(&[0x11; 20]);
        public_inputs[idx::RECIPIENT] = Bytes32::from(recipient_bytes);
        let proof = CircuitProof {
            proof: vec![1, 2, 3],
            public_inputs: public_inputs.clone(),
        };
        let params =
            withdraw_params(&proof, AlloyBytes::new()).expect("all inputs canonical");
        assert_eq!(params.recipient, AlloyAddress::from_slice(&[0x11; 20]));
        assert_eq!(
            params.token,
            bytes32_to_u256(public_inputs[idx::TOKEN]).unwrap()
        );
        assert_eq!(
            params.nullifier,
            bytes32_to_b256(public_inputs[idx::NULLIFIER]).unwrap()
        );
        assert_eq!(
            params.payloadCommitment,
            bytes32_to_b256(public_inputs[idx::PAYLOAD_COMMITMENT]).unwrap()
        );
    }

    #[test]
    fn withdraw_blocked_params_maps_the_five_ungated_public_inputs() {
        use crate::domain::public_inputs::ungated_withdraw as idx;
        let mut public_inputs = distinguishable_inputs(idx::LENGTH);
        let mut recipient_bytes = [0u8; 32];
        recipient_bytes[12..].copy_from_slice(&[0x22; 20]);
        public_inputs[idx::RECIPIENT] = Bytes32::from(recipient_bytes);
        let proof = CircuitProof {
            proof: vec![9, 9],
            public_inputs: public_inputs.clone(),
        };
        let params = withdraw_blocked_params(&proof).expect("all inputs canonical");
        assert_eq!(params.recipient, AlloyAddress::from_slice(&[0x22; 20]));
        assert_eq!(
            params.commitmentRoot,
            bytes32_to_b256(public_inputs[idx::COMMITMENT_ROOT]).unwrap()
        );
    }

    #[test]
    fn recipient_conversion_rejects_a_value_that_does_not_fit_in_160_bits() {
        let bytes = Bytes32::from([0x01; 32]);
        assert!(bytes32_to_recipient(bytes).is_err());
    }

    #[test]
    fn address_round_trips_through_alloy() {
        let addr = Address::from([0x42; 20]);
        let alloy_addr = address_to_alloy(addr);
        assert_eq!(address_from_alloy(alloy_addr), addr);
    }

    fn attestation_added(
        subject: u8,
        generation: u64,
    ) -> IAttestationRegistry::AttestationAdded {
        IAttestationRegistry::AttestationAdded {
            leaf: B256::from([0xee; 32]),
            subjectPubkeyHash: B256::from([subject; 32]),
            attester: AlloyAddress::from_slice(&[0x01; 20]),
            generation,
            issuedAt: 100,
            expiresAt: 200,
        }
    }

    /// Folds `(block, log_index, event)` triples, supplied in any order, through a
    /// fresh engine and returns it.
    fn fold_registry_events(
        entries: Vec<(u64, u32, RegistryEvent)>,
    ) -> Result<Engine<RegistryFold>, ApplyError<MerkleError>> {
        let mut batch = Batch::new();
        let mut entries = entries;
        entries.sort_by_key(|(block, log_index, _)| (*block, *log_index));
        for group in entries.chunk_by(|a, b| a.0 == b.0) {
            batch.push_block(
                BlockRef {
                    number: group[0].0,
                    hash: [group[0].0 as u8; 32],
                },
                group.iter().map(|(_, i, e)| (*i, e.clone())),
            );
        }
        let mut engine = Engine::new(RegistryFold::default(), REGISTRY_ENGINE_CONFIG)
            .expect("valid config");
        engine.apply_batch(&batch)?;
        Ok(engine)
    }

    #[test]
    fn leaf_index_is_the_event_ordinal_over_every_subject_in_chain_order() {
        // Supplied out of chain order, and interleaved across subjects: the ordinal
        // must come from the folded chain-order sequence, not from the input order and
        // not from a per-subject count.
        let entries = vec![
            (1, 1, RegistryEvent::AttestationAdded(attestation_added(0xbb, 7))),
            (2, 0, RegistryEvent::AttestationAdded(attestation_added(0xaa, 9))),
            (1, 0, RegistryEvent::AttestationAdded(attestation_added(0xaa, 5))),
        ];
        let engine = fold_registry_events(entries).expect("events apply cleanly");
        let attestations = &engine.fold().attestations;

        let (index, ev) = latest_attestation_for_subject(attestations, B256::from([0xaa; 32]))
            .expect("subject is attested");
        assert_eq!(index, LeafIndex(2));
        assert_eq!(ev.generation, 9);

        let (index, ev) = latest_attestation_for_subject(attestations, B256::from([0xbb; 32]))
            .expect("subject is attested");
        assert_eq!(index, LeafIndex(1));
        assert_eq!(ev.generation, 7);
    }

    #[test]
    fn an_unattested_subject_has_no_attestation() {
        let entries = vec![(1, 0, RegistryEvent::AttestationAdded(attestation_added(0xaa, 1)))];
        let engine = fold_registry_events(entries).expect("events apply cleanly");
        assert!(
            latest_attestation_for_subject(&engine.fold().attestations, B256::from([0xcc; 32]))
                .is_none()
        );
    }

    #[test]
    fn a_duplicate_attester_add_poisons_the_fold_and_surfaces_as_replay_inconsistent() {
        let attester = AlloyAddress::from_slice(&[0x03; 20]);
        let entries = vec![
            (1, 0, RegistryEvent::AttesterAdded(attester)),
            (1, 1, RegistryEvent::AttesterAdded(attester)),
        ];
        let error = match fold_registry_events(entries) {
            Ok(_) => panic!("a duplicate add is inconsistent"),
            Err(error) => error,
        };
        assert!(matches!(error, ApplyError::Poisoned { .. }));

        let chain_error =
            classify_registry_apply_error(error).expect("poisoned errors do not retry");
        assert!(matches!(chain_error, ChainError::ReplayInconsistent(_)));
    }

    /// Builds `count` distinct, canonical public inputs, index `i` distinguishable by
    /// its low byte, so a transposition between ABI fields shows up as a mismatch
    /// rather than every field coincidentally matching.
    fn distinguishable_inputs(count: usize) -> Vec<Bytes32> {
        (0..count)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[31] = i as u8;
                bytes[30] = 0xa0;
                Bytes32::from(bytes)
            })
            .collect()
    }
}

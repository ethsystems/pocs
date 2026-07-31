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

use std::future::Future;

use alloy::{
    contract::Error as ContractError,
    primitives::{
        Address as AlloyAddress,
        B256,
        Bytes as AlloyBytes,
        U256,
    },
    providers::Provider,
    rpc::types::Log,
    sol,
};
use ark_bn254::Fr;

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

pub struct EthereumRpc<P> {
    provider: P,
    pool: AlloyAddress,
    registry: AlloyAddress,
}

impl<P> EthereumRpc<P> {
    pub fn new(provider: P, pool: AlloyAddress, registry: AlloyAddress) -> Self {
        Self {
            provider,
            pool,
            registry,
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

fn log_key(log: &Log) -> (u64, u64) {
    (log.block_number.unwrap_or(0), log.log_index.unwrap_or(0))
}

/// Rebuilds the attester set (and each attester's `revokedAtEpoch`) by replaying
/// `AttesterAdded`/`AttesterRemoved`/`AttesterRevocationLowered` logs in block order,
/// since the fixed-depth revocation tree exposes no on-chain proof query and can only
/// be reconstructed by mirroring every write it has ever seen.
async fn attester_set_snapshot<P: Provider + Clone + Send + Sync + 'static>(
    provider: P,
    registry_addr: AlloyAddress,
) -> Result<RevocationTree, ChainError> {
    let registry = IAttestationRegistry::new(registry_addr, provider);

    let added = registry
        .event_filter::<IAttestationRegistry::AttesterAdded>()
        .from_block(0u64)
        .query()
        .await
        .map_err(|e| ChainError::Rpc(Box::new(e)))?;
    let removed = registry
        .event_filter::<IAttestationRegistry::AttesterRemoved>()
        .from_block(0u64)
        .query()
        .await
        .map_err(|e| ChainError::Rpc(Box::new(e)))?;
    let revoked = registry
        .event_filter::<IAttestationRegistry::AttesterRevocationLowered>()
        .from_block(0u64)
        .query()
        .await
        .map_err(|e| ChainError::Rpc(Box::new(e)))?;

    enum Op {
        Add(AlloyAddress),
        Remove(AlloyAddress),
        Revoke(AlloyAddress, u64),
    }
    let mut ops: Vec<((u64, u64), Op)> = Vec::new();
    for (ev, log) in &added {
        ops.push((log_key(log), Op::Add(ev.attester)));
    }
    for (ev, log) in &removed {
        ops.push((log_key(log), Op::Remove(ev.attester)));
    }
    for (ev, log) in &revoked {
        ops.push((log_key(log), Op::Revoke(ev.attester, ev.revokedAtEpoch)));
    }
    ops.sort_by_key(|(key, _)| *key);

    let mut tree = RevocationTree::new();
    for (_, op) in ops {
        let result: Result<(), MerkleError> = match op {
            Op::Add(a) => tree.add_attester(address_from_alloy(a)).map(|_| ()),
            Op::Remove(a) => tree.remove_attester(address_from_alloy(a)).map(|_| ()),
            Op::Revoke(a, epoch) => tree.lower_revocation(address_from_alloy(a), epoch).map(|_| ()),
        };
        // A failure here means the replayed event log is inconsistent with the tree's
        // write rules (e.g. a duplicate add, or a revoke/remove of an unknown attester),
        // which can only mean corrupt or missing history. Silently swallowing it used to
        // leave the tree state diverged from the registry with no diagnosable cause.
        result.map_err(ChainError::ReplayInconsistent)?;
    }
    Ok(tree)
}

/// `AttestationAdded` carries no leaf index, so it is the event's ordinal here.
/// `addAttestations` calls `_issueOne` once per subject in calldata order, and
/// `_issueOne` inserts into the append-only LeanIMT at `size` and then emits, one event
/// per insert, with no removal or update of the attestation tree anywhere in the
/// registry. So the ordinal of an `AttestationAdded` in (block, log index) order is its
/// leaf position. Reordering, filtering, or batching that loop away breaks this.
///
/// Among a subject's several attestations the last in that order, the most recent, wins.
fn latest_attestation_for_subject(
    mut events: Vec<(IAttestationRegistry::AttestationAdded, Log)>,
    subject: B256,
) -> Option<(LeafIndex, IAttestationRegistry::AttestationAdded)> {
    events.sort_by_key(|(_, log)| log_key(log));
    events
        .into_iter()
        .enumerate()
        .filter(|(_, (ev, _))| ev.subjectPubkeyHash == subject)
        .next_back()
        .map(|(index, (ev, _))| (LeafIndex(index as u64), ev))
}

impl<P: Provider + Clone + Send + Sync + 'static> AttestationSource for EthereumRpc<P> {
    fn current_attestation(
        &self,
        owner_pubkey: OwnerPubkey,
    ) -> impl Future<Output = Result<Option<AttestationRecord>, ChainError>> + Send {
        let provider = self.provider.clone();
        let registry_addr = self.registry;
        async move {
            // `subjectPubkeyHash` is `owner_pubkey` itself, not a further hash of it:
            // the contract's leaf is `PoseidonT6(subjectPubkeyHash, msg.sender, ...)`,
            // matching `domain::attestation::AttestationLeaf::hash`.
            let subject = bytes32_to_b256(owner_pubkey.as_bytes32())?;
            let registry = IAttestationRegistry::new(registry_addr, provider.clone());
            let added = registry
                .event_filter::<IAttestationRegistry::AttestationAdded>()
                .from_block(0u64)
                .query()
                .await
                .map_err(|e| ChainError::Rpc(Box::new(e)))?;

            let Some((leaf_index, ev)) = latest_attestation_for_subject(added, subject)
            else {
                return Ok(None);
            };

            let tree = attester_set_snapshot(provider, registry_addr).await?;
            let attester = address_from_alloy(ev.attester);
            let revoked_at = tree.revoked_at_epoch_of(attester).unwrap_or(u64::MAX);
            let revocation_proof = tree.proof(attester).unwrap_or_default();

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
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn log_at(block: u64, index: u64) -> Log {
        Log {
            block_number: Some(block),
            log_index: Some(index),
            ..Log::default()
        }
    }

    #[test]
    fn leaf_index_is_the_event_ordinal_over_every_subject_in_chain_order() {
        // Supplied out of chain order, and interleaved across subjects: the ordinal
        // must come from the sorted full sequence, not from the input order and not
        // from a per-subject count.
        let events = vec![
            (attestation_added(0xbb, 7), log_at(1, 1)),
            (attestation_added(0xaa, 9), log_at(2, 0)),
            (attestation_added(0xaa, 5), log_at(1, 0)),
        ];

        let (index, ev) =
            latest_attestation_for_subject(events.clone(), B256::from([0xaa; 32]))
                .expect("subject is attested");
        assert_eq!(index, LeafIndex(2));
        assert_eq!(ev.generation, 9);

        let (index, ev) = latest_attestation_for_subject(events, B256::from([0xbb; 32]))
            .expect("subject is attested");
        assert_eq!(index, LeafIndex(1));
        assert_eq!(ev.generation, 7);
    }

    #[test]
    fn an_unattested_subject_has_no_attestation() {
        let events = vec![(attestation_added(0xaa, 1), log_at(1, 0))];
        assert!(latest_attestation_for_subject(events, B256::from([0xcc; 32])).is_none());
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

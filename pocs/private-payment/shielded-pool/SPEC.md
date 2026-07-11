---
title: "Shielded Pool Private Payments"
status: Draft
version: 0.1.0
authors: ["Aaryamann"]
created: 2025-02-04
ethsystems_use_case: "https://github.com/ethsystems/map/blob/master/use-cases/private-stablecoins.md"
ethsystems_approach: "https://github.com/ethsystems/map/blob/master/approaches/approach-private-payments.md"
---

# Shielded Pool Private Payments: Protocol Specification

## Executive Summary

This protocol enables institutional stablecoin payments with transaction-level privacy while maintaining regulatory compliance. Unlike consumer-focused privacy protocols (e.g., Railgun, Tornado Cash), this design prioritizes **compliance-first privacy**: only KYC-verified participants can enter the shielded pool, verified via zero-knowledge proofs against an on-chain attestation registry. The protocol uses a UTXO-based commitment/nullifier scheme with dual-key architecture (spending key for transfers, viewing key for audits), enabling confidential payments without sacrificing institutional requirements for regulatory oversight and audit trails.

## Problem Statement

Institutional payment flows on public blockchains expose sensitive operational data:

- **Treasury operations**: Visible cash positions and movement patterns
- **Supplier relationships**: Payment destinations reveal business relationships
- **Settlement patterns**: Timing and frequency expose trading strategies
- **Competitive intelligence**: Aggregated on-chain data enables competitor analysis

Institutions require payment privacy equivalent to traditional banking while operating on public infrastructure.

### Constraints

| Category | Requirement |
|----------|-------------|
| **Privacy** | Amounts, counterparties, and transaction timing hidden from public observers. Transaction existence remains visible. |
| **Regulatory** | Only KYC-verified participants. Viewing keys enable selective disclosure for AML/CFT monitoring. |
| **Operational** | Near real-time settlement (minutes). Compatible with existing ERC-20 stablecoins without issuer modifications. |
| **Trust** | Relayers cannot steal funds or link transactions. Compliance authorities cannot forge attestations for non-verified parties. |
| **Deployable on Ethereum L1** | Inherits security properties of the L1's consensus and access to bridged liquidity |  

## Approach

### Strategy

The protocol implements a **gated shielded pool** with four core mechanisms:

1. **Attestation-Gated Entry**: Deposits require ZK proof of inclusion in an on-chain KYC attestation tree, preventing anonymous participation.
2. **UTXO Model**: Funds exist as encrypted "notes" (commitments) spent via nullifiers, enabling unlinkable transfers within the pool.
3. **Dual-Key Architecture**: Separate spending keys (for transfers) and viewing keys (for audits) support institutional key management and regulatory disclosure.
4. **Relayer Abstraction**: Third-party relayers submit transactions on behalf of users, abstracting gas costs and preventing timing correlation.

### Why This Approach

| Alternative | Trade-off | Why Not |
|------------|-----------|---------|
| Account-based encryption (e.g., Aztec) | Full programmability but requires new L2 deployment | PoC targets L1/existing stablecoins |
| Simple payload encryption | Preserves on-chain data but breaks verifiability and atomicity | Cannot prove compliance without decryption |
| Tornado Cash model | Maximum anonymity but no compliance gating | Regulatory non-starter for institutions |
| FHE-based payments | Flexible computation but higher costs, less mature tooling | ZK more practical for transfer-only scope |

The Railgun-style shielded pool provides proven privacy guarantees with mature tooling (Noir circuits) while allowing compliance gating at the protocol layer.

### Tools & Primitives

| Tool | Purpose |
|------|---------|
| **Noir** | ZK circuit language for deposit/transfer/withdraw proofs |
| **Solidity (Foundry)** | On-chain contracts: ShieldedPool, AttestationRegistry, CompositeVerifier |
| **Rust** | Off-chain client with trait-based abstraction for testability |
| **Poseidon Hash** | ZK-friendly hash for commitments, nullifiers, Merkle trees |
| **UltraHonk** | Proving system (Noir backend) for efficient verification |
| **LeanIMT** | Dynamic-depth incremental Merkle tree from zk-kit (Solidity, Rust) |

## Protocol Design

### Participants & Roles

| Role | Description | Keys Held |
|------|-------------|-----------|
| **Transactor** | Institutional user performing shielded payments | Spending key, viewing key |
| **Relayer** | Gas paymaster submitting transactions on behalf of transactors | Relayer signing key |
| **Compliance Authority (Attester)** | Entity issuing KYC attestations to verified participants | Attestation signing key |
| **Regulator** | Observer with viewing key access for audit purposes | Granted viewing keys |

### Key Derivation

Keys are derived in the following manner:

```
spending_key = random()
viewing_key  = random()

spending_pubkey = poseidon(spending_key)   // Used in commitments and attestations
viewing_pubkey  = derive_pubkey(viewing_key)   // For encrypted note delivery, uses k256
```

**Security note**: The viewing key grants read access to all transaction history. Institutions should manage viewing key distribution carefully, potentially using threshold schemes for regulator access in production.

### Data Structures

#### Note

A note represents a private balance owned by a spending key:

```
Note {
    token:          address     // ERC-20 token contract (e.g., USDC)
    amount:         u128        // Token amount (no decimals, raw units)
    owner_pubkey:   Point       // Spending public key of owner
    salt:       Field       // Random value for hiding
}
```

#### Commitment

The on-chain representation of a note (hides all note contents):

```
commitment = poseidon(token, amount, owner_pubkey, salt)
```

#### Nullifier

Prevents double-spending by marking a commitment as spent:

```
nullifier = poseidon(commitment, spending_key)
```

Only the spending key holder can compute the nullifier, linking it to the commitment without revealing which commitment was spent.

#### Attestation Leaf

KYC attestation stored in the attestation tree on-chain:

```
AttestationLeaf {
    subject_pubkey:   Point     // Spending public key of attested party
    attester:         address   // Compliance authority address
    issued_at:        u64       // Timestamp of attestation
    expires_at:       u64       // Expiration (0 = no expiry)
}

attestation_leaf = poseidon(subject_pubkey, attester, issued_at, expires_at)
```

### On-Chain State

#### ShieldedPool Contract

```solidity
contract ShieldedPool {
    using LeanIMT for LeanIMTData;

    /// @notice Maximum number of historical roots to store
    uint256 public constant MAX_HISTORICAL_ROOTS = 100;

    /// @notice LeanIMT tree data storage for commitments
    LeanIMTData internal _tree;

    /// @notice Historical roots stored in a circular buffer
    bytes32[100] public historicalRoots;
    uint256 public historicalRootIndex;
    mapping(bytes32 => bool) public validRoots;

    /// @notice Spent nullifiers (double-spend prevention)
    mapping(bytes32 => bool) public nullifiers;

    /// @notice Supported tokens for the pool
    mapping(address => bool) public supportedTokens;

    /// @notice ZK proof verifier
    IVerifier public verifier;

    /// @notice Attestation registry for KYC verification
    IAttestationRegistry public attestationRegistry;

    /// @notice Contract owner
    address public owner;

    // Events for off-chain indexing
    event Deposit(bytes32 indexed commitment, address indexed token,
                  uint256 amount, bytes encryptedNote);
    event Transfer(bytes32 indexed nullifier1, bytes32 indexed nullifier2,
                   bytes32 commitment1, bytes32 commitment2, bytes encryptedNotes);
    event Withdraw(bytes32 indexed nullifier, address indexed recipient,
                   address indexed token, uint256 amount);
}
```

#### AttestationRegistry Contract

```solidity
contract AttestationRegistry is IAttestationRegistry {
    using LeanIMT for LeanIMTData;

    /// @notice LeanIMT tree data storage
    LeanIMTData internal _tree;

    /// @notice Mapping of attestation leaf hash to existence status
    mapping(bytes32 => bool) public attestationLeaves;

    /// @notice Mapping of leaf index to leaf hash (for retrieval)
    mapping(uint40 => bytes32) public leafAtIndex;

    /// @notice Mapping of authorized attesters (compliance authorities)
    mapping(address => bool) public authorizedAttesters;

    /// @notice Contract owner
    address public owner;

    event AttestationAdded(bytes32 indexed leaf, bytes32 indexed subjectPubkeyHash,
                           address indexed attester, uint64 issuedAt, uint64 expiresAt);
    event AttestationRevoked(bytes32 indexed leaf, address indexed revokedBy);

    /// @notice Revoke an existing attestation
    /// @dev LeanIMT requires sibling nodes for updates, computed off-chain
    function revokeAttestation(uint256 oldLeaf, uint256[] calldata siblingNodes) external;
}
```

#### Verifier Contract

The `CompositeVerifier` wraps circuit-specific verifiers (auto-generated from Noir) and implements the `IVerifier` interface:

```solidity
/// @title CompositeVerifier
/// @notice Wraps circuit-specific verifiers and implements the IVerifier interface
/// @dev Each circuit (deposit, transfer, withdraw) has its own verifier contract
///      generated by Noir/Barretenberg. This contract delegates to them.
contract CompositeVerifier is IVerifier {
    /// @notice The deposit circuit verifier (auto-generated from Noir)
    address public immutable depositVerifier;

    /// @notice The transfer circuit verifier (auto-generated from Noir)
    address public immutable transferVerifier;

    /// @notice The withdraw circuit verifier (auto-generated from Noir)
    address public immutable withdrawVerifier;

    constructor(address _depositVerifier, address _transferVerifier, address _withdrawVerifier);

    function verifyDeposit(bytes calldata proof, bytes32[] memory publicInputs)
        external view returns (bool);
    function verifyTransfer(bytes calldata proof, bytes32[] calldata publicInputs)
        external view returns (bool);
    function verifyWithdraw(bytes calldata proof, bytes32[] calldata publicInputs)
        external view returns (bool);
}
```

Each circuit-specific verifier implements the `IUltraVerifier` interface:

```solidity
interface IUltraVerifier {
    function verify(bytes calldata proof, bytes32[] memory publicInputs)
        external view returns (bool);
}
```

### Flows

> **Architecture Note**: Clients maintain local Merkle trees using the `lean-imt` crate and generate proofs locally. The on-chain contracts only store commitment/nullifier data and verify proofs.

#### Attestation Issuance (KYC Onboarding)

Before a transactor can deposit into the shielded pool, they must be attested by an authorized compliance authority. This flow shows how a participant obtains a KYC attestation that is recorded in the on-chain attestation tree.

```
┌─────────────┐     ┌──────────────────────┐     ┌───────────────────────┐
│ Transactor  │     │ Compliance Authority │     │ AttestationRegistry   │
│  (Subject)  │     │     (Attester)       │     │     (On-Chain)        │
└──────┬──────┘     └──────────┬───────────┘     └───────────┬───────────┘
       │                       │                             │
       │ 1. Submit KYC         │                             │
       │    documentation      │                             │
       │──────────────────────►│                             │
       │                       │                             │
       │                       │ 2. Verify identity          │
       │                       │    (off-chain)              │
       │                       │                             │
       │                       │ 3. addAttestation(          │
       │                       │      subjectPubkeyHash,     │
       │                       │      expiresAt)             │
       │                       │────────────────────────────►│
       │                       │                             │ 4. Compute leaf =
       │                       │                             │    poseidon(pubkeyHash,
       │                       │                             │    attester, issuedAt,
       │                       │                             │    expiresAt)
       │                       │                             │
       │                       │                             │ 5. Insert leaf into
       │                       │                             │    attestation tree
       │                       │                             │
       │                       │                             │ 6. Emit AttestationAdded
       │                       │◄────────────────────────────│
       │                       │                             │
       │ 7. Index event to     │                             │
       │    learn leaf index   │                             │
       │    & build Merkle     │                             │
       │    proofs             │                             │
       │◄──────────────────────│                             │
```

**Steps**:

1. Transactor submits KYC documentation to the Compliance Authority (off-chain process)
2. Compliance Authority verifies the transactor's identity per institutional and regulatory requirements
3. Compliance Authority calls `addAttestation(subjectPubkeyHash, expiresAt)` on the AttestationRegistry contract, where `subjectPubkeyHash` is the Poseidon hash of the transactor's spending public key
4. Contract computes the attestation leaf: `poseidon(subjectPubkeyHash, msg.sender, block.timestamp, expiresAt)`
5. Contract inserts the leaf into the attestation Merkle tree and records the leaf-to-index mapping
6. Contract emits `AttestationAdded(leaf, subjectPubkeyHash, attester, issuedAt, expiresAt)`
7. Transactor's client indexes the event to learn the leaf index, enabling construction of Merkle inclusion proofs for future deposits

**Prerequisites**: The Compliance Authority must be registered as an authorized attester by the contract owner via `addAttester(address)`.

#### Attestation Revocation

When a participant's KYC expires, they become sanctioned, or a regulator directs removal, the compliance authority revokes the attestation. This removes the leaf from the attestation tree, preventing the participant from making new deposits.

```
┌─────────────┐     ┌──────────────────────┐     ┌───────────────────────┐
│  Regulator  │     │ Compliance Authority │     │ AttestationRegistry   │
│             │     │     (Attester)       │     │     (On-Chain)        │
└──────┬──────┘     └──────────┬───────────┘     └───────────┬───────────┘
       │                       │                             │
       │ 1. Direct revocation  │                             │
       │    (e.g., sanctions   │                             │
       │    match, KYC expiry) │                             │
       │──────────────────────►│                             │
       │                       │                             │
       │                       │ 2. Compute sibling nodes    │
       │                       │    for target leaf          │
       │                       │    (off-chain, from local   │
       │                       │    tree state)              │
       │                       │                             │
       │                       │ 3. revokeAttestation(       │
       │                       │      oldLeaf,               │
       │                       │      siblingNodes)          │
       │                       │────────────────────────────►│
       │                       │                             │ 4. Mark leaf as revoked
       │                       │                             │    (attestationLeaves
       │                       │                             │     [leaf] = false)
       │                       │                             │
       │                       │                             │ 5. Remove leaf from
       │                       │                             │    Merkle tree
       │                       │                             │    (root updated)
       │                       │                             │
       │                       │                             │ 6. Emit
       │                       │                             │    AttestationRevoked
       │                       │◄────────────────────────────│
       │◄──────────────────────│                             │
```

**Steps**:

1. Regulator directs the Compliance Authority to revoke a participant's attestation (e.g., due to sanctions match, KYC expiry, or compliance violation)
2. Compliance Authority computes the sibling nodes (Merkle proof path) for the target leaf from their local copy of the attestation tree
3. Compliance Authority calls `revokeAttestation(oldLeaf, siblingNodes)` on the AttestationRegistry contract
4. Contract marks the leaf as revoked: `attestationLeaves[leaf] = false`
5. Contract removes the leaf from the Merkle tree, updating the attestation root
6. Contract emits `AttestationRevoked(leaf, revokedBy)`

**Note**: After revocation, the participant can no longer produce valid Merkle inclusion proofs against the updated attestation root. This prevents new deposits. However, notes already in the shielded pool remain spendable; the protocol does not freeze in-pool funds.

#### Deposit (Shielding)

Converts public ERC-20 tokens into a private note. Requires proof of KYC attestation.

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│ Transactor  │     │   Relayer    │     │  ShieldedPool   │
└──────┬──────┘     └──────┬───────┘     └────────┬────────┘
       │                   │                      │
       │ 1. Generate note  │                      │
       │    (token, amt,   │                      │
       │     pubkey, rand) │                      │
       │                   │                      │
       │ 2. Compute        │                      │
       │    commitment     │                      │
       │                   │                      │
       │ 3. Generate ZK    │                      │
       │    proof:         │                      │
       │    - attestation  │                      │
       │      inclusion    │                      │
       │    - commitment   │                      │
       │      correctness  │                      │
       │                   │                      │
       │ 4. Approve token  │                      │
       │    transfer       ├─────────────────────►│
       │                   │                      │
       │ 5. Send deposit   │                      │
       │    request        │                      │
       │──────────────────►│                      │
       │                   │ 6. Submit tx         │
       │                   │─────────────────────►│
       │                   │                      │ 7. Verify proof
       │                   │                      │ 8. Check attestation root
       │                   │                      │ 9. Transfer tokens to pool
       │                   │                      │ 10. Add commitment to tree
       │                   │                      │ 11. Emit Deposit event
       │                   │◄─────────────────────│
       │◄──────────────────│                      │
```

**Steps**:

1. Transactor generates a new note with random salt
2. Computes commitment = poseidon(note fields)
3. Generates ZK proof proving:
   - Their spending_pubkey exists in the attestation tree
   - The commitment correctly encodes the deposited amount
4. Approves ERC-20 transfer to ShieldedPool
5. Sends deposit request to relayer (or submits directly)
6. Relayer submits transaction with proof
7. Contract verifies proof against current attestation root
8. Contract transfers tokens from transactor to pool
9. Contract appends commitment to Merkle tree
10. Contract emits Deposit event with encrypted note (for recipient's viewing key)

#### Private Transfer

Spends existing notes and creates new notes for recipients. 2-input-2-output structure.

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│   Sender    │     │   Relayer    │     │  ShieldedPool   │
└──────┬──────┘     └──────┬───────┘     └────────┬────────┘
       │                   │                      │
       │ 1. Select input   │                      │
       │    notes (2)      │                      │
       │                   │                      │
       │ 2. Create output  │                      │
       │    notes (2):     │                      │
       │    - recipient    │                      │
       │    - change       │                      │
       │                   │                      │
       │ 3. Compute        │                      │
       │    nullifiers     │                      │
       │    & commitments  │                      │
       │                   │                      │
       │ 4. Generate ZK    │                      │
       │    proof          │                      │
       │                   │                      │
       │ 5. Encrypt notes  │                      │
       │    for recipients │                      │
       │                   │                      │
       │ 6. Send transfer  │                      │
       │    request        │                      │
       │──────────────────►│                      │
       │                   │ 7. Submit tx         │
       │                   │─────────────────────►│
       │                   │                      │ 8. Verify proof
       │                   │                      │ 9. Check nullifiers unused
       │                   │                      │ 10. Mark nullifiers spent
       │                   │                      │ 11. Add new commitments
       │                   │                      │ 12. Emit Transfer event
       │                   │◄─────────────────────│
       │◄──────────────────│                      │
```

**Steps**:

1. Sender selects two input notes (pad with zero-value notes if needed)
2. Creates two output notes: one for recipient, one for change
3. Computes nullifiers for inputs and commitments for outputs
4. Generates ZK proof proving:
   - Input commitments exist in the commitment tree
   - Nullifiers are correctly derived from inputs and spending key
   - Output commitments are well-formed
   - Input amounts = output amounts (value preservation)
5. Encrypts output notes using recipients' viewing keys
6. Sends transfer request to relayer with encrypted notes
7. Relayer submits transaction
8. Contract verifies proof
9. Contract checks nullifiers not already spent
10. Contract marks nullifiers as spent
11. Contract adds output commitments to tree
12. Contract emits Transfer event with encrypted notes

#### Withdraw (Unshielding)

Converts a private note back to public ERC-20 tokens.

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│ Transactor  │     │   Relayer    │     │  ShieldedPool   │
└──────┬──────┘     └──────┬───────┘     └────────┬────────┘
       │                   │                      │
       │ 1. Select note    │                      │
       │    to unshield    │                      │
       │                   │                      │
       │ 2. Compute        │                      │
       │    nullifier      │                      │
       │                   │                      │
       │ 3. Generate ZK    │                      │
       │    proof          │                      │
       │                   │                      │
       │ 4. Send withdraw  │                      │
       │    request        │                      │
       │──────────────────►│                      │
       │                   │ 5. Submit tx         │
       │                   │─────────────────────►│
       │                   │                      │ 6. Verify proof
       │                   │                      │ 7. Check nullifier unused
       │                   │                      │ 8. Mark nullifier spent
       │                   │                      │ 9. Transfer tokens to recipient
       │                   │                      │ 10. Emit Withdraw event
       │                   │◄─────────────────────│
       │◄──────────────────│                      │
```

**Steps**:

1. Transactor selects note to withdraw
2. Computes nullifier for the note
3. Generates ZK proof proving:
   - The commitment exists in the commitment tree
   - The nullifier is correctly derived
   - The claimed amount and recipient match the note
4. Sends withdraw request to relayer
5. Relayer submits transaction
6. Contract verifies proof
7. Contract checks nullifier not spent
8. Contract marks nullifier as spent
9. Contract transfers tokens to specified recipient address
10. Contract emits Withdraw event

## Cryptographic Details

### Primitives

| Primitive | Specification | Usage |
|-----------|---------------|-------|
| **Hash Function** | Poseidon (BN254) | Commitments, nullifiers, Merkle trees |
| **Encryption** | ECDH + HKDF + AEAD (ChaCha20-Poly1305) | Note encryption for viewing keys |
| **Merkle Tree** | LeanIMT (dynamic-depth) | Commitment tree (max depth 32), attestation tree (max depth 20) |
| **Proving System** | UltraHonk (via Noir/Barretenberg) | ZK proofs |

### Circuit Constraints

All circuits use `binary_merkle_root` from zk-kit.noir for dynamic-depth Merkle proof verification. Arrays are padded to maximum depth but only `proof_length` elements are used.

#### Deposit Circuit

**Public Inputs**:
- `commitment`: The note commitment being created
- `token`: ERC-20 token address
- `amount`: Deposit amount
- `attestation_root`: Current root of attestation tree

**Private Inputs**:
- `owner_pubkey`: Depositor's spending public key (poseidon hash of spending_key)
- `salt`: Random salt
- `attester`: Attester address
- `issued_at`: Attestation timestamp
- `expires_at`: Expiration (0 = no expiry). **NOTE:** we do not enforce the value of `expires_at` in the circuit, it is assumed here that the regulator sets it correctly on-chain, and not to a value in the past.
- `attestation_proof_length`: Actual depth of the attestation tree proof
- `attestation_path`: Merkle siblings (padded to MAX_ATTESTATION_TREE_DEPTH = 20)
- `attestation_indices`: Path direction bits (padded to MAX_ATTESTATION_TREE_DEPTH = 20)

**Constraints**:
1. `commitment == poseidon4(token, amount, owner_pubkey, salt)`
2. `attestation_leaf == poseidon4(owner_pubkey, attester, issued_at, expires_at)`
3. `binary_merkle_root(attestation_leaf, attestation_proof_length, attestation_indices, attestation_path) == attestation_root`

#### Transfer Circuit

**Public Inputs**:
- `nullifier_0`, `nullifier_1`: Nullifiers for spent notes
- `commitment_out_0`, `commitment_out_1`: New note commitments
- `commitment_root`: Current commitment tree root

**Private Inputs**:
- `spending_key`: Sender's spending key
- Input notes (2): `token_in_[0,1]`, `amount_in_[0,1]`, `salt_in_[0,1]`
- Output notes (2): `token_out_[0,1]`, `amount_out_[0,1]`, `owner_out_[0,1]`, `salt_out_[0,1]`
- `proof_length`: Actual depth of the commitment tree proofs
- Merkle proofs (2): `path_[0,1]`, `indices_[0,1]` (padded to MAX_COMMITMENT_TREE_DEPTH = 32)

**Constraints**:
1. Derive owner public key: `owner_pubkey == poseidon1(spending_key)`
2. Input note 0 membership and nullifier:
   - `commitment_in_0 == poseidon4(token_in_0, amount_in_0, owner_pubkey, salt_in_0)`
   - `binary_merkle_root(commitment_in_0, proof_length, indices_0, path_0) == commitment_root`
   - `nullifier_0 == poseidon2(commitment_in_0, spending_key)`
3. Input note 1 (skipped if zero-value note):
   - Same verification as input 0
   - `nullifier_1 == poseidon2(commitment_in_1, spending_key)`
4. Output commitment formation:
   - `commitment_out_0 == poseidon4(token_out_0, amount_out_0, owner_out_0, salt_out_0)`
   - `commitment_out_1 == poseidon4(token_out_1, amount_out_1, owner_out_1, salt_out_1)`
5. Value preservation: `amount_in_0 + amount_in_1 == amount_out_0 + amount_out_1`
6. Token consistency: All notes use the same token address

#### Withdraw Circuit

**Public Inputs**:
- `nullifier`: Nullifier for spent note
- `token`: ERC-20 token address
- `amount`: Withdrawal amount
- `recipient`: Recipient address
- `commitment_root`: Current commitment tree root

**Private Inputs**:
- `spending_key`: Owner's spending key
- `salt`: Note salt
- `proof_length`: Actual depth of the commitment tree proof
- `path`: Merkle siblings (padded to MAX_COMMITMENT_TREE_DEPTH = 32)
- `indices`: Path direction bits (padded to MAX_COMMITMENT_TREE_DEPTH = 32)

**Constraints**:
1. `owner_pubkey == poseidon1(spending_key)`
2. `commitment == poseidon4(token, amount, owner_pubkey, salt)`
3. `binary_merkle_root(commitment, proof_length, indices, path) == commitment_root`
4. `nullifier == poseidon2(commitment, spending_key)`

Note: `recipient` is a public input bound to the proof but not constrained in the circuit. The contract uses this public input to send funds to the correct address.

## Architecture: Rust Traits

The client uses trait-based abstraction (ports-and-adapters pattern) for testability and phased implementation.

### Core Traits

```rust
/// Trait for generating ZK proofs for shielded pool operations.
pub trait Prover: Send + Sync {
    /// Generate a proof for a deposit operation.
    fn prove_deposit(
        &self,
        witness: &DepositWitness,
    ) -> impl Future<Output = Result<DepositProof, ProverError>>;

    /// Generate a proof for a transfer operation.
    fn prove_transfer(
        &self,
        witness: &TransferWitness,
    ) -> impl Future<Output = Result<TransferProof, ProverError>>;

    /// Generate a proof for a withdraw operation.
    fn prove_withdraw(
        &self,
        witness: &WithdrawWitness,
    ) -> impl Future<Output = Result<WithdrawProof, ProverError>>;
}

/// Trait for interacting with on-chain contracts.
///
/// Abstracts the Ethereum RPC layer for the shielded pool and attestation registry.
pub trait OnChain: Send + Sync {
    // ========== ShieldedPool Reads ==========
    fn get_commitment_root(&self) -> impl Future<Output = Result<B256, OnChainError>>;
    fn get_commitment_count(&self) -> impl Future<Output = Result<u64, OnChainError>>;
    fn is_nullifier_spent(&self, nullifier: B256) -> impl Future<Output = Result<bool, OnChainError>>;
    fn is_known_root(&self, root: B256) -> impl Future<Output = Result<bool, OnChainError>>;
    fn is_token_supported(&self, token: Address) -> impl Future<Output = Result<bool, OnChainError>>;

    // ========== AttestationRegistry Reads ==========
    fn get_attestation_root(&self) -> impl Future<Output = Result<B256, OnChainError>>;
    fn get_attestation_count(&self) -> impl Future<Output = Result<u64, OnChainError>>;
    fn get_attestation_leaf(&self, index: u64) -> impl Future<Output = Result<B256, OnChainError>>;
    fn is_authorized_attester(&self, attester: Address) -> impl Future<Output = Result<bool, OnChainError>>;

    // ========== ShieldedPool Writes ==========
    fn deposit(&self, proof: &DepositProof, commitment: B256, token: Address,
               amount: U256, encrypted_note: Bytes) -> impl Future<Output = Result<TxReceipt, OnChainError>>;
    fn transfer(&self, proof: &TransferProof, nullifiers: [B256; 2], commitments: [B256; 2],
                root: B256, encrypted_notes: Bytes) -> impl Future<Output = Result<TxReceipt, OnChainError>>;
    fn withdraw(&self, proof: &WithdrawProof, nullifier: B256, token: Address, amount: U256,
                recipient: Address, root: B256) -> impl Future<Output = Result<TxReceipt, OnChainError>>;

    // ========== Admin Operations ==========
    fn add_attester(&self, attester: Address) -> impl Future<Output = Result<TxReceipt, OnChainError>>;
    fn add_attestation(&self, subject_pubkey_hash: B256, expires_at: u64)
        -> impl Future<Output = Result<(AttestationData, TxReceipt), OnChainError>>;
    fn add_supported_token(&self, token: Address) -> impl Future<Output = Result<TxReceipt, OnChainError>>;

    // ========== ERC20 Operations ==========
    fn approve_token(&self, token: Address, amount: U256) -> impl Future<Output = Result<TxReceipt, OnChainError>>;
    fn get_token_balance(&self, token: Address, account: Address) -> impl Future<Output = Result<U256, OnChainError>>;
}
```

### Implementation Phases

| Phase | Prover | OnChain |
|-------|--------|---------|
| **Mock** | Returns dummy proofs | In-memory state |
| **Local** | Barretenberg prover (bb CLI) | Anvil (local node) |
| **Testnet** | Barretenberg prover | Sepolia RPC |

The PoC targets Mock and Local phases. Testnet integration is stretch goal.

## Security Model

### Threat Model

| Adversary | Capabilities | Mitigations |
|-----------|--------------|-------------|
| **Public Observer** | Sees all on-chain transactions, commitment tree, nullifier set | Commitments hide note contents; nullifiers unlinkable to commitments without spending key |
| **Malicious Relayer** | Can delay, reorder, or refuse to submit transactions | Cannot steal funds (no access to spending key); user can use different relayer or submit directly |
| **Compromised Viewing Key** | Can decrypt all historical and future notes for that key | Cannot spend funds; viewing key grants read-only access |
| **Malicious Compliance Authority** | Can issue attestations to unauthorized parties | Requires multi-sig or DAO governance for attester authorization in production |
| **Network Observer** | Monitors IP addresses, timing of relayer requests | Out of scope for PoC; production should use Tor/mixnet |

### Guarantees

| Property | Description |
|----------|-------------|
| **Confidentiality** | Note amounts and owners hidden in commitments; only revealed via viewing key |
| **Unlinkability** | Transfers break the link between input and output notes; observer cannot trace payment flow |
| **Double-spend Prevention** | Nullifier uniqueness enforced on-chain; spending a note marks it permanently |
| **Compliance Gating** | Deposit requires valid attestation proof; unauthorized parties cannot enter the pool |
| **Selective Disclosure** | Viewing keys enable audit without compromising spending authority |

### Limitations & Shortcuts (PoC Scope)

| Limitation | Impact | Production Mitigation |
|------------|--------|----------------------|
| **No private proofs of innocence** | Users cannot prove funds are not from sanctioned sources without revealing full history | Add optional proof-of-non-association circuits (out of scope per institutional preference) |
| **Fixed 2-in-2-out transfers** | Cannot batch multiple payments efficiently | Implement variable input/output circuits |
| **Single compliance authority** | Single point of trust for attestations | Multi-authority attestation with threshold signatures |
| **No viewing key revocation** | Compromised viewing key permanently leaks history | Implement key rotation with historical cutoff |
| **No Gas Paymaster** | All Transactions flow from user controlled addressed directly | Decentralized relayer network with incentives |
| **In-memory Merkle trees** | Client must rebuild state from events | Persistent local storage with incremental sync |
| **Testnet only** | Not production-ready | Full security audit, mainnet deployment |


## Terminology

| Term | Definition |
|------|------------|
| **Note** | A private representation of token ownership containing amount, owner, and salt |
| **Commitment** | A cryptographic hash of a note, published on-chain without revealing note contents |
| **Nullifier** | A unique identifier derived from a commitment and spending key, used to prevent double-spending |
| **Shielding (Deposit)** | Converting public ERC-20 tokens into a private note within the shielded pool |
| **Unshielding (Withdraw)** | Converting a private note back to public ERC-20 tokens |
| **Spending Key** | Private key that authorizes spending notes; used to derive nullifiers |
| **Viewing Key** | Private key that decrypts notes for read-only access; enables auditing without spending authority |
| **Attestation** | A signed statement from a compliance authority that a public key belongs to a KYC-verified entity, stored in the Attestation tree |
| **Relayer** | A service that submits transactions on behalf of users, paying gas fees and providing timing privacy |
| **Commitment Tree** | LeanIMT tree storing all note commitments; proves note existence without revealing which note |
| **Attestation Tree** | LeanIMT tree storing KYC attestations; enables ZK proof of compliance without revealing identity |

## References

- [Railgun Protocol Documentation](https://docs.railgun.org/)
- [Noir Language Documentation](https://noir-lang.org/docs/)
- [Poseidon Hash Function](https://www.poseidon-hash.info/)
- [LeanIMT (zk-kit)](https://github.com/privacy-scaling-explorations/zk-kit/tree/main/packages/lean-imt) - Dynamic-depth incremental Merkle tree
- [zk-kit.noir](https://github.com/privacy-scaling-explorations/zk-kit.noir) - Noir implementations including binary_merkle_root
- [EthSystems Map: Private Stablecoins Use Case](https://github.com/ethsystems/map/blob/master/use-cases/private-stablecoins.md)
- [EthSystems Map: Private Payments Approach](https://github.com/ethsystems/map/blob/master/approaches/approach-private-payments.md)
- [ERC-20 Token Standard](https://eips.ethereum.org/EIPS/eip-20)

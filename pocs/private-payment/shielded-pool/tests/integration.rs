//! Integration test for the shielded pool with real proof generation.
//!
//! This test demonstrates the full flow:
//! 1. Alice deposits tokens
//! 2. Bob deposits tokens
//! 3. Alice transfers to Bob
//! 4. Bob withdraws
//!
//! ## Architecture Note
//!
//! Clients maintain local Merkle trees (using lean-imt) and generate proofs locally.
//! The on-chain contracts only store commitment/nullifier data and verify proofs.
//! This matches the LeanIMT architecture where clients are responsible for tracking
//! tree state by listening to contract events.
//!
//! ## Prerequisites
//!
//! - `anvil` (Foundry's local Ethereum node)
//! - `forge` (Foundry's build tool)
//! - `nargo` (Noir compiler)
//! - `bb` (Barretenberg CLI)
//!
//! ## Running the Test
//!
//! ```bash
//! # 1. Start Anvil in a separate terminal
//! anvil
//!
//! # 2. Deploy contracts
//! cd pocs/private-payment/shielded-pool
//! forge script script/DeployVerifiers.s.sol --rpc-url http://localhost:8545 --broadcast --private-key "${PRIVATE_KEY}"
//! forge script script/Deploy.s.sol --rpc-url http://localhost:8545 --broadcast --private-key "${PRIVATE_KEY}"
//! cd ..
//!
//! # 3. Run the integration test
//! cargo test --test integration -- --nocapture
//! ```

use std::path::PathBuf;

use alloy::primitives::{
    Address,
    Bytes,
    U256,
};
use toml::Value;

use private_payment_shielded_pool::{
    adapters::{
        bb_prover::BBProver,
        ethereum_rpc::EthereumRpc,
        merkle_tree::{
            AttestationTree,
            CommitmentTree,
            b256_to_bytes,
            bytes_to_b256,
        },
    },
    domain::{
        keys::SpendingKey,
        note::Note,
        witness::{
            DepositWitness,
            TransferWitness,
            WithdrawWitness,
        },
    },
    ports::{
        on_chain::OnChain,
        prover::Prover,
    },
};

/// Configuration loaded from deployments.toml
struct DeploymentConfig {
    rpc_url: String,
    shielded_pool: Address,
    attestation_registry: Address,
    mock_token: Address,
}

impl DeploymentConfig {
    /// Load deployment configuration from deployments.toml for the Anvil chain (31337)
    fn load() -> Self {
        let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let config_path = project_root.join("deployments.toml");

        let config_str = std::fs::read_to_string(&config_path)
            .expect(&format!("Failed to read {:?}", config_path));

        let config: Value = config_str
            .parse()
            .expect("Failed to parse deployments.toml");

        // Get the Anvil (31337) configuration
        let anvil_config = config
            .get("31337")
            .expect("Missing [31337] section in deployments.toml");

        let rpc_url = anvil_config
            .get("endpoint_url")
            .and_then(|v| v.as_str())
            .unwrap_or("http://localhost:8545")
            .to_string();

        let addresses = anvil_config
            .get("address")
            .expect("Missing [31337.address] section - run `forge script` first");

        let shielded_pool: Address = addresses
            .get("shielded_pool_address")
            .and_then(|v| v.as_str())
            .expect("Missing shielded_pool_address - run `forge script` first")
            .parse()
            .expect("Invalid shielded_pool_address");

        let attestation_registry: Address = addresses
            .get("attestation_registry_address")
            .and_then(|v| v.as_str())
            .expect("Missing attestation_registry_address - run `forge script` first")
            .parse()
            .expect("Invalid attestation_registry_address");

        let mock_token: Address = addresses
            .get("mock_token_address")
            .and_then(|v| v.as_str())
            .expect("Missing mock_token_address - run `forge script` first")
            .parse()
            .expect("Invalid mock_token_address");

        Self {
            rpc_url,
            shielded_pool,
            attestation_registry,
            mock_token,
        }
    }
}

/// Full integration test with real proof generation.
///
/// Flow:
/// 1. Alice deposits 1000 tokens
/// 2. Bob deposits 500 tokens
/// 3. Alice transfers 700 to Bob (keeping 300 as change)
/// 4. Bob withdraws 700
///
/// This test uses the BBProver for real ZK proof generation.
#[tokio::test]
async fn test_full_shielded_pool_flow() {
    println!("=== Loading Configuration ===");
    let config = DeploymentConfig::load();

    println!("RPC URL: {}", config.rpc_url);
    println!("ShieldedPool: {:?}", config.shielded_pool);
    println!("AttestationRegistry: {:?}", config.attestation_registry);
    println!("MockToken: {:?}", config.mock_token);

    // Use Anvil's first default account
    let private_key =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    let rpc = EthereumRpc::new(
        &config.rpc_url,
        private_key,
        config.shielded_pool,
        config.attestation_registry,
    )
    .await
    .expect("Failed to create EthereumRpc");

    let deployer = rpc.signer_address();
    println!("Deployer: {:?}", deployer);

    // Initialize the prover with path to circuits
    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let circuits_dir = project_root.join("circuits");
    let prover = BBProver::new(circuits_dir);

    // Initialize local Merkle trees
    // In production, each party maintains their own local merkle tree
    // by listening to contract events and updating accordingly.
    let mut commitment_tree = CommitmentTree::new();
    let mut attestation_tree = AttestationTree::new();
    println!("Initialized local Merkle trees (using lean-imt)");

    // === Setup Phase ===
    println!("\n=== Setup Phase ===");

    // Add deployer as attester
    println!("Adding deployer as attester...");
    rpc.add_attester(deployer)
        .await
        .expect("Failed to add attester");

    // Add mock token as supported
    println!("Adding mock token as supported...");
    rpc.add_supported_token(config.mock_token)
        .await
        .expect("Failed to add supported token");

    // Mint tokens to deployer
    println!("Minting tokens...");
    let mint_amount = U256::from(100000u64);
    rpc.mint_mock_token(config.mock_token, deployer, mint_amount)
        .await
        .expect("Failed to mint tokens");
    println!("  Minted {} tokens to deployer", mint_amount);

    // === Create Keys for Alice and Bob ===
    println!("\n=== Creating Keys ===");
    let alice_sk = SpendingKey::random();
    let alice_pk = alice_sk.derive_owner_pubkey();
    println!("Alice pubkey: {:?}", alice_pk.0);

    let bob_sk = SpendingKey::random();
    let bob_pk = bob_sk.derive_owner_pubkey();
    println!("Bob pubkey: {:?}", bob_pk.0);

    // === Add Attestations ===
    println!("\n=== Adding Attestations ===");

    // Attestation for Alice
    let (alice_attestation_data, _) = rpc
        .add_attestation(alice_pk.0, 0)
        .await
        .expect("Failed to add Alice's attestation");
    // Add to local attestation tree
    attestation_tree.insert(&b256_to_bytes(&alice_attestation_data.leaf));
    println!(
        "Alice attestation: leaf={:?}, index={}, attester={:?}, issued_at={}, expires_at={}",
        alice_attestation_data.leaf,
        alice_attestation_data.index,
        alice_attestation_data.attester,
        alice_attestation_data.issued_at,
        alice_attestation_data.expires_at
    );

    // === Alice Deposits 1000 tokens ===
    println!("\n=== Alice Deposits 1000 Tokens ===");

    let alice_deposit_amount = U256::from(1000u64);
    let alice_deposit_note = Note::new(config.mock_token, alice_deposit_amount, alice_pk);
    let alice_commitment = alice_deposit_note.commitment();
    println!("Alice's note commitment: {:?}", alice_commitment.0);

    // Get attestation proof for Alice from local tree
    let attestation_root = bytes_to_b256(
        &attestation_tree
            .root()
            .expect("attestation tree should have root"),
    );
    let alice_attestation_proof = attestation_tree
        .generate_attestation_proof(alice_attestation_data.index)
        .expect("Failed to generate Alice's attestation proof");

    // Empty payload in this test; the proof still binds its commitment (spec 4.6)
    let alice_encrypted_note = Bytes::from(vec![]);

    // Create deposit witness for Alice
    // The deployer funds both deposits and also submits them; funding address is
    // bound in the proof and the pool pulls from it, not from msg.sender.
    let alice_deposit_witness = DepositWitness::new(
        &alice_deposit_note,
        alice_sk.clone(),
        deployer,
        attestation_root,
        alice_attestation_data.attester,
        alice_attestation_data.issued_at,
        alice_attestation_data.expires_at,
        alice_attestation_proof,
        &alice_encrypted_note,
    );

    // Generate proof
    println!("Generating deposit proof for Alice...");
    let alice_deposit_proof = prover
        .prove_deposit(&alice_deposit_witness)
        .await
        .expect("Failed to generate Alice's deposit proof");
    println!(
        "  Proof generated ({} bytes)",
        alice_deposit_proof.proof.len()
    );

    // Approve and deposit
    rpc.approve_token(config.mock_token, alice_deposit_amount)
        .await
        .unwrap();

    let alice_deposit_receipt = rpc
        .deposit(
            &alice_deposit_proof,
            alice_commitment.0,
            config.mock_token,
            alice_deposit_amount,
            deployer,
            alice_encrypted_note,
        )
        .await
        .expect("Alice's deposit failed");
    println!("  Deposit tx: {:?}", alice_deposit_receipt.tx_hash);
    assert!(alice_deposit_receipt.success);

    // Add Alice's commitment to local tree
    commitment_tree.insert(&b256_to_bytes(&alice_commitment.0));

    // Attestation for Bob
    let (bob_attestation_data, _) = rpc
        .add_attestation(bob_pk.0, 0)
        .await
        .expect("Failed to add Bob's attestation");
    // Add to local attestation tree
    attestation_tree.insert(&b256_to_bytes(&bob_attestation_data.leaf));
    println!(
        "Bob attestation: leaf={:?}, index={}, attester={:?}, issued_at={}, expires_at={}",
        bob_attestation_data.leaf,
        bob_attestation_data.index,
        bob_attestation_data.attester,
        bob_attestation_data.issued_at,
        bob_attestation_data.expires_at
    );

    // === Bob Deposits 500 tokens ===
    println!("\n=== Bob Deposits 500 Tokens ===");

    let bob_deposit_amount = U256::from(500u64);
    let bob_deposit_note = Note::new(config.mock_token, bob_deposit_amount, bob_pk);
    let bob_commitment = bob_deposit_note.commitment();
    println!("Bob's note commitment: {:?}", bob_commitment.0);

    let attestation_root = rpc.get_attestation_root().await.unwrap();

    let bob_attestation_proof = attestation_tree
        .generate_attestation_proof(bob_attestation_data.index)
        .expect("Failed to generate Bob's attestation proof");

    let bob_encrypted_note = Bytes::from(vec![]);

    // Create deposit witness for Bob
    let bob_deposit_witness = DepositWitness::new(
        &bob_deposit_note,
        bob_sk.clone(),
        deployer,
        attestation_root,
        bob_attestation_data.attester,
        bob_attestation_data.issued_at,
        bob_attestation_data.expires_at,
        bob_attestation_proof,
        &bob_encrypted_note,
    );

    // Generate proof
    println!("Generating deposit proof for Bob...");
    let bob_deposit_proof = prover
        .prove_deposit(&bob_deposit_witness)
        .await
        .expect("Failed to generate Bob's deposit proof");
    println!(
        "  Proof generated ({} bytes)",
        bob_deposit_proof.proof.len()
    );

    // Approve and deposit
    rpc.approve_token(config.mock_token, bob_deposit_amount)
        .await
        .unwrap();

    let bob_deposit_receipt = rpc
        .deposit(
            &bob_deposit_proof,
            bob_commitment.0,
            config.mock_token,
            bob_deposit_amount,
            deployer,
            bob_encrypted_note,
        )
        .await
        .expect("Bob's deposit failed");
    println!("  Deposit tx: {:?}", bob_deposit_receipt.tx_hash);
    assert!(bob_deposit_receipt.success);

    // Add Bob's commitment to local tree
    commitment_tree.insert(&b256_to_bytes(&bob_commitment.0));

    // === Alice Transfers 700 to Bob ===
    println!("\n=== Alice Transfers 700 to Bob ===");

    let commitment_root = rpc.get_commitment_root().await.unwrap();

    // Get merkle proof for Alice's note (index 0) from local tree
    let alice_commitment_proof = commitment_tree
        .generate_commitment_proof(0)
        .expect("Failed to generate Alice's commitment proof");

    // Create a zero note for padding (2-in-2-out). Use a fresh random salt (Note::zero) so the
    // ballast nullifier differs each transfer; a fixed zero salt makes it deterministic and, once
    // spent, blocks every later single-input transfer of the same token.
    let zero_note = Note::zero(config.mock_token, alice_pk);
    // Zero note uses the same proof as Alice's note (index 0) since it's a dummy
    let zero_commitment_proof = commitment_tree
        .generate_commitment_proof(0)
        .expect("Failed to generate zero note commitment proof");

    // Output notes: 700 to Bob, 300 back to Alice
    let output_to_bob = Note::new(config.mock_token, U256::from(700u64), bob_pk);
    let output_to_alice = Note::new(config.mock_token, U256::from(300u64), alice_pk);

    let transfer_encrypted_notes = Bytes::from(vec![]);

    // Create transfer witness
    let transfer_witness = TransferWitness::new(
        alice_sk.clone(),
        [alice_deposit_note.clone(), zero_note],
        [output_to_bob.clone(), output_to_alice.clone()],
        [alice_commitment_proof, zero_commitment_proof],
        commitment_root,
        &transfer_encrypted_notes,
    );

    // Generate proof
    println!("Generating transfer proof...");
    let transfer_proof = prover
        .prove_transfer(&transfer_witness)
        .await
        .expect("Failed to generate transfer proof");
    println!("  Proof generated ({} bytes)", transfer_proof.proof.len());

    // Execute transfer
    let transfer_receipt = rpc
        .transfer(
            &transfer_proof,
            transfer_proof.nullifiers(),
            transfer_proof.output_commitments(),
            commitment_root,
            transfer_encrypted_notes,
        )
        .await
        .expect("Transfer failed");
    println!("  Transfer tx: {:?}", transfer_receipt.tx_hash);
    assert!(transfer_receipt.success);

    // Add output commitments to local tree
    let output_commitments = transfer_proof.output_commitments();
    commitment_tree.insert(&b256_to_bytes(&output_commitments[0]));
    commitment_tree.insert(&b256_to_bytes(&output_commitments[1]));

    // Verify nullifier is spent
    let nullifier_0 = transfer_proof.public_inputs.nullifier_0;
    let is_spent = rpc.is_nullifier_spent(nullifier_0).await.unwrap();
    assert!(is_spent, "Alice's nullifier should be spent");
    println!("  Alice's nullifier spent: {}", is_spent);

    // === Bob Withdraws ===
    println!("\n=== Bob Withdraws ===");

    // Bob will withdraw from the note Alice sent him (output_to_bob)
    let commitment_root_after_transfer = rpc.get_commitment_root().await.unwrap();
    println!(
        "Commitment root after transfer: {:?}",
        commitment_root_after_transfer
    );

    // Bob's note from Alice is at index 2 (0=Alice deposit, 1=Bob deposit, 2=transfer output 1, 3=transfer output 2)
    let bob_from_alice_index = 2u64;
    let bob_commitment_proof = commitment_tree
        .generate_commitment_proof(bob_from_alice_index)
        .expect("Failed to generate Bob's commitment proof");

    // Recipient address for Bob's withdrawal
    let bob_recipient = Address::repeat_byte(0xBB);

    // Create withdraw witness
    let withdraw_witness = WithdrawWitness::new(
        bob_sk.clone(),
        output_to_bob.clone(),
        bob_commitment_proof,
        commitment_root_after_transfer,
        bob_recipient,
    );

    // Generate proof
    println!("Generating withdraw proof for Bob...");
    let withdraw_proof = prover
        .prove_withdraw(&withdraw_witness)
        .await
        .expect("Failed to generate Bob's withdraw proof");
    println!("  Proof generated ({} bytes)", withdraw_proof.proof.len());

    // Execute withdrawal
    let withdraw_receipt = rpc
        .withdraw(
            &withdraw_proof,
            withdraw_proof.public_inputs.nullifier,
            config.mock_token,
            U256::from(700u64),
            bob_recipient,
            commitment_root_after_transfer,
        )
        .await
        .expect("Bob's withdraw failed");
    println!("  Withdraw tx: {:?}", withdraw_receipt.tx_hash);
    assert!(withdraw_receipt.success);

    // Verify Bob received the tokens
    let bob_balance = rpc
        .get_token_balance(config.mock_token, bob_recipient)
        .await
        .unwrap();
    assert_eq!(bob_balance, U256::from(700u64));
    println!("  Bob's recipient balance: {}", bob_balance);

    // Verify Bob's nullifier is spent
    let bob_nullifier_spent = rpc
        .is_nullifier_spent(withdraw_proof.public_inputs.nullifier)
        .await
        .unwrap();
    assert!(bob_nullifier_spent, "Bob's nullifier should be spent");
    println!("  Bob's nullifier spent: {}", bob_nullifier_spent);

    // === Summary ===
    println!("\n=== Test Completed Successfully ===");
    println!("Summary:");
    println!("  - Alice deposited 1000 tokens");
    println!("  - Bob deposited 500 tokens");
    println!("  - Alice transferred 700 to Bob (300 change to Alice)");
    println!("  - Bob withdrew 700 tokens");
    println!("  - All ZK proofs generated and verified!");
    println!("  - All assertions passed!");
}

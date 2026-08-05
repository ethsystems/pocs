use chrono::Utc;
use clap::{Parser, Subcommand};
use ff::PrimeField;
use poseidon_rs::Fr;
use rand::RngExt;
use std::error::Error;
use std::fs;

use alloy::{
    primitives::{address, Bytes, FixedBytes},
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
    sol,
};

mod config;
mod keys;
mod merkle;
mod notes;
mod prover;
mod utils;

use config::{PRIVATE_BOND_ADDRESS, RPC_URL};
use notes::Note;
use prover::{build_joinsplit_witness, generate_proof, CircuitNote};
use utils::{
    ensure_data_dir, format_date, fr_to_bytes32, load_bond, load_wallet, Bond, TreeState, Wallet,
    DATA_DIR,
};

use crate::keys::ShieldedKeys;

// Contract ABI - loaded from Foundry compilation output
sol!(
    #[sol(rpc, ignore_unlinked)]
    PrivateBond,
    "../contracts/out/PrivateBond.sol/PrivateBond.json"
);

#[derive(Parser)]
#[command(name = "Bond Wallet")]
#[command(about = "CLI wallet for zero-coupon bond protocol", long_about = None)]
struct Cli {
    #[arg(long, default_value = "wallet")]
    wallet: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize issuer wallet: generate keys and create initial bond tranche
    Onboard,

    /// Register as a buyer: generate keys only (no bond creation)
    Register,

    /// Buy bond from issuer (splits issuer's note)
    Buy {
        /// Amount to buy
        #[arg(long)]
        value: u64,
        /// Path to issuer's source note (being split)
        #[arg(long)]
        source_note: String,
        /// Path to issuer's wallet (for signing)
        #[arg(long)]
        issuer_wallet: String,
    },

    /// Trade: swap two bonds P2P (atomic swap)
    Trade {
        /// Wallet A name (owner of bond_a)
        #[arg(long)]
        wallet_a: String,
        /// Path to bond A (will go to wallet B)
        #[arg(long)]
        bond_a: String,
        /// Wallet B name (owner of bond_b)
        #[arg(long)]
        wallet_b: String,
        /// Path to bond B (will go to wallet A)
        #[arg(long)]
        bond_b: String,
    },

    /// Redeem: burn bond at maturity
    Redeem {
        #[arg(long)]
        bond: String,
    },

    /// Info: display bond details
    Info {
        #[arg(long)]
        bond: String,
    },

    /// Scan: decrypt memos sent to this wallet
    Scan,
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    // Run async commands
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        match cli.command {
            Commands::Onboard => onboard(&cli.wallet).await,
            Commands::Register => register(&cli.wallet),
            Commands::Buy {
                value,
                source_note,
                issuer_wallet,
            } => buy(&cli.wallet, value, &source_note, &issuer_wallet).await,
            Commands::Trade { wallet_a, bond_a, wallet_b, bond_b } => {
                trade(&wallet_a, &bond_a, &wallet_b, &bond_b).await
            }
            Commands::Redeem { bond } => redeem(&cli.wallet, &bond).await,
            Commands::Info { bond } => info(&bond),
            Commands::Scan => scan(&cli.wallet),
        }
    });

    Ok(())
}

async fn onboard(wallet_name: &str) {
    println!("\n🔐 Issuer Onboarding: Creating initial bond tranche...");

    // Ensure data directory exists
    ensure_data_dir();

    // Generate keys for issuer
    let keys = ShieldedKeys::generate();

    let wallet = Wallet {
        keys: keys.clone(),
        created_at: Utc::now().to_rfc3339(),
    };

    // Save wallet
    let filename = format!("{}/{}.json", DATA_DIR, wallet_name);
    match fs::write(&filename, serde_json::to_string_pretty(&wallet).unwrap()) {
        Ok(_) => {
            println!("✅ Issuer wallet created!");
            println!("   Saved to: {}", filename);
        }
        Err(e) => {
            println!("❌ Error: {}", e);
            return;
        }
    }

    // Create initial Global Note commitment for the bond tranche
    // Example: $100M bond tranche maturing 2030-01-01
    let global_value = 100_000_000u64; // $100M in smallest units
    let maturity_date = 1893456000u64; // 2030-01-01

    // Generate random salt
    let mut rng = rand::rng();
    let salt = rng.random::<u64>();

    // Get owner as Fr (proper field element)
    let owner_fr = keys.public_spending_key();

    // Create CircuitNote for commitment computation (matches circuit exactly)
    let global_note = CircuitNote {
        value: global_value,
        salt,
        owner: owner_fr.clone(),
        asset_id: 1,
        maturity_date,
    };

    // Compute commitment using CircuitNote.commitment() - matches circuit's note_commit
    let commitment = global_note.commitment();
    println!("\n📊 Global Note (Bond Tranche):");
    println!("   Value:     {} (units)", global_value);
    println!(
        "   Maturity:  {} ({})",
        maturity_date,
        format_date(maturity_date)
    );
    println!("   Commitment: {}", commitment);

    // Initialize a signer with a private key
    let signer: PrivateKeySigner =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse()
            .expect("Failed to parse private key");

    // Instantiate a provider with the signer and a local anvil node
    let provider = ProviderBuilder::new()
        .wallet(signer)
        .connect("http://127.0.0.1:8545")
        .await
        .expect("Failed to configure provider");

    let private_bond_address = address!("0xdc64a140aa3e981100a9beca4e685f962f0cf6c9");
    let private_bond = PrivateBond::new(private_bond_address, provider.clone());

    let commitment_bytes_vec = commitment.to_string().into_bytes();
    // Pad or truncate to exactly 32 bytes
    let mut commitment_array = [0u8; 32];
    let len = commitment_bytes_vec.len().min(32);
    commitment_array[..len].copy_from_slice(&commitment_bytes_vec[..len]);

    let mint_batch_tx = private_bond
        .mintBatch(vec![alloy::primitives::FixedBytes::<32>::from(
            commitment_array,
        )])
        .send()
        .await
        .expect("Failed to call mintBatch");

    let mint_batch_receipt = mint_batch_tx
        .get_receipt()
        .await
        .expect("Failed to send note batch");

    println!("   Mint transaction sent:     {:#?}", mint_batch_receipt);

    // Add commitment to the global tree state
    let mut tree_state = TreeState::load();
    let leaf_index = tree_state.add_commitment(commitment);
    println!("   Added real note to merkle tree at index: {}", leaf_index);

    // Also add the dummy note (value=0, salt=0, same owner) to the tree
    // This is required because the circuit verifies merkle proofs for both inputs
    let dummy_note = CircuitNote {
        value: 0,
        salt: 0,
        owner: owner_fr.clone(),
        asset_id: 1,
        maturity_date,
    };
    let dummy_commitment = dummy_note.commitment();
    let dummy_index = tree_state.add_commitment(dummy_commitment);
    println!(
        "   Added dummy note to merkle tree at index: {}",
        dummy_index
    );

    // Save the global note as initial bond
    let bond = Bond {
        commitment: format!("{}", commitment),
        nullifier: "N/A (Global Note)".to_string(),
        value: global_value,
        salt,
        owner: keys.public_spending_key_hex,
        asset_id: 1,
        maturity_date,
        created_at: Utc::now().to_rfc3339(),
    };

    let filename = format!("{}/global_note_tranche.json", DATA_DIR);
    match fs::write(&filename, serde_json::to_string_pretty(&bond).unwrap()) {
        Ok(_) => println!("\n✅ Global note saved to: {}", filename),
        Err(e) => println!("❌ Error saving: {}", e),
    }
}

fn register(wallet_name: &str) {
    println!("\n📋 Registering new wallet...");

    // Ensure data directory exists
    ensure_data_dir();

    // Check if wallet already exists
    if load_wallet(wallet_name).is_some() {
        println!("⚠️  Wallet '{}' already exists", wallet_name);
        return;
    }

    // Generate keys
    let keys = ShieldedKeys::generate();

    let wallet = Wallet {
        keys: keys.clone(),
        created_at: Utc::now().to_rfc3339(),
    };

    // Save wallet
    let filename = format!("{}/{}.json", DATA_DIR, wallet_name);
    match fs::write(&filename, serde_json::to_string_pretty(&wallet).unwrap()) {
        Ok(_) => {
            println!("✅ Wallet created!");
            println!("   Saved to: {}", filename);
            println!("   Public key: {}", keys.public_spending_key_hex);
        }
        Err(e) => {
            println!("❌ Error: {}", e);
        }
    }
}

async fn buy(
    buyer_wallet_name: &str,
    buy_value: u64,
    source_note_path: &str,
    issuer_wallet_path: &str,
) {
    println!("\n💳 Buying bond from issuer...");
    println!("   Buy amount: {}", buy_value);

    // 1. Load buyer's wallet (to get buyer's public key)
    let buyer_wallet = match load_wallet(buyer_wallet_name) {
        Some(w) => w,
        None => {
            println!(
                "❌ Buyer wallet '{}' not found. Run 'onboard' first.",
                buyer_wallet_name
            );
            return;
        }
    };

    // 2. Load issuer's wallet (for private key to sign nullifier)
    let issuer_wallet = match load_wallet(issuer_wallet_path) {
        Some(w) => w,
        None => {
            println!("❌ Issuer wallet '{}' not found.", issuer_wallet_path);
            return;
        }
    };

    // 3. Load source note (issuer's note being split)
    let source_bond = match load_bond(source_note_path) {
        Some(b) => b,
        None => {
            println!("❌ Source note '{}' not found.", source_note_path);
            return;
        }
    };

    // Validate: buy value must be less than source note value
    if buy_value >= source_bond.value {
        println!(
            "❌ Buy value ({}) must be less than source note value ({}).",
            buy_value, source_bond.value
        );
        return;
    }

    let change_value = source_bond.value - buy_value;
    println!(
        "   Source note: {} (value={})",
        source_note_path, source_bond.value
    );
    println!("   Change to issuer: {}", change_value);
    println!(
        "   Maturity: {} ({})",
        source_bond.maturity_date,
        format_date(source_bond.maturity_date)
    );

    // 4. Create INPUT note (issuer's note being consumed)
    let issuer_owner_fr = issuer_wallet.keys.public_spending_key();

    let input_note = CircuitNote {
        value: source_bond.value,
        salt: source_bond.salt,
        owner: issuer_owner_fr.clone(),
        asset_id: source_bond.asset_id,
        maturity_date: source_bond.maturity_date,
    };

    // 5. Compute nullifiers for input notes (issuer signs)
    let input_nullifier_fr = issuer_wallet.keys.sign_nullifier(source_bond.salt);
    let dummy_nullifier_fr = issuer_wallet.keys.sign_nullifier(0); // Dummy note has salt=0


    // 6. Create OUTPUT notes
    let mut rng = rand::rng();

    // Output 1: Buyer's note
    let buyer_salt = rng.random::<u64>();
    let buyer_owner_fr = buyer_wallet.keys.public_spending_key();

    let buyer_note = CircuitNote {
        value: buy_value,
        salt: buyer_salt,
        owner: buyer_owner_fr.clone(),
        asset_id: source_bond.asset_id,
        maturity_date: source_bond.maturity_date,
    };

    // Output 2: Issuer's change note
    let change_salt = rng.random::<u64>();
    let change_note = CircuitNote {
        value: change_value,
        salt: change_salt,
        owner: issuer_owner_fr.clone(),
        asset_id: source_bond.asset_id,
        maturity_date: source_bond.maturity_date,
    };

    // 7. Compute output commitments using CircuitNote.commitment() - matches circuit
    let buyer_commitment_fr = buyer_note.commitment();
    let change_commitment_fr = change_note.commitment();

    println!("\n📊 JoinSplit Summary:");
    println!(
        "   INPUT:  value={}, nullifier={}",
        source_bond.value, input_nullifier_fr
    );
    println!(
        "   OUTPUT1 (buyer):  value={}, commitment={}",
        buy_value, buyer_commitment_fr
    );
    println!(
        "   OUTPUT2 (change): value={}, commitment={}",
        change_value, change_commitment_fr
    );

    // 8. Build merkle tree and generate proofs for both input notes
    let mut tree_state = TreeState::load();

    // Find the source note's commitment in the tree (should be at index 0)
    let source_commitment_str = &source_bond.commitment;
    let real_note_index = match tree_state.find_commitment(source_commitment_str) {
        Some(idx) => idx,
        None => {
            println!("❌ Source note commitment not found in tree state!");
            println!("   Commitment: {}", source_commitment_str);
            println!("   ℹ️  Make sure the issuer ran 'onboard' to register the initial note.");
            return;
        }
    };

    // Create dummy note (value=0, salt=0) and find its commitment (should be at index 1)
    let dummy_note = CircuitNote {
        value: 0,
        salt: 0,
        owner: issuer_owner_fr.clone(),
        asset_id: source_bond.asset_id,
        maturity_date: source_bond.maturity_date,
    };
    let dummy_commitment = dummy_note.commitment();
    let dummy_commitment_str = format!("{}", dummy_commitment);

    let dummy_note_index = match tree_state.find_commitment(&dummy_commitment_str) {
        Some(idx) => idx,
        None => {
            println!("❌ Dummy note commitment not found in tree state!");
            println!("   Commitment: {}", dummy_commitment_str);
            println!("   ℹ️  The issuer's onboard should have added both real and dummy notes.");
            return;
        }
    };

    println!("   Real note at tree index: {}", real_note_index);
    println!("   Dummy note at tree index: {}", dummy_note_index);

    // Build the merkle tree and generate proofs for BOTH notes
    let tree = tree_state.build_tree();
    let merkle_root = tree.root();
    let real_note_path = tree.generate_proof(real_note_index);
    let dummy_note_path = tree.generate_proof(dummy_note_index);

    println!("   Merkle root: {}", merkle_root);
    println!("   Real note path_indices: {:?}", real_note_path.indices);
    println!("   Dummy note path_indices: {:?}", dummy_note_path.indices);

    // Get issuer's private spending key
    let private_key_fr = issuer_wallet.keys.get_private_spending_key();

    // Build JoinSplit witness: 2 inputs (real + dummy) -> 2 outputs (buyer + change)
    let witness = build_joinsplit_witness(
        merkle_root,
        input_note,
        real_note_path,
        input_nullifier_fr,
        dummy_note,
        dummy_note_path,
        [buyer_note.clone(), change_note.clone()],
        [buyer_commitment_fr.clone(), change_commitment_fr.clone()],
        private_key_fr,
    );

    // 9. Write Prover.toml
    let circuit_dir = "../circuits";
    match witness.write_prover_toml(circuit_dir) {
        Ok(_) => println!("\n✅ Witness written to {}/Prover.toml", circuit_dir),
        Err(e) => {
            println!("❌ Failed to write witness: {}", e);
            return;
        }
    }

    // 10. Generate proof
    println!("\n🔐 Generating ZK proof...");
    let proof_result = generate_proof(circuit_dir, "circuits").await;
    let proof_path = match &proof_result {
        Ok(path) => {
            println!("   ✅ Proof saved to: {}", path);
            Some(path.clone())
        }
        Err(e) => {
            println!("   ⚠️  Proof generation failed: {}", e);
            println!("   ℹ️  You can run manually:");
            println!("      cd {} && nargo execute circuits && bb prove -b ./target/circuits.json -w ./target/circuits -o ./target", circuit_dir);
            None
        }
    };

    // 11. Call contract transfer() with proof
    if let Some(ref proof_file) = proof_path {
        println!("\n📡 Calling contract transfer()...");

        // Read proof bytes
        let proof_bytes = match fs::read(proof_file) {
            Ok(bytes) => bytes,
            Err(e) => {
                println!("   ❌ Failed to read proof file: {}", e);
                return;
            }
        };

        // Convert Fr values to bytes32
        let root_bytes = fr_to_bytes32(&merkle_root);
        let nullifier0_bytes = fr_to_bytes32(&input_nullifier_fr);
        let nullifier1_bytes = fr_to_bytes32(&dummy_nullifier_fr);
        let commitment0_bytes = fr_to_bytes32(&buyer_commitment_fr);
        let commitment1_bytes = fr_to_bytes32(&change_commitment_fr);

        // Setup provider with signer (use anvil's first account for now)
        let signer: PrivateKeySigner =
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
                .parse()
                .expect("valid private key");
        let provider = ProviderBuilder::new()
            .wallet(signer)
            .connect(RPC_URL)
            .await
            .expect("Failed to configure provider");

        let contract_address = PRIVATE_BOND_ADDRESS
            .parse()
            .expect("valid contract address");
        let contract = PrivateBond::new(contract_address, provider);

        // Call transfer()
        match contract
            .transfer(
                Bytes::from(proof_bytes),
                root_bytes,
                [nullifier0_bytes, nullifier1_bytes],
                [commitment0_bytes, commitment1_bytes],
            )
            .send()
            .await
        {
            Ok(pending) => match pending.watch().await {
                Ok(tx_hash) => {
                    println!("   ✅ Transaction confirmed: {:?}", tx_hash);
                }
                Err(e) => {
                    println!("   ⚠️  Transaction pending but watch failed: {}", e);
                }
            },
            Err(e) => {
                println!("   ❌ Contract call failed: {}", e);
                println!("   ℹ️  Make sure anvil is running and contract is deployed");
            }
        }
    }

    // 12. Save buyer's bond
    let buyer_bond = Bond {
        commitment: format!("{}", buyer_commitment_fr),
        nullifier: format!("{}", buyer_wallet.keys.sign_nullifier(buyer_salt)),
        value: buy_value,
        salt: buyer_salt,
        owner: buyer_wallet.keys.public_spending_key_hex.clone(),
        asset_id: source_bond.asset_id,
        maturity_date: source_bond.maturity_date,
        created_at: Utc::now().to_rfc3339(),
    };

    let buyer_filename = format!(
        "{}/bond_{}_{}.json",
        DATA_DIR,
        buyer_wallet_name,
        &format!("{:016x}", buyer_salt)[..8]
    );
    match fs::write(
        &buyer_filename,
        serde_json::to_string_pretty(&buyer_bond).unwrap(),
    ) {
        Ok(_) => println!("\n✅ Buyer bond saved to: {}", buyer_filename),
        Err(e) => println!("❌ Error saving buyer bond: {}", e),
    }

    // 13. Encrypt memo for issuer audit (issuer can decrypt with their viewing key)
    let buyer_note = Note {
        value: buy_value,
        salt: buyer_salt,
        owner: buyer_salt, // Use salt as owner identifier for Note struct
        asset_id: source_bond.asset_id,
        maturity_date: source_bond.maturity_date,
    };
    
    // Encrypt buyer's note so issuer can audit
    match Note::encrypt(&buyer_wallet.keys, issuer_wallet.keys.public_viewing_key(), &buyer_note) {
        Ok(memo) => {
            let memo_filename = format!("{}/memo_{}_{}.bin", DATA_DIR, buyer_wallet_name, &format!("{:016x}", buyer_salt)[..8]);
            match fs::write(&memo_filename, &memo.to_bytes()) {
                Ok(_) => println!("🔒 Encrypted memo saved to: {}", memo_filename),
                Err(e) => println!("⚠️  Failed to save memo: {}", e),
            }
        }
        Err(e) => println!("⚠️  Memo encryption failed: {}", e),
    }

    // 14. Save issuer's change note (update source)
    let change_bond = Bond {
        commitment: format!("{}", change_commitment_fr),
        nullifier: format!("{}", issuer_wallet.keys.sign_nullifier(change_salt)),
        value: change_value,
        salt: change_salt,
        owner: issuer_wallet.keys.public_spending_key_hex.clone(),
        asset_id: source_bond.asset_id,
        maturity_date: source_bond.maturity_date,
        created_at: Utc::now().to_rfc3339(),
    };

    let change_filename = format!(
        "{}/issuer_change_{}.json",
        DATA_DIR,
        &format!("{:016x}", change_salt)[..8]
    );
    match fs::write(
        &change_filename,
        serde_json::to_string_pretty(&change_bond).unwrap(),
    ) {
        Ok(_) => println!("✅ Issuer change note saved to: {}", change_filename),
        Err(e) => println!("❌ Error saving change note: {}", e),
    }

    // 14. Add new commitments to tree state (for future transactions)
    tree_state.add_commitment(buyer_commitment_fr.clone());
    tree_state.add_commitment(change_commitment_fr.clone());
    println!("   📝 Added 2 new commitments to merkle tree");
}

async fn trade(wallet_a_name: &str, bond_a_path: &str, wallet_b_name: &str, bond_b_path: &str) {
    println!("\n🔄 Atomic trade between {} and {}...", wallet_a_name, wallet_b_name);

    // 1. Load both wallets
    let wallet_a = match load_wallet(wallet_a_name) {
        Some(w) => w,
        None => {
            println!("❌ Wallet A '{}' not found", wallet_a_name);
            return;
        }
    };
    let wallet_b = match load_wallet(wallet_b_name) {
        Some(w) => w,
        None => {
            println!("❌ Wallet B '{}' not found", wallet_b_name);
            return;
        }
    };

    // 2. Load both bonds
    let bond_a = match load_bond(bond_a_path) {
        Some(b) => b,
        None => return,
    };
    let bond_b = match load_bond(bond_b_path) {
        Some(b) => b,
        None => return,
    };

    println!(
        "   Party A ({}) gives: {} (value: {})",
        wallet_a_name,
        &bond_a.commitment[..12],
        bond_a.value
    );
    println!(
        "   Party B ({}) gives: {} (value: {})",
        wallet_b_name,
        &bond_b.commitment[..12],
        bond_b.value
    );

    // 3. Check maturity for both bonds
    let now = Utc::now().timestamp() as u64;
    if now >= bond_a.maturity_date {
        println!("❌ Bond A at/past maturity - cannot trade");
        return;
    }
    if now >= bond_b.maturity_date {
        println!("❌ Bond B at/past maturity - cannot trade");
        return;
    }

    // 4. Check different nullifiers
    if bond_a.nullifier == bond_b.nullifier {
        println!("❌ Cannot trade: identical nullifiers!");
        return;
    }

    // 5. Verify ownership
    if bond_a.owner != wallet_a.keys.public_spending_key_hex {
        println!("❌ Wallet A doesn't own bond A");
        return;
    }
    if bond_b.owner != wallet_b.keys.public_spending_key_hex {
        println!("❌ Wallet B doesn't own bond B");
        return;
    }

    println!("\n✅ Trade validation passed");

    // 6. Load merkle tree
    let mut tree_state = TreeState::load();
    let tree = tree_state.build_tree();
    let merkle_root = tree.root();

    // Find both notes in tree
    let index_a = match tree_state.find_commitment(&bond_a.commitment) {
        Some(idx) => idx,
        None => {
            println!("❌ Bond A commitment not found in merkle tree");
            return;
        }
    };
    let index_b = match tree_state.find_commitment(&bond_b.commitment) {
        Some(idx) => idx,
        None => {
            println!("❌ Bond B commitment not found in merkle tree");
            return;
        }
    };

    println!("   Bond A at tree index: {}", index_a);
    println!("   Bond B at tree index: {}", index_b);

    // 7. Prepare new output notes (A's bond → B, B's bond → A)
    let new_salt_a_to_b: u64 = rand::random();
    let new_salt_b_to_a: u64 = rand::random();

    // Derive owner field from public keys
    let owner_a_bytes = hex::decode(&wallet_a.keys.public_spending_key_hex).unwrap_or_default();
    let owner_a_fr = Fr::from_str(&u64::from_be_bytes(
        owner_a_bytes.get(0..8).unwrap_or(&[0u8; 8]).try_into().unwrap()
    ).to_string()).unwrap();
    
    let owner_b_bytes = hex::decode(&wallet_b.keys.public_spending_key_hex).unwrap_or_default();
    let owner_b_fr = Fr::from_str(&u64::from_be_bytes(
        owner_b_bytes.get(0..8).unwrap_or(&[0u8; 8]).try_into().unwrap()
    ).to_string()).unwrap();

    // Output from A's input → goes to B (same value/maturity as A's bond)
    let output_to_b = CircuitNote {
        value: bond_a.value,
        salt: new_salt_a_to_b,
        owner: owner_b_fr.clone(),
        asset_id: bond_a.asset_id,
        maturity_date: bond_a.maturity_date,
    };
    let commitment_to_b = output_to_b.commitment();

    // Output from B's input → goes to A (same value/maturity as B's bond)
    let output_to_a = CircuitNote {
        value: bond_b.value,
        salt: new_salt_b_to_a,
        owner: owner_a_fr.clone(),
        asset_id: bond_b.asset_id,
        maturity_date: bond_b.maturity_date,
    };
    let commitment_to_a = output_to_a.commitment();

    println!("\n📝 Trade outputs:");
    println!("   A→B: value={}, commitment={}", bond_a.value, commitment_to_b);
    println!("   B→A: value={}, commitment={}", bond_b.value, commitment_to_a);

    // 8. Build proofs for both transfers
    // Proof A: A spends their note, creates output for B (+ dummy for change slot)
    // Proof B: B spends their note, creates output for A (+ dummy for change slot)

    let path_a = tree.generate_proof(index_a);
    let path_b = tree.generate_proof(index_b);

    // Create input notes
    let input_a = CircuitNote {
        value: bond_a.value,
        salt: bond_a.salt,
        owner: owner_a_fr.clone(),
        asset_id: bond_a.asset_id,
        maturity_date: bond_a.maturity_date,
    };
    let input_b = CircuitNote {
        value: bond_b.value,
        salt: bond_b.salt,
        owner: owner_b_fr.clone(),
        asset_id: bond_b.asset_id,
        maturity_date: bond_b.maturity_date,
    };

    // Nullifiers
    let nullifier_a = wallet_a.keys.sign_nullifier(bond_a.salt);
    let nullifier_b = wallet_b.keys.sign_nullifier(bond_b.salt);

    // Dummy notes for the second output slot (value=0)
    let dummy_output = CircuitNote {
        value: 0,
        salt: 0,
        owner: Fr::from_str("0").unwrap(),
        asset_id: bond_a.asset_id,
        maturity_date: bond_a.maturity_date,
    };
    let dummy_commitment = dummy_output.commitment();

    // Find dummy note in tree (should exist from onboard)
    let dummy_index = match tree_state.find_commitment(&format!("{}", dummy_commitment)) {
        Some(idx) => idx,
        None => {
            println!("❌ Dummy note not found in merkle tree");
            return;
        }
    };
    let dummy_path = tree.generate_proof(dummy_index);
    let _dummy_nullifier = Fr::from_str("0").unwrap(); // Dummy nullifier (unused in proof)

    // 9. Generate Proof A (A spends → B receives)
    println!("\n🔐 Generating proof A ({}→{})...", wallet_a_name, wallet_b_name);
    let witness_a = build_joinsplit_witness(
        merkle_root.clone(),
        input_a.clone(),
        path_a,
        nullifier_a.clone(),
        dummy_output.clone(),
        dummy_path.clone(),
        [output_to_b.clone(), dummy_output.clone()],
        [commitment_to_b.clone(), dummy_commitment.clone()],
        wallet_a.keys.get_private_spending_key(),
    );

    let circuit_dir = "../circuits";
    if let Err(e) = witness_a.write_prover_toml(circuit_dir) {
        println!("❌ Failed to write witness A: {}", e);
        return;
    }

    let proof_a_result = generate_proof(circuit_dir, "circuits").await;
    let proof_a_bytes = match proof_a_result {
        Ok(path) => {
            println!("   ✅ Proof A generated");
            match fs::read(&path) {
                Ok(bytes) => bytes,
                Err(e) => {
                    println!("❌ Failed to read proof A: {}", e);
                    return;
                }
            }
        }
        Err(e) => {
            println!("❌ Proof A generation failed: {}", e);
            return;
        }
    };

    // 10. Generate Proof B (B spends → A receives)
    println!("\n� Generating proof B ({}→{})...", wallet_b_name, wallet_a_name);
    let witness_b = build_joinsplit_witness(
        merkle_root.clone(),
        input_b.clone(),
        path_b,
        nullifier_b.clone(),
        dummy_output.clone(),
        dummy_path.clone(),
        [output_to_a.clone(), dummy_output.clone()],
        [commitment_to_a.clone(), dummy_commitment.clone()],
        wallet_b.keys.get_private_spending_key(),
    );

    if let Err(e) = witness_b.write_prover_toml(circuit_dir) {
        println!("❌ Failed to write witness B: {}", e);
        return;
    }

    let proof_b_result = generate_proof(circuit_dir, "circuits").await;
    let proof_b_bytes = match proof_b_result {
        Ok(path) => {
            println!("   ✅ Proof B generated");
            match fs::read(&path) {
                Ok(bytes) => bytes,
                Err(e) => {
                    println!("❌ Failed to read proof B: {}", e);
                    return;
                }
            }
        }
        Err(e) => {
            println!("❌ Proof B generation failed: {}", e);
            return;
        }
    };

    // 11. Call atomicSwap on contract
    println!("\n📡 Calling atomicSwap()...");

    let signer: PrivateKeySigner =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse()
            .expect("valid private key");
    let provider = ProviderBuilder::new()
        .wallet(signer)
        .connect(RPC_URL)
        .await
        .expect("Failed to configure provider");

    let contract_address = PRIVATE_BOND_ADDRESS.parse().expect("valid contract address");
    let contract = PrivateBond::new(contract_address, provider);

    // Build public inputs for proof A
    let root_a = fr_to_bytes32(&merkle_root);
    let null_a = fr_to_bytes32(&nullifier_a);
    let comm_a = fr_to_bytes32(&commitment_to_b);
    let maturity_a = FixedBytes::<32>::from_slice(&{
        let mut bytes = [0u8; 32];
        bytes[24..32].copy_from_slice(&bond_a.maturity_date.to_be_bytes());
        bytes
    });

    // Build public inputs for proof B
    let root_b = fr_to_bytes32(&merkle_root);
    let null_b = fr_to_bytes32(&nullifier_b);
    let comm_b = fr_to_bytes32(&commitment_to_a);
    let maturity_b = FixedBytes::<32>::from_slice(&{
        let mut bytes = [0u8; 32];
        bytes[24..32].copy_from_slice(&bond_b.maturity_date.to_be_bytes());
        bytes
    });

    match contract
        .atomicSwap(
            Bytes::from(proof_a_bytes),
            vec![root_a, null_a, comm_a, maturity_a],
            Bytes::from(proof_b_bytes),
            vec![root_b, null_b, comm_b, maturity_b],
        )
        .send()
        .await
    {
        Ok(pending) => match pending.watch().await {
            Ok(tx_hash) => {
                println!("   ✅ AtomicSwap confirmed: {:?}", tx_hash);
            }
            Err(e) => {
                println!("   ⚠️  Transaction pending but watch failed: {}", e);
            }
        },
        Err(e) => {
            println!("   ❌ atomicSwap failed: {}", e);
            return;
        }
    }

    // 12. Save new bonds
    // Bond for B (received from A)
    let bond_for_b = Bond {
        commitment: format!("{}", commitment_to_b),
        nullifier: format!("{}", wallet_b.keys.sign_nullifier(new_salt_a_to_b)),
        value: bond_a.value,
        salt: new_salt_a_to_b,
        owner: wallet_b.keys.public_spending_key_hex.clone(),
        asset_id: bond_a.asset_id,
        maturity_date: bond_a.maturity_date,
        created_at: Utc::now().to_rfc3339(),
    };
    let file_b = format!("{}/bond_{}_{}.json", DATA_DIR, wallet_b_name, &format!("{:016x}", new_salt_a_to_b)[..8]);
    if let Err(e) = fs::write(&file_b, serde_json::to_string_pretty(&bond_for_b).unwrap()) {
        println!("⚠️  Failed to save bond for B: {}", e);
    } else {
        println!("\n✅ Bond for {} saved: {}", wallet_b_name, file_b);
    }

    // Bond for A (received from B)
    let bond_for_a = Bond {
        commitment: format!("{}", commitment_to_a),
        nullifier: format!("{}", wallet_a.keys.sign_nullifier(new_salt_b_to_a)),
        value: bond_b.value,
        salt: new_salt_b_to_a,
        owner: wallet_a.keys.public_spending_key_hex.clone(),
        asset_id: bond_b.asset_id,
        maturity_date: bond_b.maturity_date,
        created_at: Utc::now().to_rfc3339(),
    };
    let file_a = format!("{}/bond_{}_{}.json", DATA_DIR, wallet_a_name, &format!("{:016x}", new_salt_b_to_a)[..8]);
    if let Err(e) = fs::write(&file_a, serde_json::to_string_pretty(&bond_for_a).unwrap()) {
        println!("⚠️  Failed to save bond for A: {}", e);
    } else {
        println!("✅ Bond for {} saved: {}", wallet_a_name, file_a);
    }

    // 13. Encrypt memos for each party
    let note_for_b = Note {
        value: bond_a.value,
        salt: new_salt_a_to_b,
        owner: new_salt_a_to_b,
        asset_id: bond_a.asset_id,
        maturity_date: bond_a.maturity_date,
    };
    if let Ok(memo) = Note::encrypt(&wallet_a.keys, wallet_b.keys.public_viewing_key(), &note_for_b) {
        let memo_file = format!("{}/memo_trade_{}_{}.bin", DATA_DIR, wallet_b_name, &format!("{:016x}", new_salt_a_to_b)[..8]);
        let _ = fs::write(&memo_file, &memo.to_bytes());
        println!("🔒 Encrypted memo for {} saved", wallet_b_name);
    }

    let note_for_a = Note {
        value: bond_b.value,
        salt: new_salt_b_to_a,
        owner: new_salt_b_to_a,
        asset_id: bond_b.asset_id,
        maturity_date: bond_b.maturity_date,
    };
    if let Ok(memo) = Note::encrypt(&wallet_b.keys, wallet_a.keys.public_viewing_key(), &note_for_a) {
        let memo_file = format!("{}/memo_trade_{}_{}.bin", DATA_DIR, wallet_a_name, &format!("{:016x}", new_salt_b_to_a)[..8]);
        let _ = fs::write(&memo_file, &memo.to_bytes());
        println!("🔒 Encrypted memo for {} saved", wallet_a_name);
    }

    // 14. Update tree state
    tree_state.add_commitment(commitment_to_b);
    tree_state.add_commitment(commitment_to_a);
    println!("   📝 Added 2 new commitments to merkle tree");

    println!("\n🎉 Trade complete!");
}

async fn redeem(wallet_name: &str, bond_path: &str) {
    println!("\n💰 Redeeming bond...");

    // 1. Load wallet and bond
    let wallet = match load_wallet(wallet_name) {
        Some(w) => w,
        None => {
            println!("❌ Wallet '{}' not found", wallet_name);
            return;
        }
    };

    let bond = match load_bond(bond_path) {
        Some(b) => b,
        None => return,
    };

    println!(
        "   Bond: {} (value: {})",
        &bond.commitment[..12],
        bond.value
    );

    // 2. Check maturity
    let now = Utc::now().timestamp() as u64;
    if now < bond.maturity_date {
        let days_left = (bond.maturity_date - now) / 86400;
        println!("❌ Cannot redeem: {} days until maturity", days_left);
        println!("   Maturity date: {}", format_date(bond.maturity_date));
        return;
    }

    println!("✅ Bond at maturity - proceeding with redemption");

    // 3. Verify ownership
    if bond.owner != wallet.keys.public_spending_key_hex {
        println!("❌ Wallet '{}' doesn't own this bond", wallet_name);
        return;
    }

    // 4. Load merkle tree and find bond
    let mut tree_state = TreeState::load();
    let tree = tree_state.build_tree();
    let merkle_root = tree.root();

    let bond_index = match tree_state.find_commitment(&bond.commitment) {
        Some(idx) => idx,
        None => {
            println!("❌ Bond commitment not found in merkle tree");
            return;
        }
    };

    // 5. Derive owner Fr from public key
    let owner_bytes = hex::decode(&wallet.keys.public_spending_key_hex).unwrap_or_default();
    let owner_fr = Fr::from_str(&u64::from_be_bytes(
        owner_bytes.get(0..8).unwrap_or(&[0u8; 8]).try_into().unwrap()
    ).to_string()).unwrap();

    // 6. Create input note
    let input_note = CircuitNote {
        value: bond.value,
        salt: bond.salt,
        owner: owner_fr.clone(),
        asset_id: bond.asset_id,
        maturity_date: bond.maturity_date,
    };

    // 7. Create dummy input note (second input slot)
    let dummy_note = CircuitNote {
        value: 0,
        salt: 0,
        owner: owner_fr.clone(),
        asset_id: bond.asset_id,
        maturity_date: bond.maturity_date,
    };
    let dummy_commitment = dummy_note.commitment();
    let dummy_commitment_str = format!("{}", dummy_commitment);

    let dummy_index = match tree_state.find_commitment(&dummy_commitment_str) {
        Some(idx) => idx,
        None => {
            println!("❌ Dummy note not found in merkle tree");
            println!("   ℹ️  Ensure issuer ran 'onboard' which creates dummy notes");
            return;
        }
    };

    println!("   Bond at tree index: {}", bond_index);
    println!("   Dummy at tree index: {}", dummy_index);

    // 8. Generate merkle proofs
    let bond_path_proof = tree.generate_proof(bond_index);
    let dummy_path_proof = tree.generate_proof(dummy_index);

    // 9. Compute nullifiers
    let nullifier = wallet.keys.sign_nullifier(bond.salt);
    let dummy_nullifier = wallet.keys.sign_nullifier(0); // dummy salt = 0

    // 10. Create output notes with value = 0 (burn)
    let output_salt_0: u64 = rand::random();
    let output_salt_1: u64 = rand::random();

    let output_note_0 = CircuitNote {
        value: 0,
        salt: output_salt_0,
        owner: owner_fr.clone(),
        asset_id: bond.asset_id,
        maturity_date: bond.maturity_date,
    };
    let output_note_1 = CircuitNote {
        value: 0,
        salt: output_salt_1,
        owner: owner_fr.clone(),
        asset_id: bond.asset_id,
        maturity_date: bond.maturity_date,
    };

    let commitment_out_0 = output_note_0.commitment();
    let commitment_out_1 = output_note_1.commitment();

    println!("\n📝 Burn transaction:");
    println!("   Input value:  {} (will be burned)", bond.value);
    println!("   Output value: 0 + 0 = 0");

    // 11. Build witness for JoinSplit (redemption = outputs sum to 0)
    let witness = build_joinsplit_witness(
        merkle_root.clone(),
        input_note,
        bond_path_proof,
        nullifier.clone(),
        dummy_note,
        dummy_path_proof,
        [output_note_0, output_note_1],
        [commitment_out_0.clone(), commitment_out_1.clone()],
        wallet.keys.get_private_spending_key(),
    );

    // 12. Write Prover.toml
    let circuit_dir = "../circuits";
    match witness.write_prover_toml(circuit_dir) {
        Ok(_) => println!("\n✅ Witness written to {}/Prover.toml", circuit_dir),
        Err(e) => {
            println!("❌ Failed to write witness: {}", e);
            return;
        }
    }

    // 13. Generate proof
    println!("\n🔐 Generating burn proof...");
    let proof_result = generate_proof(circuit_dir, "circuits").await;
    let proof_bytes = match proof_result {
        Ok(path) => {
            println!("   ✅ Proof generated: {}", path);
            match fs::read(&path) {
                Ok(bytes) => bytes,
                Err(e) => {
                    println!("❌ Failed to read proof: {}", e);
                    return;
                }
            }
        }
        Err(e) => {
            println!("❌ Proof generation failed: {}", e);
            return;
        }
    };

    // 14. Call contract burn()
    println!("\n📡 Calling contract burn()...");

    let signer: PrivateKeySigner =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse()
            .expect("valid private key");
    let provider = ProviderBuilder::new()
        .wallet(signer)
        .connect(RPC_URL)
        .await
        .expect("Failed to configure provider");

    let contract_address = PRIVATE_BOND_ADDRESS.parse().expect("valid contract address");
    let contract = PrivateBond::new(contract_address, provider);

    // Convert to bytes32
    let root_bytes = fr_to_bytes32(&merkle_root);
    let null_0 = fr_to_bytes32(&nullifier);
    let null_1 = fr_to_bytes32(&dummy_nullifier);
    let comm_0 = fr_to_bytes32(&commitment_out_0);
    let comm_1 = fr_to_bytes32(&commitment_out_1);
    let maturity_bytes = FixedBytes::<32>::from_slice(&{
        let mut bytes = [0u8; 32];
        bytes[24..32].copy_from_slice(&bond.maturity_date.to_be_bytes());
        bytes
    });
    let is_redeem = FixedBytes::<32>::from_slice(&{
        let mut bytes = [0u8; 32];
        bytes[31] = 1; // isRedeem = true
        bytes
    });

    match contract
        .burn(
            Bytes::from(proof_bytes),
            root_bytes,
            [null_0, null_1],
            [comm_0, comm_1],
            maturity_bytes,
            is_redeem,
        )
        .send()
        .await
    {
        Ok(pending) => match pending.watch().await {
            Ok(tx_hash) => {
                println!("   ✅ Burn transaction confirmed: {:?}", tx_hash);
            }
            Err(e) => {
                println!("   ⚠️  Transaction pending but watch failed: {}", e);
            }
        },
        Err(e) => {
            println!("   ❌ Burn call failed: {}", e);
            return;
        }
    }

    // 15. Mark bond as redeemed (rename file)
    let redeemed_path = bond_path.replace(".json", "_REDEEMED.json");
    if let Err(e) = fs::rename(bond_path, &redeemed_path) {
        println!("   ⚠️  Failed to mark bond as redeemed: {}", e);
    } else {
        println!("   📝 Bond marked as redeemed: {}", redeemed_path);
    }

    // 16. Update tree state
    tree_state.add_commitment(commitment_out_0);
    tree_state.add_commitment(commitment_out_1);

    println!("\n🎉 Redemption complete!");
    println!("   Value burned: {}", bond.value);
    println!("   ℹ️  Contact issuer for off-chain cash settlement");
}

fn info(bond_path: &str) {
    println!("\n📊 Bond Information:");

    let bond = match load_bond(bond_path) {
        Some(b) => b,
        None => return,
    };

    println!("   Commitment: {}", bond.commitment);
    println!("   Nullifier:  {}", bond.nullifier);
    println!("   Value:      {}", bond.value);
    println!("   Salt:       {}", bond.salt);
    println!("   Asset ID:   {}", bond.asset_id);
    println!("   Created:    {}", bond.created_at);
    println!("   Maturity:   {}", format_date(bond.maturity_date));

    let now = Utc::now().timestamp() as u64;
    if now >= bond.maturity_date {
        println!("   Status:     🔴 Matured");
    } else {
        let days = (bond.maturity_date - now) / 86400;
        println!("   Status:     🟢 {} days remaining", days);
    }
}

fn scan(wallet_name: &str) {
    println!("\n🔍 Scanning for encrypted memos...");

    // Load recipient wallet
    let recipient_wallet = match load_wallet(wallet_name) {
        Some(w) => w,
        None => {
            println!("❌ Wallet '{}' not found", wallet_name);
            return;
        }
    };

    // Find memo files for this wallet
    let entries = match fs::read_dir(DATA_DIR) {
        Ok(e) => e,
        Err(_) => {
            println!("❌ Cannot read data directory");
            return;
        }
    };

    let mut memos_found = 0;
    let mut decrypted_count = 0;

    for entry in entries.flatten() {
        let filename = entry.file_name().to_string_lossy().to_string();
        if !filename.ends_with(".bin") {
            continue;
        }
        if !filename.contains(&format!("_{}_", wallet_name)) && !filename.contains(&format!("_{}", wallet_name)) {
            continue;
        }

        memos_found += 1;
        let memo_path = entry.path();
        
        // Read memo bytes and deserialize
        let memo_bytes = match fs::read(&memo_path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let memo = match notes::Memo::from_bytes(&memo_bytes) {
            Ok(m) => m,
            Err(_) => continue,
        };

        // Decrypt memo (sender identity not needed with ephemeral keys)
        match Note::decrypt(&recipient_wallet.keys, &memo) {
            Ok(note) => {
                decrypted_count += 1;
                println!("\n   📬 Memo: {}", filename);
                println!("      Value:    {}", note.value);
                println!("      Salt:     {:016x}", note.salt);
                println!("      Asset ID: {}", note.asset_id);
                println!("      Maturity: {}", format_date(note.maturity_date));
            }
            Err(e) => {
                println!("\n   ⚠️  Failed to decrypt {}: {}", filename, e);
            }
        }
    }

    if memos_found == 0 {
        println!("   No memos found for wallet '{}'", wallet_name);
    } else {
        println!("\n✅ Found {} memos, decrypted {}", memos_found, decrypted_count);
        if decrypted_count < memos_found {
            println!("   ℹ️  Some memos could not be decrypted (wrong recipient or corrupted)");
        }
    }
}

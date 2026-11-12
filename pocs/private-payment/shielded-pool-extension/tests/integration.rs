//! In-process end-to-end test for the shielded-pool extension.
//!
//! Self-contained: spawns `anvil`, deploys the real bb-generated verifiers +
//! `MockERC20` + `ShieldedPoolExt` via a forge script (forge auto-links the
//! contract libraries), and drives the full flow with REAL proofs (bb). It
//! exercises every novel mechanism on-chain: the `epoch_created` deposit binding,
//! epoch rollover, the per-note IVC chain proof (genesis + one frozen-epoch
//! extend, recursively verified by the spend), the two-proof spend (wallet spend
//! proof + relayer insertion proof, bound by the shared nullifier list), and the
//! active-tree advance.
//!
//! Covers both spend flows (deposit -> rollover -> transfer, and the same through
//! withdraw): transfer exercises the k=2 insertion proof, withdraw the k=1 one.
//!
//! Heavy (real recursive proving + anvil + forge): `#[ignore]`d. Run with:
//!   cargo test --test integration -- --ignored --nocapture
//!
//! Prereqs: `anvil`, `forge`, `nargo` 1.0.0, `bb` 6.0.0 on PATH.

use std::{
    path::{
        Path,
        PathBuf,
    },
    process::Command,
};

use alloy::{
    node_bindings::Anvil,
    primitives::{
        Address,
        B256,
        Bytes,
        U256,
    },
};
use private_payment_shielded_pool_extension::{
    adapters::{
        bb_prover::{
            field_to_decimal,
            BbProver,
            ChainUpdateArtifact,
            ChainUpdateInput,
            DepositInput,
            InsertionToml,
            TransferInput,
            WithdrawInput,
            CHAIN_PROOF_PUB_LEN,
            RECURSIVE_PROOF_LENGTH,
            ULTRA_VK_LENGTH_IN_FIELDS,
        },
        ethereum_rpc::EthereumRpc,
        indexed_merkle_tree::IndexedMerkleTree,
    },
    domain::{
        chain_proof::expected_accumulator,
        commitment::Commitment,
        epoch::Epoch,
        indexed_merkle::NonMembershipWitness,
        keys::SpendingKey,
        note::Note,
    },
};

const DEV_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn fd(b: B256) -> String {
    field_to_decimal(b)
}

fn token_field(token: Address) -> B256 {
    B256::left_padding_from(token.as_slice())
}

fn zeros(n: usize) -> Vec<String> {
    vec!["0".to_string(); n]
}

fn index_bits(index: u64) -> Vec<bool> {
    (0..32).map(|i| (index >> i) & 1 == 1).collect()
}

fn decimal_to_b256(decimal: &str) -> B256 {
    B256::from(U256::from_str_radix(decimal, 10).expect("vk_hash decimal"))
}

/// Deploy everything via the forge script (forge deploys + links the libraries),
/// returning `(pool, token)` read back from `deployments.toml`.
fn deploy(root: &Path, endpoint: &str, chain_vk_hash: B256, empty_imt_root: B256) -> (Address, Address) {
    // Seed the [31337] chain skeleton the forge-std `Config` base reads on load
    // (it requires the file to exist with the chain table); the deploy script
    // then records the deployed addresses under [31337.address].
    std::fs::write(root.join("deployments.toml"), format!("[31337]\nendpoint_url = \"{endpoint}\"\n"))
        .expect("write deployments.toml skeleton");

    let status = Command::new("forge")
        .args([
            "script",
            "contracts/script/Deploy.s.sol:Deploy",
            "--rpc-url",
            endpoint,
            "--broadcast",
            "--private-key",
            DEV_KEY,
        ])
        .current_dir(root)
        .env("CHAIN_VK_HASH", format!("0x{}", hex::encode(chain_vk_hash)))
        .env("EMPTY_IMT_ROOT", format!("0x{}", hex::encode(empty_imt_root)))
        .status()
        .expect("run forge script");
    assert!(status.success(), "forge deploy failed");

    let content = std::fs::read_to_string(root.join("deployments.toml")).expect("deployments.toml");
    let v: toml::Value = content.parse().expect("parse deployments.toml");
    // `Config` writes chain-keyed tables: [31337.address] <key> = <addr>.
    let addrs = &v["31337"]["address"];
    let pool = addrs["shielded_pool"].as_str().unwrap().parse().expect("pool address");
    let token = addrs["mock_token"].as_str().unwrap().parse().expect("token address");
    (pool, token)
}

/// Genesis (base-case) chain-update input for a note.
fn chain_genesis(vk_hash: &str, commitment: Commitment, sk: &SpendingKey, token: Address, amount: U256, salt: B256) -> ChainUpdateInput {
    ChainUpdateInput {
        commitment: fd(commitment.0),
        epoch_created: "0".into(),
        epoch_validated_through: "0".into(),
        accumulator: "0".into(),
        fixed_vk_hash: vk_hash.into(),
        is_base_case: true,
        prior_vk: zeros(ULTRA_VK_LENGTH_IN_FIELDS),
        prior_proof: zeros(RECURSIVE_PROOF_LENGTH),
        prior_public_inputs: zeros(CHAIN_PROOF_PUB_LEN),
        frozen_root_next: "0".into(),
        spending_key: fd(sk.0),
        token: fd(token_field(token)),
        amount: fd(B256::from(amount)),
        salt: fd(salt),
        low_value: "0".into(),
        low_next_value: "0".into(),
        low_next_index: "0".into(),
        path_bits: vec![false; 32],
        siblings: zeros(32),
    }
}

/// One chain-update step: fold `frozen_root` (epoch the note wasn't spent in),
/// recursively verifying `prior`.
#[allow(clippy::too_many_arguments)]
fn chain_step(
    vk_hash: &str,
    vk_fields: &[String],
    commitment: Commitment,
    sk: &SpendingKey,
    token: Address,
    amount: U256,
    salt: B256,
    prior: &ChainUpdateArtifact,
    frozen_root: B256,
    accumulator: B256,
    nmw: &NonMembershipWitness,
) -> ChainUpdateInput {
    ChainUpdateInput {
        commitment: fd(commitment.0),
        epoch_created: "0".into(),
        epoch_validated_through: "1".into(),
        accumulator: fd(accumulator),
        fixed_vk_hash: vk_hash.into(),
        is_base_case: false,
        prior_vk: vk_fields.to_vec(),
        prior_proof: prior.proof.clone(),
        prior_public_inputs: prior.public_inputs.clone(),
        frozen_root_next: fd(frozen_root),
        spending_key: fd(sk.0),
        token: fd(token_field(token)),
        amount: fd(B256::from(amount)),
        salt: fd(salt),
        low_value: fd(nmw.low_leaf.value),
        low_next_value: fd(nmw.low_leaf.next_value),
        low_next_index: nmw.low_leaf.next_index.to_string(),
        path_bits: index_bits(nmw.low_leaf_index),
        siblings: nmw.siblings.iter().map(|s| fd(*s)).collect(),
    }
}

#[tokio::test]
#[ignore = "spawns anvil + forge + proves real circuits (minutes); run with --ignored"]
async fn transfer_flow_verifies_on_chain() {
    let root = project_root();
    let prover = BbProver::new(root.clone());

    // Off-chain constructor params: chainVkHash from bb, emptyImtRoot from the IMT.
    let (vk_fields, vk_hash) = prover.write_chain_update_vk().expect("chain vk");
    let chain_vk_hash = decimal_to_b256(&vk_hash);
    let empty_imt_root = IndexedMerkleTree::new().root();

    let anvil = Anvil::new().spawn();
    let endpoint = anvil.endpoint();
    let (pool, token) = deploy(&root, &endpoint, chain_vk_hash, empty_imt_root);

    let rpc = EthereumRpc::new(&endpoint, DEV_KEY, pool).await.expect("rpc");
    let deployer = rpc.signer_address();
    rpc.add_supported_token(token).await.expect("add token");
    let amount = U256::from(1000u64);
    rpc.mint_mock_token(token, deployer, amount).await.expect("mint");
    rpc.approve_token(token, amount).await.expect("approve");

    let sk = SpendingKey::from_bytes([3u8; 32]);
    let owner = sk.derive_owner_pubkey();
    let salt_a = B256::repeat_byte(0x07);
    let note_a = Note::with_salt(token, amount, owner, salt_a, Epoch(0));
    let commit_a = note_a.commitment();

    // ===== 1. Alice deposits at epoch 0 (real deposit proof) =====
    prover.write_evm_vk("deposit").expect("deposit vk");
    let dep = DepositInput {
        commitment: fd(commit_a.0),
        token: fd(token_field(token)),
        amount: fd(B256::from(amount)),
        current_epoch_at_deposit: 0,
        owner_pubkey: fd(owner.0),
        salt: fd(salt_a),
    };
    let dep_proof = prover.prove_evm("deposit", &dep).expect("prove deposit");
    rpc.deposit(Bytes::from(dep_proof.proof), commit_a.0, token, amount, Bytes::new())
        .await
        .expect("on-chain deposit");
    assert_eq!(rpc.commitment_count().await.unwrap(), 1);
    let commitment_root = rpc.commitment_root().await.unwrap(); // single-leaf tree => commit_a

    // ===== 2. Rollover to epoch 1 (freezes the empty epoch-0 active tree) =====
    rpc.rollover_epoch().await.expect("rollover");
    assert_eq!(rpc.current_epoch().await.unwrap(), 1);
    let frozen0 = rpc.frozen_nullifier_root(0).await.unwrap();

    // ===== 3. Alice's chain proof: genesis -> extend over frozen epoch 0 =====
    let genesis = chain_genesis(&vk_hash, commit_a, &sk, token, amount, salt_a);
    let genesis_art = prover.prove_chain_update(&genesis).expect("genesis chain proof");

    let frozen_tree = IndexedMerkleTree::new(); // empty epoch-0 tree (root == frozen0)
    assert_eq!(frozen_tree.root(), frozen0, "Rust empty IMT root == on-chain frozenNullifierRoots[0]");
    let phantom_eta_0 = commit_a.nullifier(&sk, Epoch(0)).0;
    let nmw = frozen_tree.non_membership_witness(phantom_eta_0).expect("non-membership");
    let acc1 = expected_accumulator(&[frozen0]);
    let step = chain_step(&vk_hash, &vk_fields, commit_a, &sk, token, amount, salt_a, &genesis_art, frozen0, acc1, &nmw);
    let chain_art = prover.prove_chain_update(&step).expect("chain step (caught up to epoch 1)");

    // ===== 4. Transfer: Alice's note -> 600 + 400 to herself; input 1 padding =====
    let pad = Note::with_salt(token, U256::ZERO, owner, B256::repeat_byte(0x09), Epoch(1));
    let out0 = Note::with_salt(token, U256::from(600u64), owner, B256::repeat_byte(0x01), Epoch(1));
    let out1 = Note::with_salt(token, U256::from(400u64), owner, B256::repeat_byte(0x02), Epoch(1));
    let eta0 = commit_a.nullifier(&sk, Epoch(1)).0;
    let eta1 = pad.commitment().nullifier(&sk, Epoch(1)).0;

    let ti = TransferInput {
        nullifier_active_0: fd(eta0),
        nullifier_active_1: fd(eta1),
        commitment_out_0: fd(out0.commitment().0),
        commitment_out_1: fd(out1.commitment().0),
        commitment_root: fd(commitment_root),
        current_epoch: "1".into(),
        chain_vk_hash: vk_hash.clone(),
        epoch_created_in_0: "0".into(),
        epoch_created_in_1: "1".into(),
        chain_accumulator_in_0: fd(acc1),
        chain_accumulator_in_1: "0".into(),
        spending_key: fd(sk.0),
        token_in_0: fd(token_field(token)),
        amount_in_0: 1000,
        salt_in_0: fd(salt_a),
        token_in_1: fd(token_field(token)),
        amount_in_1: 0,
        salt_in_1: fd(B256::repeat_byte(0x09)),
        token_out_0: fd(token_field(token)),
        amount_out_0: 600,
        owner_out_0: fd(owner.0),
        salt_out_0: fd(B256::repeat_byte(0x01)),
        token_out_1: fd(token_field(token)),
        amount_out_1: 400,
        owner_out_1: fd(owner.0),
        salt_out_1: fd(B256::repeat_byte(0x02)),
        proof_length: 0,
        path_0: zeros(32),
        indices_0: vec![false; 32],
        path_1: zeros(32),
        indices_1: vec![false; 32],
        chain_vk: vk_fields.clone(),
        chain_proof_0: chain_art.proof.clone(),
        chain_pub_0: chain_art.public_inputs.clone(),
        chain_proof_1: zeros(RECURSIVE_PROOF_LENGTH),
        chain_pub_1: zeros(CHAIN_PROOF_PUB_LEN),
    };
    prover.write_evm_vk("transfer").expect("transfer vk");
    let spend = prover.prove_evm("transfer", &ti).expect("prove transfer");

    // ===== 5. Relayer insertion proof for [eta0, eta1] into the active tree =====
    let mut active = IndexedMerkleTree::new(); // epoch-1 active tree starts empty
    let pre_root = active.root();
    let pre_count = active.leaf_count();
    let w0 = active.insert(eta0).expect("insert eta0");
    let w1 = active.insert(eta1).expect("insert eta1");
    let post_root = active.root();
    let it = InsertionToml::from_witnesses(pre_root, post_root, pre_count, &[eta0, eta1], &[w0, w1]);
    prover.write_evm_vk("insertion").expect("insertion vk");
    let ins = prover.prove_evm("insertion", &it).expect("prove insertion");

    // ===== 6. Submit both proofs on-chain =====
    rpc.transfer(
        Bytes::from(spend.proof),
        Bytes::from(ins.proof),
        [eta0, eta1],
        [out0.commitment().0, out1.commitment().0],
        commitment_root,
        [0, 1],
        post_root,
        Bytes::new(),
    )
    .await
    .expect("on-chain transfer (spend + insertion proofs)");

    assert_eq!(rpc.active_nullifier_root().await.unwrap(), post_root, "active root advanced");
    assert_eq!(rpc.active_leaf_count().await.unwrap(), 3, "two nullifiers appended (1 -> 3)");
    assert_eq!(rpc.commitment_count().await.unwrap(), 3, "two outputs appended (1 -> 3)");
}

#[tokio::test]
#[ignore = "spawns anvil + forge + proves real circuits (minutes); run with --ignored"]
async fn withdraw_flow_verifies_on_chain() {
    let root = project_root();
    let prover = BbProver::new(root.clone());

    // Off-chain constructor params: chainVkHash from bb, emptyImtRoot from the IMT.
    let (vk_fields, vk_hash) = prover.write_chain_update_vk().expect("chain vk");
    let chain_vk_hash = decimal_to_b256(&vk_hash);
    let empty_imt_root = IndexedMerkleTree::new().root();

    let anvil = Anvil::new().spawn();
    let endpoint = anvil.endpoint();
    let (pool, token) = deploy(&root, &endpoint, chain_vk_hash, empty_imt_root);

    let rpc = EthereumRpc::new(&endpoint, DEV_KEY, pool).await.expect("rpc");
    let deployer = rpc.signer_address();
    rpc.add_supported_token(token).await.expect("add token");
    let amount = U256::from(1000u64);
    rpc.mint_mock_token(token, deployer, amount).await.expect("mint");
    rpc.approve_token(token, amount).await.expect("approve");

    let sk = SpendingKey::from_bytes([3u8; 32]);
    let owner = sk.derive_owner_pubkey();
    let salt_a = B256::repeat_byte(0x07);
    let note_a = Note::with_salt(token, amount, owner, salt_a, Epoch(0));
    let commit_a = note_a.commitment();

    // ===== 1. Deposit at epoch 0 (real deposit proof) =====
    prover.write_evm_vk("deposit").expect("deposit vk");
    let dep = DepositInput {
        commitment: fd(commit_a.0),
        token: fd(token_field(token)),
        amount: fd(B256::from(amount)),
        current_epoch_at_deposit: 0,
        owner_pubkey: fd(owner.0),
        salt: fd(salt_a),
    };
    let dep_proof = prover.prove_evm("deposit", &dep).expect("prove deposit");
    rpc.deposit(Bytes::from(dep_proof.proof), commit_a.0, token, amount, Bytes::new())
        .await
        .expect("on-chain deposit");
    let commitment_root = rpc.commitment_root().await.unwrap(); // single-leaf tree => commit_a

    // ===== 2. Rollover to epoch 1 (freezes the empty epoch-0 active tree) =====
    rpc.rollover_epoch().await.expect("rollover");
    let frozen0 = rpc.frozen_nullifier_root(0).await.unwrap();

    // ===== 3. Chain proof: genesis -> extend over frozen epoch 0 =====
    let genesis = chain_genesis(&vk_hash, commit_a, &sk, token, amount, salt_a);
    let genesis_art = prover.prove_chain_update(&genesis).expect("genesis chain proof");
    let frozen_tree = IndexedMerkleTree::new(); // empty epoch-0 tree (root == frozen0)
    let phantom_eta_0 = commit_a.nullifier(&sk, Epoch(0)).0;
    let nmw = frozen_tree.non_membership_witness(phantom_eta_0).expect("non-membership");
    let acc1 = expected_accumulator(&[frozen0]);
    let step = chain_step(&vk_hash, &vk_fields, commit_a, &sk, token, amount, salt_a, &genesis_art, frozen0, acc1, &nmw);
    let chain_art = prover.prove_chain_update(&step).expect("chain step (caught up to epoch 1)");

    // ===== 4. Withdraw: note_a's full 1000 exits to `recipient` (1 input, no change) =====
    let recipient = Address::repeat_byte(0xBB);
    let eta = commit_a.nullifier(&sk, Epoch(1)).0;
    let wi = WithdrawInput {
        nullifier_active: fd(eta),
        token: fd(token_field(token)),
        amount: 1000,
        recipient: fd(token_field(recipient)),
        commitment_root: fd(commitment_root),
        current_epoch: "1".into(),
        chain_vk_hash: vk_hash.clone(),
        epoch_created_in: "0".into(),
        chain_accumulator_in: fd(acc1),
        spending_key: fd(sk.0),
        salt: fd(salt_a),
        proof_length: 0,
        path: zeros(32),
        indices: vec![false; 32],
        chain_vk: vk_fields.clone(),
        chain_proof: chain_art.proof.clone(),
        chain_pub: chain_art.public_inputs.clone(),
    };
    prover.write_evm_vk("withdraw").expect("withdraw vk");
    let spend = prover.prove_evm("withdraw", &wi).expect("prove withdraw");

    // ===== 5. Relayer k=1 insertion proof for [eta] (the insertion_withdraw circuit) =====
    let mut active = IndexedMerkleTree::new(); // epoch-1 active tree starts empty
    let pre_root = active.root();
    let pre_count = active.leaf_count();
    let w = active.insert(eta).expect("insert eta");
    let post_root = active.root();
    let it = InsertionToml::from_witnesses(pre_root, post_root, pre_count, &[eta], &[w]);
    prover.write_evm_vk("insertion_withdraw").expect("insertion_withdraw vk");
    let ins = prover.prove_evm("insertion_withdraw", &it).expect("prove k=1 insertion");

    // ===== 6. Submit both proofs on-chain (exercises the real k=1 withdraw verifier) =====
    rpc.withdraw(
        Bytes::from(spend.proof),
        Bytes::from(ins.proof),
        eta,
        token,
        amount,
        recipient,
        commitment_root,
        0,
        post_root,
    )
    .await
    .expect("on-chain withdraw (spend + k=1 insertion proofs)");

    assert_eq!(rpc.active_nullifier_root().await.unwrap(), post_root, "active root advanced");
    assert_eq!(rpc.active_leaf_count().await.unwrap(), 2, "one nullifier appended (1 -> 2)");
    assert_eq!(rpc.commitment_count().await.unwrap(), 1, "withdraw adds no output commitment");
}

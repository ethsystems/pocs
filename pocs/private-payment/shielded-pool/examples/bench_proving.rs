//! Benchmark for shielded pool proof generation.
//!
//! Runs 100 iterations of deposit, transfer, and withdraw proof generation
//! and reports min/mean/median/max total time per operation.
//!
//! Prerequisites: `nargo` and `bb` on PATH, compiled circuits in `circuits/`.
//!
//! ```bash
//! cargo run --example bench_proving --release -- --no-capture
//! ```

use std::path::PathBuf;
use std::time::{Duration, Instant};

use alloy::primitives::{Address, B256, U256};

use private_payment_shielded_pool::{
    adapters::{
        bb_prover::BBProver,
        merkle_tree::{AttestationTree, CommitmentTree, b256_to_bytes, bytes_to_b256},
    },
    crypto::poseidon::poseidon4,
    domain::{
        keys::SpendingKey,
        note::Note,
        witness::{DepositWitness, TransferWitness, WithdrawWitness},
    },
    ports::prover::Prover,
};

const ITERATIONS: usize = 100;

fn stats(durations: &[Duration]) -> (Duration, Duration, Duration, Duration) {
    let mut sorted: Vec<Duration> = durations.to_vec();
    sorted.sort();
    let min = sorted[0];
    let max = sorted[sorted.len() - 1];
    let mean = sorted.iter().sum::<Duration>() / sorted.len() as u32;
    let median = if sorted.len() % 2 == 0 {
        (sorted[sorted.len() / 2 - 1] + sorted[sorted.len() / 2]) / 2
    } else {
        sorted[sorted.len() / 2]
    };
    (min, mean, median, max)
}

fn fmt_duration(d: Duration) -> String {
    let ms = d.as_millis();
    if ms >= 1000 {
        format!("{:.2}s", d.as_secs_f64())
    } else {
        format!("{}ms", ms)
    }
}

#[tokio::main]
async fn main() {
    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let circuits_dir = project_root.join("circuits");
    let prover = BBProver::new(circuits_dir);

    let token = Address::ZERO;
    let amount = U256::from(1000u64);

    // --- Setup keys ---
    let alice_sk = SpendingKey::random();
    let alice_pk = alice_sk.derive_owner_pubkey();
    let bob_sk = SpendingKey::random();
    let bob_pk = bob_sk.derive_owner_pubkey();

    // --- Setup attestation tree ---
    let attester = Address::repeat_byte(0x01);
    let issued_at: u64 = 1000;
    let expires_at: u64 = 0; // no expiry

    let attestation_leaf = poseidon4(
        alice_pk.0,
        B256::left_padding_from(attester.as_slice()),
        U256::from(issued_at).into(),
        U256::from(expires_at).into(),
    );

    let mut attestation_tree = AttestationTree::new();
    attestation_tree.insert(&b256_to_bytes(&attestation_leaf));
    let attestation_root =
        bytes_to_b256(&attestation_tree.root().expect("attestation tree has root"));
    let attestation_proof = attestation_tree
        .generate_attestation_proof(0)
        .expect("attestation proof");

    // --- Setup commitment tree with 2 notes ---
    let mut commitment_tree = CommitmentTree::new();

    let alice_note = Note::new(token, amount, alice_pk);
    commitment_tree.insert(&b256_to_bytes(&alice_note.commitment().0));

    // Zero note for padding. Fresh random salt (Note::zero) so the ballast nullifier is unique.
    let zero_note = Note::zero(token, alice_pk);
    commitment_tree.insert(&b256_to_bytes(&zero_note.commitment().0));

    let commitment_root =
        bytes_to_b256(&commitment_tree.root().expect("commitment tree has root"));

    println!("=== Shielded Pool Proving Benchmarks ({ITERATIONS} iterations) ===\n");

    // === Deposit Benchmark ===
    println!("Running deposit benchmarks...");
    let mut deposit_times = Vec::with_capacity(ITERATIONS);
    for i in 0..ITERATIONS {
        let note = Note::new(token, amount, alice_pk);
        let witness = DepositWitness::new(
            &note,
            alice_sk.clone(),
            Address::ZERO,
            attestation_root,
            attester,
            issued_at,
            expires_at,
            attestation_proof.clone(),
            b"",
        );

        let start = Instant::now();
        prover
            .prove_deposit(&witness)
            .await
            .expect("deposit proof failed");
        deposit_times.push(start.elapsed());

        if (i + 1) % 10 == 0 {
            eprintln!("  deposit {}/{ITERATIONS}", i + 1);
        }
    }

    // === Transfer Benchmark ===
    println!("Running transfer benchmarks...");
    let mut transfer_times = Vec::with_capacity(ITERATIONS);
    for i in 0..ITERATIONS {
        let output_to_bob = Note::new(token, U256::from(700u64), bob_pk);
        let output_change = Note::new(token, U256::from(300u64), alice_pk);

        let alice_proof = commitment_tree
            .generate_commitment_proof(0)
            .expect("alice commitment proof");
        let zero_proof = commitment_tree
            .generate_commitment_proof(0)
            .expect("zero commitment proof");

        let witness = TransferWitness::new(
            alice_sk.clone(),
            [alice_note.clone(), zero_note.clone()],
            [output_to_bob, output_change],
            [alice_proof, zero_proof],
            commitment_root,
            b"",
        );

        let start = Instant::now();
        prover
            .prove_transfer(&witness)
            .await
            .expect("transfer proof failed");
        transfer_times.push(start.elapsed());

        if (i + 1) % 10 == 0 {
            eprintln!("  transfer {}/{ITERATIONS}", i + 1);
        }
    }

    // === Withdraw Benchmark ===
    println!("Running withdraw benchmarks...");
    let mut withdraw_times = Vec::with_capacity(ITERATIONS);
    let recipient = Address::repeat_byte(0xBB);

    for i in 0..ITERATIONS {
        let withdraw_proof = commitment_tree
            .generate_commitment_proof(0)
            .expect("withdraw commitment proof");

        let witness = WithdrawWitness::new(
            alice_sk.clone(),
            alice_note.clone(),
            withdraw_proof,
            commitment_root,
            recipient,
        );

        let start = Instant::now();
        prover
            .prove_withdraw(&witness)
            .await
            .expect("withdraw proof failed");
        withdraw_times.push(start.elapsed());

        if (i + 1) % 10 == 0 {
            eprintln!("  withdraw {}/{ITERATIONS}", i + 1);
        }
    }

    // === Results ===
    println!("\n| Operation | Min | Mean | Median | Max |");
    println!("|---|---|---|---|---|");

    for (name, times) in [
        ("Deposit", &deposit_times),
        ("Transfer", &transfer_times),
        ("Withdraw", &withdraw_times),
    ] {
        let (min, mean, median, max) = stats(times);
        println!(
            "| {} | {} | {} | {} | {} |",
            name,
            fmt_duration(min),
            fmt_duration(mean),
            fmt_duration(median),
            fmt_duration(max),
        );
    }
}

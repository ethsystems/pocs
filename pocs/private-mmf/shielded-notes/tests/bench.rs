//! Costs on the final code (SPEC, Measured Costs): for each operation, the
//! proving time, the proof size, the gas of the whole transaction, and the gas
//! of verification alone, with real proofs and the generated verifiers; then
//! the checkpoint and an attestation part. Proving time is the median of three
//! proofs of the same witness, on whatever machine runs it.
//!
//! A transaction's gas also depends on where its notes land in the commitment
//! tree: an insert hashes once per 1 bit of the leaf's index. The three
//! transfer kinds are therefore each submitted from the same chain state, and
//! the chain reverted after each, so their rows compare kinds, not positions.
//!
//! Ignored by default, since it takes minutes:
//! `cargo test --release --test bench -- --ignored --nocapture`

mod common;

use std::time::{
    Duration,
    Instant,
};

use alloy::{
    primitives::{
        Address as AlloyAddress,
        B256,
        Bytes as AlloyBytes,
        U256,
    },
    providers::Provider,
    sol,
};
use common::*;
use shielded_notes::{
    agent::{
        ClaimAction,
        TransferAgent,
    },
    chain::{
        self,
        Submission,
        to_address,
    },
    client::Client,
    domain::note::LockOpening,
    ports::prover::{
        CircuitProof,
        ProofRequest,
    },
    wallet::Output,
};

sol! {
    #[sol(rpc)]
    interface IPoolVerifier {
        function verifier() external view returns (address);
    }

    #[sol(rpc)]
    interface ICompositeVerifier {
        function verifyDeposit(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);
        function verifyTransfer(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);
        function verifyWithdraw(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);
    }
}

/// The public inputs the pool hands its verifier: 22, 32 and 10.
const DEPOSIT_INPUTS: usize = 22;
const TRANSFER_INPUTS: usize = 32;
const WITHDRAW_INPUTS: usize = 10;

struct Proved {
    proof: CircuitProof,
    median: Duration,
}

/// Proves `request` three times and keeps the last proof and the median time.
fn prove_three_times(request: ProofRequest) -> Proved {
    let mut times = Vec::new();
    let mut proof = None;
    for _ in 0..3 {
        let start = Instant::now();
        proof = Some(prover().prove(&request).expect("prove"));
        times.push(start.elapsed());
    }
    times.sort();
    Proved {
        proof: proof.expect("three proofs"),
        median: times[1],
    }
}

fn inputs(proof: &CircuitProof, n: usize) -> Vec<B256> {
    proof.public_inputs[..n]
        .iter()
        .map(|b| B256::from_slice(b.as_ref()))
        .collect()
}

/// Submits from a snapshot of the chain and reverts to it, returning the gas.
async fn gas_from_snapshot(client: &Client, submission: &Submission) -> u64 {
    let snapshot: U256 = client
        .provider
        .raw_request("evm_snapshot".into(), ())
        .await
        .expect("snapshot");
    let receipt = client.submit(submission).await.expect("submit");
    let reverted: bool = client
        .provider
        .raw_request("evm_revert".into(), (snapshot,))
        .await
        .expect("revert");
    assert!(reverted, "the chain is back at the snapshot");
    receipt.gas_used
}

fn row(name: &str, proved: &Proved, verify_gas: u64, tx_gas: u64) {
    println!(
        "| {name} | {:.1} s | {} B | {verify_gas} | {tx_gas} |",
        proved.median.as_secs_f64(),
        proved.proof.proof.len()
    );
}

#[tokio::test]
#[ignore = "a benchmark, with real proofs: run with --ignored"]
async fn costs_per_operation() {
    assert!(
        !use_mock_proofs(),
        "the benchmark needs real proofs and verifiers"
    );
    let mut agent = TransferAgent::new();
    let h = Harness::start(&agent);
    seed(&h, &mut agent).await;
    let mut alice = Investor::new("INV-ALICE");
    let mut bob = Investor::new("INV-BOB");
    onboard_and_attest(&h, &mut agent, &[&alice, &bob]).await;
    aggregate_deposit(&h, &mut agent, 300 * SHARE).await;
    hand_out(
        &h,
        &mut agent,
        &[
            (&alice, 100 * SHARE),
            (&alice, 100 * SHARE),
            (&bob, 100 * SHARE),
        ],
    )
    .await;

    let agent_client = h.client(AGENT);
    let relayer = h.client(RELAYER);
    let composite_address = IPoolVerifier::new(h.deployment.pool, h.provider(AGENT))
        .verifier()
        .call()
        .await
        .expect("the pool's verifier");
    let composite = ICompositeVerifier::new(composite_address, h.provider(AGENT));
    let mut rows = Vec::new();

    // Deposit: the agent's daily aggregate. The issuer mints its shares on the
    // public side first, ceil(units * m / S), as `aggregate_deposit` does.
    let m = chain::pool_totals(&h.provider(AGENT), &h.deployment)
        .await
        .unwrap()
        .multiplier;
    let shares = (U256::from(50 * SHARE) * m).div_ceil(U256::from(shielded_notes::S));
    h.token(AGENT)
        .mint(h.account(AGENT), shares)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    let view = agent_client.view().await.unwrap();
    let env = agent_client.env().await.unwrap();
    agent.read_feed(&view).unwrap();
    let agent_address = to_address(h.account(AGENT));
    let (w, payload) = agent
        .wallet
        .deposit(&agent.signer, &view, &env, 50 * SHARE, agent_address)
        .unwrap();
    let proved = prove_three_times(ProofRequest::Deposit(Box::new(w.clone())));
    let verify = composite
        .verifyDeposit(
            AlloyBytes::from(proved.proof.proof.clone()),
            inputs(&proved.proof, DEPOSIT_INPUTS),
        )
        .estimate_gas()
        .await
        .unwrap();
    let receipt = agent_client
        .submit(&Submission::deposit(&w, &proved.proof, &payload))
        .await
        .unwrap();
    rows.push(("Deposit", proved, verify, receipt.gas_used));

    // The three transfer kinds, built from one view and each submitted from the
    // same chain state (see the module comment).
    let view = relayer.view().await.unwrap();
    let env = relayer.env().await.unwrap();
    alice.wallet.scan(&view);
    bob.wallet.scan(&view);
    agent.read_feed(&view).unwrap();

    // Owner path, one input padded with a zero-unit note: Alice pays Bob.
    let one = alice
        .wallet
        .pay(
            &alice.signer,
            &view,
            &env,
            bob.owner(),
            bob.vpk(),
            10 * SHARE,
        )
        .unwrap();

    // Owner path, two inputs: Alice merges her two notes.
    let notes = alice.wallet.spendable(env.epoch);
    let merged = notes[0].note.units + notes[1].note.units;
    let own = |units| Output {
        owner: alice.owner(),
        units,
        opening: LockOpening::NONE,
        vpk: alice.vpk(),
    };
    let two = alice
        .wallet
        .transfer(
            &alice.signer,
            &view,
            &env,
            vec![notes[0], notes[1]],
            [own(merged), own(0)],
        )
        .unwrap();

    // Claim path: the agent freezes Bob's note in place.
    let target = bob.wallet.spendable(env.epoch)[0].commitment;
    let claim = agent
        .claim(&view, &env, target, ClaimAction::Freeze)
        .unwrap();

    for (name, built) in [
        ("Transfer, owner path, one input", &one),
        ("Transfer, owner path, two inputs", &two),
        ("Transfer, claim path", &claim),
    ] {
        let proved =
            prove_three_times(ProofRequest::Transfer(Box::new(built.witness.clone())));
        let verify = composite
            .verifyTransfer(
                AlloyBytes::from(proved.proof.proof.clone()),
                inputs(&proved.proof, TRANSFER_INPUTS),
            )
            .estimate_gas()
            .await
            .unwrap();
        let submission =
            Submission::transfer(&built.witness, &proved.proof, &built.payload);
        let gas = gas_from_snapshot(&relayer, &submission).await;
        rows.push((name, proved, verify, gas));
    }

    // Withdraw: Alice withdraws one of her notes to a public address.
    let view = relayer.view().await.unwrap();
    alice.wallet.scan(&view);
    let note = alice.wallet.spendable(env.epoch)[0];
    let recipient: AlloyAddress = h.account(HOLDER);
    h.token(AGENT)
        .setAllowlisted(recipient, true)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    let w = alice
        .wallet
        .withdraw(&alice.signer, &view, &env, &note, to_address(recipient))
        .unwrap();
    let proved = prove_three_times(ProofRequest::Withdraw(Box::new(w.clone())));
    let verify = composite
        .verifyWithdraw(
            AlloyBytes::from(proved.proof.proof.clone()),
            inputs(&proved.proof, WITHDRAW_INPUTS),
        )
        .estimate_gas()
        .await
        .unwrap();
    let receipt = relayer
        .submit(&Submission::withdraw(&w, &proved.proof))
        .await
        .unwrap();
    rows.push(("Withdraw", proved, verify, receipt.gas_used));

    println!();
    println!(
        "| Operation | Proving (median of 3) | Proof | Verification gas | Transaction gas |"
    );
    println!("|---|---|---|---|---|");
    for (name, proved, verify, tx) in &rows {
        row(name, proved, *verify, *tx);
    }

    // The agent's own transactions: the checkpoint and an attestation part.
    let view = agent_client.view().await.unwrap();
    let env = agent_client.env().await.unwrap();
    agent.read_feed(&view).unwrap();
    let checkpoint = chain::checkpoint(
        &h.provider(AGENT),
        &h.deployment,
        agent.register_hash(env.epoch),
        agent.total_units(),
    )
    .await
    .unwrap();
    println!();
    println!("| Agent transaction | Gas |");
    println!("|---|---|");
    println!("| Checkpoint | {} |", checkpoint.gas_used);
    // One part of an onboarding batch: sixteen new investors, with nothing else
    // due, fill it without padding.
    for i in 0..chain::ATTESTATION_PART {
        Investor::new(&format!("INV-BENCH-{i}")).register_with(&mut agent, &env);
    }
    let view = agent_client.view().await.unwrap();
    let round = agent.attestation_batch(&view, &env, &[], 0).unwrap();
    assert_eq!(round.batch.parts().len(), 1);
    let receipts =
        chain::add_attestations(&h.provider(AGENT), &h.deployment, &round.batch)
            .await
            .unwrap();
    println!(
        "| Attestation part of {} | {} |",
        chain::ATTESTATION_PART,
        receipts[0].gas_used
    );
}

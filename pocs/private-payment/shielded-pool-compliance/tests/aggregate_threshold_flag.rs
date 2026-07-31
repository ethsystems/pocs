//! Scenario 4: Alice's epoch total crosses the aggregate threshold, and `FLAG_AGGREGATE`
//! appears in the flags her compliance note commits to.

mod common;

use std::collections::BTreeSet;

use common::*;
use shielded_pool_compliance::{
    auditor::Auditor,
    domain::note::Note,
    policy::reference::{
        AGGREGATE_THRESHOLD,
        SINGLE_TX_THRESHOLD,
    },
    ports::merkle::LeafIndex,
    types::{
        Flags,
        Seq,
    },
    wallet::{
        DepositRequest,
        OwnedNote,
        TransferOutput,
        TransferRequest,
    },
};

const DEPOSIT: u64 = 100_000_000_000;
const FIRST: u64 = 30_000_000_000;
const SECOND: u64 = 25_000_000_000;

// The scenario is only meaningful if the first transfer clears the single-transaction
// threshold without reaching the aggregate one, and the pair crosses it.
const _: () = assert!(FIRST > SINGLE_TX_THRESHOLD && FIRST <= AGGREGATE_THRESHOLD);
const _: () = assert!(FIRST + SECOND > AGGREGATE_THRESHOLD);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crossing_the_aggregate_threshold_sets_the_flag_in_the_committed_note() {
    let stage = Stage::open(base_epoch()).await;
    let mut alice = TestWallet::new();
    let bob = TestWallet::new();
    enroll(&stage, &[&alice, &bob]).await;
    mint_and_approve(&stage.harness, &stage.deployment, DEPLOYER, DEPOSIT).await;

    let token = stage.token();
    let epoch = stage.epoch();
    let alice_owner = alice.owner;
    let bob_owner = bob.owner;

    let deposit = prove_deposit(
        &mut alice,
        &stage.ctx,
        DepositRequest {
            token,
            amount: DEPOSIT,
        },
    )
    .await
    .expect("deposit proves");
    submit_deposit(&stage.harness, &stage.deployment, &deposit)
        .await
        .expect("deposit lands");

    let mut change = OwnedNote {
        note: deposit.note,
        leaf_index: deposit.output_index,
    };
    let bob_viewing_pubkey = bob.viewing_pubkey.clone();
    let alice_viewing_pubkey = alice.viewing_pubkey.clone();
    for amount in [FIRST, SECOND] {
        let remainder = change.note.amount - amount;
        let transfer = prove_transfer(
            &mut alice,
            &stage.ctx,
            TransferRequest {
                token,
                inputs: [
                    change,
                    OwnedNote {
                        note: Note::zero(token, alice_owner),
                        leaf_index: LeafIndex(0),
                    },
                ],
                outputs: [
                    TransferOutput {
                        owner: bob_owner,
                        amount,
                        viewing_pubkey: bob_viewing_pubkey.clone(),
                    },
                    TransferOutput {
                        owner: alice_owner,
                        amount: remainder,
                        viewing_pubkey: alice_viewing_pubkey.clone(),
                    },
                ],
            },
        )
        .await
        .expect("transfer proves");
        submit_transfer(&stage.harness, &stage.deployment, &transfer)
            .await
            .expect("transfer lands");
        change = OwnedNote {
            note: transfer.outputs[1],
            leaf_index: transfer.output_indices[1],
        };
    }

    assert_eq!(alice.wallet.current_state(), Some([FIRST + SECOND]));

    let elements = observed_payload_elements(&stage.harness, &stage.deployment).await;
    let committed =
        observed_compliance_commitments(&stage.harness, &stage.deployment).await;
    let anchors: BTreeSet<_> = committed.iter().copied().collect();
    let auditor = Auditor::new(stage.audit_key);
    let chain = auditor
        .reconstruct_chain(
            stage.ctx.state_tag,
            stage.ctx.committee_version,
            &elements,
            alice_owner,
            epoch,
            &anchors,
        )
        .expect("committee ciphertexts decrypt")
        .txs;

    assert_eq!(chain.len(), 3, "deposit plus two transfers");
    assert_eq!(chain[0].seq, Seq(1));
    assert_eq!(chain[1].seq, Seq(2));
    assert_eq!(chain[2].seq, Seq(3));

    // A deposit moves no value out, so it neither accumulates nor flags.
    assert_eq!(chain[0].state, [0]);
    assert_eq!(chain[0].flags, Flags::NONE);

    assert_eq!(chain[1].state, [FIRST]);
    assert!(chain[1].flags.contains(Flags::FLAG_SINGLE_TX));
    assert!(
        !chain[1].flags.contains(Flags::FLAG_AGGREGATE),
        "the running total is still below the aggregate threshold"
    );

    assert_eq!(chain[2].state, [FIRST + SECOND]);
    assert!(chain[2].flags.contains(Flags::FLAG_AGGREGATE));

    // The flags are not merely reported by the decrypted opening: each recomputed
    // commitment is the leaf the pool accepted, so the flag is bound on chain.
    for tx in &chain {
        assert!(
            committed.contains(&tx.commitment),
            "recomputed compliance commitment {:?} is not one the pool recorded",
            tx.commitment
        );
    }
}

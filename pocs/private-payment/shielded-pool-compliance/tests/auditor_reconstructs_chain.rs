//! Scenario 9: the audit committee reconstructs Alice's chain for one epoch from the
//! ciphertexts the pool emitted, and every recomputed leaf is one the pool holds.

mod common;

use std::collections::BTreeSet;

use ark_bn254::Fr;

use common::*;
use shielded_pool_compliance::{
    auditor::Auditor,
    domain::note::Note,
    ports::merkle::LeafIndex,
    types::{
        Bytes32,
        Seq,
    },
    wallet::{
        DepositRequest,
        OwnedNote,
        TransferOutput,
        TransferRequest,
        WithdrawRequest,
    },
};

const DEPOSIT: u64 = 20_000_000_000;
const TO_BOB: u64 = 6_000_000_000;
const CHANGE: u64 = DEPOSIT - TO_BOB;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_committee_rebuilds_alices_epoch_from_ciphertexts_alone() {
    let stage = Stage::open(base_epoch()).await;
    let mut alice = TestWallet::new();
    let mut bob = TestWallet::new();
    enroll(&stage, &[&alice, &bob]).await;
    mint_and_approve(&stage.harness, &stage.deployment, DEPLOYER, DEPOSIT).await;

    let token = stage.token();
    let epoch = stage.epoch();
    let alice_owner = alice.owner;
    let bob_owner = bob.owner;
    let payee = stage.harness.account(PAYEE);

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
    bob.observe_commitments(&deposit_leaves(&deposit.proof));

    let bob_viewing_pubkey = bob.viewing_pubkey.clone();
    let alice_viewing_pubkey = alice.viewing_pubkey.clone();
    let transfer = prove_transfer(
        &mut alice,
        &stage.ctx,
        TransferRequest {
            token,
            inputs: [
                OwnedNote {
                    note: deposit.note,
                    leaf_index: deposit.output_index,
                },
                OwnedNote {
                    note: Note::zero(token, alice_owner),
                    leaf_index: LeafIndex(0),
                },
            ],
            outputs: [
                TransferOutput {
                    owner: bob_owner,
                    amount: TO_BOB,
                    viewing_pubkey: bob_viewing_pubkey,
                },
                TransferOutput {
                    owner: alice_owner,
                    amount: CHANGE,
                    viewing_pubkey: alice_viewing_pubkey,
                },
            ],
        },
    )
    .await
    .expect("transfer proves");
    submit_transfer(&stage.harness, &stage.deployment, &transfer)
        .await
        .expect("transfer lands");
    bob.observe_commitments(&transfer_leaves(&transfer.proof));

    let alice_exit = prove_withdraw(
        &mut alice,
        &stage.ctx,
        WithdrawRequest {
            input: OwnedNote {
                note: transfer.outputs[1],
                leaf_index: transfer.output_indices[1],
            },
            token,
            amount: CHANGE,
            recipient: to_crate_address(payee),
        },
    )
    .await
    .expect("gated withdraw proves");
    submit_withdraw(&stage.harness, &stage.deployment, &alice_exit)
        .await
        .expect("gated withdraw lands");
    bob.observe_commitments(&withdraw_leaves(&alice_exit.proof));

    // Bob's own transaction lands last, so the auditor has to filter by subject rather
    // than take whatever it can decrypt.
    let bob_exit = prove_withdraw(
        &mut bob,
        &stage.ctx,
        WithdrawRequest {
            input: OwnedNote {
                note: transfer.outputs[0],
                leaf_index: transfer.output_indices[0],
            },
            token,
            amount: TO_BOB,
            recipient: to_crate_address(payee),
        },
    )
    .await
    .expect("Bob's gated withdraw proves");
    submit_withdraw(&stage.harness, &stage.deployment, &bob_exit)
        .await
        .expect("Bob's gated withdraw lands");

    let elements = observed_payload_elements(&stage.harness, &stage.deployment).await;
    let committed =
        observed_compliance_commitments(&stage.harness, &stage.deployment).await;
    assert_eq!(committed.len(), 4);

    let state_tag = stage.ctx.state_tag;
    let committee_version = stage.ctx.committee_version;
    let anchors: BTreeSet<_> = committed.iter().copied().collect();
    let auditor = Auditor::new(stage.audit_key);
    let chain = auditor
        .reconstruct_chain(
            state_tag,
            committee_version,
            &elements,
            alice_owner,
            epoch,
            &anchors,
        )
        .expect("committee ciphertexts decrypt")
        .txs;

    assert_eq!(chain.len(), 3, "deposit, transfer, gated withdraw");
    assert_eq!(
        chain.iter().map(|tx| tx.seq).collect::<Vec<_>>(),
        vec![Seq(1), Seq(2), Seq(3)]
    );

    // Alice's three transactions are the first three the pool recorded, so the
    // reconstructed leaves match the on-chain ones position for position.
    assert_eq!(
        chain.iter().map(|tx| tx.commitment).collect::<Vec<_>>(),
        committed[..3].to_vec()
    );

    let no_counterparty = Bytes32::from(*shielded_pool_compliance::NO_COUNTERPARTY);
    let no_exit = Bytes32::from(*shielded_pool_compliance::NO_EXIT);

    // A deposit names no counterparty and no exit, and binds its amount in slot 0.
    assert_eq!(chain[0].counterparty, [no_counterparty; 2]);
    assert_eq!(chain[0].amount_out, [DEPOSIT, 0]);
    assert_eq!(chain[0].exit, no_exit);
    assert_eq!(chain[0].state, [0]);

    // The transfer names both output owners, change included.
    assert_eq!(
        chain[1].counterparty,
        [bob_owner.as_bytes32(), alice_owner.as_bytes32()]
    );
    assert_eq!(chain[1].amount_out, [TO_BOB, CHANGE]);
    assert_eq!(chain[1].exit, no_exit);
    assert_eq!(chain[1].state, [TO_BOB]);

    // The gated withdraw binds its destination as the exit.
    assert_eq!(chain[2].counterparty, [no_counterparty; 2]);
    assert_eq!(chain[2].amount_out, [CHANGE, 0]);
    assert_eq!(
        chain[2].exit,
        Bytes32::from(Fr::from(to_crate_address(payee)))
    );
    assert_eq!(chain[2].state, [TO_BOB + CHANGE]);

    let bob_chain = auditor
        .reconstruct_chain(
            state_tag,
            committee_version,
            &elements,
            bob_owner,
            epoch,
            &anchors,
        )
        .expect("committee ciphertexts decrypt")
        .txs;
    assert_eq!(bob_chain.len(), 1);
    assert_eq!(bob_chain[0].commitment, committed[3]);

    // A rotated committee invalidates the older ciphertexts, so nothing is claimed
    // under a version they were not encrypted under.
    let stale = auditor
        .reconstruct_chain(
            state_tag,
            committee_version + 1,
            &elements,
            alice_owner,
            epoch,
            &anchors,
        )
        .expect("committee ciphertexts decrypt");
    assert!(stale.txs.is_empty());
    assert!(stale.skipped_stale_version > 0);
}

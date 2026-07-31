//! Scenario 3: Alice transfers to Bob with change. The transaction sits at seq 1, the
//! predecessor compliance note is opened by Merkle inclusion, and three leaves land.

mod common;

use common::*;
use shielded_pool_compliance::{
    domain::{
        compliance_note::VelocityNullifier,
        note::Note,
        public_inputs::transfer as idx,
    },
    ports::merkle::LeafIndex,
    types::Seq,
    wallet::{
        DepositRequest,
        OwnedNote,
        TransferOutput,
        TransferRequest,
    },
};

const DEPOSIT: u64 = 30_000_000_000;
const TO_BOB: u64 = 8_000_000_000;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transfer_with_change_sits_at_seq_one_and_inserts_three_leaves() {
    let stage = Stage::open(base_epoch()).await;
    let mut alice = TestWallet::new();
    let bob = TestWallet::new();
    enroll(&stage, &[&alice, &bob]).await;
    mint_and_approve(&stage.harness, &stage.deployment, DEPLOYER, DEPOSIT).await;

    let epoch = stage.epoch();
    let token = stage.token();
    let alice_owner = alice.owner;

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

    let before = commitment_count(&stage.harness, &stage.deployment).await;

    let change = DEPOSIT - TO_BOB;
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
                    owner: bob.owner,
                    amount: TO_BOB,
                    viewing_pubkey: bob_viewing_pubkey,
                },
                TransferOutput {
                    owner: alice_owner,
                    amount: change,
                    viewing_pubkey: alice_viewing_pubkey,
                },
            ],
        },
    )
    .await
    .expect("transfer proves");

    // seq 1, not 2: the deposit committed its note at seq 1 and this transaction
    // consumes it, so it carries the same seq.
    let expected_vn = VelocityNullifier::derive(&alice.spending_key, epoch, Seq(1)).0;
    assert_eq!(
        transfer.proof.public_inputs[idx::VELOCITY_NULLIFIER],
        expected_vn
    );

    let receipt = submit_transfer(&stage.harness, &stage.deployment, &transfer)
        .await
        .expect("transfer lands");
    assert!(receipt.status(), "transfer reverted");
    bob.observe_commitments(&transfer_leaves(&transfer.proof));

    assert_eq!(
        commitment_count(&stage.harness, &stage.deployment).await,
        before + 3,
        "two output notes plus one compliance note"
    );

    // Only the output that left the subject counts toward the epoch accumulator; the
    // change output back to Alice does not.
    assert_eq!(alice.wallet.current_state(), Some([TO_BOB]));

    // Bob never receives his note in process: he recovers it by decrypting the `0x01`
    // value-note element the pool emitted, using nothing but his own viewing key.
    let bob_notes = owned_value_notes(&bob.wallet, &transfer.payload);
    assert_eq!(bob_notes.len(), 1);
    assert_eq!(bob_notes[0].amount, TO_BOB);
    assert_eq!(bob_notes[0].owner_pubkey, bob.owner);
    assert_eq!(transfer.outputs[1].amount, change);
    assert_eq!(transfer.outputs[1].owner_pubkey, alice.owner);

    // The spent note's nullifier is consumed, the padding input's is not a second
    // spend of anything, and both are distinct from the velocity nullifier.
    let spent = deposit
        .note
        .nullifier(&alice.spending_key)
        .expect("nullifier");
    assert_eq!(transfer.proof.public_inputs[idx::NULLIFIER_0], spent);
    assert!(nullifier_spent(&stage.harness, &stage.deployment, spent).await);
    assert!(nullifier_spent(&stage.harness, &stage.deployment, expected_vn).await);

    // The three leaves occupy the next three pool positions in the order the wallet
    // reported them, which is what lets Bob spend his output later against his own
    // mirror of the tree.
    assert_eq!(transfer.output_indices[0].0, before);
    assert_eq!(transfer.output_indices[1].0, before + 1);
}

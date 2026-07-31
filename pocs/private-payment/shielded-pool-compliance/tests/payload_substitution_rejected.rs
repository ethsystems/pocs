//! a relayer holding a valid `(proof, publicInputs)` pair cannot
//! substitute a different `encryptedNotes` blob. `payload_commitment` binds
//! `keccak256(encryptedNotes) mod r` into the proof's own public inputs, and the
//! contract recomputes that hash before accepting the proof, so a swapped payload
//! under an otherwise honest, unmodified proof must revert.

mod common;

use common::*;
use shielded_pool_compliance::{
    domain::note::Note,
    ports::merkle::LeafIndex,
    wallet::{
        DepositRequest,
        OwnedNote,
        TransferOutput,
        TransferRequest,
    },
};

const DEPOSIT: u64 = 10_000_000_000;
const TO_BOB: u64 = 2_000_000_000;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relayer_cannot_substitute_the_encrypted_payload() {
    let stage = Stage::open(base_epoch()).await;
    let mut alice = TestWallet::new();
    let bob = TestWallet::new();
    enroll(&stage, &[&alice, &bob]).await;
    mint_and_approve(&stage.harness, &stage.deployment, DEPLOYER, DEPOSIT).await;

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

    let before = commitment_count(&stage.harness, &stage.deployment).await;

    // The proof and every other public input are exactly what the wallet produced;
    // only the audit payload a relayer would forward on the caller's behalf is
    // swapped for unrelated bytes.
    let rejected = submit_transfer_with_encrypted_notes(
        &stage.harness,
        &stage.deployment,
        &transfer,
        vec![0x00, 0x00, 0x00, 0x00],
    )
    .await
    .expect_err("a swapped encryptedNotes payload must be rejected");
    assert_reverts_with::<IShieldedPool::PayloadMismatch>(&rejected);

    assert_eq!(
        commitment_count(&stage.harness, &stage.deployment).await,
        before,
        "a rejected transfer inserts nothing"
    );
}

//! Scenario 5: Bob exits through the gated withdraw path, and a withdrawal aimed at a
//! blocked destination reverts even though the proof itself is valid.

mod common;

use alloy::primitives::U256;

use common::*;
use shielded_pool_compliance::{
    domain::{
        note::Note,
        public_inputs::gated_withdraw as idx,
    },
    ports::merkle::LeafIndex,
    wallet::{
        DepositRequest,
        OwnedNote,
        TransferOutput,
        TransferRequest,
        WithdrawRequest,
    },
};

const DEPOSIT: u64 = 12_000_000_000;
const FIRST_NOTE: u64 = 5_000_000_000;
const SECOND_NOTE: u64 = DEPOSIT - FIRST_NOTE;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gated_withdraw_pays_out_and_a_blocked_destination_reverts() {
    let stage = Stage::open(base_epoch()).await;
    let mut alice = TestWallet::new();
    let mut bob = TestWallet::new();
    enroll(&stage, &[&alice, &bob]).await;
    mint_and_approve(&stage.harness, &stage.deployment, DEPLOYER, DEPOSIT).await;

    let token = stage.token();
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
    bob.observe_commitments(&deposit_leaves(&deposit.proof));

    // Both outputs go to Bob, so he holds two spendable notes.
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
                    amount: FIRST_NOTE,
                    viewing_pubkey: bob.viewing_pubkey.clone(),
                },
                TransferOutput {
                    owner: bob_owner,
                    amount: SECOND_NOTE,
                    viewing_pubkey: bob.viewing_pubkey.clone(),
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

    // Bob spends notes he learned only from chain data: decrypting the `0x01`
    // value-note elements the pool emitted, using nothing but his own viewing key.
    let bob_notes = owned_value_notes(&bob.wallet, &transfer.payload);
    assert_eq!(bob_notes.len(), 2);

    let payee = stage.harness.account(PAYEE);
    let payee_before = token_balance(&stage.harness, &stage.deployment, payee).await;

    let exit = prove_withdraw(
        &mut bob,
        &stage.ctx,
        WithdrawRequest {
            input: OwnedNote {
                note: bob_notes[0],
                leaf_index: transfer.output_indices[0],
            },
            token,
            amount: FIRST_NOTE,
            recipient: to_crate_address(payee),
        },
    )
    .await
    .expect("gated withdraw proves");
    let receipt = submit_withdraw(&stage.harness, &stage.deployment, &exit)
        .await
        .expect("gated withdraw lands");
    assert!(receipt.status(), "gated withdraw reverted");

    assert_eq!(
        token_balance(&stage.harness, &stage.deployment, payee).await,
        payee_before + U256::from(FIRST_NOTE)
    );
    let spent = bob_notes[0]
        .nullifier(&bob.spending_key)
        .expect("nullifier");
    assert!(nullifier_spent(&stage.harness, &stage.deployment, spent).await);
    // A gated withdraw inserts the compliance note and nothing else.
    assert_eq!(withdraw_leaves(&exit.proof).len(), 1);

    let sanctioned = stage.harness.account(SANCTIONED);
    block_destination(&stage.harness, &stage.deployment, sanctioned).await;

    let blocked = prove_withdraw(
        &mut bob,
        &stage.ctx,
        WithdrawRequest {
            input: OwnedNote {
                note: bob_notes[1],
                leaf_index: transfer.output_indices[1],
            },
            token,
            amount: SECOND_NOTE,
            recipient: to_crate_address(sanctioned),
        },
    )
    .await
    .expect("the blocklist is a chain-side check, so this still proves");
    assert_eq!(
        blocked.proof.public_inputs[idx::RECIPIENT],
        recipient_word(sanctioned)
    );

    let rejected = submit_withdraw(&stage.harness, &stage.deployment, &blocked)
        .await
        .expect_err("the pool refuses a blocked destination");
    assert_reverts_with::<IShieldedPool::BlockedDestination>(&rejected);

    assert_eq!(
        token_balance(&stage.harness, &stage.deployment, sanctioned).await,
        U256::ZERO
    );
    let unspent = bob_notes[1]
        .nullifier(&bob.spending_key)
        .expect("nullifier");
    assert!(
        !nullifier_spent(&stage.harness, &stage.deployment, unspent).await,
        "a refused withdrawal must leave the note spendable"
    );
}

fn recipient_word(
    address: alloy::primitives::Address,
) -> shielded_pool_compliance::types::Bytes32 {
    let mut bytes = [0u8; 32];
    bytes[12..].copy_from_slice(address.as_slice());
    shielded_pool_compliance::types::Bytes32::from(bytes)
}

//! Scenario 8: a proof generated in epoch `e` and submitted in `e + 1` is refused. The
//! epoch is a public input, so a stale proof cannot be replayed into the next window.

mod common;

use common::*;
use shielded_pool_compliance::{
    domain::public_inputs::deposit as idx,
    types::{
        Bytes32,
        Epoch,
    },
    wallet::DepositRequest,
};

const DEPOSIT: u64 = 3_000_000_000;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_proof_from_the_previous_epoch_is_refused() {
    let issue_epoch = base_epoch();
    let stage = Stage::open(issue_epoch).await;
    let mut alice = TestWallet::new();
    let bob = TestWallet::new();
    enroll(&stage, &[&alice, &bob]).await;
    mint_and_approve(&stage.harness, &stage.deployment, DEPLOYER, DEPOSIT).await;

    let proved = prove_deposit(
        &mut alice,
        &stage.ctx,
        DepositRequest {
            token: stage.token(),
            amount: DEPOSIT,
        },
    )
    .await
    .expect("deposit proves");
    assert_eq!(
        proved.proof.public_inputs[idx::EPOCH],
        epoch_word(Epoch(issue_epoch))
    );

    // One epoch on. The attestation still covers this epoch, so the epoch binding is
    // the only thing that can refuse the proof.
    stage.harness.warp_to_epoch(issue_epoch + 1).await;
    assert_eq!(stage.epoch(), Epoch(issue_epoch + 1));

    let before = commitment_count(&stage.harness, &stage.deployment).await;
    let rejected = submit_deposit(&stage.harness, &stage.deployment, &proved)
        .await
        .expect_err("the pool refuses a proof bound to the previous epoch");
    assert_reverts_with::<IShieldedPool::WrongEpoch>(&rejected);

    assert_eq!(
        commitment_count(&stage.harness, &stage.deployment).await,
        before,
        "a refused deposit inserts nothing"
    );
    assert!(
        !nullifier_spent(
            &stage.harness,
            &stage.deployment,
            proved.proof.public_inputs[idx::VELOCITY_NULLIFIER]
        )
        .await
    );
}

fn epoch_word(epoch: Epoch) -> Bytes32 {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&epoch.0.to_be_bytes());
    Bytes32::from(bytes)
}

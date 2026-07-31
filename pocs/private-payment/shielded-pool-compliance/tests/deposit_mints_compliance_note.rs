//! Scenario 2: Alice deposits, minting the compliance note her chain starts from.

mod common;

use common::*;
use shielded_pool_compliance::{
    domain::{
        compliance_note::VelocityNullifier,
        public_inputs::deposit as idx,
    },
    types::Seq,
    wallet::DepositRequest,
};

const AMOUNT: u64 = 25_000_000_000;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deposit_mints_the_seq_zero_compliance_note() {
    let stage = Stage::open(base_epoch()).await;
    let mut alice = TestWallet::new();
    let bob = TestWallet::new();
    enroll(&stage, &[&alice, &bob]).await;
    mint_and_approve(&stage.harness, &stage.deployment, DEPLOYER, AMOUNT).await;

    let epoch = stage.epoch();
    let before = commitment_count(&stage.harness, &stage.deployment).await;
    assert_eq!(before, 0);

    let proved = prove_deposit(
        &mut alice,
        &stage.ctx,
        DepositRequest {
            token: stage.token(),
            amount: AMOUNT,
        },
    )
    .await
    .expect("wallet builds and proves a deposit");

    // The transaction sits at seq 0, so its velocity nullifier is the one derived at
    // seq 0. The note it commits lands at seq 1.
    let expected_vn = VelocityNullifier::derive(&alice.spending_key, epoch, Seq(0)).0;
    assert_eq!(
        proved.proof.public_inputs[idx::VELOCITY_NULLIFIER],
        expected_vn
    );
    assert_eq!(proved.proof.public_inputs[idx::EPOCH], epoch_word(epoch.0));
    assert!(!nullifier_spent(&stage.harness, &stage.deployment, expected_vn).await);

    let receipt = submit_deposit(&stage.harness, &stage.deployment, &proved)
        .await
        .expect("deposit lands");
    assert!(receipt.status(), "deposit reverted");

    assert!(
        nullifier_spent(&stage.harness, &stage.deployment, expected_vn).await,
        "the velocity nullifier must be consumed, which is what keeps seq 0 single-use"
    );

    // Two leaves: the value note, then the compliance note, in that order.
    let leaves = deposit_leaves(&proved.proof);
    assert_eq!(
        commitment_count(&stage.harness, &stage.deployment).await,
        before + 2
    );
    assert_eq!(
        observed_compliance_commitments(&stage.harness, &stage.deployment).await,
        vec![leaves[1]]
    );

    // The wallet's mirror advanced in step, so its root is the pool's.
    let root = pool_commitment_root(&stage).await;
    assert!(
        is_known_root(&stage, root).await,
        "the pool must recognize its own current root"
    );
    assert_eq!(
        token_balance(&stage.harness, &stage.deployment, stage.deployment.pool).await,
        alloy::primitives::U256::from(AMOUNT)
    );

    // A deposit's `value_out` is zero, so the accumulator stays at zero even for an
    // amount well past the single-transaction threshold.
    assert_eq!(alice.wallet.current_state(), Some([0]));
}

fn epoch_word(epoch: u64) -> shielded_pool_compliance::types::Bytes32 {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&epoch.to_be_bytes());
    shielded_pool_compliance::types::Bytes32::from(bytes)
}

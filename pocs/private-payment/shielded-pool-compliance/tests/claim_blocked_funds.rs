//! Scenario 7: `claimBlocked` moves a credited exit to the blocked-funds account.

mod common;

use alloy::primitives::U256;

use common::*;
use shielded_pool_compliance::wallet::{
    DepositRequest,
    OwnedNote,
    WithdrawRequest,
};

const DEPOSIT: u64 = 4_000_000_000;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn claim_blocked_pays_the_blocked_funds_account_and_nobody_else() {
    let stage = Stage::open(base_epoch()).await;
    let mut alice = TestWallet::new();
    let bob = TestWallet::new();
    enroll(&stage, &[&alice, &bob]).await;
    mint_and_approve(&stage.harness, &stage.deployment, DEPLOYER, DEPOSIT).await;

    let token = stage.token();
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

    let blocked_exit = prove_withdraw_blocked(
        &alice,
        &stage.ctx,
        WithdrawRequest {
            input: OwnedNote {
                note: deposit.note,
                leaf_index: deposit.output_index,
            },
            token,
            amount: DEPOSIT,
            recipient: to_crate_address(stage.harness.account(PAYEE)),
        },
    )
    .await
    .expect("ungated withdraw proves");
    submit_withdraw_blocked(&stage.harness, &stage.deployment, &blocked_exit)
        .await
        .expect("withdrawBlocked lands");

    let nullifier = deposit
        .note
        .nullifier(&alice.spending_key)
        .expect("nullifier");
    assert_eq!(
        blocked_balance(&stage.harness, &stage.deployment, nullifier).await,
        U256::from(DEPOSIT)
    );

    let refused = claim_blocked_from(&stage.harness, &stage.deployment, PAYEE, nullifier)
        .await
        .expect_err("only the blocked-funds account may claim");
    assert_reverts_with::<IShieldedPool::NotBlockedFundsAccount>(&refused);

    let account = stage.harness.account(BLOCKED_FUNDS);
    let before = token_balance(&stage.harness, &stage.deployment, account).await;
    let receipt = claim_blocked(&stage.harness, &stage.deployment, nullifier)
        .await
        .expect("claimBlocked lands");
    assert!(receipt.status(), "claimBlocked reverted");

    assert_eq!(
        token_balance(&stage.harness, &stage.deployment, account).await,
        before + U256::from(DEPOSIT)
    );
    assert_eq!(
        token_balance(&stage.harness, &stage.deployment, stage.deployment.pool).await,
        U256::ZERO,
        "the pool paid out everything it held for this exit"
    );
    assert_eq!(
        blocked_balance(&stage.harness, &stage.deployment, nullifier).await,
        U256::ZERO,
        "the credit is zeroed before the transfer, so a second claim pays nothing"
    );
}

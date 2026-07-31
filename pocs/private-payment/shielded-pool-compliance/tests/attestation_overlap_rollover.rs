//! Regression test: the registry's overlap window lets a new cohort be
//! onboarded before the prior one lapses, so a subject issued into period `k+1`
//! during the overlap stays covered across the period boundary.

mod common;

use common::*;
use shielded_pool_compliance::{
    authority::Authority,
    domain::attestation::Generation,
    wallet::{
        DepositRequest,
        OwnedNote,
        WithdrawRequest,
    },
};

const DEPOSIT: u64 = 9_000_000_000;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cohort_issued_inside_the_overlap_window_stays_covered_across_the_boundary() {
    let issue_epoch = base_epoch();
    let stage = Stage::open(issue_epoch).await;
    let mut alice = TestWallet::new();

    // Period k.
    let first_cohort = enroll(&stage, &[&alice]).await;
    let first_leaf_count = attestation_leaves(&stage.harness, &stage.deployment)
        .await
        .len();

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
    .expect("deposit proves under the period-k attestation");
    submit_deposit(&stage.harness, &stage.deployment, &deposit)
        .await
        .expect("deposit lands");

    let boundary_epoch =
        first_cohort.expires_at / shielded_pool_compliance::EPOCH_SECONDS;
    let overlap_epoch = boundary_epoch - shielded_pool_compliance::OVERLAP_EPOCHS;
    stage.harness.warp_to_epoch(overlap_epoch).await;

    // Period k+1, issued inside period k's overlap window, before period k lapses.
    let minimum = min_cohort_size(&stage.harness, &stage.deployment).await;
    let subjects = cohort_with(&[alice.owner], minimum.0 as usize);
    let authority = Authority::new(minimum);
    let next_cohort = authority
        .build_next_period_cohort(&stage.harness.clock(), subjects, Generation(1))
        .expect("cohort meets the registry minimum");
    submit_cohort(&stage.harness, &stage.deployment, &next_cohort)
        .await
        .expect("the registry accepts the next period's calendar value inside the overlap window");

    let all_leaves = attestation_leaves(&stage.harness, &stage.deployment).await;
    alice.observe_attestations(&all_leaves[first_leaf_count..]);

    // Past period k's boundary: without the overlap-issued attestation this would be
    // the lapse epoch and every gated path would close (see
    // attestation_lapse_rollover.rs).
    stage.harness.warp_to_epoch(boundary_epoch).await;

    let spend = OwnedNote {
        note: deposit.note,
        leaf_index: deposit.output_index,
    };
    let payee = stage.harness.account(PAYEE);
    let withdraw = prove_withdraw(
        &mut alice,
        &stage.ctx,
        WithdrawRequest {
            input: spend,
            token,
            amount: DEPOSIT,
            recipient: to_crate_address(payee),
        },
    )
    .await
    .expect("period k+1's attestation covers the boundary epoch");
    let receipt = submit_withdraw(&stage.harness, &stage.deployment, &withdraw)
        .await
        .expect("withdraw lands");
    assert!(receipt.status(), "gated withdraw reverted");
}

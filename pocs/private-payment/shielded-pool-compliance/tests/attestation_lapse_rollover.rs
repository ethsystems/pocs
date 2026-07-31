//! Scenario 6: Alice's attestation lapses at the calendar rollover. Every gated path
//! becomes unprovable in her own wallet, and `withdrawBlocked` still credits her exit.

mod common;

use alloy::primitives::U256;

use common::{
    proof_backend::use_mock_proofs,
    *,
};
use shielded_pool_compliance::{
    domain::note::Note,
    error::ProverError,
    ports::merkle::LeafIndex,
    wallet::{
        self,
        DepositRequest,
        OwnedNote,
        TransferOutput,
        TransferRequest,
        WithdrawRequest,
    },
};

const DEPOSIT: u64 = 9_000_000_000;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lapsed_attestation_closes_every_gated_path_and_leaves_the_blocked_exit() {
    if use_mock_proofs() {
        // The mock prover never evaluates the attestation gadget, so the whole point of
        // this scenario, that the lapse is what makes the witness unsatisfiable, would
        // pass vacuously.
        eprintln!("skipped: needs real proofs (VCCM_USE_MOCK_PROOFS is set)");
        return;
    }

    let issue_epoch = base_epoch();
    let stage = Stage::open(issue_epoch).await;
    let mut alice = TestWallet::new();
    let bob = TestWallet::new();
    let cohort = enroll(&stage, &[&alice, &bob]).await;
    mint_and_approve(&stage.harness, &stage.deployment, DEPLOYER, DEPOSIT).await;

    let token = stage.token();
    let alice_owner = alice.owner;
    let bob_owner = bob.owner;
    let alice_viewing_pubkey = alice.viewing_pubkey.clone();
    let bob_viewing_pubkey = bob.viewing_pubkey.clone();

    let deposit = prove_deposit(
        &mut alice,
        &stage.ctx,
        DepositRequest {
            token,
            amount: DEPOSIT,
        },
    )
    .await
    .expect("deposit proves while the attestation is live");
    submit_deposit(&stage.harness, &stage.deployment, &deposit)
        .await
        .expect("deposit lands");

    // `expires_at` is a calendar boundary, and the circuit demands the whole of `epoch`
    // to fall inside it, so the first uncovered epoch is the boundary epoch itself.
    let lapse_epoch = cohort.expires_at / shielded_pool_compliance::EPOCH_SECONDS;
    assert!(lapse_epoch > issue_epoch);
    stage.harness.warp_to_epoch(lapse_epoch).await;

    let spend = OwnedNote {
        note: deposit.note,
        leaf_index: deposit.output_index,
    };

    // The blocked exit runs first: a gated build inserts its compliance note into the
    // wallet's mirror before the prover is ever called, so a failed attempt leaves the
    // mirror one leaf ahead of the pool and no later root check could pass.
    let payee = stage.harness.account(PAYEE);
    let blocked_exit = prove_withdraw_blocked(
        &alice,
        &stage.ctx,
        WithdrawRequest {
            input: spend,
            token,
            amount: DEPOSIT,
            recipient: to_crate_address(payee),
        },
    )
    .await
    .expect("the ungated circuit carries no attestation, so it still proves");
    let receipt =
        submit_withdraw_blocked(&stage.harness, &stage.deployment, &blocked_exit)
            .await
            .expect("withdrawBlocked lands");
    assert!(receipt.status(), "withdrawBlocked reverted");

    let nullifier = deposit
        .note
        .nullifier(&alice.spending_key)
        .expect("nullifier");
    assert_eq!(
        blocked_balance(&stage.harness, &stage.deployment, nullifier).await,
        U256::from(DEPOSIT),
        "the exit of last resort credits the blocked balance rather than paying out"
    );
    assert_eq!(
        token_balance(&stage.harness, &stage.deployment, payee).await,
        U256::ZERO
    );

    assert_lapsed(
        prove_deposit(
            &mut alice,
            &stage.ctx,
            DepositRequest {
                token,
                amount: 1_000,
            },
        )
        .await
        .err(),
        "deposit",
    );

    assert_lapsed(
        prove_withdraw(
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
        .err(),
        "gated withdraw",
    );

    assert_lapsed(
        prove_transfer(
            &mut alice,
            &stage.ctx,
            TransferRequest {
                token,
                inputs: [
                    spend,
                    OwnedNote {
                        note: Note::zero(token, alice_owner),
                        leaf_index: LeafIndex(0),
                    },
                ],
                outputs: [
                    TransferOutput {
                        owner: bob_owner,
                        amount: DEPOSIT,
                        viewing_pubkey: bob_viewing_pubkey.clone(),
                    },
                    TransferOutput {
                        owner: alice_owner,
                        amount: 0,
                        viewing_pubkey: alice_viewing_pubkey.clone(),
                    },
                ],
            },
        )
        .await
        .err(),
        "transfer",
    );
}

/// The wallet returns a typed error and no proof exists: the failure is the circuit
/// refusing to accept a witness built against a lapsed attestation, not a submission
/// the chain happened to reject.
#[track_caller]
fn assert_lapsed(error: Option<wallet::Error>, path: &str) {
    let error = error.unwrap_or_else(|| panic!("{path} must not produce a proof"));
    let wallet::Error::Prover(ProverError::Backend(source)) = &error else {
        panic!("{path}: expected a prover backend failure, got {error:?}");
    };
    let message = source.to_string();
    assert!(
        message.contains("attestation expired"),
        "{path}: expected the lapsed-attestation assertion, got: {message}"
    );
}

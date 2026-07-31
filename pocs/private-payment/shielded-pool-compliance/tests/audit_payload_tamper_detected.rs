//! an honest transfer's `0x03` element is bound, via AAD, to its own cleartext
//! framing (tag and `committeeVersion`). Flipping a byte inside the ciphertext the
//! pool would have emitted as `encryptedNotes` must fail the auditor's decryption
//! outright, not be silently skipped: the version claimed on the wire still matches
//! the current committee, so `reconstruct_chain` treats a decryption failure here as
//! a forged or corrupted element, per `Error::UndecryptableElement`.

mod common;

use std::collections::BTreeSet;

use common::*;
use shielded_pool_compliance::{
    auditor::{
        Auditor,
        Error,
    },
    domain::payload::Payload,
    wallet::DepositRequest,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tampered_committee_element_is_rejected_not_silently_skipped() {
    let stage = Stage::open(base_epoch()).await;
    let mut alice = TestWallet::new();
    enroll(&stage, &[&alice]).await;
    mint_and_approve(&stage.harness, &stage.deployment, DEPLOYER, 1_000).await;

    let token = stage.token();
    let epoch = stage.epoch();

    let deposit = prove_deposit(
        &mut alice,
        &stage.ctx,
        DepositRequest {
            token,
            amount: 1_000,
        },
    )
    .await
    .expect("deposit proves");

    // `build_payload` appends the `0x03` committee element last, so flipping the
    // final byte of the encoded payload corrupts its ciphertext tail without
    // disturbing the tag or `committeeVersion` framing bytes ahead of it.
    let mut tampered_bytes = deposit.payload.encode();
    *tampered_bytes
        .last_mut()
        .expect("a deposit payload is nonempty") ^= 0xff;
    let tampered_payload = Payload::decode(&tampered_bytes)
        .expect("flipping one ciphertext byte does not change the framing shape");

    let auditor = Auditor::new(stage.audit_key);
    let err = auditor
        .reconstruct_chain(
            stage.ctx.state_tag,
            stage.ctx.committee_version,
            tampered_payload.elements(),
            alice.owner,
            epoch,
            &BTreeSet::new(),
        )
        .expect_err("a tampered current-version committee element must not decrypt");

    assert!(
        matches!(err, Error::UndecryptableElement { .. }),
        "expected UndecryptableElement, got: {err}"
    );
}

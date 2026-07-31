mod common;

use common::*;
use num_bigint::BigUint;
use shielded_pool_compliance::{
    error::ChainError,
    ports::chain::ChainWriter,
    wallet::DepositRequest,
};

const ATTEMPTS: u64 = 20;

fn bn254_modulus() -> BigUint {
    BigUint::parse_bytes(
        b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10,
    )
    .expect("valid decimal literal")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn confirmed_deposits_accept_hashes_above_the_bn254_modulus_and_report_a_revert() {
    let stage = Stage::open(base_epoch()).await;
    let mut alice = TestWallet::new();
    enroll(&stage, &[&alice]).await;
    mint_and_approve(&stage.harness, &stage.deployment, DEPLOYER, ATTEMPTS).await;

    let token = stage.token();
    let modulus = bn254_modulus();
    let mut saw_hash_above_modulus = false;
    let mut last_proved = None;

    for _ in 0..ATTEMPTS {
        let proved =
            prove_deposit(&mut alice, &stage.ctx, DepositRequest { token, amount: 1 })
                .await
                .expect("deposit proves");

        let encrypted = proved.payload.encode();
        let tx_hash = stage
            .ctx
            .rpc
            .submit_deposit(&proved.proof, &encrypted)
            .await
            .expect(
                "a confirmed deposit is accepted regardless of its hash's field range",
            );

        if BigUint::from_bytes_be(&tx_hash.0) >= modulus {
            saw_hash_above_modulus = true;
        }
        last_proved = Some(proved);
    }

    assert!(
        saw_hash_above_modulus,
        "none of {ATTEMPTS} confirmed transaction hashes exceeded the BN254 modulus; \
         re-run, since this is what the old `Bytes32`-typed return value rejected"
    );

    // Resubmitting the same proof spends an already-spent velocity nullifier. The
    // fixed adapter never estimates gas before sending (see `SUBMIT_GAS_LIMIT` in
    // `adapters::ethereum_rpc`), so the revert is only visible once the transaction is
    // actually mined: exactly the case a `.tx_hash()`-only return value would report
    // as `Ok`.
    let proved = last_proved.expect("at least one deposit ran");
    let encrypted = proved.payload.encode();
    let err = stage
        .ctx
        .rpc
        .submit_deposit(&proved.proof, &encrypted)
        .await
        .expect_err("resubmitting a spent nullifier must not report success");
    assert!(
        matches!(err, ChainError::Reverted { .. }),
        "expected a confirmed revert, got: {err}"
    );
}

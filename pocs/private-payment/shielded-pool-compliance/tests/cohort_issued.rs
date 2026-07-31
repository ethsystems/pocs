//! Scenario 1: an authority issues one cohort covering Alice and Bob.

mod common;

use common::*;
use shielded_pool_compliance::{
    authority::{
        self,
        Authority,
    },
    domain::attestation::{
        Cohort,
        Generation,
    },
    ports::registry::AttestationSource,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authority_issues_a_cohort_covering_alice_and_bob() {
    let stage = Stage::open(base_epoch()).await;
    let alice = TestWallet::new();
    let bob = TestWallet::new();

    let minimum = min_cohort_size(&stage.harness, &stage.deployment).await;
    assert!(
        minimum.0 > 2,
        "a deployment whose minimum admits a two-subject cohort would not exercise this"
    );

    let authority = Authority::new(minimum);
    let refused = authority
        .build_cohort(
            &stage.harness.clock(),
            vec![alice.owner, bob.owner],
            Generation(1),
        )
        .expect_err("two subjects is below the registry's minimum");
    assert!(matches!(
        refused,
        authority::Error::CohortTooSmall { size: 2, .. }
    ));

    let calendar_expiry = Cohort::calendar_expires_at(
        stage.epoch(),
        shielded_pool_compliance::EPOCH_SECONDS,
        shielded_pool_compliance::MAX_ATTESTATION_EPOCHS,
    );
    let undersized =
        Cohort::new(vec![alice.owner, bob.owner], calendar_expiry, Generation(1));
    grant_attester(&stage).await;
    let rejected = submit_cohort(&stage.harness, &stage.deployment, &undersized)
        .await
        .expect_err("the registry enforces the same minimum on chain");
    assert_reverts_with::<IAttestationRegistry::CohortTooSmall>(&rejected);

    let cohort = enroll(&stage, &[&alice, &bob]).await;
    assert_eq!(cohort.subjects.len(), minimum.0 as usize);
    assert_eq!(cohort.expires_at, calendar_expiry);
    assert!(cohort.subjects.contains(&alice.owner));
    assert!(cohort.subjects.contains(&bob.owner));

    let leaves = attestation_leaves(&stage.harness, &stage.deployment).await;
    assert_eq!(leaves.len(), minimum.0 as usize);

    for wallet in [&alice, &bob] {
        let record = stage
            .ctx
            .rpc
            .current_attestation(wallet.owner)
            .await
            .expect("registry read")
            .expect("the cohort covers this subject");
        assert_eq!(record.generation, Generation(1));
        assert_eq!(record.expires_at, calendar_expiry);
        assert_eq!(record.attester, to_crate_address(stage.harness.deployer()));
        assert_eq!(
            leaves[record.leaf_index.0 as usize],
            subject_leaf(&record, wallet.owner)
        );
        // Never revoked: no epoch can reach `u64::MAX`, so the in-circuit
        // `epoch < revoked_at` holds for the whole life of the deployment.
        assert_eq!(record.revoked_at, u64::MAX);
    }
}

async fn grant_attester(stage: &Stage) {
    let provider = stage.harness.provider(DEPLOYER);
    IAttestationRegistry::new(stage.deployment.registry, &provider)
        .addAttester(stage.harness.deployer())
        .send()
        .await
        .expect("addAttester send")
        .get_receipt()
        .await
        .expect("addAttester receipt");
}

fn subject_leaf(
    record: &shielded_pool_compliance::ports::registry::AttestationRecord,
    owner: shielded_pool_compliance::domain::keys::OwnerPubkey,
) -> shielded_pool_compliance::types::Bytes32 {
    shielded_pool_compliance::domain::attestation::AttestationLeaf {
        owner_pubkey: owner,
        attester: record.attester,
        generation: record.generation,
        issued_at: record.issued_at,
        expires_at: record.expires_at,
    }
    .hash()
    .expect("canonical owner pubkey")
}

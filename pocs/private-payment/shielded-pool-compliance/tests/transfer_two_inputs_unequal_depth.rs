//! `adapters::commitment_tree`'s own unit tests show a LeanIMT promotes a node that
//! lacks a right sibling, so co-resident leaves can sit at different depths once the
//! tree size stops being a power of two. This is the end-to-end proof that
//! `circuits/transfer` can spend two owned notes at unequal depths in one transaction,
//! now that each input carries its own `proof_length`.

mod common;

use common::{
    proof_backend::prover,
    *,
};
use shielded_pool_compliance::{
    ports::prover::{
        ProofRequest,
        Prover,
    },
    wallet::{
        DepositRequest,
        OwnedNote,
        TransferOutput,
        TransferRequest,
    },
};

const ALICE_FIRST: u64 = 10_000_000_000;
const FILLER: u64 = 1_000_000_000;
const ALICE_SECOND: u64 = 5_000_000_000;
const TO_BOB: u64 = 6_000_000_000;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transfer_spends_two_inputs_at_unequal_leanimt_depths() {
    let stage = Stage::open(base_epoch()).await;
    let mut alice = TestWallet::new();
    let bob = TestWallet::new();
    let mut filler = TestWallet::new();
    enroll(&stage, &[&alice, &bob, &filler]).await;
    mint_and_approve(
        &stage.harness,
        &stage.deployment,
        DEPLOYER,
        ALICE_FIRST + FILLER + ALICE_SECOND,
    )
    .await;

    let token = stage.token();

    // Alice's first note lands at leaves 0/1 (commitment, compliance note).
    let dep_alice_1 = prove_deposit(
        &mut alice,
        &stage.ctx,
        DepositRequest {
            token,
            amount: ALICE_FIRST,
        },
    )
    .await
    .expect("alice's first deposit proves");
    submit_deposit(&stage.harness, &stage.deployment, &dep_alice_1)
        .await
        .expect("alice's first deposit lands");
    filler.observe_commitments(&deposit_leaves(&dep_alice_1.proof));

    // A third party fills leaves 2/3, so the tree's leaf count is 4 (not a power-
    // of-two boundary yet) when alice's second deposit lands next.
    let dep_filler = prove_deposit(
        &mut filler,
        &stage.ctx,
        DepositRequest {
            token,
            amount: FILLER,
        },
    )
    .await
    .expect("filler deposit proves");
    submit_deposit(&stage.harness, &stage.deployment, &dep_filler)
        .await
        .expect("filler deposit lands");
    alice.observe_commitments(&deposit_leaves(&dep_filler.proof));

    // Alice's second note lands at leaf 4, with its own compliance note at leaf 5:
    // six leaves total. Leaves 0-3 pair down to the root through three real
    // hashes; leaves 4/5 pair with each other once, then get promoted a level
    // before the final hash, landing two real hashes deep instead of three. Alice
    // now owns two real notes, leaf 0 and leaf 4, at different depths.
    let dep_alice_2 = prove_deposit(
        &mut alice,
        &stage.ctx,
        DepositRequest {
            token,
            amount: ALICE_SECOND,
        },
    )
    .await
    .expect("alice's second deposit proves");
    submit_deposit(&stage.harness, &stage.deployment, &dep_alice_2)
        .await
        .expect("alice's second deposit lands");

    let bob_owner = bob.owner;
    let alice_owner = alice.owner;
    let bob_viewing_pubkey = bob.viewing_pubkey.clone();
    let alice_viewing_pubkey = alice.viewing_pubkey.clone();
    let change = ALICE_FIRST + ALICE_SECOND - TO_BOB;

    let built = alice
        .wallet
        .build_transfer(
            &stage.ctx.rpc,
            &stage.ctx.clock,
            &stage.ctx.audit,
            &stage.ctx.rpc,
            TransferRequest {
                token,
                inputs: [
                    OwnedNote {
                        note: dep_alice_1.note,
                        leaf_index: dep_alice_1.output_index,
                    },
                    OwnedNote {
                        note: dep_alice_2.note,
                        leaf_index: dep_alice_2.output_index,
                    },
                ],
                outputs: [
                    TransferOutput {
                        owner: bob_owner,
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
        .expect("transfer builds");

    let (length_0, length_1) = match &built.request {
        ProofRequest::Transfer(w) => (
            w.inputs[0].proof.steps().len(),
            w.inputs[1].proof.steps().len(),
        ),
        _ => unreachable!("build_transfer always returns ProofRequest::Transfer"),
    };
    // The load-bearing assertion: under VCCM_USE_MOCK_PROOFS=1 the circuit itself
    // never runs, so this is the only check that would catch a regression back to
    // one shared proof length for both inputs.
    assert_ne!(
        length_0, length_1,
        "alice's two notes sit at different LeanIMT depths and must carry distinct proof lengths"
    );

    let proof = prover()
        .prove(&built.request)
        .expect("transfer proves at unequal input depths");
    let transfer = ProvedTransfer {
        proof,
        payload: built.payload,
        outputs: built.outputs,
        output_indices: built.output_indices,
    };
    let receipt = submit_transfer(&stage.harness, &stage.deployment, &transfer)
        .await
        .expect("transfer lands");
    assert!(receipt.status(), "transfer reverted");
}

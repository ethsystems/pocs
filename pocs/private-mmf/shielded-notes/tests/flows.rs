//! End-to-end flows from the SPEC, against a local chain. Run with real proofs
//! (`cargo test --release --test flows`) or mock proofs
//! (`SN_USE_MOCK_PROOFS=1 cargo test --release --test flows --features test-mocks`).
//! `tests/README.md` draws each flow as the calls each actor makes.

mod common;

use alloy::primitives::{
    B256,
    U256,
};
use common::*;
use shielded_notes::{
    agent::{
        AGENT_ID,
        ClaimAction,
        Holder,
        PADDING_ID,
        TransferAgent,
    },
    chain::{
        self,
        IHonkVerifier::IHonkVerifierErrors,
        IShieldedPool::IShieldedPoolErrors,
        Submission,
        to_address,
    },
    client,
    domain::{
        keys::PlanSigner,
        note::LockOpening,
    },
    error::{
        ActorError,
        ChainError,
        ClientError,
        ProverError,
    },
    wallet::Output,
};

/// Subscription with a hand-out tree, a transfer between investors, a daily
/// reinvestment, and a partial redemption, with the agent's register
/// reconciled against the pool after each step.
#[tokio::test]
async fn subscription_transfer_yield_and_redemption() {
    // The agent generates all its keys here (`TransferAgent::new`): its own
    // owner keys, split into a wallet and a signer as for any holder; the claim
    // key; the register key; and the salt key for the register hash.
    let mut agent = TransferAgent::new();
    // Spawns anvil and deploys the token, the registry, the verifiers and the
    // pool. The pool is built with the hash of the agent's claim key and the
    // public half of its register key, so every proof binds to both.
    let h = Harness::start(&agent);
    // The pool's counters: its share balance `B`, in the token's base units,
    // and its units `U`. One unit is one base unit while m = 1. Deposits and
    // withdrawals move both; transfers move units between notes and change
    // neither.
    let share = u128::from(SHARE);
    assert_pool(&h, 0, 0).await;
    // Before any investor: the agent attests its own owner value (padded with
    // owner values it holds keys for), deposits 1 share into it, and freezes
    // that note through the claim path. `U` never returns to 0 after this.
    seed(&h, &mut agent).await;
    assert_pool(&h, share, share).await;
    // Each investor's keys, split at creation: `sk` to the custody signer,
    // `pk`, `nk` and `vk` to the wallet (`OwnerKeys::split`).
    let alice = Investor::new("INV-ALICE");
    let bob = Investor::new("INV-BOB");
    let carol = Investor::new("INV-CAROL");
    // SPEC, Onboarding. Each investor sends a signed registration; the agent
    // checks it, computes the owner value, checks the caps, and attests the
    // three owner values in one `addAttestations` batch, padded to the
    // registry's minimum.
    onboard_and_attest(&h, &mut agent, &[&alice, &bob, &carol]).await;

    // Day 1: 600 shares of subscriptions, one public aggregate, then the hand-out.
    // SPEC, Subscription, steps 1 and 2. Cash is settled off-chain. The issuer
    // allowlists the agent's address and mints it the shares the deposit pulls,
    // ceil(units * m / S). The agent's wallet builds a deposit of 600 units into
    // its own owner value, its signer signs it, and the agent proves it and
    // sends it from its own address, the deposit's funding address. The pool
    // pulls 600 shares. The chain sees one public aggregate: 600 units into a
    // commitment.
    aggregate_deposit(&h, &mut agent, 600 * SHARE).await;
    // The seed's share and the day's 600.
    assert_pool(&h, 601 * share, 601 * share).await;
    // SPEC, Subscription, step 3. The agent splits its 600-unit note with
    // ordinary transfers through the owner path, signed with its own key and
    // relayed: 600 -> Alice 100 + agent 500, then 500 -> Bob 200 + Carol 300.
    // Each transfer has two outputs; its recipient payload carries each
    // output's opening encrypted to that owner's `vpk`, and its register feed
    // carries both openings encrypted to the agent's register key. On-chain
    // these look like any other transfer: nobody sees amounts or recipients.
    hand_out(
        &h,
        &mut agent,
        &[
            (&alice, 100 * SHARE),
            (&bob, 200 * SHARE),
            (&carol, 300 * SHARE),
        ],
    )
    .await;
    // Two transfers: unchanged.
    assert_pool(&h, 601 * share, 601 * share).await;

    let relayer = h.client(RELAYER);
    let view = relayer.view().await.expect("read the chain");
    let env = relayer.env().await.expect("read the pool");
    let mut alice = alice;
    let mut bob = bob;
    let mut carol = carol;
    // Each wallet reads the chain itself (`ChainView`: commitments, nullifiers,
    // payloads, attestations) and trial-decrypts every recipient payload with
    // its `vk`; the ones that open are its notes. It marks a note spent when
    // the pool records the nullifier its `nk` gives for that note.
    for inv in [&mut alice, &mut bob, &mut carol] {
        inv.wallet.scan(&view);
    }
    assert_eq!(alice.wallet.balance(env.epoch), 100 * SHARE);
    assert_eq!(bob.wallet.balance(env.epoch), 200 * SHARE);
    assert_eq!(carol.wallet.balance(env.epoch), 300 * SHARE);
    // The agent reads every new note through the register feed, with its
    // register key, so it needs no payload and no help from holders. It maps
    // each note's owner value to an investor ID from onboarding, and marks
    // notes spent with the investors' `nk`. That is its register: positions per
    // ID.
    agent.read_feed(&view).expect("read the feed");
    assert_eq!(agent.positions().get("INV-CAROL"), Some(&(300 * SHARE)));
    // The register's units add up to the pool's `U`, and the agent's local
    // trees match the pool's and the registry's roots.
    assert_register_reconciles(&h, &mut agent).await;

    // Alice pays Bob 40 shares; Bob finds the note by trial decryption.
    // The owner path, in one call (`Wallet::pay`, `src/wallet.rs`):
    // 1. The wallet picks Alice's 100-unit note, adds a zero-unit padding input
    //    (every transfer has two inputs and two outputs), and makes the
    //    outputs: 40 to Bob's owner value, 60 back to Alice's.
    // 2. It builds the plan: chain, pool, operation, path, both nullifiers,
    //    both output commitments, and an expiry.
    // 3. The custody signer rebuilds the plan's digest from those fields and
    //    the output openings, and signs it with `sk` (`sign_plan`).
    // 4. The wallet finishes the witness against the current roots: the input's
    //    Merkle path, the attestations of Alice and of each output's owner, the
    //    payload to Bob's and Alice's `vpk`, and the feed to the register key.
    // `prepare_transfer` and `finish` split steps 1-2 from step 4, for a
    // custody approval that takes hours (see `crossing_in_and_out`).
    let built = alice
        .wallet
        .pay(
            &alice.signer,
            &view,
            &env,
            bob.owner(),
            bob.vpk(),
            40 * SHARE,
        )
        .unwrap();
    // Alice's side proves (`client::prove_transfer`) and hands the relayer only
    // the pool call's parameters (`Submission`): the proof and the public
    // inputs, never the witness. The pool checks the epoch, the feed point,
    // that both nullifiers are new, and that both roots are known; then the
    // proof. It marks the nullifiers spent, inserts the two commitments and
    // emits the payload and the feed. No amount or owner appears.
    relay_transfer(&relayer, &built)
        .await
        .expect("alice pays bob");
    let view = relayer.view().await.expect("read the chain");
    alice.wallet.scan(&view);
    bob.wallet.scan(&view);
    assert_eq!(alice.wallet.balance(env.epoch), 60 * SHARE);
    assert_eq!(bob.wallet.balance(env.epoch), 240 * SHARE);
    agent.read_feed(&view).expect("read the feed");
    assert_eq!(agent.positions().get("INV-BOB"), Some(&(240 * SHARE)));

    // The daily reinvestment: 1% to the pool, as new shares. No note changes.
    // Notes hold units, not shares. The token mints the pool's yield into its
    // balance `B`, while `U` stays, so the multiplier m = B*S/U rises from 1 to
    // 1.01 and every note is worth 1% more shares without being touched. The
    // pool reads m from its balance at each deposit and withdrawal.
    let pool_before = h.balance(h.deployment.pool).await;
    h.token(AGENT)
        .reinvest(vec![h.deployment.pool], U256::from(100 * BASIS_POINT))
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    assert_eq!(
        h.balance(h.deployment.pool).await,
        pool_before + pool_before / 100
    );
    // m = B * S / U = 607.01 / 601 = 1.01.
    assert_pool(&h, 60_701 * share / 100, 601 * share).await;

    // Carol redeems 80 of her 300 shares: one transfer to the agent, change to herself.
    // SPEC, Redemption, step 1. 80 units, worth 80.8 shares at m = 1.01. Carol
    // pays the agent's owner value, as she would pay anyone: on-chain it is an
    // ordinary transfer. The agent sees from the feed a note to itself whose
    // spent input nullifier matches Carol's `nk`, so it is her redemption
    // (`TransferAgent::redemptions`). It stays pending until the agent spends
    // it.
    let built = carol
        .wallet
        .pay(
            &carol.signer,
            &view,
            &env,
            agent.owner(),
            agent.wallet.vpk(),
            80 * SHARE,
        )
        .unwrap();
    relay_transfer(&relayer, &built)
        .await
        .expect("carol redeems");
    let view = relayer.view().await.expect("read the chain");
    carol.wallet.scan(&view);
    assert_eq!(carol.wallet.balance(env.epoch), 220 * SHARE);
    agent.read_feed(&view).expect("read the feed");
    let redemptions = agent.redemptions(&view);
    assert_eq!(redemptions.len(), 1);
    assert_eq!(redemptions[0].investor_id, "INV-CAROL");
    assert_eq!(redemptions[0].units, 80 * SHARE);
    // A redemption is a transfer: nothing leaves the pool until the withdrawal.
    assert_pool(&h, 60_701 * share / 100, 601 * share).await;

    // End of day: the agent withdraws the redeemed note to its own address and
    // burns the shares on the public side.
    // SPEC, Redemption, step 3 (step 2, merging the day's notes, has only one
    // note here). A withdrawal spends one whole note to a public address; the
    // agent signs, proves and sends it itself. The chain sees 80 units leave
    // for the agent's address, and the pool pays floor(80 * m / S) = 80.8
    // shares. The agent burns them and pays Carol the cash off-chain (not
    // modelled). With the note spent, the redemption is no longer pending,
    // which the agent reads from the chain, not from memory.
    let agent_client = h.client(AGENT);
    let env = agent_client.env().await.expect("read the pool");
    let note = *agent
        .wallet
        .notes
        .iter()
        .find(|n| n.commitment == redemptions[0].commitment)
        .unwrap();
    let agent_address = h.account(AGENT);
    let before = h.balance(agent_address).await;
    let w = agent
        .wallet
        .withdraw(&agent.signer, &view, &env, &note, to_address(agent_address))
        .unwrap();
    relay_withdraw(&agent_client, &w)
        .await
        .expect("withdraw redemption");
    let paid = h.balance(agent_address).await - before;
    assert_eq!(
        paid,
        80 * u128::from(SHARE) * 101 / 100,
        "80 units at m = 1.01"
    );
    h.token(AGENT)
        .burn(agent_address, U256::from(paid))
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    assert!(
        agent
            .redemptions(&agent_client.view().await.expect("read the chain"))
            .is_empty(),
        "a redemption whose note the agent withdrew is processed"
    );
    // 80 units and 80.8 shares left the pool.
    assert_pool(&h, 52_621 * share / 100, 521 * share).await;

    // Reconciliation: the agent computes the rounding remainder and reports it
    // with the checkpoint. Here m = 1.01 exactly and every note holds whole
    // shares, so each note's withdrawal divides exactly and nothing is left.
    let remainder = assert_register_reconciles(&h, &mut agent).await;
    assert_eq!(remainder, U256::ZERO);
    // SPEC, Reconciliation, Disclosure and Corrections. The checkpoint
    // publishes a salted hash of the register and the units it expects. The
    // pool refuses it if `U` moved since the agent's snapshot, records m, and
    // halts if m fell since the last checkpoint. The agent can open the hash
    // for one day to an auditor, with that day's salt and the register.
    chain::checkpoint(
        &h.provider(AGENT),
        &h.deployment,
        agent.register_hash(env.epoch),
        agent.total_units(),
    )
    .await
    .expect("checkpoint");
}

/// Four days with two investors, Bob holding two owner values, as a desk gives
/// each counterparty its own (SPEC, Key Model, payment address): subscriptions,
/// yield at an uneven rate, a payment, a crossing in, a freeze and its release,
/// a redemption that waits overnight, and a crossing out. Each day ends with
/// the pool's counters, the investors' positions, reconciliation and a
/// checkpoint.
#[tokio::test]
async fn busy_four_days_with_several_flows() {
    let mut agent = TransferAgent::new();
    let h = Harness::start(&agent);
    seed(&h, &mut agent).await;
    // At most two investors: Bob counts once, however many owner values and
    // addresses he uses.
    agent.max_investors = Some(2);
    let relayer = h.client(RELAYER);
    let issuer = h.token(AGENT);
    let share = u128::from(SHARE);
    let s = shielded_notes::S;
    // The pool's counters, tracked here with the SPEC's rules: yield adds to
    // `B`; a deposit pulls ceil(units * m / S) and a withdrawal pays
    // floor(units * m / S), with m = floor(B * S / U). The seed holds 1 share.
    let (mut b, mut u) = (share, share);
    let m = |b: u128, u: u128| b * s / u;

    let mut alice = Investor::new("INV-ALICE");
    let mut bob_a = Investor::new("INV-BOB");
    let mut bob_b = Investor::new("INV-BOB");

    // Day 1. Alice and Bob's first owner value are attested in one batch, and
    // subscribe 100 and 200 shares.
    onboard_and_attest(&h, &mut agent, &[&alice, &bob_a]).await;
    aggregate_deposit(&h, &mut agent, 300 * SHARE).await;
    hand_out(
        &h,
        &mut agent,
        &[(&alice, 100 * SHARE), (&bob_a, 200 * SHARE)],
    )
    .await;
    (b, u) = (b + 300 * share, u + 300 * share);
    let mut alice_units = 100 * SHARE;
    let mut bob_units = 200 * SHARE;
    let remainder = close_the_day(
        &h,
        &mut agent,
        b,
        u,
        &[("INV-ALICE", alice_units), ("INV-BOB", bob_units)],
    )
    .await;
    assert_eq!(remainder, U256::ZERO, "whole shares at m = 1");

    // Day 2. Yield at 37 basis points.
    h.advance_epochs(1).await;
    reinvest(&h, 37).await;
    b += b * 37 / 10_000;
    assert_eq!(m(b, u), 1_003_700_000_000_000_000);

    // Bob's second owner value is attested in a batch of its own (SPEC,
    // Onboarding, step 4). The cap of two still holds: Bob counts once.
    onboard_and_attest(&h, &mut agent, &[&bob_b]).await;

    // Alice pays Bob's second owner value an uneven amount, so neither her
    // change nor his note withdraws a whole number of base units at m.
    let view = relayer.view().await.expect("read the chain");
    let env = relayer.env().await.expect("read the pool");
    alice.wallet.scan(&view);
    let to_bob = 33_333_333;
    let built = alice
        .wallet
        .pay(
            &alice.signer,
            &view,
            &env,
            bob_b.owner(),
            bob_b.vpk(),
            to_bob,
        )
        .unwrap();
    relay_transfer(&relayer, &built)
        .await
        .expect("alice pays bob");
    (alice_units, bob_units) = (alice_units - to_bob, bob_units + to_bob);

    // Alice crosses in 40 shares' worth of units from 50 shares she holds
    // publicly. The agent knows her public address, so it counts as hers.
    let alice_public = h.account(HOLDER);
    issuer
        .setAllowlisted(alice_public, true)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    issuer
        .mint(alice_public, U256::from(50 * SHARE))
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    h.token(HOLDER)
        .approve(h.deployment.pool, U256::MAX)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    agent
        .register_public_holder(to_address(alice_public), "INV-ALICE")
        .expect("a verified investor");
    let alice_client = h.client(HOLDER);
    let view = alice_client.view().await.expect("read the chain");
    let (w, payload) = alice
        .wallet
        .deposit(
            &alice.signer,
            &view,
            &env,
            40 * SHARE,
            to_address(alice_public),
        )
        .unwrap();
    submit_deposit(&alice_client, &w, &payload)
        .await
        .expect("alice crosses in");
    let pulled = (40 * share * m(b, u)).div_ceil(s);
    assert_eq!(h.balance(alice_public).await, 50 * share - pulled);
    (b, u) = (b + pulled, u + 40 * share);
    alice_units += 40 * SHARE;
    let remainder = close_the_day(
        &h,
        &mut agent,
        b,
        u,
        &[("INV-ALICE", alice_units), ("INV-BOB", bob_units)],
    )
    .await;
    assert!(
        remainder > U256::ZERO,
        "uneven notes leave shares that no note can withdraw"
    );

    // Day 3. Yield again.
    h.advance_epochs(1).await;
    reinvest(&h, 37).await;
    b += b * 37 / 10_000;
    let m3 = m(b, u);

    // The agent freezes the note Bob received from Alice, on a court order say.
    let view = relayer.view().await.expect("read the chain");
    let env = relayer.env().await.expect("read the pool");
    agent.read_feed(&view).expect("read the feed");
    bob_b.wallet.scan(&view);
    let target = bob_b.wallet.spendable(env.epoch)[0].commitment;
    let built = agent
        .claim(&view, &env, target, ClaimAction::Freeze)
        .unwrap();
    relay_transfer(&relayer, &built).await.expect("freeze");

    // Bob redeems 50 shares' worth of units from his first owner value. The
    // agent withdraws them tomorrow, so they accrue overnight.
    let view = relayer.view().await.expect("read the chain");
    bob_a.wallet.scan(&view);
    let built = bob_a
        .wallet
        .pay(
            &bob_a.signer,
            &view,
            &env,
            agent.owner(),
            agent.wallet.vpk(),
            50 * SHARE,
        )
        .unwrap();
    relay_transfer(&relayer, &built).await.expect("bob redeems");
    let view = relayer.view().await.expect("read the chain");
    agent.read_feed(&view).expect("read the feed");
    let redemptions = agent.redemptions(&view);
    assert_eq!(redemptions.len(), 1);
    assert_eq!(redemptions[0].investor_id, "INV-BOB");
    assert_eq!(redemptions[0].units, 50 * SHARE);
    bob_b.wallet.scan(&view);
    assert_eq!(bob_b.wallet.balance(env.epoch), 0, "the frozen note");
    // The frozen note is still Bob's position; the redeemed units are the agent's.
    bob_units -= 50 * SHARE;
    close_the_day(
        &h,
        &mut agent,
        b,
        u,
        &[("INV-ALICE", alice_units), ("INV-BOB", bob_units)],
    )
    .await;

    // Day 4. Yield again.
    h.advance_epochs(1).await;
    reinvest(&h, 37).await;
    b += b * 37 / 10_000;

    // The agent withdraws yesterday's redemption at today's multiplier, burns
    // the shares, and pays Bob the cash off-chain.
    let agent_client = h.client(AGENT);
    let view = agent_client.view().await.expect("read the chain");
    let env = agent_client.env().await.expect("read the pool");
    agent.read_feed(&view).expect("read the feed");
    let commitment = agent.redemptions(&view)[0].commitment;
    let note = *agent
        .wallet
        .notes
        .iter()
        .find(|n| n.commitment == commitment)
        .unwrap();
    let agent_address = h.account(AGENT);
    let before = h.balance(agent_address).await;
    let w = agent
        .wallet
        .withdraw(&agent.signer, &view, &env, &note, to_address(agent_address))
        .unwrap();
    relay_withdraw(&agent_client, &w)
        .await
        .expect("withdraw the redemption");
    let paid = h.balance(agent_address).await - before;
    assert_eq!(paid, 50 * share * m(b, u) / s);
    assert!(
        paid > 50 * share * m3 / s,
        "the redemption accrued overnight"
    );
    issuer
        .burn(agent_address, U256::from(paid))
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    (b, u) = (b - paid, u - 50 * share);

    // Bob crosses out: his first owner value's remaining note, to his public
    // address.
    let bob_public = h.account(OTHER_HOLDER);
    issuer
        .setAllowlisted(bob_public, true)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    agent
        .register_public_holder(to_address(bob_public), "INV-BOB")
        .expect("a verified investor");
    let view = relayer.view().await.expect("read the chain");
    bob_a.wallet.scan(&view);
    let note = bob_a.wallet.spendable(env.epoch)[0];
    assert_eq!(note.note.units, 150 * SHARE);
    let w = bob_a
        .wallet
        .withdraw(&bob_a.signer, &view, &env, &note, to_address(bob_public))
        .unwrap();
    relay_withdraw(&relayer, &w).await.expect("bob crosses out");
    let out = 150 * share * m(b, u) / s;
    assert_eq!(h.balance(bob_public).await, out);
    (b, u) = (b - out, u - 150 * share);
    bob_units -= 150 * SHARE;

    // The agent releases the freeze, and Bob's second owner value can spend
    // again.
    let view = relayer.view().await.expect("read the chain");
    agent.read_feed(&view).expect("read the feed");
    let frozen = agent
        .register
        .iter()
        .find(|e| {
            !e.spent
                && e.holder.as_ref().map(Holder::as_str) == Some("INV-BOB")
                && e.opening == LockOpening::freeze()
        })
        .unwrap()
        .commitment;
    let built = agent
        .claim(&view, &env, frozen, ClaimAction::Release)
        .unwrap();
    relay_transfer(&relayer, &built).await.expect("release");
    let view = relayer.view().await.expect("read the chain");
    bob_b.wallet.scan(&view);
    assert_eq!(bob_b.wallet.balance(env.epoch), to_bob);
    close_the_day(
        &h,
        &mut agent,
        b,
        u,
        &[("INV-ALICE", alice_units), ("INV-BOB", bob_units)],
    )
    .await;

    // The cap: Bob counts once across two owner values and a public address,
    // so with Alice the fund is full, and a third investor is refused.
    let carol = Investor::new("INV-CAROL");
    let view = relayer.view().await.expect("read the chain");
    let owner = carol.register_with(&mut agent, &env);
    let public = holding_publicly(&h, &agent).await;
    assert!(matches!(
        agent.check_cap(&view, &env, &[owner], &public),
        Err(ActorError::CapReached { cap: 2 })
    ));
}

/// The issuer's daily reinvestment into the pool, at `bps` basis points.
async fn reinvest(h: &Harness, bps: u64) {
    h.token(AGENT)
        .reinvest(vec![h.deployment.pool], U256::from(bps * BASIS_POINT))
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
}

/// The end of a day: the pool's counters `B` and `U`, the investors' positions
/// in the agent's register, reconciliation, and the checkpoint. Returns the
/// rounding remainder.
async fn close_the_day(
    h: &Harness,
    agent: &mut TransferAgent,
    balance: u128,
    units: u128,
    positions: &[(&str, u64)],
) -> U256 {
    assert_pool(h, balance, units).await;
    let client = h.client(AGENT);
    let view = client.view().await.expect("read the chain");
    let env = client.env().await.expect("read the pool");
    agent.read_feed(&view).expect("read the feed");
    let held = agent.positions();
    for (id, units) in positions {
        assert_eq!(held.get(*id), Some(units), "{id}'s position");
    }
    let remainder = assert_register_reconciles(h, agent).await;
    chain::checkpoint(
        &h.provider(AGENT),
        &h.deployment,
        agent.register_hash(env.epoch),
        agent.total_units(),
    )
    .await
    .expect("checkpoint");
    remainder
}

/// The claim path: the agent freezes a holder's note in place, releases it,
/// and finally seizes it to its own owner value.
#[tokio::test]
async fn claims_freeze_release_and_seize() {
    // Alice holds one 100-share note, the target of every claim below. Bob is
    // attested only so that Alice has someone to try to pay.
    let mut agent = TransferAgent::new();
    let h = Harness::start(&agent);
    seed(&h, &mut agent).await;
    let mut alice = Investor::new("INV-ALICE");
    let bob = Investor::new("INV-BOB");
    onboard_and_attest(&h, &mut agent, &[&alice, &bob]).await;
    aggregate_deposit(&h, &mut agent, 100 * SHARE).await;
    hand_out(&h, &mut agent, &[(&alice, 100 * SHARE)]).await;

    let relayer = h.client(RELAYER);
    let view = relayer.view().await.expect("read the chain");
    let env = relayer.env().await.expect("read the pool");
    alice.wallet.scan(&view);
    let target = alice.wallet.spendable(env.epoch)[0].commitment;

    // A race (SPEC, Claims): the agent builds a freeze on Alice's note, but
    // Alice redeems part of it first. The freeze fails, and Alice's spend,
    // which shares its nullifier, is still her redemption.
    agent.read_feed(&view).expect("read the feed");
    let late = agent
        .claim(&view, &env, target, ClaimAction::Freeze)
        .unwrap();
    let built = alice
        .wallet
        .pay(
            &alice.signer,
            &view,
            &env,
            agent.owner(),
            agent.wallet.vpk(),
            10 * SHARE,
        )
        .unwrap();
    relay_transfer(&relayer, &built)
        .await
        .expect("alice redeems first");
    let err = relay_transfer(&relayer, &late)
        .await
        .expect_err("the freeze lost the race");
    assert!(
        rejected(&err, |e| matches!(
            e,
            IShieldedPoolErrors::NullifierSpent(_)
        )),
        "{err:?}"
    );
    let view = relayer.view().await.expect("read the chain");
    agent.read_feed(&view).expect("read the feed");
    assert!(agent.pending_claims.is_empty(), "the lost claim is dropped");
    let redemptions = agent.redemptions(&view);
    assert_eq!(redemptions.len(), 1);
    assert_eq!(redemptions[0].investor_id, "INV-ALICE");
    assert_eq!(redemptions[0].units, 10 * SHARE);
    alice.wallet.scan(&view);
    let target = alice.wallet.spendable(env.epoch)[0].commitment;

    // Freeze: the note is re-created for Alice with a freeze lock.
    agent.read_feed(&view).expect("read the feed");
    let built = agent
        .claim(&view, &env, target, ClaimAction::Freeze)
        .unwrap();
    relay_transfer(&relayer, &built).await.expect("freeze");
    let view = relayer.view().await.expect("read the chain");
    agent.read_feed(&view).expect("read the feed");
    assert!(
        agent.register.iter().any(|e| !e.spent
            && e.note.units > 0
            && e.opening == shielded_notes::domain::note::LockOpening::freeze()),
        "the agent reads the freeze terms from the feed"
    );
    alice.wallet.scan(&view);
    assert_eq!(
        alice.wallet.balance(env.epoch),
        0,
        "a frozen note is not spendable"
    );
    assert!(matches!(
        alice
            .wallet
            .pay(&alice.signer, &view, &env, bob.owner(), bob.vpk(), SHARE),
        Err(ActorError::InsufficientUnits { .. })
    ));

    // The owner path cannot spend it even if the wallet tries: no proof exists.
    if !use_mock_proofs() {
        let frozen = *alice
            .wallet
            .notes
            .iter()
            .find(|n| !n.spent && n.note.units > 0)
            .unwrap();
        let attempt = alice.wallet.transfer(
            &alice.signer,
            &view,
            &env,
            vec![frozen],
            [
                shielded_notes::wallet::Output {
                    owner: bob.owner(),
                    units: 90 * SHARE,
                    opening: shielded_notes::domain::note::LockOpening::NONE,
                    vpk: bob.vpk(),
                },
                shielded_notes::wallet::Output {
                    owner: alice.owner(),
                    units: 0,
                    opening: shielded_notes::domain::note::LockOpening::NONE,
                    vpk: alice.vpk(),
                },
            ],
        );
        let built = attempt.unwrap();
        let err = relay_transfer(&relayer, &built)
            .await
            .expect_err("the circuit rejects spending a frozen note");
        assert!(
            matches!(&err, ClientError::Prover(ProverError::Unsatisfied { assertion, .. }) if assertion == "note is locked"),
            "{err:?}"
        );
    }

    // Release: re-created without the lock. The frozen note is Alice's only
    // note with units, which the agent finds in its register.
    agent.read_feed(&view).expect("read the feed");
    let frozen = agent
        .register
        .iter()
        .find(|e| {
            !e.spent
                && e.note.units > 0
                && e.holder.as_ref().map(Holder::as_str) == Some("INV-ALICE")
        })
        .unwrap()
        .commitment;
    let built = agent
        .claim(&view, &env, frozen, ClaimAction::Release)
        .unwrap();
    relay_transfer(&relayer, &built).await.expect("release");
    let view = relayer.view().await.expect("read the chain");
    alice.wallet.scan(&view);
    assert_eq!(alice.wallet.balance(env.epoch), 90 * SHARE);

    // Seize: re-created for the agent's own owner value.
    agent.read_feed(&view).expect("read the feed");
    let released = agent
        .register
        .iter()
        .find(|e| {
            !e.spent
                && e.note.units > 0
                && e.holder.as_ref().map(Holder::as_str) == Some("INV-ALICE")
        })
        .unwrap()
        .commitment;
    let built = agent
        .claim(
            &view,
            &env,
            released,
            ClaimAction::Seize {
                to: agent.owner(),
                to_vpk: agent.wallet.vpk(),
            },
        )
        .unwrap();
    relay_transfer(&relayer, &built).await.expect("seize");
    let view = relayer.view().await.expect("read the chain");
    alice.wallet.scan(&view);
    agent.read_feed(&view).expect("read the feed");
    assert_eq!(alice.wallet.balance(env.epoch), 0);
    // The seized units, the redeemed ones and the frozen seed. Alice's
    // redemption is still pending, since the agent has not withdrawn it; the
    // seizure is not a redemption.
    assert_eq!(agent.positions().get(AGENT_ID), Some(&(101 * SHARE)));
    let pending = |agent: &TransferAgent| -> Vec<u64> {
        agent.redemptions(&view).iter().map(|r| r.units).collect()
    };
    assert_eq!(pending(&agent), [10 * SHARE]);

    // The chain shows the seizure as a transfer: only the agent's claim
    // records tell it apart. They live in the agent's memory, so a restarted
    // agent needs them back from its own store.
    let records = std::mem::take(&mut agent.claims);
    assert_eq!(
        records.len(),
        4,
        "the seed's freeze, the freeze, the release, the seizure"
    );
    assert_eq!(
        pending(&agent),
        [10 * SHARE, 90 * SHARE],
        "without its records, the seizure would read as a redemption"
    );
    agent.claims = records;
    assert_eq!(pending(&agent), [10 * SHARE]);
    assert_register_reconciles(&h, &mut agent).await;
}

/// Crossing in and out (SPEC, Moving Between Public and Confidential Holdings):
/// a public holder deposits its own shares into its owner value, then withdraws
/// the whole note back to its public address. The withdrawal is signed first and
/// proved later, against roots that moved in between (SPEC, Transaction Plan).
#[tokio::test]
async fn crossing_in_and_out() {
    let mut agent = TransferAgent::new();
    let h = Harness::start(&agent);
    seed(&h, &mut agent).await;
    let mut holder = Investor::new("INV-PUBLIC");
    onboard_and_attest(&h, &mut agent, &[&holder]).await;

    // The holder holds 50 shares publicly: the issuer allowlists its address and
    // mints them there, and the holder approves the pool to pull them.
    let holder_address = h.account(HOLDER);
    let issuer = h.token(AGENT);
    issuer
        .setAllowlisted(holder_address, true)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    issuer
        .mint(holder_address, U256::from(50 * SHARE))
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    h.token(HOLDER)
        .approve(h.deployment.pool, U256::MAX)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    // Crossing in: a deposit from the holder's own address, the funding address
    // the proof binds. At m = 1 the pool pulls 50 shares for 50 units.
    let client = h.client(HOLDER);
    let view = client.view().await.expect("read the chain");
    let env = client.env().await.expect("read the pool");
    let (w, payload) = holder
        .wallet
        .deposit(
            &holder.signer,
            &view,
            &env,
            50 * SHARE,
            to_address(holder_address),
        )
        .unwrap();
    submit_deposit(&client, &w, &payload)
        .await
        .expect("cross in");
    assert_eq!(h.balance(holder_address).await, 0);

    let view = client.view().await.expect("read the chain");
    holder.wallet.scan(&view);
    let note = holder.wallet.spendable(env.epoch)[0];

    // The custody signer approves the withdrawal, which can take hours. The
    // plan holds no root, so the wallet takes the roots only when it proves.
    let pending = holder
        .wallet
        .prepare_withdraw(&env, &note, to_address(holder_address));
    let signature = holder.signer.sign_plan(&pending.plan, &[]).unwrap();

    // Meanwhile the agent attests a new investor and issues, which moves both roots.
    let signed_view = view;
    let late = Investor::new("INV-LATE");
    onboard_and_attest(&h, &mut agent, &[&late]).await;
    aggregate_deposit(&h, &mut agent, 10 * SHARE).await;

    // Crossing out: the wallet finishes the withdrawal against today's roots,
    // with the signature from before, and the whole note pays 50 shares back.
    let view = client.view().await.expect("read the chain");
    let env = client.env().await.expect("read the pool");
    let w = pending.finish(signature, &view, &env).unwrap();
    assert_ne!(w.commitment_root, signed_view.commitments.root());
    assert_ne!(w.attestation_root, signed_view.attestations.root());
    relay_withdraw(&client, &w)
        .await
        .expect("cross out, with roots taken after the signature");
    assert_eq!(h.balance(holder_address).await, u128::from(50 * SHARE));
    assert_register_reconciles(&h, &mut agent).await;
}

/// Whether the pool refused the operation with the expected error.
fn rejected(err: &ClientError, expected: impl Fn(&IShieldedPoolErrors) -> bool) -> bool {
    matches!(err, ClientError::Chain(ChainError::PoolRejected(e)) if expected(e))
}

/// Whether the verifier refused the proof. The generated verifier reverts with
/// `SumcheckFailed` when the public inputs the pool filled in differ from the
/// proof's, rather than returning false to the pool.
fn proof_rejected(err: &ClientError) -> bool {
    matches!(
        err,
        ClientError::Chain(ChainError::ProofRejected(
            IHonkVerifierErrors::SumcheckFailed(_)
        ))
    )
}

fn output(owner: &Investor, units: u64) -> Output {
    Output {
        owner: owner.owner(),
        units,
        opening: LockOpening::NONE,
        vpk: owner.vpk(),
    }
}

/// A register-key rotation (SPEC, Governance and Key Rotation): a transfer
/// signed before the rotation is proved after it with the same signature, since
/// the plan does not cover the feed, and the agent reads the notes created
/// under each key with that key.
#[tokio::test]
async fn register_key_rotation() {
    let mut agent = TransferAgent::new();
    let h = Harness::start(&agent);
    seed(&h, &mut agent).await;
    let mut alice = Investor::new("INV-ALICE");
    let bob = Investor::new("INV-BOB");
    onboard_and_attest(&h, &mut agent, &[&alice, &bob]).await;
    aggregate_deposit(&h, &mut agent, 100 * SHARE).await;
    hand_out(&h, &mut agent, &[(&alice, 100 * SHARE)]).await;

    let relayer = h.client(RELAYER);
    let view = relayer.view().await.expect("read the chain");
    let env = relayer.env().await.expect("read the pool");
    // Alice signs a payment of 40 to Bob before the rotation. `before` is its
    // witness finished under the old register key, as a slow relay would hold it.
    alice.wallet.scan(&view);
    let note = alice.wallet.spendable(env.epoch)[0];
    let pending = alice
        .wallet
        .prepare_transfer(
            &env,
            vec![note],
            [output(&bob, 40 * SHARE), output(&alice, 60 * SHARE)],
        )
        .expect("prepare the transfer");
    let signature = alice
        .signer
        .sign_plan(&pending.plan, &pending.outputs)
        .unwrap();
    let before = pending.clone().finish(signature, &view, &env).unwrap();

    // The rotation: the agent makes a fresh key, the pool takes its public half
    // (`setRegisterKey`, the next version), and only then does the agent keep
    // it, next to the old one, which it still needs for the notes before.
    let rotation = agent.new_register_key();
    let tpk = rotation.public_key;
    chain::set_register_key(&h.provider(AGENT), &h.deployment, &tpk, rotation.version)
        .await
        .expect("rotate the register key");
    agent
        .commit_register_key(rotation)
        .expect("the next version");

    // A proof built for the old key no longer verifies: the pool pins the new one.
    if !use_mock_proofs() {
        let err = relay_transfer(&relayer, &before)
            .await
            .expect_err("a proof for the old register key");
        assert!(proof_rejected(&err), "{err:?}");
    }

    let view = relayer.view().await.expect("read the chain");
    let env = relayer.env().await.expect("read the pool");
    assert_eq!(env.register_key, tpk);
    // The same plan and signature, finished under the new key: the plan covers
    // the outputs, not the feed, so the custody signer is not asked again.
    let built = pending.finish(signature, &view, &env).unwrap();
    relay_transfer(&relayer, &built)
        .await
        .expect("the same signature, proved under the new key");

    // Alice's first note was created under key 0, the payment's outputs under
    // key 1; the agent reads each with its own key.
    agent
        .read_feed(&relayer.view().await.expect("read the chain"))
        .expect("notes under both register keys");
    assert_eq!(agent.positions().get("INV-BOB"), Some(&(40 * SHARE)));
    assert_eq!(agent.positions().get("INV-ALICE"), Some(&(60 * SHARE)));
    assert_register_reconciles(&h, &mut agent).await;
}

/// The policy fallback (SPEC, Public Token Requirements; Multiplier Rules): the
/// issuer keeps its administrative powers over the pool. A forced transfer out
/// that the yield since the last checkpoint covers passes the on-chain check,
/// and only the agent's reconciliation finds it. A larger one halts the pool at
/// the agent's checkpoint, until the shares are returned and governance clears
/// the halt.
#[tokio::test]
async fn outflows_and_the_halt() {
    // `start_with(.., false)`: the pool is not exempt from the issuer's
    // administrative powers, so the issuer can force-transfer shares out of it.
    // Alice holds one 100-share note.
    let mut agent = TransferAgent::new();
    let h = Harness::start_with(&agent, false);
    seed(&h, &mut agent).await;
    let mut alice = Investor::new("INV-ALICE");
    onboard_and_attest(&h, &mut agent, &[&alice]).await;
    aggregate_deposit(&h, &mut agent, 100 * SHARE).await;
    hand_out(&h, &mut agent, &[(&alice, 100 * SHARE)]).await;
    let agent_client = h.client(AGENT);
    // No note changes between these checkpoints, only the pool's shares, so
    // one snapshot of the register's units serves them all.
    let units = agent.total_units();
    let checkpoint = || async {
        chain::checkpoint(&h.provider(AGENT), &h.deployment, B256::ZERO, units)
            .await
            .expect("checkpoint")
    };
    let halted = || async {
        chain::halted(&h.provider(AGENT), &h.deployment)
            .await
            .unwrap()
    };
    // The first checkpoint records m. No outflow yet.
    checkpoint().await;
    assert!(
        agent
            .unexplained_outflows(&agent_client.view().await.expect("read the chain"))
            .is_empty()
    );

    // A day's yield of 1%, then the issuer moves half a percent of the pool's
    // shares out. The agent's scan matches every outflow of the pool against
    // its withdrawals, and this one matches none.
    let pool = h.deployment.pool;
    let issuer = h.token(AGENT);
    let issuer_address = h.account(AGENT);
    issuer
        .reinvest(vec![pool], U256::from(100 * BASIS_POINT))
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    let small = U256::from(h.balance(pool).await / 200);
    issuer
        .forceTransfer(pool, issuer_address, small)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    assert_eq!(
        agent
            .unexplained_outflows(&agent_client.view().await.expect("read the chain"))
            .len(),
        1,
        "the agent finds the forced transfer"
    );
    // The agent checkpoints at once. A day of yield (1%) covers the 0.5%
    // outflow, so the check passes and every note bears the loss.
    checkpoint().await;
    assert!(!halted().await);

    // A forced transfer of 1%, with no yield since the last checkpoint: m falls
    // below what that checkpoint recorded, so the next one latches the halt.
    let large = U256::from(h.balance(pool).await / 100);
    issuer
        .forceTransfer(pool, issuer_address, large)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    assert_eq!(
        agent
            .unexplained_outflows(&agent_client.view().await.expect("read the chain"))
            .len(),
        2
    );
    checkpoint().await;
    assert!(
        halted().await,
        "no yield since the last checkpoint covers it"
    );

    // While the pool is halted, deposits and withdrawals revert, so Alice cannot
    // withdraw; transfers still work.
    let relayer = h.client(RELAYER);
    let view = relayer.view().await.expect("read the chain");
    let env = relayer.env().await.expect("read the pool");
    alice.wallet.scan(&view);
    let note = alice.wallet.spendable(env.epoch)[0];
    let alice_address = h.account(HOLDER);
    issuer
        .setAllowlisted(alice_address, true)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    let w = alice
        .wallet
        .withdraw(&alice.signer, &view, &env, &note, to_address(alice_address))
        .unwrap();
    let err = relay_withdraw(&relayer, &w)
        .await
        .expect_err("no withdrawal while halted");
    assert!(
        rejected(&err, |e| matches!(e, IShieldedPoolErrors::PoolHalted(_))),
        "{err:?}"
    );

    // The issuer returns the shares, and governance clears the halt.
    issuer
        .transfer(pool, small + large)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    chain::clear_halt(&h.provider(AGENT), &h.deployment)
        .await
        .expect("clear the halt");
    assert!(!halted().await);
    let w = alice
        .wallet
        .withdraw(
            &alice.signer,
            &view,
            &relayer.env().await.expect("read the pool"),
            &note,
            to_address(alice_address),
        )
        .unwrap();
    relay_withdraw(&relayer, &w)
        .await
        .expect("withdraw after the halt is cleared");
    // Alice's withdrawal moves shares out too, but the agent matches it to its
    // `Withdraw` event: the count of unexplained outflows stays at two.
    assert_eq!(
        agent
            .unexplained_outflows(&agent_client.view().await.expect("read the chain"))
            .len(),
        2,
        "a withdrawal is not an unexplained outflow"
    );
    assert_register_reconciles(&h, &mut agent).await;
}

/// Time passing (SPEC, Lock; Attestation Registry; Transaction Plan): a holding
/// period ends by itself; a proof regenerated after an epoch boundary reuses its
/// signature, while a relayer cannot swap its payload; two notes merge and the
/// result is withdrawn; and a holder whose attestation lapsed is frozen and
/// seized through the claim path.
#[tokio::test]
async fn holding_periods_epochs_and_lapses() {
    // Alice and Bob subscribe 200 and 100 shares in one hand-out; Alice gets two
    // notes of 100, for the merge below.
    let mut agent = TransferAgent::new();
    let h = Harness::start(&agent);
    seed(&h, &mut agent).await;
    let mut alice = Investor::new("INV-ALICE");
    let mut bob = Investor::new("INV-BOB");
    onboard_and_attest(&h, &mut agent, &[&alice, &bob]).await;
    aggregate_deposit(&h, &mut agent, 300 * SHARE).await;
    let relayer = h.client(RELAYER);

    // Bob's order carries a holding period, ending two epochs from now. His
    // note is created locked, through the claim path, so he never holds it
    // unlocked (SPEC, Subscription, step 3).
    let until = relayer.env().await.expect("read the pool").epoch + 2;
    hand_out_held(
        &h,
        &mut agent,
        &[
            (&alice, 100 * SHARE, None),
            (&alice, 100 * SHARE, None),
            (&bob, 100 * SHARE, Some(until)),
        ],
    )
    .await;
    let view = relayer.view().await.expect("read the chain");
    let env = relayer.env().await.expect("read the pool");
    bob.wallet.scan(&view);
    assert_eq!(bob.wallet.balance(env.epoch), 0, "held from the start");
    agent.read_feed(&view).expect("read the feed");
    assert!(
        agent.register.iter().any(|e| {
            e.holder.as_ref().map(Holder::as_str) == Some("INV-BOB")
                && e.opening == LockOpening::hold(until)
        }),
        "the agent reads the hold from the feed"
    );

    // Two epochs on, the hold's release epoch has come: the wallet counts the
    // note as spendable, and the circuit lets the owner path spend it, since it
    // checks the lock against the public epoch.
    h.advance_epochs(2).await;
    let env = relayer.env().await.expect("read the pool");
    assert_eq!(env.epoch, until);
    assert_eq!(
        bob.wallet.balance(env.epoch),
        100 * SHARE,
        "the holding period ended"
    );
    let built = bob
        .wallet
        .pay(
            &bob.signer,
            &view,
            &env,
            alice.owner(),
            alice.vpk(),
            10 * SHARE,
        )
        .unwrap();
    relay_transfer(&relayer, &built)
        .await
        .expect("spend after the holding period");

    // A proof built in one epoch and submitted in the next is refused; the
    // plan excludes the epoch, so the wallet proves again with the same signature.
    let view = relayer.view().await.expect("read the chain");
    alice.wallet.scan(&view);
    let note = *alice
        .wallet
        .spendable(env.epoch)
        .iter()
        .find(|n| n.note.units == 100 * SHARE)
        .unwrap();
    let pending = alice
        .wallet
        .prepare_transfer(
            &env,
            vec![note],
            [output(&bob, 5 * SHARE), output(&alice, 95 * SHARE)],
        )
        .expect("prepare the transfer");
    let signature = alice
        .signer
        .sign_plan(&pending.plan, &pending.outputs)
        .unwrap();
    let stale = pending.clone().finish(signature, &view, &env).unwrap();
    h.advance_epochs(1).await;
    let err = relay_transfer(&relayer, &stale)
        .await
        .expect_err("a proof for the previous epoch");
    assert!(
        rejected(&err, |e| matches!(e, IShieldedPoolErrors::WrongEpoch(_))),
        "{err:?}"
    );
    let view = relayer.view().await.expect("read the chain");
    let env = relayer.env().await.expect("read the pool");
    let built = pending.finish(signature, &view, &env).unwrap();
    let submission = client::prove_transfer(&prover(), &built)
        .await
        .expect("prove for the new epoch");
    if !use_mock_proofs() {
        // The pool hashes the payload it emits into the public inputs, so a
        // relayer cannot swap it in the submission it was handed.
        let mut swapped = submission.clone();
        if let Submission::Transfer(params) = &mut swapped {
            params.recipientPayload = b"swapped".to_vec().into();
        }
        let err = ClientError::from(
            relayer
                .submit(&swapped)
                .await
                .expect_err("a swapped recipient payload"),
        );
        assert!(proof_rejected(&err), "{err:?}");
    }
    relayer
        .submit(&submission)
        .await
        .expect("proved again for the new epoch, same signature");

    // Two notes merged into one, which is then withdrawn whole.
    let view = relayer.view().await.expect("read the chain");
    alice.wallet.scan(&view);
    let mut notes = alice.wallet.spendable(env.epoch);
    notes.sort_by_key(|n| std::cmp::Reverse(n.note.units));
    let merged = notes[0].note.units + notes[1].note.units;
    let built = alice
        .wallet
        .transfer(
            &alice.signer,
            &view,
            &env,
            vec![notes[0], notes[1]],
            [output(&alice, merged), output(&alice, 0)],
        )
        .unwrap();
    relay_transfer(&relayer, &built)
        .await
        .expect("merge two notes");
    let view = relayer.view().await.expect("read the chain");
    alice.wallet.scan(&view);
    let note = *alice
        .wallet
        .spendable(env.epoch)
        .iter()
        .find(|n| n.note.units == merged)
        .unwrap();
    let alice_address = h.account(HOLDER);
    h.token(AGENT)
        .setAllowlisted(alice_address, true)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    let w = alice
        .wallet
        .withdraw(&alice.signer, &view, &env, &note, to_address(alice_address))
        .unwrap();
    relay_withdraw(&relayer, &w)
        .await
        .expect("withdraw the merged note");
    assert_eq!(h.balance(alice_address).await, u128::from(merged));

    // Every attestation lapses. Bob can no longer move his notes. The agent has
    // revoked him: it renews every other value it attests, not his, then
    // freezes Bob's note in place and seizes it.
    h.advance_epochs(30).await;
    let view = relayer.view().await.expect("read the chain");
    let env = relayer.env().await.expect("read the pool");
    bob.wallet.scan(&view);
    assert!(matches!(
        bob.wallet
            .pay(&bob.signer, &view, &env, alice.owner(), alice.vpk(), SHARE),
        Err(ActorError::NotAttested(_))
    ));
    agent.stop_renewing(bob.owner()).expect("revoke Bob");
    onboard_and_attest(&h, &mut agent, &[]).await;
    let view = relayer.view().await.expect("read the chain");
    let env = relayer.env().await.expect("read the pool");
    assert!(
        view.attestation_of(bob.owner(), env.epoch, env.min_accepted_generation)
            .is_none()
    );
    agent.read_feed(&view).expect("read the feed");
    let lapsed = agent
        .register
        .iter()
        .filter(|e| !e.spent && e.holder.as_ref().map(Holder::as_str) == Some("INV-BOB"))
        .max_by_key(|e| e.note.units)
        .unwrap()
        .clone();
    let built = agent
        .claim(&view, &env, lapsed.commitment, ClaimAction::Freeze)
        .unwrap();
    relay_transfer(&relayer, &built)
        .await
        .expect("freeze a lapsed holder's note");
    let view = relayer.view().await.expect("read the chain");
    agent.read_feed(&view).expect("read the feed");
    let frozen = built.outputs[0].commitment();
    let built = agent
        .claim(
            &view,
            &env,
            frozen,
            ClaimAction::Seize {
                to: agent.owner(),
                to_vpk: agent.wallet.vpk(),
            },
        )
        .unwrap();
    relay_transfer(&relayer, &built)
        .await
        .expect("seize the lapsed holder's note");
    let view = relayer.view().await.expect("read the chain");
    agent.read_feed(&view).expect("read the feed");
    // A seizure is not a redemption. Bob's position is his 100, less the 10 he
    // paid Alice and the seized note, plus the 5 she paid him.
    assert!(agent.redemptions(&view).is_empty());
    assert_eq!(
        agent.positions().get("INV-BOB").copied().unwrap_or(0),
        100 * SHARE - 10 * SHARE + 5 * SHARE - lapsed.note.units
    );
    assert_register_reconciles(&h, &mut agent).await;
}

/// Onboarding (SPEC, Onboarding, steps 3 to 5): the investor cap counts every
/// investor attested or holding a note, including one whose attestation lapsed
/// and whose note the agent has not read yet; units sent to a padding value are
/// reported as the padding's; and the period's renewals take the standing
/// padding with the investors, leave out a newcomer past the cap, and go out
/// in parts of 16.
#[tokio::test]
async fn onboarding_caps_and_batches() {
    // A cap of two investors. Alice and Bob are attested and Alice holds a
    // 100-share note; Carol, the third, comes later.
    let mut agent = TransferAgent::new();
    agent.max_investors = Some(2);
    let h = Harness::start(&agent);
    seed(&h, &mut agent).await;
    let mut alice = Investor::new("INV-ALICE");
    let bob = Investor::new("INV-BOB");
    let carol = Investor::new("INV-CAROL");
    onboard_and_attest(&h, &mut agent, &[&alice, &bob]).await;
    aggregate_deposit(&h, &mut agent, 100 * SHARE).await;
    hand_out(&h, &mut agent, &[(&alice, 100 * SHARE)]).await;
    let relayer = h.client(RELAYER);

    // Alice pays Bob, then sends units to one of the agent's padding values.
    // The agent does not read the feed in between.
    let (padding, padding_vpk) =
        (agent.padding[0].owner(), agent.padding[0].view.public_key());
    for (to, vpk, units) in [
        (bob.owner(), bob.vpk(), 10 * SHARE),
        (padding, padding_vpk, 5 * SHARE),
    ] {
        let view = relayer.view().await.expect("read the chain");
        let env = relayer.env().await.expect("read the pool");
        alice.wallet.scan(&view);
        let built = alice
            .wallet
            .pay(&alice.signer, &view, &env, to, vpk, units)
            .unwrap();
        relay_transfer(&relayer, &built).await.expect("alice pays");
    }

    // A month on, every attestation has lapsed. Alice and Bob still hold notes,
    // so both still count and Carol is refused, though the agent has not read
    // Bob's note: the cap check reads the feed first.
    h.advance_epochs(31).await;
    let client = h.client(AGENT);
    let view = client.view().await.expect("read the chain");
    let env = client.env().await.expect("read the pool");
    let carol_owner = carol.register_with(&mut agent, &env);
    let public = holding_publicly(&h, &agent).await;
    assert!(matches!(
        agent.check_cap(&view, &env, &[carol_owner], &public),
        Err(ActorError::CapReached { cap: 2 })
    ));
    assert_eq!(
        agent.positions().get(PADDING_ID),
        Some(&(5 * SHARE)),
        "units sent to a padding value are reported as such"
    );

    // The period's renewals: the agent's own value, Alice, Bob and the 29
    // standing padding values from the two batches so far, 32 in all, which
    // fill two parts without new padding. Carol is left out, past the cap, and
    // stays due.
    let padding_values = agent.padding.len();
    assert_eq!(padding_values, 29);
    let view = client.view().await.expect("read the chain");
    assert_eq!(attest_due(&h, &mut agent).await, [carol_owner]);
    assert_eq!(agent.padding.len(), padding_values);
    let after = client.view().await.expect("read the chain");
    let renewed = &after.attestation_records[view.attestation_records.len()..];
    assert_eq!(renewed.len(), 2 * shielded_notes::chain::ATTESTATION_PART);
    assert!(
        agent
            .padding
            .iter()
            .all(|k| renewed.iter().any(|r| r.owner == k.owner())),
        "every standing padding value is renewed"
    );
    assert_register_reconciles(&h, &mut agent).await;
}

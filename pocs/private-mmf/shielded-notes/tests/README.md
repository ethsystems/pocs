# Tests

- `flows.rs`: the SPEC's flows end to end, against a local chain, with real or mock proofs.
- `common/`: their harness: the chain and deployment, the investors, and the steps the flows share (onboarding, the aggregate deposit, the hand-out).
- `tree_parity.rs`: the Rust tree against the contracts' LeanIMT.
- `bench.rs`: the costs per operation, ignored by default.

How to run them is in the [README](../README.md#test).

## The flows, call by call

Each flow in `flows.rs`, drawn as the calls each actor makes. Who holds what, and what the chain sees:
- **Investors:** each one's custody signer holds `sk`; its wallet holds `pk`, `nk` and `vk`.
- **Transfer agent:** its own owner keys (it holds notes too, for issuance and redemption), the claim key, the register key, and each investor's `pk`, `nk` and `vpk`.
- **Relayer:** nobody's keys. It submits what the owner of an operation proved and pays the gas. The SPEC has the agent relay; here it is a separate account.
- **Chain:** commitments, nullifiers, attested owner values, encrypted payloads and feeds, and the units at the edges (deposits, withdrawals). Never who holds which note, nor a transfer's amount.

In the harness, the agent's account is also the deployer, the issuer and governance. Every actor first reads the chain with `Client::view` and `Client::env`, left out below. Test helpers are in brackets. The harness runs every actor in one process, so `Investor::register_with` also makes the agent's two onboarding calls. The first diagram draws the setup in full; the others start from it in a note.

### `subscription_transfer_yield_and_redemption`

A subscription with a hand-out tree, a transfer between investors, a reinvestment, a partial redemption and the checkpoint.

```mermaid
sequenceDiagram
    participant I as Investors<br/>(Wallet, custody signer)
    participant A as Transfer agent<br/>(TransferAgent)
    participant R as Relayer<br/>(Client)
    participant C as Chain<br/>(pool, registry, token)

    Note over I,C: Setup
    A->>A: TransferAgent::new(): own owner keys, claim key, register key, salt key
    A->>C: deploy (DeployLocal.s.sol) with the claim key's hash and the register key [Harness::start]
    I->>I: OwnerKeys::random().split(): sk to the signer, the rest to Wallet::new [Investor::new]

    Note over I,C: Seed [seed]: the onboarding below with no investors, a 1-share deposit from agent.seed_deposit,<br/>then agent.freeze_seed, proved and relayed like a transfer

    Note over I,C: Onboarding [onboard_and_attest, Investor::register_with]
    loop each investor
        I->>A: KYC, off-chain
        A->>A: agent.verify_investor(id, jurisdiction)
        I->>I: wallet.registration(&env, id) returns Registration
        I->>I: signer.sign_registration(&registration) returns signature
        I->>A: registration, signature and nk, off-chain
        A->>A: agent.onboard(id, &env, &registration, &signature, &nk) returns owner value
    end
    A->>A: [attest_due] agent.attestation_batch(&view, &env, &public, generation): every value due,<br/>caps checked, fresh padding to a multiple of 16, shuffled, the period's expiry
    A->>C: chain::add_attestations(&batch): AttestationRegistry.addAttestations(part, expiresAt, generation), per part of 16

    Note over I,C: Day 1: subscription [aggregate_deposit]
    A->>C: as issuer: token.setAllowlisted(agent, true), token.mint(agent, 600)
    A->>C: token.approve(pool, MAX)
    A->>A: agent.read_feed(&view)
    A->>A: agent.wallet.deposit(&agent.signer, &view, &env, 600, agent) returns witness, payload
    A->>A: client::prove_deposit(&prover, &witness, &payload) returns Submission
    A->>C: Client::submit: ShieldedPool.deposit(p), which calls token.safeTransferFrom(agent, pool, 600)

    Note over I,C: Hand-out [hand_out]
    A->>A: agent.plan_hand_out(&orders) returns the tree: (1) Alice 100 + an agent note of 500, (2) that note into Bob 200 + Carol 300
    loop two transfers: (1) Alice 100, (2) Bob 200 + Carol 300
        A->>A: agent.hand_out_transfer(&view, &env, note, outputs) returns BuiltTransfer
        A->>A: client::prove_transfer(&prover, &built) returns Submission [relay_transfer]
        A->>R: Submission
        R->>C: Client::submit: ShieldedPool.transfer(p)
    end
    I->>I: wallet.scan(&view), wallet.balance(epoch)
    A->>A: agent.read_feed(&view), agent.positions()
    A->>A: agent.reconcile(&view, chain::pool_totals(..)) [assert_register_reconciles]

    Note over I,C: Alice pays Bob 40
    I->>I: Bob gives Alice bob.owner() and bob.vpk(), off-chain, like an address
    I->>I: alice.wallet.pay(&alice.signer, &view, &env, bob.owner(), bob.vpk(), 40) returns BuiltTransfer<br/>(prepare_transfer, signer.sign_plan, finish)
    I->>I: client::prove_transfer(&prover, &built) returns Submission [relay_transfer]
    I->>R: Submission
    R->>C: Client::submit: ShieldedPool.transfer(p)
    I->>I: alice.wallet.scan(&view), bob.wallet.scan(&view)
    A->>A: agent.read_feed(&view)

    Note over I,C: Reinvestment
    A->>C: as issuer: token.reinvest([pool], 1 percent)

    Note over I,C: Carol redeems 80
    I->>I: carol.wallet.pay(&carol.signer, &view, &env, agent.owner(), agent.wallet.vpk(), 80)
    I->>I: client::prove_transfer(&prover, &built) returns Submission [relay_transfer]
    I->>R: Submission
    R->>C: Client::submit: ShieldedPool.transfer(p)
    A->>A: agent.read_feed(&view), agent.redemptions(&view) returns Carol, 80

    Note over I,C: End of day
    A->>A: agent.wallet.withdraw(&agent.signer, &view, &env, &note, agent) returns witness
    A->>A: client::prove_withdraw(&prover, &witness) returns Submission [relay_withdraw]
    A->>C: Client::submit: ShieldedPool.withdraw(p), which sends 80.8 shares to the agent
    A->>C: as issuer: token.burn(agent, 80.8), Carol's cash paid off-chain
    A->>A: agent.redemptions(&view) returns none
    A->>A: agent.reconcile(&view, chain::pool_totals(..)) [assert_register_reconciles]
    A->>C: chain::checkpoint: ShieldedPool.checkpoint(agent.register_hash(epoch), agent.total_units())
```

### `busy_four_days_with_several_flows`

Four days with two investors, Bob holding two owner values: subscriptions, yield at an uneven rate, a payment, a crossing in, a freeze and its release, a redemption that waits overnight, and a crossing out. Each day ends with [`close_the_day`]: the pool's counters ([`assert_pool`]), the positions, reconciliation and a checkpoint.

```mermaid
sequenceDiagram
    participant I as Investors<br/>(Wallet, custody signer)
    participant A as Transfer agent<br/>(TransferAgent)
    participant R as Relayer<br/>(Client)
    participant C as Chain<br/>(pool, registry, token)

    Note over I,C: Setup as in the subscription flow, then agent.max_investors = Some(2).<br/>Investor::new for Alice, and twice with INV-BOB for Bob's two owner values

    Note over I,C: Day 1
    A->>A: [onboard_and_attest] Alice and Bob's first owner value: verify_investor, onboard, attestation_batch
    A->>C: chain::add_attestations: AttestationRegistry.addAttestations
    A->>C: [aggregate_deposit] 300: token.mint, ShieldedPool.deposit
    A->>A: [hand_out] one transfer: agent.hand_out_transfer, client::prove_transfer
    A->>R: Submission
    R->>C: Client::submit: ShieldedPool.transfer(p)
    A->>A: [close_the_day]: agent.read_feed, agent.positions, agent.reconcile, remainder 0
    A->>C: chain::checkpoint: ShieldedPool.checkpoint(agent.register_hash(epoch), agent.total_units())

    Note over I,C: Day 2
    A->>C: [advance_epochs], then as issuer [reinvest]: token.reinvest([pool], 37 basis points)
    A->>A: [onboard_and_attest] Bob's second owner value, in a batch of its own: the cap counts Bob once
    A->>C: chain::add_attestations: AttestationRegistry.addAttestations
    I->>I: alice.wallet.pay(&alice.signer, &view, &env, bob_b.owner(), bob_b.vpk(), 33.333333), client::prove_transfer
    I->>R: Submission
    R->>C: Client::submit: ShieldedPool.transfer(p)
    A->>C: as issuer: token.setAllowlisted(alice_public, true), token.mint(alice_public, 50)
    I->>C: from alice_public: token.approve(pool, MAX)
    A->>A: agent.register_public_holder(alice_public, INV-ALICE)
    I->>I: alice.wallet.deposit(&alice.signer, &view, &env, 40, alice_public), client::prove_deposit
    I->>C: Client::submit from alice_public: ShieldedPool.deposit(p), which pulls ceil(40 * m / S) shares
    A->>A: [close_the_day]: remainder above 0
    A->>C: ShieldedPool.checkpoint

    Note over I,C: Day 3
    A->>C: [advance_epochs], token.reinvest([pool], 37 basis points)
    A->>A: agent.claim(&view, &env, bob_b's note, ClaimAction::Freeze), client::prove_transfer
    A->>R: Submission
    R->>C: Client::submit: ShieldedPool.transfer(p)
    I->>I: bob_a.wallet.pay(&bob_a.signer, &view, &env, agent.owner(), agent.wallet.vpk(), 50), client::prove_transfer
    I->>R: Submission
    R->>C: Client::submit: ShieldedPool.transfer(p)
    A->>A: agent.read_feed, agent.redemptions(&view) returns Bob, 50
    A->>A: [close_the_day]
    A->>C: ShieldedPool.checkpoint

    Note over I,C: Day 4
    A->>C: [advance_epochs], token.reinvest([pool], 37 basis points)
    A->>A: agent.wallet.withdraw(&agent.signer, &view, &env, &redemption_note, agent), client::prove_withdraw
    A->>C: Client::submit: ShieldedPool.withdraw(p), which pays floor(50 * m / S) to the agent
    A->>C: as issuer: token.burn(agent, paid), Bob's cash paid off-chain
    A->>C: as issuer: token.setAllowlisted(bob_public, true)
    A->>A: agent.register_public_holder(bob_public, INV-BOB)
    I->>I: bob_a.wallet.withdraw(&bob_a.signer, &view, &env, &note, bob_public), client::prove_withdraw
    I->>R: Submission
    R->>C: Client::submit: ShieldedPool.withdraw(p), which pays floor(150 * m / S) to bob_public
    A->>A: agent.claim(&view, &env, the frozen note, ClaimAction::Release), client::prove_transfer
    A->>R: Submission
    R->>C: Client::submit: ShieldedPool.transfer(p)
    A->>A: [close_the_day]
    A->>C: ShieldedPool.checkpoint

    Note over I,C: The cap
    I->>A: Carol's registration [Investor::register_with]: verify_investor, onboard
    A->>A: agent.check_cap(&view, &env, &[carol], &public) returns CapReached, cap 2
```

### `claims_freeze_release_and_seize`

The claim path: a freeze that loses the race to the holder's redemption, then a freeze, a release and a seizure, all of one note of Alice's.

```mermaid
sequenceDiagram
    participant I as Investors<br/>(Wallet, custody signer)
    participant A as Transfer agent<br/>(TransferAgent)
    participant R as Relayer<br/>(Client)
    participant C as Chain<br/>(pool, registry, token)

    Note over I,C: Setup as in the subscription flow: Alice and Bob onboarded, a 100-share deposit handed out to Alice

    Note over I,C: A race
    A->>A: agent.claim(&view, &env, alice_note, ClaimAction::Freeze) returns late
    I->>I: alice.wallet.pay(&alice.signer, &view, &env, agent.owner(), agent.wallet.vpk(), 10), client::prove_transfer
    I->>R: Submission
    R->>C: Client::submit: ShieldedPool.transfer(p), Alice redeems first
    A->>A: client::prove_transfer(&prover, &late) returns Submission
    A->>R: Submission
    R->>C: Client::submit: ShieldedPool.transfer(p) reverts, NullifierSpent
    A->>A: agent.read_feed drops the lost claim, agent.redemptions(&view) returns Alice, 10

    Note over I,C: Freeze
    A->>A: agent.claim(&view, &env, alice_note, ClaimAction::Freeze), client::prove_transfer
    A->>R: Submission
    R->>C: Client::submit: ShieldedPool.transfer(p)
    I->>I: alice.wallet.scan: balance 0, and alice.wallet.pay returns InsufficientUnits
    I->>I: with real proofs: alice.wallet.transfer of the frozen note, then client::prove_transfer fails, note is locked

    Note over I,C: Release
    A->>A: agent.claim(&view, &env, frozen, ClaimAction::Release), client::prove_transfer
    A->>R: Submission
    R->>C: Client::submit: ShieldedPool.transfer(p)
    I->>I: alice.wallet.scan: balance 90

    Note over I,C: Seize
    A->>A: agent.claim(&view, &env, released, ClaimAction::Seize to agent.owner()), client::prove_transfer
    A->>R: Submission
    R->>C: Client::submit: ShieldedPool.transfer(p)
    A->>A: agent.positions: the agent holds 101, agent.redemptions(&view) returns Alice, 10 only
    A->>A: without agent.claims, its claim records, agent.redemptions would count the seizure too
    A->>A: [assert_register_reconciles]
```

### `crossing_in_and_out`

A public holder deposits its own shares, then withdraws the note again, signed before the roots move and proved after.

```mermaid
sequenceDiagram
    participant I as Investors<br/>(Wallet, custody signer)
    participant A as Transfer agent<br/>(TransferAgent)
    participant R as Relayer<br/>(Client)
    participant C as Chain<br/>(pool, registry, token)

    Note over I,C: Setup as in the subscription flow: the holder (INV-PUBLIC) onboarded, nothing handed out

    A->>C: as issuer: token.setAllowlisted(holder, true), token.mint(holder, 50)
    I->>C: from the holder's address: token.approve(pool, MAX)
    I->>I: holder.wallet.deposit(&holder.signer, &view, &env, 50, holder), client::prove_deposit [submit_deposit]
    I->>C: Client::submit from the holder's address: ShieldedPool.deposit(p), which pulls 50 shares
    I->>I: holder.wallet.scan(&view)
    I->>I: holder.wallet.prepare_withdraw(&env, &note, holder) returns PendingWithdraw
    I->>I: holder.signer.sign_plan(&pending.plan, &[]) returns signature

    Note over I,C: Meanwhile, the roots move
    A->>A: [onboard_and_attest] a new investor
    A->>C: chain::add_attestations: AttestationRegistry.addAttestations
    A->>C: [aggregate_deposit] 10: ShieldedPool.deposit

    I->>I: pending.finish(signature, &view, &env) against today's roots, client::prove_withdraw [relay_withdraw]
    I->>C: Client::submit from the holder's address: ShieldedPool.withdraw(p), which pays 50 shares
    A->>A: [assert_register_reconciles]
```

### `register_key_rotation`

A payment signed before a register-key rotation, proved after it with the same signature, and read by the agent under each key.

```mermaid
sequenceDiagram
    participant I as Investors<br/>(Wallet, custody signer)
    participant A as Transfer agent<br/>(TransferAgent)
    participant R as Relayer<br/>(Client)
    participant C as Chain<br/>(pool, registry, token)

    Note over I,C: Setup as in the subscription flow: Alice and Bob onboarded, 100 handed out to Alice

    I->>I: alice.wallet.prepare_transfer(&env, vec![note], 40 to Bob and 60 to Alice) returns PendingTransfer
    I->>I: alice.signer.sign_plan(&pending.plan, &pending.outputs) returns signature
    I->>I: pending.clone().finish(signature, &view, &env) returns before, under register key 0

    A->>A: agent.new_register_key() returns rotation
    A->>C: chain::set_register_key: ShieldedPool.setRegisterKey(x, y, version)
    A->>A: agent.commit_register_key(rotation)

    I->>I: with real proofs: client::prove_transfer(&prover, &before)
    I->>R: Submission
    R->>C: Client::submit: ShieldedPool.transfer(p) reverts, the verifier refuses it under key 1
    I->>I: pending.finish(signature, &view, &env) under key 1, client::prove_transfer
    I->>R: Submission
    R->>C: Client::submit: ShieldedPool.transfer(p)
    A->>A: agent.read_feed: Alice's note under key 0, the payment's outputs under key 1
    A->>A: agent.positions, [assert_register_reconciles]
```

### `outflows_and_the_halt`

The policy fallback: the issuer keeps its powers over the pool. A forced transfer out that the yield covers is found only by the agent; a larger one halts the pool until the shares are returned and governance clears the halt.

```mermaid
sequenceDiagram
    participant I as Investors<br/>(Wallet, custody signer)
    participant A as Transfer agent<br/>(TransferAgent)
    participant R as Relayer<br/>(Client)
    participant C as Chain<br/>(pool, registry, token)

    Note over I,C: Setup as in the subscription flow, but with Harness::start_with(&agent, false):<br/>the pool is not exempt from the issuer's powers. Alice onboarded, 100 handed out to her

    A->>C: chain::checkpoint: ShieldedPool.checkpoint(0, units), which records m
    A->>A: agent.unexplained_outflows(&view) returns none
    A->>C: as issuer: token.reinvest([pool], 100 basis points)
    A->>C: as issuer: token.forceTransfer(pool, issuer, half a percent of B)
    A->>A: agent.unexplained_outflows(&view) returns one
    A->>C: ShieldedPool.checkpoint: m is still above its record, no halt
    A->>C: as issuer: token.forceTransfer(pool, issuer, 1% of B)
    A->>A: agent.unexplained_outflows(&view) returns two
    A->>C: ShieldedPool.checkpoint: m fell below its record, which latches the halt [chain::halted]

    A->>C: as issuer: token.setAllowlisted(alice_public, true)
    I->>I: alice.wallet.withdraw(&alice.signer, &view, &env, &note, alice_public), client::prove_withdraw [relay_withdraw]
    I->>R: Submission
    R->>C: Client::submit: ShieldedPool.withdraw(p) reverts, PoolHalted

    A->>C: as issuer: token.transfer(pool, both amounts)
    A->>C: as governance: chain::clear_halt: ShieldedPool.clearHalt()
    I->>I: alice.wallet.withdraw again, client::prove_withdraw
    I->>R: Submission
    R->>C: Client::submit: ShieldedPool.withdraw(p)
    A->>A: agent.unexplained_outflows(&view) still returns two, [assert_register_reconciles]
```

### `holding_periods_epochs_and_lapses`

Time passing: a holding period that ends by itself, a proof refused across an epoch boundary and proved again with the same signature, a merge and a withdrawal, and a holder whose attestation lapsed, frozen and seized.

```mermaid
sequenceDiagram
    participant I as Investors<br/>(Wallet, custody signer)
    participant A as Transfer agent<br/>(TransferAgent)
    participant R as Relayer<br/>(Client)
    participant C as Chain<br/>(pool, registry, token)

    Note over I,C: Setup as in the subscription flow: Alice and Bob onboarded, a 300-share deposit

    Note over I,C: A holding period
    A->>A: [hand_out_held] two transfers, agent.hand_out_transfer: the second, with Bob's output locked by LockOpening::hold(until), through the claim path
    A->>R: Submission, twice
    R->>C: Client::submit: ShieldedPool.transfer(p), twice
    I->>I: bob.wallet.scan: balance 0, held from the start
    A->>A: agent.read_feed: the hold, from the feed
    A->>C: [advance_epochs] 2
    I->>I: bob.wallet.pay(&bob.signer, &view, &env, alice.owner(), alice.vpk(), 10), client::prove_transfer
    I->>R: Submission
    R->>C: Client::submit: ShieldedPool.transfer(p)

    Note over I,C: An epoch boundary
    I->>I: alice.wallet.prepare_transfer(5 to Bob, 95 to Alice), alice.signer.sign_plan, pending.finish returns stale
    A->>C: [advance_epochs] 1
    I->>R: stale's Submission
    R->>C: Client::submit: ShieldedPool.transfer(p) reverts, WrongEpoch
    I->>I: pending.finish(signature, &view, &env) for the new epoch, client::prove_transfer
    I->>R: Submission
    R->>C: with real proofs, a copy with a swapped recipient payload reverts: the verifier refuses it
    R->>C: Client::submit: ShieldedPool.transfer(p)

    Note over I,C: A merge and a withdrawal
    I->>I: alice.wallet.transfer(&alice.signer, &view, &env, two notes, into one), client::prove_transfer
    I->>R: Submission
    R->>C: Client::submit: ShieldedPool.transfer(p)
    A->>C: as issuer: token.setAllowlisted(alice_public, true)
    I->>I: alice.wallet.withdraw(&alice.signer, &view, &env, &merged, alice_public), client::prove_withdraw
    I->>R: Submission
    R->>C: Client::submit: ShieldedPool.withdraw(p)

    Note over I,C: Lapses
    A->>C: [advance_epochs] 30: every attestation lapses
    I->>I: bob.wallet.pay returns NotAttested
    A->>A: agent.stop_renewing(bob.owner()): the agent revokes Bob
    A->>A: [onboard_and_attest] with no investors: the agent renews everything else it attests
    A->>C: chain::add_attestations: AttestationRegistry.addAttestations
    A->>A: agent.claim(&view, &env, Bob's note, ClaimAction::Freeze), client::prove_transfer
    A->>R: Submission
    R->>C: Client::submit: ShieldedPool.transfer(p)
    A->>A: agent.claim(&view, &env, frozen, ClaimAction::Seize to agent.owner()), client::prove_transfer
    A->>R: Submission
    R->>C: Client::submit: ShieldedPool.transfer(p)
    A->>A: agent.redemptions(&view) returns none, agent.positions, [assert_register_reconciles]
```

### `onboarding_caps_and_batches`

The investor cap counting holders whose attestation lapsed, units sent to a padding value, and the period's renewals: the standing padding with the investors, a newcomer past the cap left out, two parts of 16.

```mermaid
sequenceDiagram
    participant I as Investors<br/>(Wallet, custody signer)
    participant A as Transfer agent<br/>(TransferAgent)
    participant R as Relayer<br/>(Client)
    participant C as Chain<br/>(pool, registry, token)

    Note over I,C: Setup as in the subscription flow, with agent.max_investors = Some(2):<br/>Alice and Bob onboarded, 100 handed out to Alice

    loop 10 to Bob, then 5 to a padding value (agent.padding[0])
        I->>I: alice.wallet.pay(&alice.signer, &view, &env, to, vpk, units), client::prove_transfer
        I->>R: Submission
        R->>C: Client::submit: ShieldedPool.transfer(p)
    end
    Note over A: the agent does not read the feed in between

    A->>C: [advance_epochs] 31: every attestation lapses
    I->>A: Carol's registration [Investor::register_with]: verify_investor, onboard
    A->>A: [holding_publicly], agent.check_cap(&view, &env, &[carol], &public) returns CapReached, cap 2
    A->>A: agent.positions: PADDING_ID holds 5

    A->>A: [attest_due] agent.attestation_batch: the renewals of the agent's value, Alice, Bob and 29 padding values;<br/>Carol in over_cap
    A->>C: chain::add_attestations: two AttestationRegistry.addAttestations transactions of 16
    A->>A: [assert_register_reconciles]
```

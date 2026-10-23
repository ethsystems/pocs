# Shielded Notes: Confidential MMF Shares in an Omnibus Pool

> **Status:** In Progress
> **Privacy primitive:** confidential fund shares held as notes in a single-fund shielded pool that holds the fund's existing permissioned token, with spends authorized by a custody signature checked in-circuit and a register feed to the transfer agent bound in-circuit.

The configuration of the [Private Money Market Fund](../README.md) group that is built end to end. It builds on [shielded-pool-compliance](../../private-payment/shielded-pool-compliance/), whose code it started from.

- Notes hold units. A multiplier derived from the pool's own token balance carries the fund's daily reinvestment to every note without touching it.
- The transfer agent is the single attester. It issues with one public aggregate deposit a day and shielded hand-outs, redeems when holders transfer notes to it, and freezes or seizes through a claim path that looks like any other transfer on-chain.
- Every spend needs an ECDSA secp256k1 signature over a transaction plan, verified in-circuit, so sign-only HSM and MPC custody works.
- Every new note's opening is encrypted to the transfer agent's register key in-circuit, so the agent can rebuild its register from the chain.

[SPEC.md](SPEC.md) is authoritative. Trust assumptions, the threat model and the guarantees are in its [Security Model](SPEC.md#security-model).

## Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) 1.95.0, edition 2024, pinned in `rust-toolchain.toml`. Install it with rustup, and make sure rustup's `cargo` comes first on `PATH`: a `cargo` installed another way, for example with Homebrew, ignores the pin.
- [Foundry](https://getfoundry.sh/) (`forge`, `anvil`).
- [Nargo](https://noir-lang.org/docs/getting_started/noir_installation) 1.0.0-beta.21: `noirup -v 1.0.0-beta.21`.
- [Barretenberg](https://github.com/AztecProtocol/aztec-packages/tree/master/barretenberg) `bb` 5.0.0-nightly.20260324, only for `scripts/generate-verifiers.sh`: `bbup -v 5.0.0-nightly.20260324`. Proving links `libbarretenberg` in-process instead of spawning `bb`. The first `cargo build` downloads that static library from the Barretenberg GitHub releases (`BB_LIB_DIR` points it at a local build), and the prover downloads the part of the BN254 CRS it needs into `~/.bb-crs`, the cache `bb` uses (`BB_CRS_PATH` overrides).
- Python 3, only for the removal checks in `scripts/`.

Check the installed versions with `nargo --version` and `bb --version`. `noirup --version` and `bbup --version` do not print a version: without a value, they install the latest release.

## Build

```bash
cd pocs/private-mmf/shielded-notes
forge soldeer install
(cd circuits && nargo compile --workspace)
forge build
cargo build
```

`forge soldeer install` fills `dependencies/`, which git ignores. If `forge` reports "Unable to resolve imports", the directory is incomplete: remove it and run `forge soldeer install` again.

## Test

```bash
(cd circuits && nargo test --workspace)                 # 113 circuit tests
forge test                                              # 125 contract tests
cargo test --lib --features test-mocks                  # 74 unit tests
cargo test --release --test tree_parity                 # the Rust tree against LeanIMT
cargo test --release --test flows -- --test-threads=1   # 8 end-to-end flows, real proofs
```

The costs per operation (see [Costs](#costs)) come from an ignored test, with real proofs:

```bash
cargo test --release --test bench -- --ignored --nocapture
```

Each end-to-end flow spawns its own `anvil`, deploys the stack into it with `forge script`, and drives the transfer agent and the investors' wallets against it. No node needs to be running beforehand. Every operation carries a real UltraHonk proof, checked on-chain by the generated verifiers. `--test-threads=1` runs the flows one after another, so each proof gets the whole CPU.

Every flow first seeds the pool, as a deployment does: before any investor's owner value is attested, the transfer agent attests its own, padded with owner values whose keys it holds, deposits one share and freezes it, so the pool's units never return to zero. The pool itself takes an empty pool's first deposit from the agent only.

Each key stays with its holder, as in the SPEC's Key Model. An investor's spend key is held by its signer, apart from the wallet, which receives only signatures. The agent receives `pk`, `nk` and `vpk`; the custody signer signs the registration with `nk`'s hash and never sees `nk`. The owner of each operation proves it, and the relayer receives only the pool call's parameters.

- `subscription_transfer_yield_and_redemption`: onboarding, an aggregate deposit and its hand-out tree, a transfer between investors, a reinvestment, a partial redemption, and a checkpoint.
- `claims_freeze_release_and_seize`: the claim path: a freeze that loses the race to the holder's redemption, which still counts as one; then a freeze, a release and a seizure to the agent, which the agent's claim records keep from reading as a redemption. With real proofs, the owner's attempt to spend the frozen note fails on the lock.
- `crossing_in_and_out`: a public holder deposits its own shares and withdraws them again. The withdrawal is signed first and proved later, against roots that moved in between, as with a custody approval that takes hours.
- `register_key_rotation`: a transfer signed before the agent rotates its register key is proved after it with the same signature, and the agent reads the notes created under each key. With real proofs, a proof built for the old key is refused.
- `outflows_and_the_halt`: the issuer keeps its administrative powers over the pool. A forced transfer out that the yield covers passes the on-chain check and is found by the agent's reconciliation; a larger one halts the pool at the agent's checkpoint, until the shares are returned and governance clears the halt.
- `holding_periods_epochs_and_lapses`: a note handed out with a holding period, locked from the start through the claim path, which ends by itself; a proof refused in the next epoch and proved again with the same signature; two notes merged and withdrawn; and a holder whose attestation lapsed, frozen and seized through the claim path. With real proofs, a relayer's swapped payload is refused.
- `onboarding_caps_and_batches`: the investor cap counting a holder whose attestation lapsed and whose note the agent has not read yet; units sent to a padding value, reported as such; the period's renewals, which take the standing padding with the investors, leave out a newcomer past the cap, and go out in two parts of 16.
- `busy_four_days_with_several_flows`: two investors over four days, one of them with two owner values attested in different batches. Subscriptions, yield at an uneven rate, a payment, a crossing in, a freeze and its release, a redemption that waits overnight, and a crossing out, with the pool's counters, the positions, reconciliation and a checkpoint at the end of each day. It ends with a third investor refused by a cap of two.

Each flow ends with the transfer agent's reconciliation: its register accounts for every unit in the pool, and the actors' commitment and attestation trees match the pool's and the registry's roots. [tests/README.md](tests/README.md) draws each flow as a sequence diagram of the calls each actor makes.

`SN_USE_MOCK_PROOFS=1` swaps the in-process prover for `MockProver` and, from the same variable, tells the deploy script to install mock verifiers, so the two cannot disagree. A mock verifier (`BindingMockVerifier`) accepts only the mock prover's proof for exactly the public inputs the pool assembles, so a public input that Rust and the pool lay out or fill in differently fails under mocks too. It needs `--features test-mocks`, which compiles `MockProver` in, and runs in seconds:

```bash
SN_USE_MOCK_PROOFS=1 cargo test --release --test flows --features test-mocks
```

Under mocks the contract-level checks and the public inputs still hold, and the circuit-level ones become vacuous. `forge test` uses accepting mock verifiers throughout; the generated verifiers are exercised by the end-to-end flows with real proofs.

### Removal checks

```bash
python3 scripts/mutate-circuits.py
python3 scripts/mutate-contracts.py
```

The first removes or weakens one constraint at a time in a copy of `circuits/`, runs the affected tests, and reports whether a test caught the change. Every constraint whose removal matters must be caught; the script lists the expected survivors and why, and exits non-zero on any other. The second does the same for the checks in the pool, the registry, the composite verifier and the public-input library, in a copy of the Foundry project, where none is expected to survive. Each takes several minutes.

## Costs

On an Apple M1 Pro, with real proofs and the generated verifiers; the method and the attestation batches are in [Measured Costs](SPEC.md#measured-costs).

| Operation | Gates | Proving | Gas |
|-----------|-------|---------|-----|
| Deposit | 81,073 | 1.3 s | 2.96M |
| Transfer, owner or claim path | 200,699 | 2.7 s | 3.17M |
| Withdraw | 103,539 | 1.4 s | 2.81M |
| Checkpoint | | | 38k |

Verification is about nine-tenths of each operation's gas. The transfer's paths cost the same when measured from one chain state; a transaction's gas otherwise varies with where its notes land in the tree.

## Changing the circuits

After any change to a circuit:

1. Regenerate the Solidity verifiers: `bash scripts/generate-verifiers.sh`.
2. Re-sign the circuit test fixtures whose plan changed. Noir cannot sign, so each fixture's signature is made once with a fixed test key: `nargo test --show-output test_print_digest` (deposit and withdraw) or `test_print_digests` (transfer) prints each fixture's plan digest, and `cargo run --example sign_digest -- <key> <digest>` prints the signature to paste, with key `0x0b` for an owner and `0x0c` for the claim key.
3. Update the values pinned on both sides if one changed: the parity vectors (`test_parity_vectors` in the circuits; `src/poseidon.rs` and `src/domain`), the feed's known answer (`test_known_answer_two_outputs`; `src/domain/feed.rs`) and the attestation leaf's (`test_known_answer_leaf`; `contracts/test/AttestationRegistry.t.sol`). `nargo test --show-output test_parity_vectors` prints the parity vectors.
4. Rerun the constraint-removal check and the end-to-end flows with real proofs.

Formatting: `cargo +nightly fmt` (`.rustfmt.toml` uses nightly-only options), `nargo fmt` in `circuits/`, and `forge fmt`, which skips the generated verifiers.

## Deploy

`deployments.toml` holds the parameters per chain; only the local chain (31337) is defined, and another chain needs its own section (the file says which keys). The fund token, the role addresses, the claim key hash, the register key and the local verifier mode come from the environment; `.env.example` lists them.

`Deploy` deploys a pool for the fund's existing token, with the generated verifiers only. It deploys no mock: a mock verifier accepts proofs anyone can make. The token's issuer then allowlists the pool and exempts it from the balance limit and from forced transfers (SPEC, [Public Token Requirements](SPEC.md#public-token-requirements)).

```bash
cp .env.example .env   # fill in the token, the role addresses and keys
FOUNDRY_PROFILE=deploy forge script contracts/script/Deploy.s.sol:Deploy \
  --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" --broadcast --slow
```

`DeployLocal` is what the tests run, on the local chain only: it deploys a mock fund token with the broadcaster as its issuer, the same pool, and the pool's registration on the token, with mock verifiers when `USE_MOCK_VERIFIER` is true. `--slow` sends each transaction once the previous one is confirmed, which anvil needs: it can leave a burst's later transactions queued for good.

`FOUNDRY_PROFILE=deploy` is required: `forge script` simulates all of `run()` in one call frame, and the generated verifiers exceed the default profile's gas limit. `contracts/script/DeployVerifiers.s.sol` deploys the three verifiers on their own; setting the `*_VERIFIER_ADDRESS` variables from that run makes both scripts reuse them, once they have checked that each one's code is the generated verifier's. Neither script writes anything back to `deployments.toml`: it prints the addresses it deploys, and forge records them under `contracts/broadcast/`.

Then seed the pool, before attesting any investor (SPEC, [Deployment Parameters](SPEC.md#deployment-parameters)): the transfer agent attests its own owner value, padded with owner values whose keys it holds, deposits one share and freezes the note through the claim path. Both need proofs, so the deploy script cannot do it. `TransferAgent::seed_deposit` and `freeze_seed` build the two operations, and `seed` in `tests/common/mod.rs` runs them.

## Limitations

The protocol's limitations are in the SPEC's [Limitations](SPEC.md#limitations-and-shortcuts-poc-scope). The implementation also leaves out or simplifies:
- **SPEC procedures not built:**
  - the agent putting one investor's several owner values in different batches on its own (`busy_four_days_with_several_flows` does it by hand)
  - a padding retirement policy: `stop_renewing` retires a value, but nothing chooses which padding or when, so the standing padding only grows
  - merging the day's redemption notes before withdrawing them: the flows withdraw a redemption note on its own
  - unit corrections through the claim path
  - `recordGrant` from Rust, and disclosure under a mandate
  - the alerts to governance and the guardian on an outflow, and the daily cadence of checkpoints
  - hand-out rounds batched into one block: the tree's transfers go one after another
- **The test setup:**
  - The end-to-end harness uses one account for governance, the guardian and the transfer agent; the Foundry tests use separate ones, so the role checks are covered there.
  - The relayer is a separate account, where the SPEC's PoC has the agent relay.
  - The mock token models the allowlist, the balance limit and the pool's exemptions, forced transfers and burns, but not freezes, wallet recovery or per-country rules. The agent's own address is subject to its balance limit.
- **No reorg handling.** The agent and the wallets read the chain at its latest block and never roll back, so a claim counts as done as soon as it is seen, where the SPEC waits for finality. Moving the chain reading onto [chainfold](https://github.com/ethsystems/works), which follows a safe head and rolls back on a reorg, is the planned fix.
- **The agent's state:** the claim records, the register keys and the salt key live in memory. They cannot be rebuilt from the chain, so persisting them is the operator's job; a register key prepared for a rotation, before sending `setRegisterKey`.
- **The custody signer** is a software key. It rebuilds each plan and registration before signing, but sets no limit on `expiry`.
- **The generation floor has no ceiling,** as in the base. `raiseMinAcceptedGeneration` checks the new floor against neither the current generation nor the attestations issued under it. Every circuit checks the floor, so a floor above the agent's attestations stops every operation, withdrawals included, from its activation epoch until the agent re-attests, one generation per batch. The base's other implementation limitations do not apply: the wallet keeps no state it cannot rebuild from the chain, there is one attester and no revocation tree, and the pool pins the epoch length.
- **The toolchain** is Noir 1.0.0-beta.21 with a nightly Barretenberg.

## Layout

```
shielded-notes/
├── SPEC.md                     protocol specification (primary deliverable)
├── circuits/                   Noir workspace
│   ├── lib/                    owner value, note, lock, attestation, plan, register feed
│   └── deposit/ transfer/ withdraw/
├── contracts/
│   ├── src/                    ShieldedPool, AttestationRegistry, CompositeVerifier,
│   │                           MockFundToken, generated verifiers
│   ├── script/                 Deploy, DeployVerifiers, TreeParity
│   └── test/
├── src/                        Rust: domain, chain adapter, prover, wallet, transfer agent
├── tests/                      end-to-end flows, tree parity, the benchmark
├── examples/                   sign_digest, for the circuit test fixtures
└── scripts/                    generate-verifiers.sh, mutate-circuits.py, mutate-contracts.py
```

## Security disclaimer

Research code. It is not production-ready and has not been audited. The protocol's limitations are in [Limitations and Shortcuts](SPEC.md#limitations-and-shortcuts-poc-scope).

# Shielded Pool: Verifiable-Coverage Continuous Monitoring

> **Status:** Complete
> **Privacy primitive:** confidential transfers in a KYC-gated shielded pool
> where the compliance policy is a circuit constraint rather than a
> side-artifact, with a per-account per-epoch running total chained through
> the commitment tree.

Extension of the [shielded-pool](../shielded-pool/) private-payments construction with:

- A compliance policy compiled into all three gated circuits. Screening runs on every operation that moves value to a party-chosen destination. One ungated exit remains, and it reaches only the blocked-funds account.
- A compliance note: per-account per-epoch state, chained by nullifiers, carrying a running total that conservation makes impossible to reset within an epoch.
- Attestation expiry, which turns revocation into a lapse. That removes every in-circuit non-membership proof. One blocklist survives at the contract layer, on withdrawal destinations only.

## What this shows

Non-bypassable coverage. Comparable shielded systems place the screening proof beside the spend, as a separate artifact the transactor produces at will. An institution running such a system cannot honestly say it screened every payment, because the protocol never required one.

Here the policy is a function inside the circuit that conserves value. A policy-blocked transaction has no satisfying witness, so no proof exists and nothing reaches the chain. Destination blocking is a contract-layer revert. Coverage becomes as non-bypassable as conservation of value, enforced by the same mechanism.

Coverage and readability are separate properties. The policy runs on every gated transaction and the running total is committed correctly. Reading that total requires the subject to have encrypted honestly, and no circuit constrains the ciphertext, here it is assumed that the party is legally bound - and if the data is undecryptable, subject to legal action.

[SPEC.md](SPEC.md) is authoritative. Trust assumptions, threat model, and guarantees are documented in [Security Model](SPEC.md#security-model).

## Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) 1.90, edition 2024 (pinned in `rust-toolchain.toml`)
- [Foundry](https://getfoundry.sh/) (`forge`, `anvil`)
- [Nargo](https://noir-lang.org/docs/getting_started/noir_installation) 1.0.0-beta.21
- [Barretenberg](https://github.com/AztecProtocol/aztec-packages/tree/master/barretenberg) `bb` 5.0.0-nightly.20260324

## Build

```bash
cd pocs/private-payment/shielded-pool-compliance
forge soldeer install
(cd circuits && nargo compile --workspace)
bash scripts/generate-verifiers.sh   # optional: regenerate the four Solidity verifiers
forge build
cargo build
```

Regenerating the verifiers changes the verification keys, which invalidates
`contracts/test/fixtures/deposit_proof.json`. Rewrite it with
`cargo run --release --example wallet_prove_check`.

## Test

```bash
(cd circuits && nargo test --workspace)      # 44 circuit tests
forge test                                   # 138 contract tests
cargo test --lib --features test-mocks       # 132 client unit tests
cargo test --release --test tree_parity      # client trees against the deployed Solidity
cargo test --release --tests                 # nine end-to-end scenarios
```

Each scenario spawns its own `anvil` on a free port, deploys the stack into it
with `forge script`, and drives `Authority`, `Wallet`, and `Auditor` against it
through the production `EthereumRpc` adapter. No node needs to be running
beforehand.

`VCCM_USE_MOCK_PROOFS=1` swaps the in-process prover for `MockProver` and, from
the same variable, tells the deploy script to install `MockUltraVerifier` in
place of the generated ones, so the proving and verifying halves can never
disagree about which mode a run is in. It requires `--features test-mocks`,
which is what compiles `MockProver` in:

```bash
VCCM_USE_MOCK_PROOFS=1 cargo test --release --tests --features test-mocks
```

Under mocks the contract-level invariants still hold (nullifier consumption,
root freshness, epoch acceptance, the destination blocklist, the
blocked-funds claim path), and the circuit-level ones become vacuous.
`stale_epoch_proof_rejected` is the scenario that distinguishes them.

`forge test` runs against mock verifiers throughout except
`contracts/test/RealVerifier.t.sol`, which deploys the generated
`DepositVerifier` and checks a real proof, a proof with one flipped bit, and a
perturbed public input.

Proving cost:

```bash
cargo run --release --example bench_proving
```

## Deploy

`deployments.toml` holds per-chain parameters; `.env.example` lists the
addresses and the mode switch the script resolves from the environment.

```bash
cp .env.example .env   # fill in the role addresses
FOUNDRY_PROFILE=deploy forge script contracts/script/Deploy.s.sol:Deploy \
  --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" --broadcast
```

`FOUNDRY_PROFILE=deploy` is required. `forge script` simulates all of `run()`
inside one call frame, and the four generated verifiers plus the linked
Poseidon libraries sum past the default profile's block limit. That limit stays
honest for `forge test`.

`contracts/script/DeployVerifiers.s.sol` deploys the four verifiers on their
own. Setting `*_VERIFIER_ADDRESS` from that run makes `Deploy` reuse them
instead of redeploying.

## Layout

```
shielded-pool-compliance/
├── SPEC.md                     protocol specification (primary deliverable)
├── circuits/                   Noir workspace
│   ├── lib/                    compliance note, attestation, policy, TxFacts
│   ├── deposit/ transfer/ withdraw/     gated circuits
│   └── withdraw_ungated/       the blocked-funds exit
├── contracts/
│   ├── src/                    ShieldedPool, AttestationRegistry,
│   │                           AttesterRevocationTree, CompositeVerifier
│   ├── script/                 Deploy, DeployVerifiers, TreeParity
│   └── test/
├── src/                        Rust client, ports and adapters
│   ├── domain/ policy/ crypto/ notes, policy, encryption
│   ├── ports/                  chain, prover, merkle, registry, audit, clock
│   ├── adapters/               alloy RPC, bb prover, rotortree, ECIES
│   └── wallet/ authority/ auditor/      the three actors
├── tests/                      tree parity plus nine end-to-end scenarios
└── examples/                   proving benchmark, wallet-to-circuit check
```

## Implementation divergences from SPEC

### Audit channel
- `AuditEncryptor` is instantiated by `EciesAuditEncryptor`, a single ECIES
  keypair standing in for the specified Silent Threshold Encryption committee
  at `t = n = 1`. The committee version is carried and checked; the threshold
  is not exercised.

### Policy identity
- A policy is identified on chain by the hash of `circuits/lib/src/policy.nr`
  together with the address of the verifier deployed for it. Swapping the
  ruleset means generating a verifier and registering the pair. The Noir
  `Policy` trait carries its accumulator width `K` as an associated constant,
  so the circuits are generic over the ruleset at compile time and monomorphic
  once deployed.

### Trees
- The client mirrors the on-chain LeanIMT with `rotortree`, a different
  implementation with its own storage layer. `tests/tree_parity.rs` pins the
  two to the same roots and Merkle proofs, driving the Solidity side through
  `contracts/script/TreeParity.s.sol`, so a divergence fails a test rather than
  a proof.
- `AttesterRevocationTree` is fixed-depth with room for 32 attesters and
  removes by swap-and-pop, which relocates the last attester. The client
  rebuilds it by replaying the registry's own events, since the contract
  exposes no Merkle proof.

### Governance
- The role set (governance, timelock controller, guardian, curator, audit
  committee, blocked-funds account) is deployed as plain addresses. Timelock
  delays and multi-party control are the deployer's concern; nothing here
  enforces that any of them is a multisig.
- Who administers `blockedFundsAccount`, and the process that moves value out
  of it, are left where [SPEC.md](SPEC.md#open-questions) leaves them, off
  protocol and unanswered.

### Out of scope
- Third-party deposits. A deposit credits the depositor's own pubkey.
- Recursive policy verification, and any in-circuit proof that the audit
  ciphertext decrypts to the committed facts.
- Lane sharding, and any accumulator spanning more than one epoch.
- Key rotation. A new spending key forks the compliance chain.

## Cryptographic assumptions

Everything here inherits the parent's primitive choices and adds no new curve.

| Primitive | Instantiation | Assumption |
|---|---|---|
| Algebraic hash | Poseidon version 1 over BN254, circomlib parameterization | Collision and preimage resistance at the parameters used, with a distinct permutation width per arity |
| Proving system | UltraHonk over BN254 via Noir and Barretenberg, zero-knowledge flavor selected explicitly | Knowledge soundness, plus a correct verifying key bound to the deployed verifier. The default flavor is a SNARK whose commitments are functions of the witness, so the ZK flavor is required for every confidentiality claim |
| Commitment tree | LeanIMT, inherited | Collision resistance of the node hash |
| Attestation tree | LeanIMT, inherited | The same, plus an honest Compliance Authority for issuance |
| Note encryption | ECDH, HKDF, and an AEAD, inherited | Classical hardness only. No post-quantum path |
| Audit channel | Silent Threshold Encryption retargeted to BN254 | Security in the Generic Group Model, plus a KZG powers-of-tau reference string. The committee is fixed between setups, and the per-ciphertext threshold is chosen by the encryptor. Research code, non-production |

The compliance state is a hash commitment, so the accumulator is not a harvest-now-decrypt-later target. The audit channel and the note channel are.

`scripts/generate-verifiers.sh` passes `-t evm`, never `-t evm-no-zk`. The
non-ZK flavor commits to the witness, which would void every confidentiality
claim in the table above.

## Known limitations and shortcuts

The protocol-level table is [Limitations](SPEC.md#limitations) in the spec, and
the seven departures from the shared requirements are
[Requirements deltas](SPEC.md#requirements-deltas). The implementation-level
divergences are listed above. In addition:

- **Wallet has no failure recovery.** `build_*` durably commits local state
  (tree leaves, the compliance chain) before proving or submission, with no
  rollback API. A prover error, a transient RPC failure, a lost race against
  another submitter, or any chain revert (including the spec-mandated
  regenerate-after-rollover case) leaves the local root permanently diverged
  from any root the chain will ever know, and every later `build_*` call then
  fails with `UnknownRoot`. `build_transfer` also only checks `have < need`,
  so overpaying inputs without an explicit change output can build an
  unsatisfiable witness after state has already been committed, triggering
  the same stranding. Recovery today means discarding and re-deriving wallet
  state from chain history.
- **`raiseMinAcceptedGeneration` has no ceiling.** The call enforces no bound
  relative to `currentGeneration` and does not require the replacement
  generation's first cohort root to already be recorded, so one
  mis-parameterized but otherwise valid, timelocked call can freeze every
  gated path for the affected subjects until governance intervenes. Any
  single attester can also ratchet `currentGeneration` forward via
  `addAttestations`, which can grief other attesters' pending batches into
  `WrongGeneration`.
- **`AttesterRevocationTree`'s zero-floor invariant is not self-enforced.**
  "The floor can never legitimately be 0" holds only because
  `ShieldedPool`'s constructor requires `epochSeconds <= block.timestamp`.
  `AttestationRegistry`, where `lowerRevocation` actually lives, has no
  equivalent check when deployed standalone; deployed with
  `currentEpoch() == 0`, `lowerRevocation(attester, 0)` followed by
  `removeAttester` and a re-add resurrects that attester unrevoked.
- **`EPOCH_SECONDS` and `singleTxThreshold` are unpinned deployment twins.**
  `EPOCH_SECONDS` is a free `ShieldedPool` constructor argument, but the
  circuits hard-pin `86400` in `domain.nr` and assert it against the
  `epoch_seconds` public input; deploying with any other value produces a
  pool where no gated proof can ever verify, and nothing checks this at
  deploy time. `singleTxThreshold` and the circuit's `SINGLE_TX_THRESHOLD`
  constant are the same kind of twin at lower stakes: they only diverge after
  a `setSingleTxThreshold` call, after which `SizeFlag` no longer matches the
  policy's own threshold-based flag inside the circuit.

## Documents

- [SPEC.md](./SPEC.md), the protocol specification.
- Parent SPEC: [`../shielded-pool/SPEC.md`](../shielded-pool/SPEC.md)
- Parent REQUIREMENTS: [`../REQUIREMENTS.md`](../REQUIREMENTS.md)
- Sibling extension: [`../shielded-pool-extension/SPEC.md`](../shielded-pool-extension/SPEC.md)

## Security disclaimer

Research code. This is not production-ready, has not been audited, and carries
the assumptions listed above. [SPEC.md](./SPEC.md) restates them alongside the
open questions an implementation must resolve.

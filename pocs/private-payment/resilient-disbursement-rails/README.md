# Resilient Disbursement Rails

> **Status:** Complete
> **Privacy primitive:** confidential disbursement to a cohort of
> recipients via shielded ERC-20 + cohort-anonymous claim circuit +
> on-card stealth derivation.

Distributes a fixed per-recipient amount to a cohort of smartcard
holders in a jurisdiction whose authorities are hostile to the funder,
implementing partner, or recipients themselves. The off-ramp is the
primary linkage vector. Recipients cannot run ZK provers on-card, may
have intermittent network, and lose devices.

The protocol uses per-recipient pool commitments deposited atomically
by the round factory, plus a cross-circuit `M` binding that links the
claim and pool-withdraw proofs through their shared `claim_nullifier`
preimage. Funder residual recovery is balance accounting gated by the
funder multisig and a 30-day timelock; there is no batch-withdraw
circuit.

[SPEC.md](SPEC.md) is authoritative. Cryptographic primitives,
trust assumptions, threat model, and guarantees are documented in
[Cryptographic Details](SPEC.md#cryptographic-details) and
[Security Model](SPEC.md#security-model).

## Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (`stable`, edition 2024)
- [Foundry](https://getfoundry.sh/) (`forge`, `anvil`)
- [Nargo](https://noir-lang.org/docs/getting_started/noir_installation)
- [Barretenberg](https://github.com/AztecProtocol/aztec-packages/tree/master/barretenberg)
  (`bb` CLI on PATH)

## Build

```bash
cd pocs/private-payment/resilient-disbursement-rails
forge soldeer install
nargo compile --workspace
bash scripts/generate-verifiers.sh   # optional: regenerate Solidity verifiers
forge build
cargo check
```

## Test

```bash
nargo test --workspace                  # Noir circuits
forge test                              # Solidity (mock verifiers)
cargo test --lib                        # Rust unit tests
cargo test --test golden_path           # integration vs anvil + real bb (slow)
RDR_USE_MOCK_PROOFS=1 cargo test        # mock-mode (sub-minute)
```

`RDR_USE_MOCK_PROOFS=1` swaps both the in-process `ProofBackend`
(returns empty bytes) and the on-chain composite verifier (returns
true), so contract-level invariants - cross-proof binding,
relay-submitter check, chain-id check, nullifier consumption - are
still exercised. `cross_card_spend_rejected.rs` and
`wrong_recipient_rejected.rs` demonstrate constraint-system properties
that are vacuous under the mock verifier and only meaningful with real
proofs.

End-to-end proof generation:

```bash
cargo run --release --example bench_proving
```

## Implementation divergences from SPEC

`SPEC.md` 0.5.0 is authoritative. The implementation diverges as
follows.

### Domain tags
- Noir circuits and the Rust `poseidon` module use small distinct
  integer literals (`LEAF_DOMAIN_TAG = 1`,
  `COMMITMENT_DOMAIN_TAG = 2`, `NULL_DOMAIN_TAG = 3`) rather than
  `Poseidon1_t2(0, SHA256("RDR/<purpose>/v1") mod r_BN254)`. The
  domain-separation property holds; the values themselves diverge.
- SHA-256 string-domain tags (`DOMAIN_VOUCHER`, `DOMAIN_HEADER`,
  `DOMAIN_STEALTH`) match SPEC byte-for-byte.

### Pool model
- Per-claim-contract sub-trees: each registered claim contract has its
  own LeanIMT.
- The factory creates `cohortSize` opaque commitments per round and
  deposits each one separately. SPEC's "single shield call" framing is
  realized as `cohortSize` deposit calls inside one factory transaction.
- No ZK on deposit; the factory is the sole authorized depositor.
- No in-pool transfer circuit.
- Funder residual recovery is balance accounting; **no ZK on the
  residual path**. The claim contract computes
  `residual = (cohortSize - nullifiersConsumedCount) * perRecipient`
  and forwards a single `pool.recoverResidual(...)` call.
- `firstPoolLeafIndex` is captured BEFORE the deposit loop by reading
  `pool.subTreeSize(claimContract)`; not funder-signed, not part of
  `H_header`.
- `pool.commitmentIndex(cc, commitment)` returns `leafIndex + 1`
  (0 means "absent") to disambiguate Solidity zero-init.

### Round Factory
- `RoundFactory.publishRound` does not verify a detached funder ECDSA
  signature on `H_header`. On-chain authorization is
  `msg.sender == funderMultisig` via `Multisig.execute`. The funder's
  ECDSA signature on `H_header` is delivered out-of-band alongside the
  header and verified only by companion devices
  (`Companion::verify_signed_header`). The `RoundPublished` event emits
  `hHeader` for traceability but no `funderSig` blob.

### Smartcard
- Rust software emulator (`SoftwareSmartcard` in `src/adapters/`).
  Exposes APDU-shaped `Smartcard::transmit(apdu) -> response` with
  three INS bytes: `GENERATE_KEY`, `EXPORT_KEY`, `SIGN_VOUCHER`.
- Refuses 32-byte APDU bodies (pre-hashed digests) with
  `CardError::PreHashedHMsgRefused`. The card always constructs the
  308-byte preimage itself.
- ECDSA uses RFC 6979 deterministic nonces rather than TRNG-derived
  nonces per
  [Smartcard Requirements](SPEC.md#smartcard-requirements). The
  emulator has no TRNG.

### Mesh and anonymous transport
- `ISubmission` and `IAnonymousTransport` are defined as ports
  (`src/ports/submission.rs`, `src/ports/anon_transport.rs`) with
  in-process direct adapters (`DirectSubmission`,
  `DirectAnonymousTransport`). The companion pushes encrypted vouchers
  through `Submission::submit_voucher`; the relay pulls via the
  adapter's `pull_voucher`. The relay signs the claim transaction
  client-side and hands raw EIP-2718 bytes to
  `AnonymousTransport::submit`, which forwards via alloy's
  `send_raw_transaction`. No mesh hops, no Tor / Nym; the adapters
  exist to make the boundary visible at every call site.

### Operational concerns (out of scope)
- Software smartcard; JCOP-class hardware deployment is out of scope.
- Relay EOA rotation per round (operator concern).
- Reorg margin is a deployer-side policy applied to relay submission
  decisions; the on-chain claim gate is `block.timestamp < closeTime`
  with no built-in margin.
- Source-fingerprinting mitigations at the network layer.
- Cross-funder anonymity at the pool (per the per-claim-contract
  sub-tree partition).
- Forward secrecy under card seizure (per
  [Limitations and Shortcuts](SPEC.md#limitations-and-shortcuts-poc-scope)).

## References

- [SPEC.md](SPEC.md) - protocol specification.
- ethsystems/map [use case](https://github.com/ethsystems/map/blob/master/use-cases/resilient-disbursement-rails.md)
  and [approach](https://github.com/ethsystems/map/blob/master/approaches/approach-private-payments.md).

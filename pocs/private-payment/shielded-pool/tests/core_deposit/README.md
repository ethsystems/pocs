# Ungated deposit test fixture

The PoC implements the attestation-gated pool. This fixture covers the ungated
deposit statement of 2/SHIELDED-POOL 5.3, which the gated deposit circuit does
not exercise: the same commitment relation and u128 amount bound, with a free
owner public key and no attestation.

[2/SHIELDED-POOL 5.3](https://github.com/ethsystems/specs-private/blob/master/specs/2/README.md#53-proof-statements)
explicitly permits a free `owner_pubkey`, so a depositor can shield to a recipient
without knowing that recipient's spending key. The
[3/ATTESTED-POOL 5.3](https://github.com/ethsystems/specs-private/blob/master/specs/3/README.md#53-proof-statements)
entry predicate adds `owner_pubkey == Poseidon1(spending_key)` and attestation
membership. That ownership check prevents entry proofs built from public registry
data in the gated pool. This fixture has no registry or entry predicate.
Deriving the owner key here would remove the core's shield-to-recipient case.

The core public inputs remain `commitment, token, amount, funding_address,
payload_hash`. Funding authorisation belongs to the contract, as specified in
2/SHIELDED-POOL 5.3. The existing gated circuit derives the owner key; transfer
inputs and withdrawals also require the spending key to spend an existing note.

`circuit/` is a member of the PoC Nargo workspace, so `nargo test --workspace`
from the PoC root runs its eight tests. `circuit/Prover.toml` holds the fixture
values, which `tests/core_deposit_fixture.rs` reparses so Rust and Noir pin the
same commitment.

`proof_checks.rs`, included by `tests/core_deposit_fixture.rs`, proves both
deposit statements through Barretenberg's FFI backend. It checks that each public
input is bound: it flips one bit in each of the five inputs and requires a
rejection, and requires each deposit mode's proof to fail under the other
mode's key. Every rejection has a valid-proof control. Backend errors fail the
test instead of counting as rejections.

Run from the PoC root with Nargo 1.0.0-beta.21 on PATH. Cargo downloads the
static library for the pinned `barretenberg-rs` version, as in the compliance
PoC. An existing matching library can be supplied with `BB_LIB_DIR`.
The test reads the first 2^19 BN254 SRS points from
`$BB_CRS_PATH/bn254_g1.dat` (default: `~/.bb-crs/bn254_g1.dat`).
This is the same cache used by the compliance prover and `bb`. A missing or
short cache fails with its path; provision it before running the test.
Neither proving nor verification invokes `bb`; Nargo still executes the witness.

```bash
nargo test --workspace
cargo test --test core_deposit_fixture -- --nocapture
```

Successful runs save proofs, keys, public inputs, circuit artifacts, and a
`results.json` hash manifest in a fresh `target/core-deposit-checks-*` directory.

The fixture does not cover token funding, recipient discovery, or spending, and
it is not a standalone core-only pool. The disclosure in 2/SHIELDED-POOL 7.1
stands.

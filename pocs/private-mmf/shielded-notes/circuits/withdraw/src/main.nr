use sn_lib::attestation::{self, AttestationWitness};
use sn_lib::domain;
use sn_lib::lock;
use sn_lib::merkle;
use sn_lib::note::{self, InputNote};
use sn_lib::owner::{self, SpendKey};
use sn_lib::plan::{self, Plan};

// Withdraw: spends one whole note to a public address. The pool pays
// floor(units * m / S) shares to `recipient`. Owner path only. Public-input
// order MUST match `WithdrawPublicInputs` in `contracts/src/PublicInputs.sol`
// index for index.
fn main(
    nullifier: pub Field,
    token: pub Field,
    units: pub u64,
    recipient: pub Field,
    commitment_root: pub Field,
    attestation_root: pub Field,
    min_accepted_generation: pub u64,
    epoch: pub u64,
    chain_id: pub Field,
    pool: pub Field,
    owner_key: SpendKey,
    nk: Field,
    signature: [u8; 64],
    expiry: u64,
    input: InputNote,
    attestation_witness: AttestationWitness,
) {
    token.assert_max_bit_size::<160>();
    recipient.assert_max_bit_size::<160>();
    assert(input.units == units, "units mismatch");

    let owner = owner::owner_value(owner_key, nk);
    let commitment = input.note(token, owner).commitment();
    assert(input.proof_length <= domain::MAX_COMMITMENT_TREE_DEPTH);
    merkle::verify(
        commitment,
        commitment_root,
        input.proof_length,
        input.indices,
        input.path,
    );
    assert(nullifier == note::nullifier(commitment, nk), "nullifier mismatch");

    attestation::verify(
        owner,
        attestation_witness,
        epoch,
        min_accepted_generation,
        attestation_root,
    );
    lock::check_input(input.lock, input.lock_opening, epoch);

    plan::check_expiry(epoch, expiry);
    let digest = plan::digest(
        Plan {
            chain_id,
            pool,
            op: domain::OP_WITHDRAW,
            path: domain::PATH_OWNER,
            nullifiers: [nullifier, 0],
            outputs: [0, 0],
            public_units: units as Field,
            recipient,
            expiry,
        },
    );
    plan::verify_signature(owner_key, signature, digest);
}

mod tests {
    use super::main;
    use sn_lib::attestation::{self, AttestationWitness};
    use sn_lib::domain;
    use sn_lib::fixtures;
    use sn_lib::hasher::hash_2;
    use sn_lib::lock::{self, LockOpening, NO_LOCK};
    use sn_lib::note::{self, InputNote};
    use sn_lib::owner::{self, SpendKey};
    use sn_lib::plan::{self, Plan};

    global RECIPIENT: Field = 0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc;
    global UNITS: u64 = 1000;

    // Signature by test secret 0x0b over the happy fixture's plan digest, from
    // `cargo run --example sign_digest -- 0x0b <digest>`. Regenerate with
    // `nargo test --show-output test_print_digest` whenever the fixture changes.
    global SIGNATURE: [u8; 64] = [
        216, 138, 34, 25, 157, 252, 217, 5, 156, 43, 113, 252, 199, 165, 102, 40, 91, 84, 250, 131,
        164, 200, 25, 86, 177, 209, 251, 61, 95, 252, 93, 150, 103, 131, 38, 106, 204, 244, 130,
        163, 136, 52, 27, 138, 104, 219, 197, 71, 18, 216, 61, 234, 128, 121, 8, 49, 183, 38, 64,
        182, 251, 16, 98, 67,
    ];

    // The released hold and the short withdrawal, also from `test_print_digest`.
    global SIG_RELEASED_HOLD: [u8; 64] = [
        171, 99, 35, 92, 73, 139, 177, 142, 73, 47, 91, 18, 14, 63, 161, 31, 142, 175, 221, 158,
        241, 176, 127, 193, 82, 91, 12, 53, 218, 13, 179, 154, 47, 66, 114, 43, 74, 218, 224, 171,
        43, 83, 120, 28, 64, 59, 43, 151, 118, 150, 113, 222, 176, 250, 159, 194, 208, 89, 0, 217,
        251, 146, 200, 198,
    ];
    global SIG_SHORT: [u8; 64] = [
        243, 8, 79, 62, 142, 23, 148, 230, 60, 142, 113, 250, 190, 149, 237, 166, 125, 94, 134, 235,
        44, 92, 22, 250, 217, 13, 210, 220, 7, 245, 4, 90, 118, 74, 160, 163, 189, 42, 85, 78, 225,
        169, 245, 27, 79, 247, 191, 44, 77, 174, 28, 69, 117, 235, 191, 118, 92, 192, 6, 83, 251,
        79, 6, 132,
    ];

    struct Fixture {
        nullifier: Field,
        token: Field,
        units: u64,
        recipient: Field,
        commitment_root: Field,
        attestation_root: Field,
        min_accepted_generation: u64,
        epoch: u64,
        chain_id: Field,
        pool: Field,
        expiry: u64,
        owner_key: SpendKey,
        nk: Field,
        signature: [u8; 64],
        input: InputNote,
        attestation_witness: AttestationWitness,
    }

    fn build(opening: LockOpening, owner_expires_at: u64) -> Fixture {
        let owner = owner::owner_value(fixtures::owner_key(), fixtures::OWNER_NK);
        let lock = if opening.reason == 0 {
            0
        } else {
            lock::lock_value(opening)
        };
        let mut input = InputNote {
            units: UNITS,
            salt: 0x11,
            lock,
            lock_opening: opening,
            proof_length: 1,
            indices: [false; domain::MAX_COMMITMENT_TREE_DEPTH],
            path: [0; domain::MAX_COMMITMENT_TREE_DEPTH],
        };
        input.path[0] = 0x1234;
        let commitment = input.note(fixtures::TOKEN, owner).commitment();
        let (attestation_witness, attestation_root) =
            attestation::single_leaf_fixture(owner, owner_expires_at);
        Fixture {
            nullifier: note::nullifier(commitment, fixtures::OWNER_NK),
            token: fixtures::TOKEN,
            units: UNITS,
            recipient: RECIPIENT,
            commitment_root: hash_2([commitment, 0x1234]),
            attestation_root,
            min_accepted_generation: 1,
            epoch: fixtures::EPOCH,
            chain_id: fixtures::CHAIN_ID,
            pool: fixtures::POOL,
            expiry: fixtures::EXPIRY,
            owner_key: fixtures::owner_key(),
            nk: fixtures::OWNER_NK,
            signature: SIGNATURE,
            input,
            attestation_witness,
        }
    }

    fn valid_fixture() -> Fixture {
        build(NO_LOCK, 200 * domain::EPOCH_SECONDS)
    }

    // A note under a holding period that ended at epoch 50, before the
    // fixture's epoch 100.
    fn released_hold() -> Fixture {
        let hold = LockOpening { reason: domain::LOCK_HOLD, release_after: 50, claim_party: 0 };
        let mut f = build(hold, 200 * domain::EPOCH_SECONDS);
        f.signature = SIG_RELEASED_HOLD;
        f
    }

    // One unit less than the note holds. Signed, so the units rule is the
    // only one it breaks.
    fn short() -> Fixture {
        let mut f = valid_fixture();
        f.units = UNITS - 1;
        f.signature = SIG_SHORT;
        f
    }

    fn digest_of(f: Fixture) -> Field {
        plan::digest(
            Plan {
                chain_id: f.chain_id,
                pool: f.pool,
                op: domain::OP_WITHDRAW,
                path: domain::PATH_OWNER,
                nullifiers: [f.nullifier, 0],
                outputs: [0, 0],
                public_units: f.units as Field,
                recipient: f.recipient,
                expiry: f.expiry,
            },
        )
    }

    fn run(f: Fixture) {
        main(
            f.nullifier,
            f.token,
            f.units,
            f.recipient,
            f.commitment_root,
            f.attestation_root,
            f.min_accepted_generation,
            f.epoch,
            f.chain_id,
            f.pool,
            f.owner_key,
            f.nk,
            f.signature,
            f.expiry,
            f.input,
            f.attestation_witness,
        );
    }

    #[test]
    fn test_print_digest() {
        std::println(digest_of(valid_fixture()));
        std::println(digest_of(released_hold()));
        std::println(digest_of(short()));
    }

    #[test]
    fn test_withdraw_happy_path() {
        run(valid_fixture());
    }

    #[test]
    fn test_withdraw_a_note_whose_hold_ended() {
        run(released_hold());
    }

    #[test(should_fail_with = "units mismatch")]
    fn test_withdraw_less_than_the_note_fails() {
        run(short());
    }

    #[test(should_fail_with = "units mismatch")]
    fn test_withdraw_more_than_the_note_fails() {
        let mut f = valid_fixture();
        f.units = UNITS + 1;
        run(f);
    }

    #[test(should_fail_with = "merkle proof failed")]
    fn test_withdraw_note_not_in_tree_fails() {
        let mut f = valid_fixture();
        f.input.path[0] = f.input.path[0] + 1;
        run(f);
    }

    #[test(should_fail_with = "nullifier mismatch")]
    fn test_withdraw_wrong_nullifier_fails() {
        let mut f = valid_fixture();
        f.nullifier = f.nullifier + 1;
        run(f);
    }

    #[test(should_fail_with = "attestation expired")]
    fn test_withdraw_lapsed_owner_fails() {
        run(build(NO_LOCK, 50 * domain::EPOCH_SECONDS));
    }

    #[test(should_fail_with = "note is locked")]
    fn test_withdraw_frozen_note_fails() {
        let freeze = LockOpening {
            reason: domain::LOCK_FREEZE,
            release_after: 0xffffffffffffffff,
            claim_party: 0,
        };
        run(build(freeze, 200 * domain::EPOCH_SECONDS));
    }

    #[test(should_fail_with = "plan expired")]
    fn test_withdraw_expired_plan_fails() {
        let mut f = valid_fixture();
        f.expiry = (f.epoch + 1) * domain::EPOCH_SECONDS - 1;
        run(f);
    }

    #[test(should_fail_with = "invalid plan signature")]
    fn test_withdraw_redirected_recipient_fails() {
        let mut f = valid_fixture();
        f.recipient = f.recipient + 1;
        run(f);
    }

    #[test(should_fail_with = "call to assert_max_bit_size")]
    fn test_withdraw_oversized_recipient_fails() {
        let mut f = valid_fixture();
        f.recipient = 0x10000000000000000000000000000000000000000;
        run(f);
    }

    #[test(should_fail_with = "call to assert_max_bit_size")]
    fn test_withdraw_oversized_token_fails() {
        let mut f = valid_fixture();
        f.token = 0x10000000000000000000000000000000000000000;
        run(f);
    }

    // Call sites: the library's own tests check lapse, the generation floor
    // and holds; these check that this circuit calls them with its epoch
    // and floor, so a slip at a call site cannot switch a rule off.

    // The hold ends at epoch 50; at epoch 49 the note is still locked.
    #[test(should_fail_with = "note is locked")]
    fn test_hold_before_its_release_fails() {
        let mut f = released_hold();
        f.epoch = 49;
        run(f);
    }

    // An owner attested under a retired generation cannot withdraw.
    #[test(should_fail_with = "attestation generation retired")]
    fn test_retired_generation_fails() {
        let mut f = valid_fixture();
        f.min_accepted_generation = 2;
        run(f);
    }

    // An attestation that lapsed at the end of epoch 100 no longer covers
    // epoch 101.
    #[test(should_fail_with = "attestation expired")]
    fn test_lapsed_at_the_boundary_fails() {
        let mut f = build(NO_LOCK, 101 * domain::EPOCH_SECONDS);
        f.epoch = 101;
        run(f);
    }
}

use sn_lib::attestation::{self, AttestationWitness};
use sn_lib::domain;
use sn_lib::feed::{self, FeedSecret};
use sn_lib::lock;
use sn_lib::merkle;
use sn_lib::note::{self, InputNote, Note};
use sn_lib::owner::{self, SpendKey};
use sn_lib::plan::{self, Plan};

// Transfer: spends one or two notes of one owner and creates two notes. On the
// owner path the owner's key signs; on the claim path the transfer agent's
// claim key signs, which implements freeze, release and seizure. Which path a
// proof took is private. Public-input order MUST match `TransferPublicInputs`
// in `contracts/src/PublicInputs.sol` index for index.
fn main(
    nullifier_0: pub Field,
    nullifier_1: pub Field,
    commitment_out_0: pub Field,
    commitment_out_1: pub Field,
    commitment_root: pub Field,
    attestation_root: pub Field,
    min_accepted_generation: pub u64,
    epoch: pub u64,
    chain_id: pub Field,
    pool: pub Field,
    claim_key_hash: pub Field,
    register_key: pub [Field; 2],
    feed_r: pub [Field; 2],
    feed_ct: pub [Field; 2 * domain::FEED_FIELDS],
    payload_commitment: pub Field,
    claim: bool,
    token: Field,
    owner_key: SpendKey,
    nk: Field,
    claim_key: SpendKey,
    signature: [u8; 64],
    expiry: u64,
    inputs: [InputNote; 2],
    outputs: [Note; 2],
    output_locks: [lock::LockOpening; 2],
    input_attestation: AttestationWitness,
    output_attestations: [AttestationWitness; 2],
    feed_secret: FeedSecret,
) {
    // Unconstrained here: the contract checks it against keccak256 of the
    // recipient payload it emits, which ties the payload to this proof.
    let _ = payload_commitment;
    token.assert_max_bit_size::<160>();

    // Inputs: both belong to the owner opening's owner value.
    let owner_in = owner::owner_value(owner_key, nk);
    let c_in_0 = inputs[0].note(token, owner_in).commitment();
    assert(inputs[0].proof_length <= domain::MAX_COMMITMENT_TREE_DEPTH);
    merkle::verify(
        c_in_0,
        commitment_root,
        inputs[0].proof_length,
        inputs[0].indices,
        inputs[0].path,
    );
    assert(nullifier_0 == note::nullifier(c_in_0, nk), "nullifier mismatch");

    // A one-input transfer pads the second input with a zero-unit note. Its
    // commitment and nullifier stay constrained; only inclusion is skipped, for
    // any zero-unit input: the padding note is not in the tree, and a zero-unit
    // note carries no value, so it needs no inclusion proof.
    let c_in_1 = inputs[1].note(token, owner_in).commitment();
    if inputs[1].units != 0 {
        assert(inputs[1].proof_length <= domain::MAX_COMMITMENT_TREE_DEPTH);
        merkle::verify(
            c_in_1,
            commitment_root,
            inputs[1].proof_length,
            inputs[1].indices,
            inputs[1].path,
        );
    }
    assert(nullifier_1 == note::nullifier(c_in_1, nk), "nullifier mismatch");

    assert(outputs[0].token == token, "token mismatch");
    assert(outputs[1].token == token, "token mismatch");
    assert(commitment_out_0 == outputs[0].commitment(), "commitment mismatch");
    assert(commitment_out_1 == outputs[1].commitment(), "commitment mismatch");

    // u64 addition traps on overflow, so no choice of outputs wraps around.
    assert(
        inputs[0].units + inputs[1].units == outputs[0].units + outputs[1].units,
        "units not conserved",
    );

    if !claim {
        // Owner path: the input owner and both output owners are attested,
        // locked inputs must be released, and no output may carry a lock.
        attestation::verify(
            owner_in,
            input_attestation,
            epoch,
            min_accepted_generation,
            attestation_root,
        );
        lock::check_input(inputs[0].lock, inputs[0].lock_opening, epoch);
        lock::check_input(inputs[1].lock, inputs[1].lock_opening, epoch);
        assert(outputs[0].lock == 0, "owner path cannot create locks");
        assert(outputs[1].lock == 0, "owner path cannot create locks");
    }
    // Every new owner is checked on both paths. The claim path skips outputs
    // that stay with the input owner, so a lapsed holder's note can be frozen
    // or released in place.
    for j in 0..2 {
        if (!claim) | (outputs[j].owner != owner_in) {
            attestation::verify(
                outputs[j].owner,
                output_attestations[j],
                epoch,
                min_accepted_generation,
                attestation_root,
            );
        }
    }

    // The feed carries each output's lock terms, bound to its lock, so the
    // agent's register is complete from the chain alone.
    let (derived_r, k) = feed::derive(feed_secret, register_key);
    assert(feed_r == derived_r, "feed mismatch");
    for j in 0..2 {
        lock::check_terms(outputs[j].lock, output_locks[j]);
        let ct = feed::encrypt(k, outputs[j], output_locks[j], j);
        for i in 0..domain::FEED_FIELDS {
            assert(feed_ct[domain::FEED_FIELDS * j + i] == ct[i], "feed mismatch");
        }
    }

    if claim {
        assert(owner::key_hash(claim_key) == claim_key_hash, "claim key mismatch");
    }
    let signer = if claim { claim_key } else { owner_key };
    plan::check_expiry(epoch, expiry);
    let digest = plan::digest(
        Plan {
            chain_id,
            pool,
            op: domain::OP_TRANSFER,
            path: claim as Field,
            nullifiers: [nullifier_0, nullifier_1],
            outputs: [commitment_out_0, commitment_out_1],
            public_units: 0,
            recipient: 0,
            expiry,
        },
    );
    plan::verify_signature(signer, signature, digest);
}

mod tests {
    use super::main;
    use sn_lib::attestation::{self, AttestationWitness};
    use sn_lib::domain;
    use sn_lib::feed::{self, FeedSecret};
    use sn_lib::fixtures;
    use sn_lib::hasher::hash_2;
    use sn_lib::lock::{self, LockOpening, NO_LOCK};
    use sn_lib::note::{self, InputNote, Note};
    use sn_lib::owner::{self, SpendKey};
    use sn_lib::plan::{self, Plan};

    global RECIPIENT: Field = 0x4ec1;
    global FAR: u64 = 200 * domain::EPOCH_SECONDS;
    global LAPSED: u64 = 50 * domain::EPOCH_SECONDS;

    // Signatures over each scenario's plan digest, from
    // `cargo run --example sign_digest -- <0x0b owner | 0x0c claim> <digest>`.
    // Regenerate with `nargo test --show-output test_print_digests` whenever a
    // scenario changes.
    global SIG_OWNER_PATH: [u8; 64] = [
        216, 64, 16, 25, 56, 201, 154, 202, 176, 57, 172, 66, 80, 74, 108, 191, 186, 49, 93, 228,
        98, 174, 237, 76, 110, 227, 17, 148, 222, 1, 245, 245, 106, 135, 190, 9, 232, 81, 245, 5,
        16, 114, 237, 45, 171, 158, 205, 254, 142, 138, 209, 25, 139, 232, 63, 116, 162, 124, 35,
        87, 51, 177, 139, 205,
    ];
    global SIG_PADDED: [u8; 64] = [
        147, 18, 2, 197, 122, 119, 149, 225, 190, 175, 97, 127, 96, 191, 216, 228, 96, 181, 27, 173,
        216, 75, 77, 35, 100, 14, 188, 38, 173, 83, 15, 131, 28, 242, 221, 248, 6, 202, 116, 10,
        113, 201, 87, 90, 103, 85, 75, 20, 16, 39, 235, 253, 250, 33, 79, 139, 181, 128, 117, 153,
        99, 225, 26, 1,
    ];
    global SIG_SEIZE: [u8; 64] = [
        59, 245, 128, 111, 52, 239, 60, 19, 124, 253, 181, 88, 128, 31, 248, 135, 198, 24, 61, 49,
        141, 3, 92, 232, 35, 236, 122, 118, 200, 138, 123, 41, 94, 131, 162, 61, 202, 226, 109, 174,
        222, 23, 145, 141, 190, 215, 116, 208, 254, 64, 92, 47, 158, 115, 234, 241, 214, 100, 60,
        113, 66, 114, 166, 213,
    ];
    global SIG_RELEASE: [u8; 64] = [
        87, 247, 114, 117, 169, 202, 42, 179, 92, 167, 179, 220, 113, 109, 62, 4, 42, 224, 187, 31,
        235, 103, 20, 175, 164, 250, 189, 10, 145, 207, 21, 8, 97, 161, 241, 199, 147, 221, 245,
        223, 235, 30, 66, 20, 30, 47, 235, 126, 6, 54, 218, 39, 44, 159, 49, 235, 250, 190, 160,
        102, 174, 107, 215, 216,
    ];
    global SIG_FREEZE: [u8; 64] = [
        153, 36, 130, 93, 115, 227, 88, 191, 155, 249, 81, 209, 53, 152, 14, 197, 4, 225, 85, 20,
        222, 97, 103, 178, 174, 54, 138, 66, 36, 27, 14, 36, 98, 31, 199, 174, 152, 184, 76, 26,
        201, 105, 104, 231, 206, 200, 101, 90, 166, 190, 245, 9, 145, 136, 194, 150, 132, 62, 41,
        143, 152, 71, 39, 186,
    ];

    // The freeze digest signed by the owner's key 0x0b, and the freeze plan
    // with the owner path's `path` signed by the claim key 0x0c: the last
    // digest `test_print_digests` prints.
    global SIG_FREEZE_BY_OWNER: [u8; 64] = [
        40, 27, 61, 140, 236, 163, 105, 215, 140, 95, 100, 201, 196, 106, 163, 122, 31, 145, 144,
        243, 141, 189, 219, 73, 0, 204, 175, 86, 140, 235, 150, 78, 102, 251, 246, 248, 223, 67, 86,
        186, 115, 50, 246, 44, 169, 65, 3, 1, 218, 119, 55, 243, 77, 2, 136, 153, 196, 1, 81, 28,
        126, 20, 241, 182,
    ];
    global SIG_FREEZE_AS_OWNER_PATH: [u8; 64] = [
        68, 0, 249, 196, 102, 32, 217, 230, 0, 84, 167, 65, 130, 203, 155, 60, 43, 3, 6, 11, 44,
        210, 246, 169, 141, 53, 97, 130, 109, 239, 174, 166, 105, 223, 191, 211, 225, 48, 66, 153,
        203, 190, 75, 103, 105, 29, 120, 146, 69, 4, 188, 105, 232, 140, 151, 17, 217, 40, 227, 44,
        253, 184, 194, 142,
    ];

    // The burn and the held hand-out, also from `test_print_digests`: owner
    // key 0x0b and claim key 0x0c.
    global SIG_BURN: [u8; 64] = [
        150, 82, 127, 199, 195, 186, 113, 118, 163, 62, 69, 166, 121, 142, 212, 144, 91, 180, 242,
        212, 219, 96, 33, 8, 23, 120, 0, 172, 211, 219, 213, 215, 60, 161, 47, 89, 62, 50, 72, 216,
        73, 24, 73, 225, 112, 121, 85, 213, 19, 185, 188, 222, 242, 235, 84, 179, 71, 46, 127, 200,
        59, 72, 126, 218,
    ];
    global SIG_HELD_HAND_OUT: [u8; 64] = [
        144, 244, 3, 237, 1, 73, 41, 40, 185, 135, 144, 139, 27, 117, 234, 142, 92, 69, 215, 101,
        205, 97, 238, 9, 212, 208, 87, 224, 181, 195, 121, 134, 9, 100, 71, 248, 28, 7, 174, 231,
        130, 196, 68, 119, 163, 4, 150, 89, 205, 249, 158, 205, 160, 51, 49, 6, 160, 112, 78, 178,
        242, 196, 17, 197,
    ];

    struct Fixture {
        nullifier_0: Field,
        nullifier_1: Field,
        commitment_out_0: Field,
        commitment_out_1: Field,
        commitment_root: Field,
        attestation_root: Field,
        min_accepted_generation: u64,
        epoch: u64,
        chain_id: Field,
        pool: Field,
        expiry: u64,
        claim_key_hash: Field,
        register_key: [Field; 2],
        feed_r: [Field; 2],
        feed_ct: [Field; 2 * domain::FEED_FIELDS],
        payload_commitment: Field,
        claim: bool,
        token: Field,
        owner_key: SpendKey,
        nk: Field,
        claim_key: SpendKey,
        signature: [u8; 64],
        inputs: [InputNote; 2],
        outputs: [Note; 2],
        output_locks: [LockOpening; 2],
        input_attestation: AttestationWitness,
        output_attestations: [AttestationWitness; 2],
        feed_secret: FeedSecret,
    }

    fn owner_in() -> Field {
        owner::owner_value(fixtures::owner_key(), fixtures::OWNER_NK)
    }

    fn lock_of(opening: LockOpening) -> Field {
        if opening.reason == 0 {
            0
        } else {
            lock::lock_value(opening)
        }
    }

    fn input(units: u64, salt: Field, opening: LockOpening) -> InputNote {
        InputNote {
            units,
            salt,
            lock: lock_of(opening),
            lock_opening: opening,
            proof_length: 1,
            indices: [false; domain::MAX_COMMITMENT_TREE_DEPTH],
            path: [0; domain::MAX_COMMITMENT_TREE_DEPTH],
        }
    }

    fn output(units: u64, owner: Field, salt: Field, terms: LockOpening) -> (Note, LockOpening) {
        (Note { token: fixtures::TOKEN, units, owner, salt, lock: lock_of(terms) }, terms)
    }

    // Puts the inputs in a depth-1 commitment tree (the second only if it is
    // not padding), attests the input owner and RECIPIENT, and derives every
    // public value from the notes.
    fn build(
        claim: bool,
        inputs: [InputNote; 2],
        outputs: [(Note, LockOpening); 2],
        owner_expires_at: u64,
        signature: [u8; 64],
    ) -> Fixture {
        let output_locks = [outputs[0].1, outputs[1].1];
        let outputs = [outputs[0].0, outputs[1].0];
        let mut inputs = inputs;
        let owner = owner_in();
        let c0 = inputs[0].note(fixtures::TOKEN, owner).commitment();
        let c1 = inputs[1].note(fixtures::TOKEN, owner).commitment();
        let sibling = if inputs[1].units == 0 { 0x1234 } else { c1 };
        inputs[0].path[0] = sibling;
        inputs[1].path[0] = c0;
        inputs[1].indices[0] = true;
        let commitment_root = hash_2([c0, sibling]);

        let (w_owner, w_recipient, attestation_root) =
            attestation::two_leaf_fixture(owner, owner_expires_at, RECIPIENT, FAR);
        let witness_for = |o: Field| if o == RECIPIENT { w_recipient } else { w_owner };

        let register_key = feed::register_key_of(FeedSecret { lo: 0x7777, hi: 0x1 });
        let feed_secret = FeedSecret { lo: 0x4321, hi: 0x8765 };
        let (feed_r, k) = feed::derive(feed_secret, register_key);
        let mut feed_ct = [0; 2 * domain::FEED_FIELDS];
        for j in 0..2 {
            let ct = feed::encrypt(k, outputs[j], output_locks[j], j);
            for i in 0..domain::FEED_FIELDS {
                feed_ct[domain::FEED_FIELDS * j + i] = ct[i];
            }
        }

        Fixture {
            nullifier_0: note::nullifier(c0, fixtures::OWNER_NK),
            nullifier_1: note::nullifier(c1, fixtures::OWNER_NK),
            commitment_out_0: outputs[0].commitment(),
            commitment_out_1: outputs[1].commitment(),
            commitment_root,
            attestation_root,
            min_accepted_generation: 1,
            epoch: fixtures::EPOCH,
            chain_id: fixtures::CHAIN_ID,
            pool: fixtures::POOL,
            expiry: fixtures::EXPIRY,
            claim_key_hash: owner::key_hash(fixtures::claim_key()),
            register_key,
            feed_r,
            feed_ct,
            payload_commitment: 0x9a10ad,
            claim,
            token: fixtures::TOKEN,
            owner_key: fixtures::owner_key(),
            nk: fixtures::OWNER_NK,
            claim_key: fixtures::claim_key(),
            signature,
            inputs,
            outputs,
            output_locks,
            input_attestation: w_owner,
            output_attestations: [witness_for(outputs[0].owner), witness_for(outputs[1].owner)],
            feed_secret,
        }
    }

    // Owner path: two inputs, the second under a holding period that ended at
    // epoch 50; 600 units to RECIPIENT and 400 back to the owner.
    fn owner_path() -> Fixture {
        let hold = LockOpening { reason: domain::LOCK_HOLD, release_after: 50, claim_party: 0 };
        build(
            false,
            [input(700, 0x11, NO_LOCK), input(300, 0x22, hold)],
            [output(600, RECIPIENT, 0x33, NO_LOCK), output(400, owner_in(), 0x44, NO_LOCK)],
            FAR,
            SIG_OWNER_PATH,
        )
    }

    // Owner path, one input padded with a zero-unit note.
    fn padded() -> Fixture {
        build(
            false,
            [input(1000, 0x11, NO_LOCK), input(0, 0x55, NO_LOCK)],
            [output(1000, RECIPIENT, 0x33, NO_LOCK), output(0, owner_in(), 0x44, NO_LOCK)],
            FAR,
            SIG_PADDED,
        )
    }

    // Claim path: the agent freezes a lapsed holder's note in place.
    fn freeze() -> Fixture {
        let freeze = LockOpening {
            reason: domain::LOCK_FREEZE,
            release_after: 0xffffffffffffffff,
            claim_party: 0,
        };
        build(
            true,
            [input(1000, 0x11, NO_LOCK), input(0, 0x55, NO_LOCK)],
            [output(1000, owner_in(), 0x66, freeze), output(0, owner_in(), 0x77, NO_LOCK)],
            LAPSED,
            SIG_FREEZE,
        )
    }

    // Claim path: the agent seizes a lapsed holder's note to an attested new
    // owner (RECIPIENT stands for the agent's own owner value or a beneficiary).
    fn seize() -> Fixture {
        build(
            true,
            [input(1000, 0x11, NO_LOCK), input(0, 0x55, NO_LOCK)],
            [output(1000, RECIPIENT, 0x88, NO_LOCK), output(0, owner_in(), 0x99, NO_LOCK)],
            LAPSED,
            SIG_SEIZE,
        )
    }

    // Claim path: the agent releases a frozen note in place, unlocked.
    fn release() -> Fixture {
        let freeze = LockOpening {
            reason: domain::LOCK_FREEZE,
            release_after: 0xffffffffffffffff,
            claim_party: 0,
        };
        build(
            true,
            [input(1000, 0x66, freeze), input(0, 0x55, NO_LOCK)],
            [output(1000, owner_in(), 0xaa, NO_LOCK), output(0, owner_in(), 0xbb, NO_LOCK)],
            FAR,
            SIG_RELEASE,
        )
    }

    // Owner path: 700 and 300 in, 600 and 399 out. Signed, so conservation is
    // the only rule it breaks.
    fn burn() -> Fixture {
        build(
            false,
            [input(700, 0x11, NO_LOCK), input(300, 0x22, NO_LOCK)],
            [output(600, RECIPIENT, 0x33, NO_LOCK), output(399, owner_in(), 0x44, NO_LOCK)],
            FAR,
            SIG_BURN,
        )
    }

    // Claim path: a hand-out with a holding period (SPEC, Subscription, step
    // 3). The agent's note pays 600 to RECIPIENT, locked until epoch 400, and
    // keeps 400 as change.
    fn held_hand_out() -> Fixture {
        let hold = LockOpening { reason: domain::LOCK_HOLD, release_after: 400, claim_party: 0 };
        build(
            true,
            [input(1000, 0x11, NO_LOCK), input(0, 0x55, NO_LOCK)],
            [output(600, RECIPIENT, 0xcc, hold), output(400, owner_in(), 0xdd, NO_LOCK)],
            FAR,
            SIG_HELD_HAND_OUT,
        )
    }

    fn digest_of(f: Fixture) -> Field {
        digest_with_path(f, f.claim as Field)
    }

    fn digest_with_path(f: Fixture, path: Field) -> Field {
        plan::digest(
            Plan {
                chain_id: f.chain_id,
                pool: f.pool,
                op: domain::OP_TRANSFER,
                path,
                nullifiers: [f.nullifier_0, f.nullifier_1],
                outputs: [f.commitment_out_0, f.commitment_out_1],
                public_units: 0,
                recipient: 0,
                expiry: f.expiry,
            },
        )
    }

    fn run(f: Fixture) {
        main(
            f.nullifier_0,
            f.nullifier_1,
            f.commitment_out_0,
            f.commitment_out_1,
            f.commitment_root,
            f.attestation_root,
            f.min_accepted_generation,
            f.epoch,
            f.chain_id,
            f.pool,
            f.claim_key_hash,
            f.register_key,
            f.feed_r,
            f.feed_ct,
            f.payload_commitment,
            f.claim,
            f.token,
            f.owner_key,
            f.nk,
            f.claim_key,
            f.signature,
            f.expiry,
            f.inputs,
            f.outputs,
            f.output_locks,
            f.input_attestation,
            f.output_attestations,
            f.feed_secret,
        );
    }

    #[test]
    fn test_print_digests() {
        std::println(digest_of(owner_path()));
        std::println(digest_of(padded()));
        std::println(digest_of(freeze()));
        std::println(digest_of(seize()));
        std::println(digest_of(release()));
        std::println(digest_of(burn()));
        std::println(digest_of(held_hand_out()));
        // For the signer tests: the freeze plan with the owner path's `path`.
        std::println(digest_with_path(freeze(), domain::PATH_OWNER));
    }

    #[test]
    fn test_owner_path_happy() {
        run(owner_path());
    }

    #[test]
    fn test_owner_path_padded_single_input() {
        run(padded());
    }

    #[test]
    fn test_claim_path_freezes_lapsed_holder_in_place() {
        run(freeze());
    }

    #[test]
    fn test_claim_path_seizes_lapsed_holders_note_to_attested_owner() {
        run(seize());
    }

    #[test]
    fn test_claim_path_releases_frozen_note_in_place() {
        run(release());
    }

    #[test]
    fn test_claim_path_hands_out_a_held_note() {
        run(held_hand_out());
    }

    #[test(should_fail_with = "units not conserved")]
    fn test_units_not_conserved_fails() {
        let mut f = owner_path();
        f.outputs[0].units = 601;
        f.commitment_out_0 = f.outputs[0].commitment();
        run(f);
    }

    #[test(should_fail_with = "units not conserved")]
    fn test_units_burned_fails() {
        run(burn());
    }

    #[test(should_fail_with = "attempt to add with overflow")]
    fn test_units_overflow_traps() {
        // Both inputs are in the tree, so the proof reaches the sum.
        let f = build(
            false,
            [input(0xffffffffffffffff, 0x11, NO_LOCK), input(1, 0x22, NO_LOCK)],
            [output(0, RECIPIENT, 0x33, NO_LOCK), output(0, owner_in(), 0x44, NO_LOCK)],
            FAR,
            SIG_OWNER_PATH,
        );
        run(f);
    }

    #[test(should_fail_with = "nullifier mismatch")]
    fn test_wrong_nullifier_0_fails() {
        let mut f = owner_path();
        f.nullifier_0 = f.nullifier_0 + 1;
        run(f);
    }

    #[test(should_fail_with = "nullifier mismatch")]
    fn test_wrong_nullifier_1_fails() {
        let mut f = owner_path();
        f.nullifier_1 = f.nullifier_1 + 1;
        run(f);
    }

    #[test(should_fail_with = "merkle proof failed")]
    fn test_input_not_in_tree_fails() {
        let mut f = owner_path();
        f.inputs[0].salt = 0x99;
        run(f);
    }

    #[test(should_fail_with = "merkle proof failed")]
    fn test_input_1_not_in_tree_fails() {
        // Input 1 carries units, so it must be in the tree; its path no longer
        // leads to the root.
        let mut f = owner_path();
        f.inputs[1].path[0] = f.inputs[1].path[0] + 1;
        run(f);
    }

    #[test(should_fail_with = "commitment mismatch")]
    fn test_wrong_commitment_out_0_fails() {
        let mut f = owner_path();
        f.commitment_out_0 = f.commitment_out_0 + 1;
        run(f);
    }

    #[test(should_fail_with = "commitment mismatch")]
    fn test_wrong_commitment_out_1_fails() {
        let mut f = owner_path();
        f.commitment_out_1 = f.commitment_out_1 + 1;
        run(f);
    }

    #[test(should_fail_with = "token mismatch")]
    fn test_output_0_with_another_token_fails() {
        let mut f = owner_path();
        f.outputs[0].token = f.outputs[0].token + 1;
        f.commitment_out_0 = f.outputs[0].commitment();
        run(f);
    }

    #[test(should_fail_with = "token mismatch")]
    fn test_output_1_with_another_token_fails() {
        let mut f = owner_path();
        f.outputs[1].token = f.outputs[1].token + 1;
        f.commitment_out_1 = f.outputs[1].commitment();
        run(f);
    }

    #[test(should_fail_with = "call to assert_max_bit_size")]
    fn test_oversized_token_fails() {
        let mut f = owner_path();
        f.token = 0x10000000000000000000000000000000000000000;
        run(f);
    }

    #[test(should_fail_with = "merkle proof failed")]
    fn test_another_owners_note_fails() {
        // A different nk derives a different owner value, so the commitment the
        // circuit rebuilds is not in the tree.
        let mut f = owner_path();
        f.nk = f.nk + 1;
        run(f);
    }

    #[test(should_fail_with = "attestation expired")]
    fn test_owner_path_lapsed_owner_fails() {
        // Both outputs go to an attested third party, so only the input
        // owner's own attestation can fail.
        let hold = LockOpening { reason: domain::LOCK_HOLD, release_after: 50, claim_party: 0 };
        let f = build(
            false,
            [input(700, 0x11, NO_LOCK), input(300, 0x22, hold)],
            [output(600, RECIPIENT, 0x33, NO_LOCK), output(400, RECIPIENT, 0x44, NO_LOCK)],
            LAPSED,
            SIG_OWNER_PATH,
        );
        run(f);
    }

    #[test(should_fail_with = "note is locked")]
    fn test_owner_path_frozen_input_fails() {
        let f = freeze();
        // The frozen note from the freeze scenario, spent by its owner.
        let frozen = f.outputs[0];
        let g = build(
            false,
            [
                input(
                    1000,
                    frozen.salt,
                    LockOpening {
                        reason: domain::LOCK_FREEZE,
                        release_after: 0xffffffffffffffff,
                        claim_party: 0,
                    },
                ),
                input(0, 0x55, NO_LOCK),
            ],
            [output(1000, RECIPIENT, 0x33, NO_LOCK), output(0, owner_in(), 0x44, NO_LOCK)],
            FAR,
            SIG_PADDED,
        );
        run(g);
    }

    #[test(should_fail_with = "note is locked")]
    fn test_owner_path_frozen_input_1_fails() {
        let freeze = LockOpening {
            reason: domain::LOCK_FREEZE,
            release_after: 0xffffffffffffffff,
            claim_party: 0,
        };
        let f = build(
            false,
            [input(700, 0x11, NO_LOCK), input(300, 0x22, freeze)],
            [output(600, RECIPIENT, 0x33, NO_LOCK), output(400, owner_in(), 0x44, NO_LOCK)],
            FAR,
            SIG_OWNER_PATH,
        );
        run(f);
    }

    #[test(should_fail_with = "owner path cannot create locks")]
    fn test_owner_path_locked_output_fails() {
        let mut f = owner_path();
        f.outputs[0].lock = 0x10c4;
        f.commitment_out_0 = f.outputs[0].commitment();
        run(f);
    }

    #[test(should_fail_with = "owner path cannot create locks")]
    fn test_owner_path_locked_output_1_fails() {
        let mut f = owner_path();
        f.outputs[1].lock = 0x10c4;
        f.commitment_out_1 = f.outputs[1].commitment();
        run(f);
    }

    #[test(should_fail_with = "merkle proof failed")]
    fn test_unattested_recipient_fails() {
        let mut f = owner_path();
        f.outputs[0].owner = 0xbad;
        f.commitment_out_0 = f.outputs[0].commitment();
        run(f);
    }

    #[test(should_fail_with = "merkle proof failed")]
    fn test_unattested_output_1_fails() {
        let mut f = owner_path();
        f.outputs[1].owner = 0xbad;
        f.commitment_out_1 = f.outputs[1].commitment();
        run(f);
    }

    #[test(should_fail_with = "merkle proof failed")]
    fn test_claim_path_to_unattested_owner_fails() {
        let mut f = freeze();
        f.outputs[0].owner = 0xbad;
        f.commitment_out_0 = f.outputs[0].commitment();
        run(f);
    }

    #[test(should_fail_with = "feed mismatch")]
    fn test_tampered_feed_r_fails() {
        let mut f = owner_path();
        f.feed_r[0] = f.feed_r[0] + 1;
        run(f);
    }

    #[test(should_fail_with = "feed mismatch")]
    fn test_tampered_feed_output_0_fails() {
        let mut f = owner_path();
        f.feed_ct[1] = f.feed_ct[1] + 1;
        run(f);
    }

    #[test(should_fail_with = "feed mismatch")]
    fn test_tampered_feed_output_1_fails() {
        let mut f = owner_path();
        f.feed_ct[domain::FEED_FIELDS + 1] = f.feed_ct[domain::FEED_FIELDS + 1] + 1;
        run(f);
    }

    #[test(should_fail_with = "lock terms mismatch")]
    fn test_feed_with_other_lock_terms_fails() {
        // The freeze is bound to its terms; a feed claiming a holding period
        // instead does not match the output's lock.
        let mut f = freeze();
        f.output_locks[0] =
            LockOpening { reason: domain::LOCK_HOLD, release_after: 400, claim_party: 0 };
        run(f);
    }

    #[test(should_fail_with = "lock terms mismatch")]
    fn test_feed_with_terms_on_an_unlocked_output_fails() {
        let mut f = owner_path();
        f.output_locks[0] =
            LockOpening { reason: domain::LOCK_HOLD, release_after: 400, claim_party: 0 };
        run(f);
    }

    #[test(should_fail_with = "plan expired")]
    fn test_expired_plan_fails() {
        let mut f = owner_path();
        f.expiry = (f.epoch + 1) * domain::EPOCH_SECONDS - 1;
        run(f);
    }

    #[test(should_fail_with = "claim key mismatch")]
    fn test_claim_path_wrong_claim_key_fails() {
        let mut f = freeze();
        f.claim_key_hash = f.claim_key_hash + 1;
        run(f);
    }

    // The two signatures below are valid for what they sign, so each test
    // fails only on the one thing it changes: the key, or the path.
    #[test]
    fn test_signer_test_signatures_are_valid() {
        plan::verify_signature(
            fixtures::owner_key(),
            SIG_FREEZE_BY_OWNER,
            digest_of(freeze()),
        );
        plan::verify_signature(
            fixtures::claim_key(),
            SIG_FREEZE_AS_OWNER_PATH,
            digest_with_path(freeze(), domain::PATH_OWNER),
        );
    }

    #[test(should_fail_with = "invalid plan signature")]
    fn test_claim_path_rejects_the_owners_signature() {
        // The freeze plan exactly, signed by the owner's key instead of the
        // claim key.
        let mut f = freeze();
        f.signature = SIG_FREEZE_BY_OWNER;
        run(f);
    }

    #[test(should_fail_with = "invalid plan signature")]
    fn test_claim_path_rejects_a_signature_over_the_owner_path() {
        // The claim key signed the freeze plan with the owner path's `path`;
        // the digests differ only in the path.
        let mut f = freeze();
        f.signature = SIG_FREEZE_AS_OWNER_PATH;
        run(f);
    }

    // Call sites: the library's own tests check lapse, the generation floor
    // and holds; these check that this circuit calls them with its epoch
    // and floor, so a slip at a call site cannot switch a rule off.

    fn hold_until(epoch: u64) -> LockOpening {
        LockOpening { reason: domain::LOCK_HOLD, release_after: epoch, claim_party: 0 }
    }

    // Input 1 is held until epoch 50; at epoch 49 the owner path refuses it.
    #[test(should_fail_with = "note is locked")]
    fn test_owner_path_input_1_before_its_release_fails() {
        let mut f = owner_path();
        f.epoch = 49;
        run(f);
    }

    // Input 0 is held until epoch 101 and spent at epoch 100. The lock check
    // fails before the signature's, so the fixture's signature does not matter.
    #[test(should_fail_with = "note is locked")]
    fn test_owner_path_input_0_before_its_release_fails() {
        let f = build(
            false,
            [input(700, 0x11, hold_until(101)), input(300, 0x22, NO_LOCK)],
            [output(600, RECIPIENT, 0x33, NO_LOCK), output(400, owner_in(), 0x44, NO_LOCK)],
            FAR,
            SIG_OWNER_PATH,
        );
        run(f);
    }

    // The input owner's attestation covers epoch 100 only; at epoch 101 it
    // has lapsed. Both outputs go to RECIPIENT, so only the input owner's
    // attestation can fail.
    #[test(should_fail_with = "attestation expired")]
    fn test_owner_path_lapsed_input_owner_fails() {
        let mut f = build(
            false,
            [input(700, 0x11, NO_LOCK), input(300, 0x22, hold_until(50))],
            [output(600, RECIPIENT, 0x33, NO_LOCK), output(400, RECIPIENT, 0x44, NO_LOCK)],
            101 * domain::EPOCH_SECONDS,
            SIG_OWNER_PATH,
        );
        f.epoch = 101;
        run(f);
    }

    // A payment made in epoch 101 to a recipient whose attestation lapsed at
    // the end of epoch 100. The plan is unchanged, so only the recipient's
    // attestation can fail.
    #[test(should_fail_with = "attestation expired")]
    fn test_owner_path_to_a_lapsed_recipient_fails() {
        let mut f = owner_path();
        let (w_owner, w_recipient, root) =
            attestation::two_leaf_fixture(owner_in(), FAR, RECIPIENT, 101 * domain::EPOCH_SECONDS);
        f.attestation_root = root;
        f.input_attestation = w_owner;
        f.output_attestations = [w_recipient, w_owner];
        f.epoch = 101;
        run(f);
    }

    // Two leaves with different generations: the owner's at gen_owner, RECIPIENT's at gen_recipient.
    fn generations(
        gen_owner: u64,
        gen_recipient: u64,
    ) -> (AttestationWitness, AttestationWitness, Field) {
        let (mut wa, mut wb, _) = attestation::two_leaf_fixture(owner_in(), FAR, RECIPIENT, FAR);
        wa.generation = gen_owner;
        wb.generation = gen_recipient;
        let la = attestation::leaf(owner_in(), wa);
        let lb = attestation::leaf(RECIPIENT, wb);
        wa.path[0] = lb;
        wb.path[0] = la;
        (wa, wb, hash_2([la, lb]))
    }

    // The input owner's leaf is from a retired generation.
    #[test(should_fail_with = "attestation generation retired")]
    fn test_owner_path_retired_input_owner_fails() {
        let mut f = build(
            false,
            [input(700, 0x11, NO_LOCK), input(300, 0x22, hold_until(50))],
            [output(600, RECIPIENT, 0x33, NO_LOCK), output(400, RECIPIENT, 0x44, NO_LOCK)],
            FAR,
            SIG_OWNER_PATH,
        );
        let (w_owner, w_recipient, root) = generations(1, 2);
        f.attestation_root = root;
        f.input_attestation = w_owner;
        f.output_attestations = [w_recipient, w_recipient];
        f.min_accepted_generation = 2;
        run(f);
    }

    // A seizure to an owner whose leaf is from a retired generation.
    #[test(should_fail_with = "attestation generation retired")]
    fn test_claim_path_to_a_retired_owner_fails() {
        let mut f = seize();
        f.min_accepted_generation = 2;
        run(f);
    }
}

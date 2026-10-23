use sn_lib::attestation::{self, AttestationWitness};
use sn_lib::domain;
use sn_lib::feed::{self, FeedSecret};
use sn_lib::lock::NO_LOCK;
use sn_lib::note::Note;
use sn_lib::owner::{self, SpendKey};
use sn_lib::plan::{self, Plan};

// Deposit: mints one unlocked note for the owner value it names, authorized by
// that owner's signature over a plan naming `funding_address`. The pool pulls
// the shares from `funding_address`, which MUST be the caller.
// Public-input order MUST match `DepositPublicInputs` in
// `contracts/src/PublicInputs.sol` index for index.
fn main(
    commitment: pub Field,
    token: pub Field,
    units: pub u64,
    funding_address: pub Field,
    attestation_root: pub Field,
    min_accepted_generation: pub u64,
    epoch: pub u64,
    chain_id: pub Field,
    pool: pub Field,
    register_key: pub [Field; 2],
    feed_r: pub [Field; 2],
    feed_ct: pub [Field; domain::FEED_FIELDS],
    payload_commitment: pub Field,
    owner_key: SpendKey,
    nk: Field,
    signature: [u8; 64],
    expiry: u64,
    salt: Field,
    attestation_witness: AttestationWitness,
    feed_secret: FeedSecret,
) {
    // Unconstrained here: the contract checks it against keccak256 of the
    // recipient payload it emits, which ties the payload to this proof.
    let _ = payload_commitment;
    token.assert_max_bit_size::<160>();
    funding_address.assert_max_bit_size::<160>();

    let owner = owner::owner_value(owner_key, nk);
    let note = Note { token, units, owner, salt, lock: 0 };
    assert(commitment == note.commitment(), "commitment mismatch");

    attestation::verify(
        owner,
        attestation_witness,
        epoch,
        min_accepted_generation,
        attestation_root,
    );

    let (derived_r, k) = feed::derive(feed_secret, register_key);
    assert(feed_r == derived_r, "feed mismatch");
    assert(feed_ct == feed::encrypt(k, note, NO_LOCK, 0), "feed mismatch");

    plan::check_expiry(epoch, expiry);
    let digest = plan::digest(
        Plan {
            chain_id,
            pool,
            op: domain::OP_DEPOSIT,
            path: domain::PATH_OWNER,
            nullifiers: [0, 0],
            outputs: [commitment, 0],
            public_units: units as Field,
            recipient: funding_address,
            expiry,
        },
    );
    plan::verify_signature(owner_key, signature, digest);
}

mod tests {
    use super::main;
    use sn_lib::attestation::{self, AttestationWitness};
    use sn_lib::domain;
    use sn_lib::feed::{self, FeedSecret};
    use sn_lib::fixtures;
    use sn_lib::lock::NO_LOCK;
    use sn_lib::note::Note;
    use sn_lib::owner::{self, SpendKey};
    use sn_lib::plan::{self, Plan};

    global FUNDER: Field = 0x70997970c51812dc3a010c7d01b50e0d17dc79c8;
    global UNITS: u64 = 1_000_000;

    struct Fixture {
        commitment: Field,
        token: Field,
        units: u64,
        funding_address: Field,
        attestation_root: Field,
        min_accepted_generation: u64,
        epoch: u64,
        chain_id: Field,
        pool: Field,
        expiry: u64,
        register_key: [Field; 2],
        feed_r: [Field; 2],
        feed_ct: [Field; domain::FEED_FIELDS],
        payload_commitment: Field,
        owner_key: SpendKey,
        nk: Field,
        signature: [u8; 64],
        salt: Field,
        attestation_witness: AttestationWitness,
        feed_secret: FeedSecret,
    }

    // Signature by test secret 0x0b over this fixture's plan digest, from
    // `cargo run --example sign_digest -- 0x0b <digest>`. Regenerate it with
    // `nargo test --show-output test_print_digest` whenever the fixture changes.
    global SIGNATURE: [u8; 64] = [
        121, 63, 243, 18, 102, 31, 27, 130, 170, 221, 14, 9, 227, 156, 212, 156, 252, 184, 48, 118,
        63, 30, 190, 240, 205, 3, 250, 0, 88, 185, 165, 136, 113, 132, 155, 90, 113, 125, 156, 147,
        72, 186, 255, 93, 211, 89, 124, 160, 166, 228, 248, 103, 19, 61, 138, 112, 244, 61, 12, 9,
        176, 144, 247, 163,
    ];

    fn valid_fixture() -> Fixture {
        let owner_key = fixtures::owner_key();
        let nk = fixtures::OWNER_NK;
        let owner = owner::owner_value(owner_key, nk);
        let salt: Field = 0xabcd;
        let note = Note { token: fixtures::TOKEN, units: UNITS, owner, salt, lock: 0 };
        let commitment = note.commitment();
        let (attestation_witness, attestation_root) =
            attestation::single_leaf_fixture(owner, 200 * domain::EPOCH_SECONDS);
        let register_key = feed::register_key_of(FeedSecret { lo: 0x7777, hi: 0x1 });
        let feed_secret = FeedSecret { lo: 0x1234, hi: 0x5678 };
        let (feed_r, k) = feed::derive(feed_secret, register_key);
        let feed_ct = feed::encrypt(k, note, NO_LOCK, 0);
        Fixture {
            commitment,
            token: fixtures::TOKEN,
            units: UNITS,
            funding_address: FUNDER,
            attestation_root,
            min_accepted_generation: 1,
            epoch: fixtures::EPOCH,
            chain_id: fixtures::CHAIN_ID,
            pool: fixtures::POOL,
            expiry: fixtures::EXPIRY,
            register_key,
            feed_r,
            feed_ct,
            payload_commitment: 0x9a10ad,
            owner_key,
            nk,
            signature: SIGNATURE,
            salt,
            attestation_witness,
            feed_secret,
        }
    }

    fn digest_of(f: Fixture) -> Field {
        plan::digest(
            Plan {
                chain_id: f.chain_id,
                pool: f.pool,
                op: domain::OP_DEPOSIT,
                path: domain::PATH_OWNER,
                nullifiers: [0, 0],
                outputs: [f.commitment, 0],
                public_units: f.units as Field,
                recipient: f.funding_address,
                expiry: f.expiry,
            },
        )
    }

    fn run(f: Fixture) {
        main(
            f.commitment,
            f.token,
            f.units,
            f.funding_address,
            f.attestation_root,
            f.min_accepted_generation,
            f.epoch,
            f.chain_id,
            f.pool,
            f.register_key,
            f.feed_r,
            f.feed_ct,
            f.payload_commitment,
            f.owner_key,
            f.nk,
            f.signature,
            f.expiry,
            f.salt,
            f.attestation_witness,
            f.feed_secret,
        );
    }

    #[test]
    fn test_print_digest() {
        std::println(digest_of(valid_fixture()));
    }

    #[test]
    fn test_deposit_happy_path() {
        run(valid_fixture());
    }

    #[test(should_fail_with = "commitment mismatch")]
    fn test_deposit_wrong_units_fails() {
        let mut f = valid_fixture();
        f.units = UNITS + 1;
        run(f);
    }

    #[test(should_fail_with = "commitment mismatch")]
    fn test_deposit_for_another_owner_fails() {
        // The commitment is built for this nk's owner value; a different nk
        // derives a different owner, so the note cannot be minted to it.
        let mut f = valid_fixture();
        f.nk = f.nk + 1;
        run(f);
    }

    #[test(should_fail_with = "attestation expired")]
    fn test_deposit_expired_attestation_fails() {
        let mut f = valid_fixture();
        f.epoch = 200;
        run(f);
    }

    #[test(should_fail_with = "feed mismatch")]
    fn test_deposit_tampered_feed_fails() {
        let mut f = valid_fixture();
        f.feed_ct[1] = f.feed_ct[1] + 1;
        run(f);
    }

    #[test(should_fail_with = "feed mismatch")]
    fn test_deposit_tampered_feed_r_fails() {
        let mut f = valid_fixture();
        f.feed_r[0] = f.feed_r[0] + 1;
        run(f);
    }

    #[test(should_fail_with = "feed mismatch")]
    fn test_deposit_feed_to_another_register_key_fails() {
        let mut f = valid_fixture();
        f.register_key = feed::register_key_of(FeedSecret { lo: 0x8888, hi: 0x1 });
        run(f);
    }

    #[test(should_fail_with = "plan expired")]
    fn test_deposit_expired_plan_fails() {
        let mut f = valid_fixture();
        f.expiry = (f.epoch + 1) * domain::EPOCH_SECONDS - 1;
        run(f);
    }

    #[test(should_fail_with = "invalid plan signature")]
    fn test_deposit_signature_over_another_plan_fails() {
        let mut f = valid_fixture();
        f.expiry = f.expiry + 1;
        run(f);
    }

    #[test(should_fail_with = "invalid plan signature")]
    fn test_deposit_redirected_funding_address_fails() {
        let mut f = valid_fixture();
        f.funding_address = f.funding_address + 1;
        run(f);
    }

    #[test(should_fail_with = "call to assert_max_bit_size")]
    fn test_deposit_oversized_token_fails() {
        let mut f = valid_fixture();
        f.token = 0x10000000000000000000000000000000000000000;
        run(f);
    }

    #[test(should_fail_with = "call to assert_max_bit_size")]
    fn test_deposit_oversized_funding_address_fails() {
        let mut f = valid_fixture();
        f.funding_address = 0x10000000000000000000000000000000000000000;
        run(f);
    }

    // Call sites: the library's own tests check lapse, the generation floor
    // and holds; these check that this circuit calls them with its epoch
    // and floor, so a slip at a call site cannot switch a rule off.

    // An owner attested under a retired generation cannot deposit.
    #[test(should_fail_with = "attestation generation retired")]
    fn test_retired_generation_fails() {
        let mut f = valid_fixture();
        f.min_accepted_generation = 2;
        run(f);
    }
}

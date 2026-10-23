use crate::domain;
use crate::hasher::{hash_2, hash_3};
use crate::lock::LockOpening;
use crate::note::Note;
use std::embedded_curve_ops::{
    EmbeddedCurvePoint, EmbeddedCurveScalar, fixed_base_scalar_mul, multi_scalar_mul,
};

// The sender's ephemeral Grumpkin scalar `r`, as two 128-bit limbs. Fresh per
// proof; the wallet MUST NOT reuse it.
pub struct FeedSecret {
    pub lo: Field,
    pub hi: Field,
}

fn scalar(secret: FeedSecret) -> EmbeddedCurveScalar {
    secret.lo.assert_max_bit_size::<128>();
    secret.hi.assert_max_bit_size::<128>();
    EmbeddedCurveScalar { lo: secret.lo, hi: secret.hi }
}

// R = r*G, and k = Poseidon1(FEED_TAG, rt.x, rt.y) with rt = r*tpk.
pub fn derive(secret: FeedSecret, register_key: [Field; 2]) -> ([Field; 2], Field) {
    let r = scalar(secret);
    let big_r = fixed_base_scalar_mul(r);
    // r = 0 gives the point at infinity, encoded (0, 0), and a key anyone can
    // compute. No other point has x = y = 0: y^2 = x^3 - 17 has no such point.
    assert((big_r.x != 0) | (big_r.y != 0), "feed point at infinity");
    let tpk = EmbeddedCurvePoint { x: register_key[0], y: register_key[1] };
    let rt = multi_scalar_mul([tpk], [r]);
    ([big_r.x, big_r.y], hash_3([domain::FEED_TAG, rt.x, rt.y]))
}

// Output j's feed fields: the note's opening, then its lock terms.
pub fn fields(note: Note, terms: LockOpening) -> [Field; domain::FEED_FIELDS] {
    let n = note.fields();
    [n[0], n[1], n[2], n[3], n[4], terms.reason, terms.release_after as Field, terms.claim_party]
}

// ct[j][i] = f_i + Poseidon1(k, 8*j + i), for output j's feed fields f.
pub fn encrypt(k: Field, note: Note, terms: LockOpening, j: u32) -> [Field; domain::FEED_FIELDS] {
    let f = fields(note, terms);
    let mut ct = [0; domain::FEED_FIELDS];
    for i in 0..domain::FEED_FIELDS {
        ct[i] = f[i] + hash_2([k, (domain::FEED_FIELDS * j + i) as Field]);
    }
    ct
}

// The agent's side: rt = tk*R, then subtract the keystream.
pub fn decrypt(
    tk: FeedSecret,
    feed_r: [Field; 2],
    ct: [Field; domain::FEED_FIELDS],
    j: u32,
) -> [Field; domain::FEED_FIELDS] {
    let rt = multi_scalar_mul(
        [EmbeddedCurvePoint { x: feed_r[0], y: feed_r[1] }],
        [scalar(tk)],
    );
    let k = hash_3([domain::FEED_TAG, rt.x, rt.y]);
    let mut f = [0; domain::FEED_FIELDS];
    for i in 0..domain::FEED_FIELDS {
        f[i] = ct[i] - hash_2([k, (domain::FEED_FIELDS * j + i) as Field]);
    }
    f
}

pub fn register_key_of(tk: FeedSecret) -> [Field; 2] {
    let p = fixed_base_scalar_mul(scalar(tk));
    [p.x, p.y]
}

#[test]
fn test_agent_decrypts_what_the_sender_encrypts() {
    let tk = FeedSecret { lo: 0x7777, hi: 0x1 };
    let tpk = register_key_of(tk);
    let terms = LockOpening { reason: domain::LOCK_HOLD, release_after: 400, claim_party: 0 };
    let note = Note {
        token: 0xc0ffee,
        units: 1000,
        owner: 0xbeef,
        salt: 0x5a17,
        lock: crate::lock::lock_value(terms),
    };
    let (feed_r, k) = derive(FeedSecret { lo: 0x1234, hi: 0x5678 }, tpk);
    let ct = encrypt(k, note, terms, 1);
    assert(decrypt(tk, feed_r, ct, 1) == fields(note, terms));
    assert(decrypt(FeedSecret { lo: 0x7778, hi: 0x1 }, feed_r, ct, 1) != fields(note, terms));
}

#[test(should_fail_with = "call to assert_max_bit_size")]
fn test_oversized_low_limb_fails() {
    let tpk = register_key_of(FeedSecret { lo: 0x7777, hi: 0x1 });
    let _ = derive(
        FeedSecret { lo: 0x100000000000000000000000000000000, hi: 0 },
        tpk,
    );
}

#[test(should_fail_with = "call to assert_max_bit_size")]
fn test_oversized_high_limb_fails() {
    let tpk = register_key_of(FeedSecret { lo: 0x7777, hi: 0x1 });
    let _ = derive(
        FeedSecret { lo: 0, hi: 0x100000000000000000000000000000000 },
        tpk,
    );
}

#[test(should_fail_with = "feed point at infinity")]
fn test_zero_scalar_fails() {
    let tpk = register_key_of(FeedSecret { lo: 0x7777, hi: 0x1 });
    let _ = derive(FeedSecret { lo: 0, hi: 0 }, tpk);
}

// Known answer, also pinned in `src/domain/feed.rs`: a two-output feed under
// the parity vectors' keys, hashed to one value. It fixes the field order and
// the keystream index, which a change made on both sides at once would leave
// every round-trip test passing.
#[test]
fn test_known_answer_two_outputs() {
    let tpk = register_key_of(FeedSecret { lo: 0x7777, hi: 0x1 });
    let (_, k) = derive(FeedSecret { lo: 0x1234, hi: 0x5678 }, tpk);
    let hold = LockOpening { reason: domain::LOCK_HOLD, release_after: 400, claim_party: 0 };
    let held = Note { token: 1, units: 2, owner: 3, salt: 4, lock: crate::lock::lock_value(hold) };
    let free = Note { token: 1, units: 5, owner: 6, salt: 7, lock: 0 };
    let ct0 = encrypt(k, held, hold, 0);
    let ct1 = encrypt(k, free, crate::lock::NO_LOCK, 1);
    let mut all = [0; 2 * domain::FEED_FIELDS];
    for i in 0..domain::FEED_FIELDS {
        all[i] = ct0[i];
        all[domain::FEED_FIELDS + i] = ct1[i];
    }
    assert(
        crate::hasher::sponge(all)
            == 0x2f51828023fd41a233ed1374bb09f441a20bba5102c048c6abb2268c1746b1a9,
    );
}

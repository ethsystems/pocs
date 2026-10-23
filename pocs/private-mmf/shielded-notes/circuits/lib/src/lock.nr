use crate::domain;
use crate::hasher::hash_4;

// A lock's terms (SPEC, Lock). The note stores only their hash.
pub struct LockOpening {
    pub reason: Field,
    pub release_after: u64,
    pub claim_party: Field,
}

pub global NO_LOCK: LockOpening = LockOpening { reason: 0, release_after: 0, claim_party: 0 };

// lock = Poseidon1(LOCK_TAG, reason, release_after, claim_party).
pub fn lock_value(opening: LockOpening) -> Field {
    hash_4(
        [domain::LOCK_TAG, opening.reason, opening.release_after as Field, opening.claim_party],
    )
}

// Owner-path rule for one input: an unlocked note passes; a locked note passes
// once its release epoch is reached. The opening is ignored for unlocked notes.
pub fn check_input(lock: Field, opening: LockOpening, epoch: u64) {
    if lock != 0 {
        assert(lock_value(opening) == lock, "lock opening mismatch");
        assert(epoch >= opening.release_after, "note is locked");
    }
}

// Binds an output's lock terms, as the register feed carries them, to its
// lock: they hash to `lock` with a FREEZE or HOLD reason, or are all zero when
// the note is unlocked. Any other reason, one of 2^64 or more included, would
// give the agent a feed record it cannot decode.
pub fn check_terms(lock: Field, terms: LockOpening) {
    if lock == 0 {
        assert(
            (terms.reason == 0) & (terms.release_after == 0) & (terms.claim_party == 0),
            "lock terms mismatch",
        );
    } else {
        assert(lock_value(terms) == lock, "lock terms mismatch");
        assert(
            (terms.reason == domain::LOCK_FREEZE) | (terms.reason == domain::LOCK_HOLD),
            "lock terms mismatch",
        );
    }
}

#[test]
fn test_unlocked_note_passes_with_any_opening() {
    check_input(
        0,
        LockOpening { reason: 9, release_after: 0xffffffffffffffff, claim_party: 9 },
        0,
    );
}

#[test]
fn test_hold_passes_from_its_release_epoch() {
    let opening = LockOpening { reason: domain::LOCK_HOLD, release_after: 400, claim_party: 0 };
    check_input(lock_value(opening), opening, 400);
}

#[test(should_fail_with = "note is locked")]
fn test_hold_fails_before_its_release_epoch() {
    let opening = LockOpening { reason: domain::LOCK_HOLD, release_after: 400, claim_party: 0 };
    check_input(lock_value(opening), opening, 399);
}

#[test(should_fail_with = "note is locked")]
fn test_freeze_never_releases() {
    let opening = LockOpening {
        reason: domain::LOCK_FREEZE,
        release_after: 0xffffffffffffffff,
        claim_party: 0,
    };
    check_input(lock_value(opening), opening, 0xfffffffffffffffe);
}

#[test(should_fail_with = "lock opening mismatch")]
fn test_wrong_opening_fails() {
    let freeze = LockOpening {
        reason: domain::LOCK_FREEZE,
        release_after: 0xffffffffffffffff,
        claim_party: 0,
    };
    let claimed = LockOpening { reason: domain::LOCK_HOLD, release_after: 1, claim_party: 0 };
    check_input(lock_value(freeze), claimed, 2);
}

#[test]
fn test_terms_of_a_lock_pass() {
    let opening = LockOpening { reason: domain::LOCK_HOLD, release_after: 400, claim_party: 0 };
    check_terms(lock_value(opening), opening);
    check_terms(0, NO_LOCK);
}

#[test(should_fail_with = "lock terms mismatch")]
fn test_other_terms_fail() {
    let hold = LockOpening { reason: domain::LOCK_HOLD, release_after: 400, claim_party: 0 };
    let other = LockOpening { reason: domain::LOCK_HOLD, release_after: 401, claim_party: 0 };
    check_terms(lock_value(hold), other);
}

#[test(should_fail_with = "lock terms mismatch")]
fn test_terms_on_an_unlocked_note_fail() {
    let hold = LockOpening { reason: domain::LOCK_HOLD, release_after: 400, claim_party: 0 };
    check_terms(0, hold);
}

// Each part of the zero-terms rule is needed: with any one dropped, an
// unlocked output could carry arbitrary terms in the register feed.
#[test(should_fail_with = "lock terms mismatch")]
fn test_a_reason_on_an_unlocked_note_fails() {
    check_terms(
        0,
        LockOpening { reason: domain::LOCK_FREEZE, release_after: 0, claim_party: 0 },
    );
}

#[test(should_fail_with = "lock terms mismatch")]
fn test_a_claim_party_on_an_unlocked_note_fails() {
    check_terms(
        0,
        LockOpening { reason: 0, release_after: 0, claim_party: 1 },
    );
}

// All-zero terms hash to a non-zero lock, but name no reason.
#[test(should_fail_with = "lock terms mismatch")]
fn test_a_lock_needs_a_reason() {
    check_terms(lock_value(NO_LOCK), NO_LOCK);
}

// A reason the agent cannot read as one of its own.
#[test(should_fail_with = "lock terms mismatch")]
fn test_a_lock_reason_outside_freeze_and_hold_fails() {
    let terms = LockOpening { reason: 0x10000000000000000, release_after: 0, claim_party: 0 };
    check_terms(lock_value(terms), terms);
}

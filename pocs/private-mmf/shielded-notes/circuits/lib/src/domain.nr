// Domain tags sit above 2^160, so no address-sized value can equal one, and
// above the base pool's tags (2^160 + 1 to 2^160 + 5), so the two pools never
// share a digest.
pub global NK_TAG: Field = 1461501637330902918203684832716283019655932542992;
pub global OWNER_TAG: Field = 1461501637330902918203684832716283019655932542993;
pub global LOCK_TAG: Field = 1461501637330902918203684832716283019655932542994;
pub global PLAN_TAG: Field = 1461501637330902918203684832716283019655932542995;
pub global FEED_TAG: Field = 1461501637330902918203684832716283019655932542996;

// Plan `op` and `path` values (SPEC, Transaction Plan).
pub global OP_DEPOSIT: Field = 1;
pub global OP_TRANSFER: Field = 2;
pub global OP_WITHDRAW: Field = 3;
pub global PATH_OWNER: Field = 0;
pub global PATH_CLAIM: Field = 1;

// Lock reasons (SPEC, Lock).
pub global LOCK_FREEZE: Field = 1;
pub global LOCK_HOLD: Field = 2;

pub global MAX_COMMITMENT_TREE_DEPTH: u32 = 32;
pub global MAX_ATTESTATION_TREE_DEPTH: u32 = 20;
pub global EPOCH_SECONDS: u64 = 86400;

// Fields per note opening: token, units, owner, salt, lock.
pub global NOTE_FIELDS: u32 = 5;

// Fields per output in the register feed: the note's opening, then its lock
// terms (reason, release_after, claim_party), all zero for an unlocked note.
pub global FEED_FIELDS: u32 = 8;

#[test]
fn test_tags_sit_above_the_base_tags() {
    let two_pow_160: Field = 1461501637330902918203684832716283019655932542976;
    assert(NK_TAG == two_pow_160 + 16);
    assert(OWNER_TAG == two_pow_160 + 17);
    assert(LOCK_TAG == two_pow_160 + 18);
    assert(PLAN_TAG == two_pow_160 + 19);
    assert(FEED_TAG == two_pow_160 + 20);
}

use crate::domain;
use crate::hasher::{hash_3, hash_4};
use crate::policy;

// 3 slots per permutation, padded so no length or projection crosses the
// policy interface.
pub global PADDED: u32 = 3 * ((policy::K + 2) / 3);

pub fn state_tag(policy_source_hash: Field) -> Field {
    hash_3(
        [domain::STATE_DOMAIN, policy_source_hash, policy::K as Field],
    )
}

pub fn commit(tag: Field, st: policy::State) -> Field {
    let mut p: [Field; PADDED] = [0; PADDED];
    for i in 0..policy::K {
        p[i] = st.s[i] as Field;
    }

    let mut acc = tag;
    for i in 0..(PADDED / 3) {
        acc = hash_4([acc, p[3 * i], p[3 * i + 1], p[3 * i + 2]]);
    }
    acc
}

// Cross-language parity vector: tag = 7, K = 1 state [42]. Rust's
// `policy::commit::commit::<ReferencePolicy>` on the same inputs must produce this
// same decimal.
#[test]
fn test_commit_parity_vector_tag_7_state_42() {
    let result = commit(7, policy::State { s: [42] });
    assert(result == 21596994159255025703084662498772874565058600479438079129086634022518144844191);
}

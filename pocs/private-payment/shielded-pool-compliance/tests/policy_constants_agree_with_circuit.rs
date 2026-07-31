//! `policy::K`, `SINGLE_TX_THRESHOLD`, and `AGGREGATE_THRESHOLD` are duplicated
//! literals today, in `circuits/lib/src/policy.nr`, `src/policy/reference.rs`, and
//! (until this closes it) `tests/aggregate_threshold_flag.rs`. This test reads the
//! Noir source and asserts the Rust constants agree with it, so a change to one alone
//! fails here rather than silently diverging.

use std::path::Path;

use shielded_pool_compliance::policy::{
    Policy,
    reference::{
        AGGREGATE_THRESHOLD,
        ReferencePolicy,
        SINGLE_TX_THRESHOLD,
    },
};

fn extract_u64(contents: &str, marker: &str) -> u64 {
    let start = contents
        .find(marker)
        .unwrap_or_else(|| panic!("marker `{marker}` not found in policy.nr"));
    let rest = &contents[start + marker.len()..];
    let end = rest
        .find(';')
        .expect("a Noir global declaration ends with `;`");
    let literal = rest[..end].trim().replace('_', "");
    literal.parse().unwrap_or_else(|_| {
        panic!("`{literal}` (from `{marker}`) is not a valid integer")
    })
}

#[test]
fn policy_constants_agree_with_the_noir_source() {
    let policy_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("circuits/lib/src/policy.nr");
    let contents = std::fs::read_to_string(&policy_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", policy_path.display()));

    let k = extract_u64(&contents, "pub global K: u32 =");
    let single_tx_threshold = extract_u64(&contents, "global SINGLE_TX_THRESHOLD: u64 =");
    let aggregate_threshold = extract_u64(&contents, "global AGGREGATE_THRESHOLD: u64 =");

    assert_eq!(
        k as usize,
        ReferencePolicy::K,
        "policy::K disagrees with policy.nr"
    );
    assert_eq!(
        single_tx_threshold, SINGLE_TX_THRESHOLD,
        "SINGLE_TX_THRESHOLD disagrees with policy.nr"
    );
    assert_eq!(
        aggregate_threshold, AGGREGATE_THRESHOLD,
        "AGGREGATE_THRESHOLD disagrees with policy.nr"
    );
}

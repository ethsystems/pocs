//! the checked-in `circuits/lib/src/policy_tag.nr` must be exactly what
//! `cargo run --bin policy-tag` would (re)generate from `circuits/lib/src/policy.nr`,
//! and `deployments.toml`'s `initial_policy_source_hash` must agree with it too. This
//! test does not regenerate anything; it fails loudly if either has drifted.

use std::path::Path;

use shielded_pool_compliance::{
    policy::{
        commit::state_tag,
        reference::ReferencePolicy,
        source_hash::policy_source_hash,
        tag_file::parse,
    },
    types::Bytes32,
};

fn manifest_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn configured_policy_source_hash(doc: &toml::Value, chain: &str) -> Bytes32 {
    let hex_value = doc
        .get(chain)
        .and_then(|t| t.get("bytes32"))
        .and_then(|t| t.get("initial_policy_source_hash"))
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| {
            panic!("deployments.toml [{chain}.bytes32] has no initial_policy_source_hash")
        });
    let bytes = hex::decode(hex_value.trim_start_matches("0x"))
        .expect("initial_policy_source_hash is valid hex");
    let array: [u8; 32] = bytes
        .try_into()
        .expect("initial_policy_source_hash is exactly 32 bytes");
    Bytes32::from(array)
}

#[test]
fn generated_tag_file_and_deployment_config_agree_with_the_policy_source() {
    let policy_path = manifest_dir().join("circuits/lib/src/policy.nr");
    let source_hash = policy_source_hash(&policy_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", policy_path.display()));
    let tag = state_tag::<ReferencePolicy>(source_hash);

    let tag_file_path = manifest_dir().join("circuits/lib/src/policy_tag.nr");
    let tag_file_contents = std::fs::read_to_string(&tag_file_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", tag_file_path.display()));
    let (checked_in_source_hash, checked_in_tag) = parse(&tag_file_contents)
        .expect("circuits/lib/src/policy_tag.nr has POLICY_SOURCE_HASH and STATE_TAG");

    assert_eq!(
        checked_in_source_hash, source_hash,
        "circuits/lib/src/policy_tag.nr's POLICY_SOURCE_HASH is stale relative to \
         circuits/lib/src/policy.nr; regenerate it with `cargo run --bin policy-tag`"
    );
    assert_eq!(
        checked_in_tag, tag,
        "circuits/lib/src/policy_tag.nr's STATE_TAG is stale relative to \
         circuits/lib/src/policy.nr; regenerate it with `cargo run --bin policy-tag`"
    );

    let deployments_path = manifest_dir().join("deployments.toml");
    let deployments_contents = std::fs::read_to_string(&deployments_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", deployments_path.display()));
    let doc: toml::Value =
        toml::from_str(&deployments_contents).expect("deployments.toml parses");

    for chain in ["31337", "11155111"] {
        let configured = configured_policy_source_hash(&doc, chain);
        assert_eq!(
            Bytes32::from(source_hash),
            configured,
            "deployments.toml [{chain}.bytes32].initial_policy_source_hash disagrees \
             with circuits/lib/src/policy.nr; a regeneration that skipped the config \
             would show up here"
        );
    }
}

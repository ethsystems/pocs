use std::path::Path;

use shielded_pool_compliance::policy::{
    commit::state_tag,
    reference::ReferencePolicy,
    source_hash::policy_source_hash,
    tag_file::render,
};

fn main() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let policy_path = manifest_dir.join("circuits/lib/src/policy.nr");
    let source_hash = policy_source_hash(&policy_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", policy_path.display()));
    let tag = state_tag::<ReferencePolicy>(source_hash);

    let contents = render(source_hash, tag);

    let output_path = manifest_dir.join("circuits/lib/src/policy_tag.nr");
    std::fs::write(&output_path, contents)
        .unwrap_or_else(|e| panic!("failed to write {}: {e}", output_path.display()));
}

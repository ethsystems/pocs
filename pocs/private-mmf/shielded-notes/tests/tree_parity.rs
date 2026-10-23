//! The Rust tree against zk-kit's LeanIMT, which the pool and the registry run.
//! The wallet's Merkle paths come from `LeanTree` and the roots it proves
//! against from the pool, so a difference fails every proof without naming the
//! cause. The flows compare roots on their own sequences; this covers every
//! size up to 70, including the odd ones where LeanIMT promotes an unpaired node.
//!
//! Needs `forge` on `PATH`. `forge script` without `--rpc-url` runs in an
//! in-memory EVM, so no node is involved.

use std::process::Command;

use ark_bn254::Fr;
use shielded_notes::{
    chain,
    domain::tree::LeanTree,
};

#[test]
fn the_rust_tree_matches_leanimt_at_every_size_up_to_70() {
    let leaves: Vec<Fr> = (1..=70u64).map(|i| Fr::from(i * 7919 + 13)).collect();
    let csv: Vec<String> = leaves.iter().map(|l| chain::u256(*l).to_string()).collect();
    let output = Command::new("forge")
        .args([
            "script",
            "contracts/script/TreeParity.s.sol:CommitmentTreeParity",
        ])
        .env("PARITY_LEAVES", csv.join(","))
        .env("FOUNDRY_DISABLE_NIGHTLY_WARNING", "1")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("forge on PATH");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "forge script failed\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let mut tree = LeanTree::new();
    for (i, leaf) in leaves.iter().enumerate() {
        tree.insert(*leaf);
        let label = format!("COMMITMENT_ROOT_{}=", i + 1);
        let solidity = stdout
            .lines()
            .find_map(|line| line.trim().strip_prefix(&label))
            .unwrap_or_else(|| panic!("no {label} in the script's output"));
        assert_eq!(
            solidity,
            chain::b256(tree.root()).to_string(),
            "the roots differ at {} leaves",
            i + 1
        );
    }
}

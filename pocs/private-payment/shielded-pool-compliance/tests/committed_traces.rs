//! Every committed trace in `traces/` passes the checks a consumer runs: SPEC Section
//! 4.2, then each note opening under its key and each balance summing (Section 4.3).
//! A change to `trace-recorder` that breaks a committed trace fails here, without a
//! chain or a prover.

mod common;

use std::fs;

use common::{
    project_root,
    trace::open,
};

#[test]
fn every_committed_trace_checks() {
    let mut checked = 0;
    for entry in fs::read_dir(project_root().join("traces")).expect("traces/") {
        let path = entry.expect("a directory entry").path();
        if path.extension().is_none_or(|ext| ext != "jsonl") {
            continue;
        }
        let text = fs::read_to_string(&path).expect("a readable trace");
        let trace = trace_recorder::parse(&text)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert!(
            !trace.header.mock_proofs,
            "{} has mock proofs",
            path.display()
        );
        trace_recorder::check_notes(&trace, open)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        checked += 1;
    }
    assert_eq!(checked, 5, "the five recorded scenarios");
}

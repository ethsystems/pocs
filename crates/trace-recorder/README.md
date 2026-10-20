# trace-recorder

Writes and validates demo traces: one JSONL file per recorded run of a PoC scenario. [SPEC.md](SPEC.md) defines the format.

```rust
let mut recorder = Recorder::new(header);
let tx = recorder.next_id();   // one counter for every artifact id
recorder.push(step);
recorder.check(open)?;   // Section 4.2, then opens every note and sums every balance (4.3)
recorder.finish(Path::new("traces/my_scenario.jsonl"), open)?;   // checks, then streams

let text = fs::read_to_string(path)?;
let trace = trace_recorder::parse(&text)?;   // Section 4.2; strings borrow from `text`
trace_recorder::check_notes(&trace, open)?;   // Section 4.3
```

`open(domain, key, sealed)` returns a sealed note's plaintext, or `None` when it does not open. The PoC supplies it, because sealring fixes the domain tag at compile time.

## Adding a PoC

1. Add the crate as a dev-dependency, and add a feature that turns writing on. Record and `check` on every test run, so that a change that breaks recording fails the ordinary tests, and write the file only under the feature:

   ```toml
   [dev-dependencies]
   trace-recorder = { path = "../../../crates/trace-recorder" }

   [features]
   trace = []
   ```

2. Give each persona fixed keys. The header prints the keys that open its notes, and traces become public, so the keys must be throwaway.
3. List in the header's `simplifications` what the run does differently from the PoC's spec, and set `mock_proofs` when it uses mock proofs. Refuse to write a mock trace into `traces/`.
4. Record each action where it happens. The crate ships no wrappers, because each PoC defines its own ports. Record in your own port wrapper, or in the test harness helpers if the scenarios call the chain directly.
5. For each step, record the artifacts, a cell for every observer and field pair that cites its evidence, and the balances of every persona. Give each transaction that verifies a proof its calldata as `input`, and name each circuit's public inputs in `circuits`.
6. Use the field ids `sender`, `recipient`, `amount`, `asset`, `linkage` and `policy_state` where they apply, so that matrices line up across PoCs.
7. Record notes as `sealed` when sealring 0.3 opens them with a key in the header. Give a byte-packed plaintext a `fixed` layout and a JSON one a `json` layout. A consumer must already know the domain tag, because sealring fixes it at compile time. Record a note as `opened` only when no header key opens it.
8. Write the trace to `<poc>/traces/<scenario>.jsonl`. Generate it with real proofs, and commit it. Add a test that parses and checks every committed trace, so that a change to this crate that breaks them fails there.

`pocs/private-payment/shielded-pool-compliance/tests/common/trace.rs` is a complete example. It records at the harness helpers, because that PoC's scenarios send pool calls directly.

use std::{
    error::Error as _,
    fs,
};

use serde_json::{
    Value,
    json,
};
use trace_recorder::{
    Error,
    Header,
    Key,
    NoteDomain,
    Recorder,
    Sealed,
    Trace,
    check_notes,
    parse,
};

fn header() -> Value {
    json!({
        "type": "header",
        "schema": 1,
        "poc": "pocs/example",
        "scenario": "deposit",
        "title": "Deposit",
        "summary": "Alice deposits and pays Bob.",
        "source": "tests/deposit.rs",
        "map": {"use_case": "private-payments", "approach": "shielding", "patterns": ["pattern-shielding"]},
        "chains": [{"chain_id": 1, "name": "local"}],
        "assets": [{"id": "usd", "symbol": "USD", "decimals": 6, "chain_id": 1, "address": "0x01"}],
        "personas": [
            {"id": "alice", "label": "Alice", "role": "sender",
             "keys": [{"id": "viewing", "secret": "0x02", "opens": "notes to Alice"}]},
            {"id": "bob", "label": "Bob", "role": "recipient"}
        ],
        "observers": [{"id": "public", "role": "public", "label": "Public"}],
        "fields": [{"id": "amount", "label": "Amount"}],
        "note_domains": [{"id": "pool", "kem": "k256", "tag": "example-v1"}],
        "note_layouts": [
            {"id": "value", "label": "Value note", "codec": {"fixed": {"len": 40, "fields": [
                {"name": "amount", "offset": 0, "type": "u64"},
                {"name": "salt", "offset": 8, "type": "bytes32"}
            ]}}},
            {"id": "memo", "label": "Memo", "codec": "json"}
        ]
    })
}

/// One step that uses every artifact kind, so each rule has something to break.
fn step() -> Value {
    json!({
        "type": "step",
        "actor": "alice",
        "action": "deposit",
        "title": "Alice deposits",
        "roles": {"public": "bob"},
        "artifacts": [
            {"kind": "tx", "id": 1, "chain_id": 1, "from": "0x0a", "to": "0x0b", "method": "deposit",
             "outcome": {"status": "confirmed", "hash": "0x0c", "block_number": 7, "gas_used": 21000},
             "input": "0xaa0ebb"},
            {"kind": "proof", "id": 2, "system": "ultrahonk", "circuit": "deposit",
             "public_inputs": ["0x0d"], "bytes": "0x0e", "precomputed": false, "verified_by": 1},
            {"kind": "note", "id": 3, "label": "Value note", "recipient": "alice", "carried_by": 1, "element": 0,
             "sealed": {"domain": "pool", "layout": "value", "key": "viewing", "aad": "0x", "ciphertext": "0x0f"}},
            {"kind": "message", "id": 4, "channel": "p2p", "from": "alice", "to": "bob", "body": {}},
            {"kind": "note", "id": 5, "label": "Payment", "recipient": "bob", "carried_by": 4, "element": 0,
             "opened": {"plaintext": {"amount": "5"}, "decrypted_by": "bob"}},
            {"kind": "state", "id": 6, "label": "root", "data": "0x10"}
        ],
        "observations": {"public": {"amount": {"level": "visible", "why": "The deposit is public.", "evidence": [1]}}},
        "wallets": {
            "alice": [{"asset": "usd", "kind": "confidential", "amount": "10", "notes": [3]}],
            "bob": [{"asset": "usd", "kind": "confidential", "amount": "5", "notes": [5]},
                    {"asset": "usd", "kind": "public", "amount": "0"}]
        }
    })
}

fn render(lines: &[Value]) -> String {
    lines.iter().map(|line| format!("{line}\n")).collect()
}

fn check(edit: impl FnOnce(&mut Value, &mut Value)) -> Result<(), Error> {
    let (mut h, mut s) = (header(), step());
    edit(&mut h, &mut s);
    parse(&render(&[h, s])).map(drop)
}

/// The value layout's 40 bytes: `amount` as a big-endian u64, then a zero salt.
fn value_plaintext(amount: u64) -> Vec<u8> {
    let mut bytes = amount.to_be_bytes().to_vec();
    bytes.resize(40, 0);
    bytes
}

/// Opens the fixture's one sealed note, ciphertext `0x0f`, to Alice's 10.
fn opener(
    plaintext: Vec<u8>,
) -> impl FnMut(&NoteDomain<'_>, &Key<'_>, &Sealed<'_>) -> Option<Vec<u8>> {
    move |_, _, sealed| (*sealed.ciphertext == [0x0f]).then(|| plaintext.clone())
}

#[track_caller]
fn rejects(rule: u8, edit: impl FnOnce(&mut Value, &mut Value)) {
    match check(edit) {
        Err(Error::Invalid { rule: got, detail }) => assert_eq!(got, rule, "{detail}"),
        other => panic!("expected rule {rule}, got {other:?}"),
    }
}

#[test]
fn accepts_every_artifact_kind_and_codec() {
    check(|_, _| ()).unwrap();
    check(|_, s| s["artifacts"][2]["sealed"]["layout"] = json!("memo")).unwrap();
    check(|h, _| {
        h["note_layouts"][0]["codec"]["fixed"]["fields"][0]["type"] = json!("u256")
    })
    .unwrap();
    check(|_, s| s["wallets"]["alice"][0]["notes"] = json!([])).unwrap();
    check(|h, _| {
        h["simplifications"] = json!(["A local chain"]);
        h["mock_proofs"] = json!(true);
        h["circuits"] = json!([{"id": "deposit", "public_inputs": ["commitment"]}]);
    })
    .unwrap();
    check(|_, s| {
        let reverted = json!({"kind": "tx", "id": 7, "chain_id": 1, "from": "0x0a", "to": "0x0b",
            "method": "withdraw", "outcome": {"status": "reverted", "hash": "0x0d",
            "block_number": 8, "gas_used": 30000, "revert": "BlockedDestination()"}});
        s["artifacts"].as_array_mut().unwrap().push(reverted);
    })
    .unwrap();
}

#[test]
fn a_proof_may_name_a_later_steps_transaction() {
    let mut proving = step();
    let proof = proving["artifacts"][1].clone();
    proving["artifacts"] = json!([proof]);
    proving["observations"]["public"]["amount"]["evidence"] = json!([2]);
    proving["wallets"]["alice"][0]["notes"] = json!([]);
    proving["wallets"]["bob"][0]["notes"] = json!([]);
    let mut submitting = step();
    submitting["artifacts"].as_array_mut().unwrap().remove(1);
    parse(&render(&[header(), proving, submitting])).unwrap();
}

#[test]
fn rejects_each_broken_rule() {
    for text in [
        render(&[step()]),
        render(&[header(), header()]),
        render(&[step(), header()]),
    ] {
        assert!(
            matches!(parse(&text), Err(Error::Invalid { rule: 1, .. })),
            "{text}"
        );
    }

    rejects(2, |_, s| s["actor"] = json!("carol"));
    rejects(2, |_, s| s["action"] = json!("mint"));
    rejects(2, |_, s| s["roles"] = json!({"regulator": "bob"}));
    rejects(2, |_, s| s["roles"] = json!({"public": "carol"}));
    rejects(2, |_, s| s["artifacts"][3]["to"] = json!("carol"));

    rejects(3, |_, s| s["artifacts"][1]["id"] = json!(1));

    rejects(4, |_, s| s["artifacts"][0]["chain_id"] = json!(2));

    rejects(5, |_, s| s["artifacts"][2]["recipient"] = json!("carol"));
    rejects(5, |_, s| {
        s["artifacts"][2]["sealed"]["domain"] = json!("other")
    });
    rejects(5, |_, s| {
        s["artifacts"][2]["sealed"]["layout"] = json!("other")
    });
    rejects(5, |_, s| s["artifacts"][2]["recipient"] = json!("bob"));
    rejects(5, |_, s| {
        s["artifacts"][4]["opened"]["plaintext"] = json!("5")
    });
    rejects(5, |_, s| {
        s["artifacts"][4]["opened"]["decrypted_by"] = json!("carol")
    });
    rejects(5, |_, s| {
        s["artifacts"][2]["opened"] =
            json!({"plaintext": {"amount": "10"}, "decrypted_by": "alice"})
    });
    rejects(5, |_, s| {
        s["artifacts"][2].as_object_mut().unwrap().remove("sealed");
    });

    rejects(6, |_, s| s["observations"] = json!({}));
    rejects(6, |_, s| {
        s["observations"]["public"]["sender"] =
            s["observations"]["public"]["amount"].clone()
    });

    rejects(7, |_, s| {
        s["observations"]["public"]["amount"]["level"] = json!("n/a")
    });
    rejects(7, |_, s| {
        s["observations"]["public"]["amount"]["evidence"] = json!([])
    });

    rejects(8, |_, s| {
        s["observations"]["public"]["amount"]["evidence"] = json!([99])
    });
    rejects(8, |_, s| s["artifacts"][2]["carried_by"] = json!(2));
    rejects(8, |_, s| s["artifacts"][1]["verified_by"] = json!(4));
    rejects(8, |_, s| {
        s["artifacts"][0]["outcome"] =
            json!({"status": "rejected", "revert": "InvalidProof()"})
    });
    rejects(8, |_, s| {
        s["artifacts"][0].as_object_mut().unwrap().remove("input");
    });
    rejects(8, |_, s| s["artifacts"][0]["input"] = json!("0xaabb"));

    rejects(9, |_, s| s["wallets"] = json!({"alice": []}));
    rejects(9, |_, s| s["wallets"]["bob"][1]["asset"] = json!("eur"));
    rejects(9, |_, s| s["wallets"]["bob"][1]["amount"] = json!("1.5"));

    rejects(10, |_, s| s["wallets"]["alice"][0]["notes"] = json!([1]));
    rejects(10, |h, _| {
        h["note_layouts"][0]["codec"]["fixed"]["fields"][0]["type"] = json!("bytes32")
    });
    rejects(10, |_, s| {
        s["artifacts"][4]["opened"]["plaintext"] = json!({"amount": 5})
    });
    rejects(10, |_, s| s["wallets"]["alice"][0]["notes"] = json!([3, 3]));
    rejects(10, |_, s| {
        s["wallets"]["alice"][0]["notes"] = json!([]);
        s["wallets"]["bob"][0]["notes"] = json!([3, 5]);
    });
    rejects(10, |_, s| {
        s["wallets"]["bob"][0]["notes"] = json!([]);
        s["wallets"]["bob"][1]["notes"] = json!([5]);
    });

    rejects(12, |h, _| h["schema"] = json!(2));
    rejects(12, |h, _| h["personas"][1]["id"] = json!("alice"));
    rejects(12, |h, _| {
        let key = h["personas"][0]["keys"][0].clone();
        h["personas"][0]["keys"].as_array_mut().unwrap().push(key);
    });
    rejects(12, |h, _| {
        h["actions"] = json!([{"id": "deposit", "label": "Deposit"}])
    });
    rejects(
        12,
        |h, _| {
            h["chains"] =
                json!([{"chain_id": 1, "name": "a"}, {"chain_id": 1, "name": "b"}])
        },
    );
    rejects(12, |h, _| h["assets"][0]["chain_id"] = json!(2));
    rejects(12, |h, _| {
        h["note_layouts"][0]["codec"]["fixed"]["len"] = json!(39)
    });
    rejects(12, |h, _| {
        h["note_layouts"][0]["codec"]["fixed"]["fields"][1]["offset"] = json!(u32::MAX)
    });
    rejects(12, |h, _| {
        h["note_layouts"][0]["codec"]["fixed"]["fields"][1]["name"] = json!("amount")
    });
    rejects(
        12,
        |h, _| {
            h["circuits"] = json!([{"id": "a", "public_inputs": []}, {"id": "a", "public_inputs": []}])
        },
    );

    rejects(
        13,
        |h, _| {
            h["circuits"] =
                json!([{"id": "deposit", "public_inputs": ["commitment", "amount"]}])
        },
    );
}

#[test]
fn check_notes_opens_every_note_and_sums_each_balance() {
    let text = render(&[header(), step()]);
    let trace = parse(&text).unwrap();
    check_notes(&trace, opener(value_plaintext(10))).unwrap();

    let opening = |result: Result<(), Error>| matches!(result, Err(Error::Opening(_)));
    assert!(
        opening(check_notes(&trace, |_, _, _| None)),
        "a note that does not open"
    );
    assert!(
        opening(check_notes(&trace, opener(value_plaintext(11)))),
        "notes that do not sum"
    );
    assert!(
        opening(check_notes(&trace, opener(vec![0; 39]))),
        "a short plaintext"
    );
}

#[test]
fn malformed_hex_fails_to_parse_under_rule_11() {
    for hex in ["0xAB", "0x1", "ab"] {
        match check(|_, s| s["artifacts"][1]["bytes"] = json!(hex)) {
            Err(e @ Error::Json { .. }) => {
                let source = e.source().unwrap().to_string();
                assert!(source.contains("rule 11"), "{source}");
            }
            other => panic!("{hex}: {other:?}"),
        }
    }
}

#[test]
fn unknown_members_fail_to_parse() {
    for edit in [
        (|h: &mut Value, _: &mut Value| h["extra"] = json!(1))
            as fn(&mut Value, &mut Value),
        |h, _| h["note_layouts"][0]["codec"]["fixed"]["extra"] = json!(1),
        |_, s| s["artifacts"][2]["sealed"]["extra"] = json!(1),
        |_, s| s["artifacts"][2]["extra"] = json!(1),
    ] {
        assert!(matches!(check(edit), Err(Error::Json { .. })));
    }
}

#[test]
fn recorder_writes_what_parse_reads() {
    let text = render(&[header(), step()]);
    let Trace {
        header: parsed,
        steps,
    } = parse(&text).unwrap();
    let mut recorder = Recorder::new(parsed);
    steps.into_iter().for_each(|s| recorder.push(s));
    let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("round-trip.jsonl");
    recorder.finish(&path, opener(value_plaintext(10))).unwrap();

    let written = fs::read_to_string(&path).unwrap();
    let lines: Vec<Value> = written
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines, [header(), step()]);
}

#[test]
fn recorder_writes_nothing_for_an_invalid_trace() {
    let mut h = header();
    h.as_object_mut().unwrap().remove("type");
    h["schema"] = json!(2);
    let text = h.to_string();
    let header: Header = serde_json::from_str(&text).unwrap();
    let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("invalid.jsonl");
    let _ = fs::remove_file(&path);
    assert!(matches!(
        Recorder::new(header).finish(&path, |_, _, _| None),
        Err(Error::Invalid { rule: 12, .. })
    ));
    assert!(!path.exists());
}

#[test]
fn parsed_strings_borrow_from_the_text() {
    let text = render(&[header(), step()]);
    let trace = parse(&text).unwrap();
    let span = text.as_bytes().as_ptr_range();
    let why = &trace.steps[0].observations["public"]["amount"].why;
    assert!(span.contains(&trace.header.title.as_ptr()));
    assert!(span.contains(&why.as_ptr()));
}

# Demo Trace Format, Version 1

## 1. Introduction

A proof of concept (PoC) shows its privacy properties only to a reader who runs its tests and reads their output. A recorded run lets a reader see the same thing without running the PoC: what each party did, what each observer learned, and what each wallet held after each step.

This document specifies that record, the Trace. A Trace is a JSON Lines file. It carries the transactions, proofs and encrypted notes of one run, a privacy matrix for each step, and the keys that open the notes. The Consumer renders the Trace and runs no protocol computation of its own.

### 1.1 Scope

This document specifies the file format, the validation rules, and how a Consumer opens a sealed note. It does not specify how a Consumer presents a Trace or how a PoC hooks recording into its code.

## 2. Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown here.

- **Trace**: one JSON Lines file that records one run of one PoC scenario.
- **Header**: the first line of a Trace. It declares everything the Steps refer to.
- **Step**: one later line of a Trace. It records one action by one Persona.
- **Persona**: a party in the scenario, such as a payer, a payee or an auditor.
- **Observer**: a column of the privacy matrix, such as the public or a regulator.
- **Field**: a row of the privacy matrix, such as the sender or the amount.
- **Cell**: what one Observer learns about one Field in one Step.
- **Artifact**: a transaction, proof, note, message or state snapshot that a Step records.
- **Note**: an encrypted payload addressed to a Persona.
- **Producer**: the program that writes a Trace, a PoC scenario linked against `trace-recorder`.
- **Consumer**: a program that reads a Trace, validates it, opens its Notes and presents it.

## 3. Architecture

| Participant | Role | Operator |
|---|---|---|
| Producer | Runs a scenario against a local chain and writes a Trace | PoC test, run by hand |
| Consumer | Validates a Trace, opens its Notes and presents it | Not specified |

The Producer is trusted to record what the run did and to classify each Cell honestly. The Consumer can check three claims without that trust: that each sealed Note opens under its declared key, that each confidential balance that lists Notes equals their sum, and that each verified proof travelled in the calldata of a confirmed transaction. It cannot check a Cell's level, and it does not re-verify proofs. The transaction that ran the on-chain verifier is the evidence for a proof.

A Trace is public. `pocs-private` syncs to the public `ethsystems/pocs` repository after seven days.

## 4. Protocol Operations

### 4.1 Recording

1. The Producer builds the Header before the first action.
2. After each action, the Producer appends one Step. The Step records the Artifacts of the action, a Cell for every Observer and Field pair, and the balances of every Persona after the action.
3. A call that the node rejects before it is mined is recorded as a `reject` Step with a `rejected` transaction. A call that is mined and then reverts is recorded as a `reject` Step with a `reverted` transaction, which has a hash and a block (Section 5.5).
4. At the end of the run, the Producer validates the Trace against Section 4.2, opens every Note and checks every balance as Section 4.3 says, and writes it to `<poc>/traces/<scenario>.jsonl`. The Producer MUST NOT write a Trace that fails a check.
5. The Producer sets `mock_proofs` when the run used mock proofs, and SHOULD NOT write such a Trace where Traces are published.

### 4.2 Validation

The Producer and the Consumer MUST both reject a Trace that breaks any of these rules. `trace-recorder` reports a broken rule by its number.

1. The Header is the first non-blank line and appears exactly once.
2. Every `actor`, `roles` value and message `from` and `to` names a declared Persona. Every `roles` key names a declared Observer. Every `action` is a core action (Section 5.4) or is declared in `actions`.
3. Artifact ids are unique across the Trace.
4. Every transaction names a declared chain.
5. Every Note's `recipient` is a declared Persona, and every Note has exactly one of `sealed` and `opened`. A sealed Note names a declared domain and layout, and a key its `recipient` holds. An opened Note's `plaintext` is a JSON object and its `decrypted_by` is a declared Persona.
6. Every Step's `observations` cover exactly the declared Observers, and each Observer covers exactly the declared Fields.
7. A Cell has a non-empty `evidence` list exactly when its level is not `n/a`.
8. Every `evidence` and `carried_by` value names an Artifact recorded in the same Step or an earlier one, and `carried_by` names a transaction or a message. A proof's `verified_by` names a `confirmed` transaction in any Step, and that transaction's `input` contains the proof's `bytes`.
9. Every Step's `wallets` cover exactly the declared Personas. Every balance names a declared asset and has a decimal `amount`.
10. Every Note a balance lists is a recorded Note with an amount, addressed to the balance's Persona. Only a `confidential` balance lists Notes, and no Note appears twice among a Step's balances. A sealed Note's `fixed` layout has an integer field named `amount`; under a `json` layout the Consumer checks the `amount` member on opening. An opened Note has a decimal string `amount` in `plaintext`.
11. Every hex value is lowercase, `0x`-prefixed and of even length.
12. The Header has `schema` 1, unique ids within each list, within each Persona's keys and within each `fixed` layout's fields, no declared action that is already core, unique chain ids, assets on declared chains, and `fixed` layout fields that end within `len`.
13. Every proof whose `circuit` the Header declares in `circuits` has one public input per declared name.

Unknown members are errors in every object this document defines. A value typed `any` or `object` is not checked.

### 4.3 Opening a Note

To open a sealed Note, the Consumer:

1. Looks up the domain named by `sealed.domain`, and the key named by `sealed.key` among the keys of the Note's `recipient`.
2. Calls sealring 0.3 `open` [sealring] with that key, the domain's `kem` and `tag`, `sealed.aad` and `sealed.ciphertext`.
3. MUST treat a failure to open, a `fixed` plaintext whose length is not `len`, or a `json` plaintext that is not a JSON object, as an invalid Trace.
4. Reads the fields from the plaintext as its layout's codec defines (Section 5.6).

For each confidential balance that lists Notes, the Consumer SHOULD check that their amounts sum to the balance's `amount`. A Consumer SHOULD run both checks before it presents a Trace, so that it rejects a broken Trace rather than shows it.

## 5. Data Formats

### 5.1 File

A Trace is UTF-8 JSON Lines [JSONL]. Each non-blank line is one JSON object [RFC8259] with a `type` member: `"header"` on the first line and `"step"` on every other line. Steps appear in run order, and a Step's position is its index.

In the layouts below, `?` marks an optional member, `hex` is a hex string (rule 11), an Artifact id is an integer, and `amount` is a base-unit integer as a decimal string, because a 256-bit integer does not fit a JSON number. An optional list defaults to empty.

### 5.2 Header

```
Header:
    schema         integer      # MUST be 1
    poc            string       # repository path of the PoC
    scenario       string       # the file stem
    title          string
    summary        string
    simplifications? [string]   # what the run simplifies, in words
    mock_proofs?   bool         # default false
    source         string       # the producing test, relative to poc
    map            Map
    chains         [Chain]
    assets         [Asset]
    personas       [Persona]
    observers      [Observer]   # matrix columns
    fields         [Field]      # matrix rows
    actions?       [{id, label}]
    circuits?      [Circuit]
    note_domains?  [NoteDomain] # Section 5.6
    note_layouts?  [NoteLayout] # Section 5.6

Map:       use_case, approach: string; patterns: [string]   # ethsystems/map slugs [map]
Chain:     chain_id: integer; name: string
Asset:     id, symbol: string; decimals: integer; chain_id: integer; address: hex
Persona:   id, label, role: string; address?: hex; owner_pubkey?: hex; keys?: [Key]
Key:       id: string; secret: hex; opens: string
Observer:  id, label: string; role: "public" | "counterparty" | "regulator" | "operator" | "issuer" | "other"
Field:     id, label: string
Circuit:   id: string; public_inputs: [string]   # the names, in order
```

A Trace is meant to be read without its PoC, so `simplifications` lists in words what the run does differently from the PoC's specification, for example a role that one account plays for several parties, a smaller committee, a local chain or a near-empty pool. `mock_proofs` is true when no proof in the Trace would pass a real verifier. A Consumer SHOULD show both before the first Step. `circuits` names each circuit's public inputs, so that a Consumer can label them.

`owner_pubkey` is the Persona's in-protocol identifier; the Consumer names the Persona wherever a decrypted field equals it. A Key is a secret that opens Notes, and `opens` says which in words. Key ids are scoped to their Persona. Side-by-side views align Observers across PoCs by `role`. A Trace SHOULD use the Field ids `sender`, `recipient`, `amount`, `asset`, `linkage` and `policy_state` where they apply.

### 5.3 Step

```
Step:
    actor         string                          # Persona id
    action        string
    title         string
    roles?        {Observer id: Persona id}       # who plays an Observer here
    artifacts     [Artifact]                      # Section 5.5
    observations  {Observer id: {Field id: Cell}}
    wallets       {Persona id: [Balance]}         # after the Step

Cell:     level: Level; why: string; evidence?: [Artifact id]
Balance:  asset: string; kind: "confidential" | "public"; amount: amount; notes?: [Note id]
```

| Level | Meaning |
|---|---|
| `hidden` | The Observer cannot learn the Field |
| `visible` | The Field is public, or the Observer is given it |
| `key-gated` | The Observer learns the Field only with a key it holds |
| `inferable` | The Field is not shown, but the Observer can derive it |
| `n/a` | The Step has no such Field |

### 5.4 Actions

The core actions are `onboard`, `deposit`, `transfer`, `receive`, `withdraw`, `disclose`, `swap`, `redeem`, `prove`, `submit` and `reject`. A Step MAY use them undeclared. Any other action MUST be declared in `actions`.

### 5.5 Artifacts

Every Artifact has a `kind` and an integer `id`.

```
tx:       chain_id: integer; from, to: hex; method: string; outcome: Outcome; events?: [{name, args: {string: string}}]; input?: hex
Outcome:  {status: "confirmed", hash: hex, block_number, gas_used: integer}
        | {status: "rejected", revert: string}               # never mined, so no hash
        | {status: "reverted", hash: hex, block_number, gas_used: integer, revert: string}
proof:    system, circuit: string; public_inputs: [hex]; bytes: hex; precomputed: bool; verified_by?: tx id
note:     label: string; recipient: Persona id; carried_by: tx or message id; element: integer; and exactly one of
            sealed:  {domain, layout, key: string; aad, ciphertext: hex}   # key: a recipient key id
            opened:  {plaintext: object; decrypted_by: Persona id}
message:  channel: string; from, to: Persona id; body: any
state:    label: string; data: any
```

`input` is the transaction's calldata. A transaction that a proof's `verified_by` names MUST carry it. A `reverted` transaction published its calldata although its effects were undone. `verified_by` MAY name a transaction in a later Step, so that a `prove` Step can precede its `submit` Step. `element` is the Note's position within what carried it. A Producer uses `opened` only for a Note that no key in the Header opens, such as one held by a threshold key service; the plaintext is then the Producer's claim. `precomputed` is true for a proof the run did not generate.

### 5.6 Note Domains and Layouts

```
NoteDomain:   id: string; kem: "k256" | "x25519" | "grumpkin"; tag: string
NoteLayout:   id, label: string; codec: "json" | {fixed: {len: integer; fields: [LayoutField]}}
LayoutField:  name: string; offset: integer; type: "bytes32" | "address" | "u64" | "u128" | "u256"; labels?: {hex: string}
```

`tag` is the sealring domain tag. sealring fixes it at compile time, so the Consumer's decryptor MUST already know every tag a Trace names; a new tag needs a Consumer release. A `fixed` plaintext is exactly `len` bytes. `bytes32` and `address` take 32 bytes, an address left-padded with zeros; `u64`, `u128` and `u256` take 8, 16 and 32 bytes, big-endian. `labels` names sentinel values by their hex encoding. A `json` plaintext is a UTF-8 JSON object, read by member name; a Note a balance lists has an `amount` member, a decimal string or a `0x` hex string.

## 6. Security Considerations

### 6.1 Threat Model

- Anyone can read every Trace, including its keys.
- A Producer can contain a bug that records a wrong Cell or a wrong balance.
- A Trace can be edited by hand after it is recorded, for example in a pull request.
- The Consumer can parse the Trace on the reader's machine.

### 6.2 Properties

- **Note integrity.** A sealed Note that opens under its key was encrypted to that key with that `aad`, and its ciphertext has not changed since, under the security of the sealring key encapsulation mechanism and authenticated encryption. Opening does not identify who encrypted it.
- **Balance consistency.** A confidential balance that lists Notes and passes Section 4.3 equals the sum of Notes the Trace actually carries.

Neither property holds for an opened Note, which the Consumer takes on trust.

### 6.3 Per-Operation Analysis

- **Recording.** Keys in a Trace are disclosed by design. A Producer MUST use throwaway keys generated for the demo and MUST NOT record a key that protects anything else. Personas, addresses and amounts SHOULD be generic.
- **Validation.** Rules 2, 6 and 9 stop a Trace that omits an Observer, a Field or a Persona, which would otherwise render as a matrix or wallet that looks complete and is not. Rule 8 stops evidence that points at an Artifact the Step has not produced yet, and ties each verified proof to the calldata of a confirmed transaction, so that a proof cannot cite a mint or a refused call as its evidence. Rule 10 stops a wallet that counts a Note twice, or counts another Persona's Note.
- **Presentation.** Every string in a Trace is untrusted. The Consumer MUST render strings as text and MUST NOT evaluate them as HTML or code.

### 6.4 Known Limitations

- A Cell's level is the Producer's claim. No rule checks that a `hidden` Field is in fact hidden.
- The Consumer does not re-verify proofs. It shows the verifier transaction instead, and rule 8 checks only that the proof travelled in its calldata.
- Traces are recorded on a local development chain. Transaction hashes cannot be looked up on a public explorer, and the Consumer SHOULD link an explorer only for chain ids it knows are public.

## 7. References

### 7.1 Normative References

- **[RFC2119]** Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997, <https://www.rfc-editor.org/info/rfc2119>.
- **[RFC8174]** Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, May 2017, <https://www.rfc-editor.org/info/rfc8174>.
- **[RFC8259]** Bray, T., Ed., "The JavaScript Object Notation (JSON) Data Interchange Format", STD 90, RFC 8259, December 2017, <https://www.rfc-editor.org/info/rfc8259>.
- **[JSONL]** "JSON Lines", <https://jsonlines.org>.
- **[sealring]** sealring, version 0.3, <https://crates.io/crates/sealring>.

### 7.2 Informative References

- **[map]** EthSystems, "ethsystems/map", <https://github.com/ethsystems/map>.

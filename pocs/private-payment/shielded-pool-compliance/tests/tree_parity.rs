//! Cross-language Merkle parity. The Rust root feeds witness generation and the
//! Solidity root is what the circuit verifies against, so a divergence fails every
//! gated proof with no diagnostic naming the cause.
//!
//! Requires `forge` on `PATH`. `forge script` with no `--rpc-url` runs against a fresh
//! in-memory EVM, so no node is spawned or assumed.
//!
//! `RotorMerkleTree<32>` at production depth overflows libtest's default 2 MiB test
//! thread in an unoptimized build, so the debug run needs `RUST_MIN_STACK` at 8 MiB or
//! above. A release build fits without it.
//!
//! `forge build && cargo test --release --test tree_parity`

use std::{
    cell::RefCell,
    process::Command,
    sync::Mutex,
};

use ark_bn254::Fr;
use light_poseidon::{
    Poseidon,
    PoseidonHasher,
};
use shielded_pool_compliance::{
    adapters::{
        commitment_tree::RotorMerkleTree,
        revocation_tree::RevocationTree,
    },
    ports::merkle::{
        MerkleStore,
        Side,
    },
    types::{
        Address,
        Bytes32,
    },
};

thread_local! {
    static P2: RefCell<Poseidon<Fr>> =
        RefCell::new(Poseidon::<Fr>::new_circom(2).expect("arity 2 is a valid circom width"));
}

/// `crate::poseidon` is `pub(crate)`, so the parity test builds its own hasher. That
/// makes the reference leg independent of the adapter under test rather than a
/// re-entry into it.
fn poseidon1(left: Fr, right: Fr) -> Fr {
    P2.with(|p| {
        p.borrow_mut()
            .hash(&[left, right])
            .expect("two inputs for width 2")
    })
}

/// zk-kit's LeanIMT rule, written from the rule rather than from the adapter: a node
/// with no right sibling is promoted verbatim to the next level, every other node
/// pairs left to right under `Poseidon1(left, right)`.
fn reference_leanimt_root(leaves: &[Fr]) -> Fr {
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| match pair {
                [left, right] => poseidon1(*left, *right),
                [promoted] => *promoted,
                _ => unreachable!("chunks(2) yields one or two elements"),
            })
            .collect()
    }
    level[0]
}

/// `forge` shares `contracts/out` and `contracts/cache` across invocations, so
/// concurrent test threads must not drive it at the same time.
static FORGE: Mutex<()> = Mutex::new(());

fn forge_script(contract: &str, env: &[(&str, String)]) -> String {
    let _guard = FORGE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut cmd = Command::new("forge");
    cmd.current_dir(env!("CARGO_MANIFEST_DIR")).args([
        "script",
        &format!("contracts/script/TreeParity.s.sol:{contract}"),
    ]);
    for (key, value) in env {
        cmd.env(key, value);
    }
    let output = cmd.output().expect("forge on PATH");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "forge script {contract} failed\nstdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr),
    );
    stdout
}

#[track_caller]
fn logged(stdout: &str, key: &str) -> String {
    let needle = format!("{key}=");
    stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix(&needle).map(str::to_owned))
        .unwrap_or_else(|| panic!("{key} missing from forge output:\n{stdout}"))
}

#[track_caller]
fn logged_bytes32(stdout: &str, key: &str) -> Bytes32 {
    let value = logged(stdout, key);
    let raw = hex::decode(value.strip_prefix("0x").expect("0x-prefixed hex"))
        .expect("valid hex");
    Bytes32::from(<[u8; 32]>::try_from(raw.as_slice()).expect("32 bytes"))
}

fn hex_word(value: Bytes32) -> String {
    format!("0x{}", hex::encode(value.as_ref()))
}

fn commitment_leaf(n: u64) -> Fr {
    poseidon1(Fr::from(0u64), Fr::from(n + 1))
}

/// Eight leaves, checked at every prefix, so counts 1, 3, 5, and 7 exercise LeanIMT's
/// promotion path. A power-of-two-only sequence never promotes and would agree even if
/// the two promotion rules differed.
#[test]
fn commitment_tree_root_agrees_across_rust_reference_and_solidity() {
    const LEAF_COUNT: usize = 8;
    let leaves: Vec<Fr> = (0..LEAF_COUNT as u64).map(commitment_leaf).collect();

    let csv = leaves
        .iter()
        .map(|leaf| hex_word(Bytes32::from(*leaf)))
        .collect::<Vec<_>>()
        .join(",");
    let stdout = forge_script("CommitmentTreeParity", &[("PARITY_LEAVES", csv)]);

    let dir = tempfile::tempdir().expect("create tmp dir");
    let tree = RotorMerkleTree::<32>::open(dir.path()).expect("open tree");

    for n in 1..=LEAF_COUNT {
        tree.insert(Bytes32::from(leaves[n - 1])).expect("insert");
        let rotor = tree.root().expect("root after insert");
        let reference = Bytes32::from(reference_leanimt_root(&leaves[..n]));
        let solidity = logged_bytes32(&stdout, &format!("COMMITMENT_ROOT_{n}"));

        assert_eq!(
            rotor, reference,
            "rotortree vs reference LeanIMT, {n} leaves"
        );
        assert_eq!(rotor, solidity, "rotortree vs on-chain LeanIMT, {n} leaves");
        println!("commitment tree, {n} leaves: {rotor}");
    }
}

#[derive(Clone, Copy)]
enum Op {
    Add(Address),
    Remove(Address),
    Lower(Address, u64),
}

fn addr(byte: u8) -> Address {
    Address::from([byte; 20])
}

/// Op word consumed by `RevocationTreeParity`:
/// `kind << 224 | revokedAtEpoch << 160 | uint160(attester)`.
fn op_word(kind: u8, attester: Address, revoked_at_epoch: u64) -> String {
    let mut word = [0u8; 32];
    word[3] = kind;
    word[4..12].copy_from_slice(&revoked_at_epoch.to_be_bytes());
    word[12..].copy_from_slice(attester.as_ref());
    format!("0x{}", hex::encode(word))
}

/// Replays `ops` on both sides and compares the root, `subject`'s `revokedAtEpoch`,
/// and the fold of `subject`'s Rust-produced path under the on-chain Poseidon. Roots
/// agreeing while paths disagree is a real failure mode, so the path leg is asserted
/// against the Solidity root rather than the Rust one.
#[track_caller]
fn assert_revocation_parity(label: &str, ops: &[Op], subject: Address) {
    let mut tree = RevocationTree::new();
    let mut words = Vec::with_capacity(ops.len());
    for op in ops {
        match *op {
            Op::Add(attester) => {
                tree.add_attester(attester).expect("add attester");
                words.push(op_word(0, attester, 0))
            }
            Op::Remove(attester) => {
                tree.remove_attester(attester).expect("remove attester");
                words.push(op_word(1, attester, 0))
            }
            Op::Lower(attester, epoch) => {
                tree.lower_revocation(attester, epoch)
                    .expect("lower revocation");
                words.push(op_word(2, attester, epoch))
            }
        }
    }

    let epoch = tree
        .revoked_at_epoch_of(subject)
        .expect("subject is present");
    let path = tree.proof(subject).expect("subject inclusion path");
    let leaf = poseidon1(Fr::from(subject), Fr::from(epoch));

    let siblings = path
        .steps()
        .iter()
        .map(|step| hex_word(step.sibling))
        .collect::<Vec<_>>()
        .join(",");
    let sides = path
        .steps()
        .iter()
        .map(|step| match step.side {
            Side::Left => "0",
            Side::Right => "1",
        })
        .collect::<Vec<_>>()
        .join(",");

    let stdout = forge_script(
        "RevocationTreeParity",
        &[
            ("REVOCATION_OPS", words.join(",")),
            (
                "REVOCATION_SUBJECT",
                format!("0x{}", hex::encode(subject.as_ref())),
            ),
            ("REVOCATION_PATH_LEAF", hex_word(Bytes32::from(leaf))),
            ("REVOCATION_PATH_SIBLINGS", siblings),
            ("REVOCATION_PATH_SIDES", sides),
        ],
    );

    let solidity_root = logged_bytes32(&stdout, "REVOCATION_ROOT");
    assert_eq!(tree.root(), solidity_root, "{label}: root");
    assert_eq!(
        logged(&stdout, "REVOCATION_SUBJECT_EPOCH"),
        epoch.to_string(),
        "{label}: subject revokedAtEpoch",
    );
    assert_eq!(
        logged_bytes32(&stdout, "REVOCATION_PATH_ROOT"),
        solidity_root,
        "{label}: Rust path folded by on-chain Poseidon",
    );
    println!("revocation tree, {label}: {solidity_root}");
}

#[test]
fn revocation_tree_root_agrees_for_a_populated_tree() {
    assert_revocation_parity(
        "populated",
        &[
            Op::Add(addr(1)),
            Op::Add(addr(2)),
            Op::Add(addr(3)),
            Op::Add(addr(4)),
        ],
        addr(3),
    )
}

#[test]
fn revocation_tree_root_agrees_after_a_lowering() {
    assert_revocation_parity(
        "lowered",
        &[
            Op::Add(addr(1)),
            Op::Add(addr(2)),
            Op::Add(addr(3)),
            Op::Add(addr(4)),
            Op::Lower(addr(2), 42),
        ],
        addr(2),
    )
}

/// Removing the second of four attesters is swap-and-pop on both sides, so the fourth
/// relocates into slot 1. The subject is that relocated survivor: if the two sides
/// disagree about the destination slot, only this shape catches it. Removing the last
/// element would prove nothing.
#[test]
fn revocation_tree_root_agrees_after_a_removal_that_relocates_a_survivor() {
    assert_revocation_parity(
        "removal relocates survivor",
        &[
            Op::Add(addr(1)),
            Op::Add(addr(2)),
            Op::Add(addr(3)),
            Op::Add(addr(4)),
            Op::Remove(addr(2)),
        ],
        addr(4),
    )
}

/// Rust carries `revokedAtEpoch` in the swapped tuple while Solidity keeps it in a
/// mapping keyed by address, so relocation preserves it for different reasons on each
/// side. Lowering before the removal is what makes that divergence observable.
#[test]
fn revocation_tree_root_agrees_when_a_relocated_survivor_carries_a_lowered_epoch() {
    assert_revocation_parity(
        "relocated survivor keeps lowered epoch",
        &[
            Op::Add(addr(1)),
            Op::Add(addr(2)),
            Op::Add(addr(3)),
            Op::Add(addr(4)),
            Op::Lower(addr(4), 7),
            Op::Remove(addr(2)),
        ],
        addr(4),
    )
}

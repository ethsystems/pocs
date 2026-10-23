//! The LeanIMT with Poseidon1 nodes that the pool and the registry keep on-chain
//! (zk-kit LeanIMT): a node with no right sibling is promoted unchanged, so some
//! leaves have proofs shorter than the tree's depth. Backed by `rotortree`'s
//! LeanIMT, which keeps every level, so the root is read and a path assembled
//! without rehashing. A view builds its trees in one batch (`from_leaves`), which
//! `rotortree` hashes level by level, in parallel.

use ark_bn254::Fr;
use rotortree::{
    Hash,
    HashState,
    Hasher,
    LeanIMT,
};

use crate::poseidon::{
    fr_from_be_bytes,
    fr_to_be_bytes,
    poseidon2,
};

/// The commitment tree's depth, which bounds the attestation tree's too.
const DEPTH: usize = crate::MAX_COMMITMENT_TREE_DEPTH as usize;

/// One proof step: the sibling, and whether the proved node is the right child
/// (the circuits' `indices[i] == true`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Step {
    pub sibling: Fr,
    pub is_right: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MerkleProof(pub Vec<Step>);

fn node(left: &Hash, right: &Hash) -> Hash {
    fr_to_be_bytes(&poseidon2(fr_from_be_bytes(left), fr_from_be_bytes(right)))
}

/// A LeanIMT node, `Poseidon1(left, right)`, as zk-kit and the circuits hash it.
#[derive(Clone)]
struct NodeHasher;

/// `rotortree` hashes this tree's nodes through `hash_children`; the streaming
/// form computes the same node from the two children's bytes.
struct NodeState(Vec<u8>);

impl HashState for NodeState {
    fn update(&mut self, data: &[u8]) {
        self.0.extend_from_slice(data);
    }

    fn finalize(self) -> Hash {
        let (left, right) = self.0.split_at(32);
        node(
            left.try_into().expect("a node hashes two 32-byte children"),
            right
                .try_into()
                .expect("a node hashes two 32-byte children"),
        )
    }
}

impl Hasher for NodeHasher {
    type State = NodeState;

    fn new_state(&self) -> NodeState {
        NodeState(Vec::with_capacity(64))
    }

    fn hash_children(&self, children: &[Hash]) -> Hash {
        let [left, right] = children else {
            unreachable!("a binary tree hashes two children; one alone is promoted")
        };
        node(left, right)
    }
}

pub struct LeanTree {
    leaves: Vec<Fr>,
    tree: LeanIMT<NodeHasher, 2, DEPTH>,
}

impl LeanTree {
    pub fn new() -> Self {
        Self {
            leaves: Vec::new(),
            tree: LeanIMT::new(NodeHasher),
        }
    }

    /// A tree of `leaves`, hashed in one batch. A view builds its trees this way:
    /// inserting one leaf at a time would rehash a path per leaf.
    pub fn from_leaves(leaves: &[Fr]) -> Self {
        let mut tree = Self::new();
        tree.extend(leaves);
        tree
    }

    /// Appends `leaves` in one batch.
    pub fn extend(&mut self, leaves: &[Fr]) {
        if leaves.is_empty() {
            return;
        }
        let hashes: Vec<Hash> = leaves.iter().map(fr_to_be_bytes).collect();
        self.tree
            .insert_many(&hashes)
            .expect("the pool's and the registry's trees fit the circuits' depth");
        self.leaves.extend_from_slice(leaves);
    }

    pub fn insert(&mut self, leaf: Fr) -> usize {
        self.extend(&[leaf]);
        self.leaves.len() - 1
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    pub fn leaf(&self, index: usize) -> Fr {
        self.leaves[index]
    }

    pub fn position(&self, leaf: Fr) -> Option<usize> {
        self.leaves.iter().position(|l| *l == leaf)
    }

    /// The root; zero for an empty tree, as on-chain.
    pub fn root(&self) -> Fr {
        self.tree
            .root()
            .map_or(Fr::from(0u64), |root| fr_from_be_bytes(&root))
    }

    /// The path from leaf `index` to the root; `None` past the last leaf. A level
    /// where the node was promoted has no sibling, and no step.
    pub fn proof(&self, index: usize) -> Option<MerkleProof> {
        let proof = self.tree.snapshot().generate_proof(index as u64).ok()?;
        Some(MerkleProof(
            proof.levels[..proof.level_count]
                .iter()
                .filter(|level| level.sibling_count > 0)
                .map(|level| Step {
                    sibling: fr_from_be_bytes(&level.siblings[0]),
                    is_right: level.position == 1,
                })
                .collect(),
        ))
    }
}

impl Default for LeanTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Rebuilt from the leaves: `rotortree`'s tree is not `Clone`.
impl Clone for LeanTree {
    fn clone(&self) -> Self {
        Self::from_leaves(&self.leaves)
    }
}

impl std::fmt::Debug for LeanTree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeanTree")
            .field("len", &self.len())
            .field("root", &self.root())
            .finish()
    }
}

impl MerkleProof {
    pub fn fold(&self, leaf: Fr) -> Fr {
        self.0.iter().fold(leaf, |node, step| {
            if step.is_right {
                poseidon2(step.sibling, node)
            } else {
                poseidon2(node, step.sibling)
            }
        })
    }
}

/// The tree as the PoC first built it: every root and path rehashes every
/// level from the leaves. Kept for tests, as a reference implementation, and
/// as the baseline of the tree benchmark.
#[cfg(test)]
pub(crate) mod rehashing {
    use ark_bn254::Fr;

    use super::{
        MerkleProof,
        Step,
    };
    use crate::poseidon::poseidon2;

    fn next_level(level: &[Fr]) -> Vec<Fr> {
        level
            .chunks(2)
            .map(|pair| match pair {
                [l, r] => poseidon2(*l, *r),
                [single] => *single,
                _ => unreachable!("chunks of two"),
            })
            .collect()
    }

    pub(crate) fn root(leaves: &[Fr]) -> Fr {
        if leaves.is_empty() {
            return Fr::from(0u64);
        }
        let mut level = leaves.to_vec();
        while level.len() > 1 {
            level = next_level(&level);
        }
        level[0]
    }

    pub(crate) fn proof(leaves: &[Fr], index: usize) -> Option<MerkleProof> {
        if index >= leaves.len() {
            return None;
        }
        let mut steps = Vec::new();
        let mut level = leaves.to_vec();
        let mut i = index;
        while level.len() > 1 {
            if i % 2 == 1 {
                steps.push(Step {
                    sibling: level[i - 1],
                    is_right: true,
                });
            } else if i + 1 < level.len() {
                steps.push(Step {
                    sibling: level[i + 1],
                    is_right: false,
                });
            }
            level = next_level(&level);
            i /= 2;
        }
        Some(MerkleProof(steps))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_proof_folds_to_the_root() {
        let mut tree = LeanTree::new();
        for n in 1..=11u64 {
            tree.insert(Fr::from(n));
            for i in 0..tree.len() {
                assert_eq!(
                    tree.proof(i).unwrap().fold(tree.leaf(i)),
                    tree.root(),
                    "n={n} i={i}"
                );
            }
            assert!(
                tree.proof(tree.len()).is_none(),
                "n={n}: past the last leaf"
            );
        }
    }

    #[test]
    fn single_leaf_root_is_the_leaf() {
        let mut tree = LeanTree::new();
        tree.insert(Fr::from(7u64));
        assert_eq!(tree.root(), Fr::from(7u64));
        assert!(tree.proof(0).unwrap().0.is_empty());
    }

    /// The same roots as the rehashing reference for every tree up to 34
    /// leaves, built in one batch or one leaf at a time, with every path
    /// folding to it; the same paths as the reference, promotions included,
    /// around the powers of two up to 70 leaves; and a tree grown in uneven
    /// batches.
    #[test]
    fn roots_and_paths_match_the_rehashing_reference() {
        let leaves: Vec<Fr> = (1..=70u64).map(|i| Fr::from(i * 7919)).collect();
        let mut grown = LeanTree::new();
        for n in 0..=34 {
            let batch = LeanTree::from_leaves(&leaves[..n]);
            if n > 0 {
                grown.insert(leaves[n - 1]);
            }
            let root = rehashing::root(&leaves[..n]);
            for tree in [&batch, &grown] {
                assert_eq!(tree.root(), root, "n={n}");
                for (i, leaf) in leaves[..n].iter().enumerate() {
                    assert_eq!(tree.proof(i).unwrap().fold(*leaf), root, "n={n} i={i}");
                }
            }
        }
        for n in [1, 2, 3, 7, 8, 9, 31, 32, 33, 63, 64, 65, 70] {
            let tree = LeanTree::from_leaves(&leaves[..n]);
            for i in [0, n / 2, n - 1] {
                assert_eq!(
                    tree.proof(i),
                    rehashing::proof(&leaves[..n], i),
                    "n={n} i={i}"
                );
            }
        }
        let mut uneven = LeanTree::new();
        for chunk in leaves.chunks(17) {
            uneven.extend(chunk);
        }
        assert_eq!(uneven.root(), rehashing::root(&leaves));
        assert_eq!(uneven.proof(69), rehashing::proof(&leaves, 69));
    }

    #[test]
    fn an_empty_tree_has_a_zero_root_and_no_proof() {
        let tree = LeanTree::new();
        assert_eq!(tree.root(), Fr::from(0u64));
        assert!(tree.proof(0).is_none());
        let cloned = LeanTree::from_leaves(&[Fr::from(1u64), Fr::from(2u64)]).clone();
        assert_eq!(
            cloned.root(),
            rehashing::root(&[Fr::from(1u64), Fr::from(2u64)])
        );
    }
}

/// The tree benchmark: the rehashing tree the PoC first used (before) against
/// the `rotortree`-backed one (after), on the work a wallet or the agent does to
/// build one transfer. Ignored by default; run it in release:
/// `cargo test --release --lib tree::benchmark -- --ignored --nocapture`
#[cfg(test)]
mod benchmark {
    use std::{
        hint::black_box,
        time::{
            Duration,
            Instant,
        },
    };

    use super::*;

    fn leaves(n: usize) -> Vec<Fr> {
        (0..n as u64).map(|i| Fr::from(i * 7919 + 1)).collect()
    }

    /// The median of `runs` timings of `f`.
    fn timed(runs: usize, mut f: impl FnMut()) -> Duration {
        let mut times: Vec<Duration> = (0..runs)
            .map(|_| {
                let start = Instant::now();
                f();
                start.elapsed()
            })
            .collect();
        times.sort();
        times[runs / 2]
    }

    fn show(d: Duration) -> String {
        if d >= Duration::from_secs(1) {
            format!("{:.1} s", d.as_secs_f64())
        } else if d >= Duration::from_millis(1) {
            format!("{:.1} ms", d.as_secs_f64() * 1e3)
        } else {
            format!("{:.0} µs", d.as_secs_f64() * 1e6)
        }
    }

    fn ratio(before: Duration, after: Duration) -> String {
        format!("{:.0}×", before.as_secs_f64() / after.as_secs_f64())
    }

    /// The leaves whose paths one transfer needs: its two inputs in the
    /// commitment tree, and in the attestation tree the input owner's leaf and
    /// the two outputs' owners'.
    fn spread(n: usize, k: usize) -> Vec<usize> {
        (1..=k).map(|j| n * j / (k + 1)).collect()
    }

    /// What building one transfer asks of the trees (`wallet.rs`): the
    /// commitment tree's root and two paths, and the attestation tree's root
    /// and three paths. Before, each of the seven rehashes the whole tree.
    fn transfer_before(commitments: &[Fr], attestations: &[Fr]) {
        black_box(rehashing::root(commitments));
        for i in spread(commitments.len(), 2) {
            black_box(rehashing::proof(commitments, i));
        }
        black_box(rehashing::root(attestations));
        for i in spread(attestations.len(), 3) {
            black_box(rehashing::proof(attestations, i));
        }
    }

    fn transfer_after(commitments: &LeanTree, attestations: &LeanTree) {
        black_box(commitments.root());
        for i in spread(commitments.len(), 2) {
            black_box(commitments.proof(i));
        }
        black_box(attestations.root());
        for i in spread(attestations.len(), 3) {
            black_box(attestations.proof(i));
        }
    }

    /// One transfer's tree work three ways: before; after, with both trees
    /// built for a fresh view, as every read of the chain does today; and
    /// after, with the trees kept between views and only the last transfer's
    /// two outputs appended, as a chain reader that folds events would allow.
    fn transfer(
        n_commitments: usize,
        n_attestations: usize,
        runs_before: usize,
    ) -> [Duration; 3] {
        let c = leaves(n_commitments);
        let a = leaves(n_attestations);
        let before = timed(runs_before, || transfer_before(&c, &a));
        let after = timed(3, || {
            let ct = LeanTree::from_leaves(&c);
            let at = LeanTree::from_leaves(&a);
            transfer_after(&ct, &at);
        });
        let mut ct = LeanTree::from_leaves(&c);
        let at = LeanTree::from_leaves(&a);
        let two = [Fr::from(3u64), Fr::from(5u64)];
        let kept = timed(5, || {
            ct.extend(&two);
            transfer_after(&ct, &at);
        });
        [before, after, kept]
    }

    #[test]
    #[ignore = "a benchmark: run with --release --ignored --nocapture"]
    fn benchmark() {
        let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
        println!(
            "\nTree benchmark, {threads} threads available (rotortree hashes a batch in parallel)."
        );

        println!(
            "\n| Leaves | Root, before | Root, after | Path, before | Path, after | Building a view's tree, before | Building a view's tree, after |"
        );
        println!("|---|---|---|---|---|---|---|");
        for n in [1_000usize, 10_000, 100_000, 1_000_000] {
            let l = leaves(n);
            let slow = n <= 10_000;
            let (root_before, path_before) = if n <= 100_000 {
                let runs = if slow { 3 } else { 1 };
                (
                    show(timed(runs, || {
                        black_box(rehashing::root(&l));
                    })),
                    show(timed(runs, || {
                        black_box(rehashing::proof(&l, n / 3));
                    })),
                )
            } else {
                ("not run".into(), "not run".into())
            };
            let build_before = timed(3, || {
                let mut v = Vec::new();
                v.extend_from_slice(&l);
                black_box(v);
            });
            let tree = LeanTree::from_leaves(&l);
            let root_after = timed(5, || {
                black_box(tree.root());
            });
            let path_after = timed(5, || {
                black_box(tree.proof(n / 3));
            });
            let build_after = timed(if n < 1_000_000 { 3 } else { 1 }, || {
                black_box(LeanTree::from_leaves(&l));
            });
            println!(
                "| {n} | {root_before} | {} | {path_before} | {} | {} | {} |",
                show(root_after),
                show(path_after),
                show(build_before),
                show(build_after),
            );
        }

        println!(
            "\nOne transfer's tree work (2 roots, 5 paths), both trees of the given size:"
        );
        println!(
            "\n| Leaves per tree | Before | After, trees built per view | Speedup | After, trees kept between views |"
        );
        println!("|---|---|---|---|---|");
        for n in [1_000usize, 10_000, 100_000] {
            let [before, after, kept] = transfer(n, n, if n <= 10_000 { 3 } else { 1 });
            println!(
                "| {n} | {} | {} | {} | {} |",
                show(before),
                show(after),
                ratio(before, after),
                show(kept)
            );
        }

        // The fund profiles of the cost estimate, at the end of year one: notes
        // from the day's activity over 250 dealing days; attestation leaves at
        // 12 a year per owner value, with as many padding values as investors.
        println!("\nThe fund profiles at the end of year one:");
        println!(
            "\n| Fund | Notes | Attestation leaves | Transfer, before | Transfer, after | Daily hand-out, before | Daily hand-out, after | Transfer, trees kept |"
        );
        println!("|---|---|---|---|---|---|---|---|");
        for (fund, notes, attested, subscriptions) in [
            ("200 investors", 3_750usize, 4_800usize, 4u32),
            ("2,000 investors", 30_000, 48_000, 30),
            ("10,000 investors", 150_000, 240_000, 150),
        ] {
            let [before, after, kept] = transfer(notes, attested, 1);
            let hand_out = subscriptions - 1;
            println!(
                "| {fund} | {notes} | {attested} | {} | {} | {} | {} | {} |",
                show(before),
                show(after),
                show(before * hand_out),
                show(after * hand_out),
                show(kept),
            );
        }
    }
}

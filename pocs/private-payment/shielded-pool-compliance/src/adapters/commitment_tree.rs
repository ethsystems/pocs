//! The `rotortree`-backed `MerkleStore` adapter. Wraps `rotortree::RotorTree`, not
//! `LeanIMT`: the `storage` feature is a separate persistent type, not persistence
//! bolted onto `LeanIMT`. Also home of the attestation tree, since both are the same
//! `N = 2` construction at different depths.

use std::path::Path;

use rotortree::{
    CheckpointPolicy,
    FlushPolicy,
    Hash as RotorHash,
    HashState,
    Hasher,
    NaryProof,
    RotorTree,
    RotorTreeConfig,
    TieringConfig,
    TreeError,
};

use crate::{
    error::MerkleError,
    ports::merkle::{
        LeafIndex,
        MerklePath,
        MerkleStore,
        PathStep,
        Side,
    },
    poseidon::{
        fr_from_be_bytes,
        fr_to_be_bytes,
        poseidon2,
    },
    types::Bytes32,
};

const COMMITMENT_TREE_DEPTH: usize = crate::MAX_COMMITMENT_TREE_DEPTH as usize;
const ATTESTATION_TREE_DEPTH: usize = crate::MAX_ATTESTATION_TREE_DEPTH as usize;

/// A `LeanIMT` node hash: `Poseidon1(left, right)`, matching zk-kit's canonical
/// two-child node hash bit for bit.
#[derive(Clone)]
pub struct Poseidon1Hasher;

/// Buffers bytes and finalizes by folding 32-byte chunks with `poseidon2`, so the
/// streaming path stays consistent with `hash_children` for any caller that reaches it
/// through `Hasher::new_state`/`HashState::update` instead of the overridden
/// `hash_children` below. `hash_children` is what `RotorTree`/`TreeSnapshot` actually
/// call for this `N = 2` tree, so this path is exercised only by direct tests of
/// `Poseidon1State` itself.
pub struct Poseidon1State {
    buf: Vec<u8>,
}

impl HashState for Poseidon1State {
    fn update(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    fn finalize(self) -> RotorHash {
        let mut acc = ark_bn254::Fr::from(0u64);
        for chunk in self.buf.chunks(32) {
            let mut padded = [0u8; 32];
            padded[32 - chunk.len()..].copy_from_slice(chunk);
            acc = poseidon2(acc, fr_from_be_bytes(&padded));
        }
        fr_to_be_bytes(&acc)
    }
}

impl Hasher for Poseidon1Hasher {
    type State = Poseidon1State;

    fn new_state(&self) -> Self::State {
        Poseidon1State { buf: Vec::new() }
    }

    fn hash_children(&self, children: &[RotorHash]) -> RotorHash {
        // N = 2 is a const generic on every tree this hasher opens, so this is
        // unreachable in normal operation; a live check is cheap insurance given the
        // tree root feeds every proof and every on-chain comparison (audit B3).
        let [l, r] = children else {
            panic!("binary LeanIMT hashes exactly two children")
        };
        let l = fr_from_be_bytes(l);
        let r = fr_from_be_bytes(r);
        fr_to_be_bytes(&poseidon2(l, r))
    }
}

fn bytes32_to_hash(value: Bytes32) -> RotorHash {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(value.as_ref());
    bytes
}

/// Drops levels the tree promoted (`sibling_count == 0`) and reads the direction bit
/// from `position`: `position == 1` means our node is the right child, matching
/// `Side::Right` / `indices[i] == true` in the vendored Noir `binary_merkle_root`.
fn flatten_proof<const N: usize, const D: usize>(proof: &NaryProof<N, D>) -> MerklePath {
    let steps = proof.levels[..proof.level_count]
        .iter()
        .filter(|level| level.sibling_count > 0)
        .map(|level| PathStep {
            sibling: Bytes32::from(level.siblings[0]),
            side: if level.position == 1 {
                Side::Right
            } else {
                Side::Left
            },
        })
        .collect();
    MerklePath::new(steps)
}

/// A `rotortree::RotorTree`-backed append-only Merkle store, generic over its
/// compile-time depth so `CommitmentTree` and `AttestationTree` share one
/// implementation.
pub struct RotorMerkleTree<const D: usize>(RotorTree<Poseidon1Hasher, 2, D>);

pub type CommitmentTree = RotorMerkleTree<COMMITMENT_TREE_DEPTH>;
pub type AttestationTree = RotorMerkleTree<ATTESTATION_TREE_DEPTH>;

impl<const D: usize> RotorMerkleTree<D> {
    /// Opens or creates a tree persisted under `path`. Tests get `path` from
    /// `tempfile`.
    pub fn open(path: &Path) -> Result<Self, MerkleError> {
        let config = RotorTreeConfig {
            path: path.to_path_buf(),
            flush_policy: FlushPolicy::default(),
            checkpoint_policy: CheckpointPolicy::default(),
            tiering: TieringConfig::default(),
            verify_checkpoint: true,
        };
        let tree = RotorTree::open(Poseidon1Hasher, config)
            .map_err(|e| MerkleError::Storage(Box::new(e)))?;
        Ok(Self(tree))
    }
}

impl<const D: usize> MerkleStore for RotorMerkleTree<D> {
    fn root(&self) -> Option<Bytes32> {
        self.0.root().map(Bytes32::from)
    }

    fn size(&self) -> u64 {
        self.0.size()
    }

    fn get_proof(&self, index: LeafIndex) -> Result<MerklePath, MerkleError> {
        let snapshot = self.0.snapshot();
        let proof = snapshot.generate_proof(index.0).map_err(|e| match e {
            TreeError::IndexOutOfRange { index, size } => {
                MerkleError::IndexOutOfRange { index, size }
            }
            TreeError::MaxDepthExceeded { max_depth } => MerkleError::DepthExceeded {
                max_depth: max_depth as u64,
            },
            other => MerkleError::Storage(Box::new(other)),
        })?;
        Ok(flatten_proof(&proof))
    }

    /// Uses `insert_durable`, blocking until the leaf is fsynced, over the
    /// batching `insert`: the wallet inserts one leaf at a time and correctness (a
    /// root the wallet can hand to a proof) matters more here than throughput.
    fn insert(&self, leaf: Bytes32) -> Result<LeafIndex, MerkleError> {
        let index = self.0.size();
        self.0
            .insert_durable(bytes32_to_hash(leaf))
            .map_err(|e| MerkleError::Storage(Box::new(e)))?;
        Ok(LeafIndex(index))
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;

    use super::*;
    use crate::poseidon::poseidon2 as fr_poseidon2;

    fn temp_tree<const D: usize>() -> (tempfile::TempDir, RotorMerkleTree<D>) {
        let dir = tempfile::tempdir().expect("create tmp dir");
        let tree = RotorMerkleTree::<D>::open(dir.path()).expect("open tree");
        (dir, tree)
    }

    fn leaf(n: u8) -> Bytes32 {
        let hash = fr_poseidon2(Fr::from(0u64), Fr::from(n as u64));
        Bytes32::from(hash)
    }

    /// Hand-rolled zk-kit-style LeanIMT reference: a node with no right sibling is
    /// promoted verbatim (bit-identical to zk-kit's promotion rule), everything else
    /// pairs left-to-right with `Poseidon1(left, right)`.
    fn reference_root(leaves: &[Fr]) -> Fr {
        let mut level: Vec<Fr> = leaves.to_vec();
        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            let mut i = 0;
            while i < level.len() {
                if i + 1 < level.len() {
                    next.push(fr_poseidon2(level[i], level[i + 1]));
                } else {
                    next.push(level[i]); // promoted: no right sibling
                }
                i += 2;
            }
            level = next;
        }
        level[0]
    }

    #[test]
    fn root_matches_reference_leanimt_for_an_even_leaf_count() {
        let (_dir, tree) = temp_tree::<10>();
        let leaves: Vec<Bytes32> = (0..4).map(leaf).collect();
        for l in &leaves {
            tree.insert(*l).expect("insert");
        }
        let fr_leaves: Vec<Fr> = leaves
            .iter()
            .map(|b| Fr::try_from(*b).expect("canonical"))
            .collect();
        let expected = Bytes32::from(reference_root(&fr_leaves));
        assert_eq!(tree.root(), Some(expected));
    }

    #[test]
    fn root_matches_reference_leanimt_at_the_promotion_case() {
        // Odd leaf count: the last leaf at every level with no sibling is promoted
        // rather than rehashed. Sizes 1, 3, 5, 7 all exercise a promotion.
        for size in [1usize, 3, 5, 7] {
            let (_dir, tree) = temp_tree::<10>();
            let leaves: Vec<Bytes32> = (0..size as u8).map(leaf).collect();
            for l in &leaves {
                tree.insert(*l).expect("insert");
            }
            let fr_leaves: Vec<Fr> = leaves
                .iter()
                .map(|b| Fr::try_from(*b).expect("canonical"))
                .collect();
            let expected = Bytes32::from(reference_root(&fr_leaves));
            assert_eq!(tree.root(), Some(expected), "size = {size}");
        }
    }

    #[test]
    fn nary_proof_verify_passes_for_every_inserted_leaf() {
        let (_dir, tree) = temp_tree::<10>();
        let leaves: Vec<Bytes32> = (0..5).map(leaf).collect();
        for l in &leaves {
            tree.insert(*l).expect("insert");
        }
        let snapshot = tree.0.snapshot();
        for i in 0..leaves.len() as u64 {
            let proof = snapshot.generate_proof(i).expect("generate proof");
            assert!(proof.verify(&Poseidon1Hasher).expect("verify runs"));
        }
    }

    #[test]
    fn merkle_path_extraction_drops_promotion_levels() {
        let (_dir, tree) = temp_tree::<10>();
        // 3 leaves: leaf index 2 is promoted at level 0 (no sibling), so its
        // MerklePath has fewer steps than the tree's structural depth.
        for l in (0..3).map(leaf) {
            tree.insert(l).expect("insert");
        }
        let promoted = tree
            .get_proof(LeafIndex(2))
            .expect("proof for promoted leaf");
        let paired = tree.get_proof(LeafIndex(0)).expect("proof for paired leaf");
        assert!(promoted.len() < paired.len());
    }

    #[test]
    fn get_proof_rejects_an_out_of_range_index() {
        let (_dir, tree) = temp_tree::<10>();
        tree.insert(leaf(0)).expect("insert");
        assert!(matches!(
            tree.get_proof(LeafIndex(5)),
            Err(MerkleError::IndexOutOfRange { index: 5, size: 1 })
        ));
    }

    #[test]
    fn insert_returns_sequential_leaf_indices() {
        let (_dir, tree) = temp_tree::<10>();
        assert_eq!(tree.insert(leaf(0)).unwrap(), LeafIndex(0));
        assert_eq!(tree.insert(leaf(1)).unwrap(), LeafIndex(1));
        assert_eq!(tree.insert(leaf(2)).unwrap(), LeafIndex(2));
    }

    #[test]
    fn empty_tree_has_no_root() {
        let (_dir, tree) = temp_tree::<10>();
        assert_eq!(tree.root(), None);
        assert_eq!(tree.size(), 0);
    }
}

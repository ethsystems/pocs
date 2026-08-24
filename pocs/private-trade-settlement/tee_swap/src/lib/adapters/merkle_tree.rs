use alloy::primitives::B256;

use crate::domain::commitment::Commitment;
use crate::domain::merkle::{CommitmentMerkleProof, CommitmentTree};

/// Local Merkle tree adapter that wraps `CommitmentTree` with root history tracking.
///
/// Maintains a history of all roots (matching the on-chain root history in `PrivateUTXO.sol`).
/// This is used by parties and the coordinator to:
/// - Generate Merkle proofs for note spending
/// - Verify that a given root was valid at some point
#[derive(Clone)]
pub struct LocalMerkleTree {
    tree: CommitmentTree,
    /// Historical roots (oldest first). The on-chain contract stores a similar history.
    root_history: Vec<B256>,
}

impl LocalMerkleTree {
    pub fn new() -> Self {
        Self {
            tree: CommitmentTree::new(),
            root_history: Vec::new(),
        }
    }

    /// Insert a commitment and record the new root in history.
    pub fn insert_commitment(&mut self, commitment: &Commitment) {
        self.tree.insert_commitment(commitment);
        if let Some(root) = self.tree.root_b256() {
            self.root_history.push(root);
        }
    }

    /// Check if a root exists in the history (mirrors on-chain `isKnownRoot`).
    pub fn is_known_root(&self, root: B256) -> bool {
        self.root_history.contains(&root)
    }

    /// Get the current (latest) root, or None if tree is empty.
    pub fn current_root(&self) -> Option<B256> {
        self.tree.root_b256()
    }

    /// Generate a Merkle proof for the commitment at the given leaf index.
    pub fn generate_proof(&self, leaf_index: u64) -> Option<CommitmentMerkleProof> {
        self.tree.generate_commitment_proof(leaf_index)
    }

    /// Get the number of commitments in the tree.
    pub fn len(&self) -> usize {
        self.tree.len()
    }

    /// Check if the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.tree.is_empty()
    }

    /// Get the full root history.
    pub fn root_history(&self) -> &[B256] {
        &self.root_history
    }
}

impl Default for LocalMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_commitment(byte: u8) -> Commitment {
        Commitment(B256::repeat_byte(byte))
    }

    #[test]
    fn test_insert_and_root_tracking() {
        let mut tree = LocalMerkleTree::new();
        assert!(tree.is_empty());
        assert!(tree.current_root().is_none());
        assert!(tree.root_history().is_empty());

        tree.insert_commitment(&test_commitment(0x01));

        assert_eq!(tree.len(), 1);
        assert!(tree.current_root().is_some());
        assert_eq!(tree.root_history().len(), 1);
    }

    #[test]
    fn test_root_history_grows() {
        let mut tree = LocalMerkleTree::new();

        tree.insert_commitment(&test_commitment(0x01));
        let root1 = tree.current_root().unwrap();

        tree.insert_commitment(&test_commitment(0x02));
        let root2 = tree.current_root().unwrap();

        tree.insert_commitment(&test_commitment(0x03));
        let root3 = tree.current_root().unwrap();

        assert_eq!(tree.root_history().len(), 3);
        assert_ne!(root1, root2);
        assert_ne!(root2, root3);
    }

    #[test]
    fn test_is_known_root() {
        let mut tree = LocalMerkleTree::new();

        tree.insert_commitment(&test_commitment(0x01));
        let root1 = tree.current_root().unwrap();

        tree.insert_commitment(&test_commitment(0x02));
        let root2 = tree.current_root().unwrap();

        // Both historical roots should be known
        assert!(tree.is_known_root(root1));
        assert!(tree.is_known_root(root2));

        // Random root should not be known
        assert!(!tree.is_known_root(B256::repeat_byte(0xFF)));
    }

    #[test]
    fn test_generate_proof() {
        let mut tree = LocalMerkleTree::new();

        tree.insert_commitment(&test_commitment(0x01));
        tree.insert_commitment(&test_commitment(0x02));

        let proof = tree.generate_proof(0);
        assert!(proof.is_some());

        let proof = proof.unwrap();
        assert_eq!(proof.leaf_index, 0);
        assert!(!proof.path.is_empty());
    }

    #[test]
    fn test_proof_for_each_leaf() {
        let mut tree = LocalMerkleTree::new();

        for i in 0..4u8 {
            tree.insert_commitment(&test_commitment(i + 1));
        }

        for i in 0..4u64 {
            let proof = tree.generate_proof(i);
            assert!(proof.is_some(), "Proof should exist for leaf {i}");
        }
    }
}

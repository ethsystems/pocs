use alloy::primitives::B256;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use lean_imt::hashed_tree::{HashedLeanIMT, LeanIMTHasher};
use light_poseidon::{Poseidon, PoseidonHasher};

use super::commitment::Commitment;

/// Maximum depth of the commitment Merkle tree (supports up to 2^32 commitments).
/// LeanIMT uses dynamic depth, but arrays are sized to this maximum.
pub const MAX_COMMITMENT_TREE_DEPTH: usize = 32;

/// Merkle proof for a commitment in the commitment tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitmentMerkleProof {
    /// Sibling hashes along the path from leaf to root.
    pub path: Vec<B256>,
    /// Index bits indicating left (0) or right (1) at each level.
    pub indices: Vec<u8>,
    /// The leaf index in the tree.
    pub leaf_index: u64,
    /// The actual proof length (tree depth at time of proof generation).
    pub proof_length: usize,
}

impl CommitmentMerkleProof {
    pub fn new(path: Vec<B256>, indices: Vec<u8>, leaf_index: u64) -> Self {
        let proof_length = path.len();
        Self {
            path,
            indices,
            leaf_index,
            proof_length,
        }
    }
}

// --- Merkle tree implementation ---

/// Poseidon hasher for LeanIMT.
/// Uses light-poseidon with Circom-compatible configuration (matching Solidity's PoseidonT3).
#[derive(Debug, Default, Clone)]
pub struct PoseidonHash;

impl LeanIMTHasher<32> for PoseidonHash {
    fn hash(input: &[u8]) -> [u8; 32] {
        let hash = Poseidon::<Fr>::new_circom(2)
            .expect("Failed to initialize Poseidon")
            .hash(&[
                Fr::from_be_bytes_mod_order(&input[..32]),
                Fr::from_be_bytes_mod_order(&input[32..]),
            ])
            .expect("Poseidon hash failed");

        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&hash.into_bigint().to_bytes_be());
        hash_bytes
    }
}

/// Commitment tree using LeanIMT with Poseidon hashing.
#[derive(Clone)]
pub struct CommitmentTree(HashedLeanIMT<32, PoseidonHash>);

/// Extract direction bits from a leaf index (LSB to MSB).
fn decode_path(index: usize, path_len: usize) -> Vec<u8> {
    (0..path_len).map(|i| ((index >> i) & 1) as u8).collect()
}

/// Convert a B256 value to bytes for tree insertion.
pub fn b256_to_bytes(value: &B256) -> [u8; 32] {
    value.0
}

/// Convert bytes from the tree to a B256 value.
pub fn bytes_to_b256(bytes: &[u8; 32]) -> B256 {
    B256::from_slice(bytes)
}

impl CommitmentTree {
    /// Create a new empty commitment tree.
    pub fn new() -> Self {
        Self(HashedLeanIMT::new(&[], PoseidonHash).unwrap())
    }

    /// Insert a commitment leaf into the tree.
    pub fn insert(&mut self, leaf: &[u8; 32]) {
        self.0.insert(leaf);
    }

    /// Insert a Commitment into the tree.
    pub fn insert_commitment(&mut self, commitment: &Commitment) {
        self.insert(&b256_to_bytes(&commitment.0));
    }

    /// Get the number of leaves in the tree.
    pub fn len(&self) -> usize {
        self.0.size()
    }

    /// Check if the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get the current root of the tree, or None if empty.
    pub fn root(&self) -> Option<[u8; 32]> {
        self.0.root()
    }

    /// Get the current root as B256, or None if empty.
    pub fn root_b256(&self) -> Option<B256> {
        self.root().map(|r| bytes_to_b256(&r))
    }

    /// Generate a Merkle proof for the leaf at the given index.
    pub fn generate_commitment_proof(
        &self,
        leaf_index: u64,
    ) -> Option<CommitmentMerkleProof> {
        let proof = self.0.generate_proof(leaf_index as usize).ok()?;

        let path: Vec<B256> = proof
            .siblings
            .iter()
            .map(|s| B256::from_slice(s))
            .collect();

        let indices = decode_path(proof.index, proof.siblings.len());
        let proof_length = path.len();

        Some(CommitmentMerkleProof {
            path,
            indices,
            leaf_index,
            proof_length,
        })
    }
}

impl Default for CommitmentTree {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commitment_tree_insert_and_root() {
        let mut tree = CommitmentTree::new();
        assert!(tree.is_empty());

        let leaf = [1u8; 32];
        tree.insert(&leaf);

        assert_eq!(tree.len(), 1);
        assert!(tree.root().is_some());
    }

    #[test]
    fn test_commitment_tree_root_changes_on_insert() {
        let mut tree = CommitmentTree::new();

        tree.insert(&[1u8; 32]);
        let root1 = tree.root().unwrap();

        tree.insert(&[2u8; 32]);
        let root2 = tree.root().unwrap();

        assert_ne!(root1, root2, "Root should change after insertion");
    }

    #[test]
    fn test_commitment_tree_proof_generation() {
        let mut tree = CommitmentTree::new();
        tree.insert(&[1u8; 32]);
        tree.insert(&[2u8; 32]);

        let proof = tree.generate_commitment_proof(0).unwrap();

        assert_eq!(proof.leaf_index, 0);
        assert_eq!(proof.proof_length, proof.path.len());
        assert!(!proof.path.is_empty());
    }

    #[test]
    fn test_commitment_tree_proof_for_second_leaf() {
        let mut tree = CommitmentTree::new();
        tree.insert(&[1u8; 32]);
        tree.insert(&[2u8; 32]);
        tree.insert(&[3u8; 32]);

        let proof = tree.generate_commitment_proof(1).unwrap();

        assert_eq!(proof.leaf_index, 1);
        assert_eq!(proof.proof_length, proof.path.len());
    }

    #[test]
    fn test_insert_commitment_type() {
        let mut tree = CommitmentTree::new();
        let commitment = Commitment(B256::repeat_byte(0x42));

        tree.insert_commitment(&commitment);

        assert_eq!(tree.len(), 1);
        assert!(tree.root().is_some());
    }

    #[test]
    fn test_b256_conversion_roundtrip() {
        let original = B256::from_slice(&[42u8; 32]);
        let bytes = b256_to_bytes(&original);
        let converted = bytes_to_b256(&bytes);
        assert_eq!(original, converted);
    }

    #[test]
    fn test_root_b256() {
        let mut tree = CommitmentTree::new();
        tree.insert(&[1u8; 32]);

        let root_bytes = tree.root().unwrap();
        let root_b256 = tree.root_b256().unwrap();

        assert_eq!(root_bytes, b256_to_bytes(&root_b256));
    }
}

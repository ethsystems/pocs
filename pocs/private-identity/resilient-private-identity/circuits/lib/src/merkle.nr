use binary_merkle_root::binary_merkle_root;
use crate::hasher::hash_merkle_node;

// Wrapper that passes hash_merkle_node (PoseidonT3, no domain tag) as the hash
// function. This matches LeanIMT's on-chain hash exactly.
fn merkle_hash(pair: [Field; 2]) -> Field {
    hash_merkle_node(pair[0], pair[1])
}

// Verify a Merkle inclusion proof against a known root.
//
// Uses binary_merkle_root from zk-kit.noir with variable proof depth.
// The hash function is PoseidonT3 (no domain tag) to match LeanIMT.
//
// # Arguments
// * `leaf` - The leaf value to verify membership of
// * `root` - Expected Merkle root
// * `proof_length` - Actual depth of the proof (tree may be dynamic)
// * `path_indices` - Bit decomposition of the leaf index (LSB first)
// * `path_elements` - Sibling hashes at each level (bottom to top)
pub fn verify_membership(
    leaf: Field,
    root: Field,
    proof_length: u32,
    path_indices: [bool; 20],
    path_elements: [Field; 20],
) {
    let computed_root = binary_merkle_root(
        merkle_hash,
        leaf,
        proof_length,
        path_indices,
        path_elements,
    );
    assert(computed_root == root, "Merkle proof verification failed");
}

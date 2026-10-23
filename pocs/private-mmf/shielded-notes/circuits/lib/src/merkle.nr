use crate::hasher::hash_merkle_node;

fn merkle_hash(pair: [Field; 2]) -> Field {
    hash_merkle_node(pair[0], pair[1])
}

// LeanIMT promotes a node that lacks a right sibling, so co-resident leaves sit
// at different depths and a leaf's own path is shorter than the tree's, hence
// `depth` is a runtime parameter distinct from the compile-time `MAX_DEPTH`.
pub fn binary_merkle_root<let MAX_DEPTH: u32>(
    hasher: fn([Field; 2]) -> Field,
    leaf: Field,
    depth: u32,
    indices: [bool; MAX_DEPTH],
    siblings: [Field; MAX_DEPTH],
) -> Field {
    let mut node = leaf;
    for i in 0..MAX_DEPTH {
        if i < depth {
            let sibling = siblings[i];
            let (left, right) = if indices[i] {
                (sibling, node)
            } else {
                (node, sibling)
            };
            node = hasher([left, right]);
        }
    }
    node
}

pub fn verify<let MAX_DEPTH: u32>(
    leaf: Field,
    root: Field,
    depth: u32,
    indices: [bool; MAX_DEPTH],
    siblings: [Field; MAX_DEPTH],
) {
    let computed = binary_merkle_root(merkle_hash, leaf, depth, indices, siblings);
    assert(computed == root, "merkle proof failed");
}

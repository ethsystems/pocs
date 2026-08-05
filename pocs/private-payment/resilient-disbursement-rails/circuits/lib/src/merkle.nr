use crate::hasher::hash_merkle_node;

// Ported from zk-kit.noir's binary-merkle-root-v0.0.1 (pinned to an old
// nargo whose `u1` type this compiler no longer accepts); reimplemented
// in-tree with `bool` indices, same semantics.
fn binary_merkle_root<let MAX_DEPTH: u32>(
    leaf: Field,
    depth: u32,
    indices: [bool; MAX_DEPTH],
    siblings: [Field; MAX_DEPTH],
) -> Field {
    let mut node = leaf;
    for i in 0..MAX_DEPTH {
        if i < depth {
            let sibling = siblings[i];
            let (left, right) = if !indices[i] {
                (node, sibling)
            } else {
                (sibling, node)
            };
            node = hash_merkle_node(left, right);
        }
    }
    node
}

pub fn verify_membership_cohort(
    leaf: Field,
    root: Field,
    proof_length: u32,
    path_indices: [bool; 20],
    path_elements: [Field; 20],
) {
    let computed = binary_merkle_root(leaf, proof_length, path_indices, path_elements);
    assert(computed == root, "cohort merkle proof failed");
}

pub fn verify_membership_pool(
    leaf: Field,
    root: Field,
    proof_length: u32,
    path_indices: [bool; 32],
    path_elements: [Field; 32],
) {
    let computed = binary_merkle_root(leaf, proof_length, path_indices, path_elements);
    assert(computed == root, "pool merkle proof failed");
}

#[test]
fn test_cohort_path_zero_siblings() {
    let leaf: Field = 0x1234;
    let path: [Field; 20] = [0; 20];
    let bits: [bool; 20] = [false; 20];
    let mut current = leaf;
    for i in 0..20 {
        current = hash_merkle_node(current, path[i]);
    }
    verify_membership_cohort(leaf, current, 20, bits, path);
}

#[test]
fn test_pool_path_zero_siblings() {
    let leaf: Field = 0x5678;
    let path: [Field; 32] = [0; 32];
    let bits: [bool; 32] = [false; 32];
    let mut current = leaf;
    for i in 0..32 {
        current = hash_merkle_node(current, path[i]);
    }
    verify_membership_pool(leaf, current, 32, bits, path);
}

#[test(should_fail)]
fn test_cohort_path_tampered() {
    let leaf: Field = 0x1234;
    let mut path: [Field; 20] = [0; 20];
    let bits: [bool; 20] = [false; 20];
    let mut current = leaf;
    for i in 0..20 {
        current = hash_merkle_node(current, path[i]);
    }
    let real_root = current;
    // Tamper with one sibling after computing the root
    path[5] = 0xABCD;
    verify_membership_cohort(leaf, real_root, 20, bits, path);
}

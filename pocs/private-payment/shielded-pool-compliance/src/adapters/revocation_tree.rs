//! Fixed-depth attester revocation tree, mirroring `contracts/src/AttesterRevocationTree.sol`
//! exactly: `ATTESTER_TREE_DEPTH = 5` (32 leaf slots), leaf `Poseidon1(attester,
//! revokedAtEpoch)`, empty slot `Poseidon1(0, 0)`, recomputed in full on every write.
//!
//! Deliberately not built on `rotortree`: a lowering rewrites an existing leaf in
//! place, so the structure is non-monotone. `rotortree::LeanIMT`/`RotorTree` expose
//! `insert`/`insert_many` only, with no rewrite-at-index primitive, so this is a
//! hand-rolled full binary tree instead, and does not implement `ports::merkle::MerkleStore`:
//! that trait's `insert`-only write model does not fit add/remove/lower, and forcing
//! it through the same interface would blur the distinction rather than reuse
//! anything real.

use std::collections::HashMap;

use ark_bn254::Fr;

use crate::{
    error::MerkleError,
    ports::merkle::{
        MerklePath,
        PathStep,
        Side,
    },
    poseidon::poseidon2,
    types::{
        Address,
        Bytes32,
    },
};

const ATTESTER_TREE_DEPTH: usize = crate::ATTESTER_TREE_DEPTH as usize;
const ATTESTER_TREE_CAPACITY: usize = 1 << ATTESTER_TREE_DEPTH;

/// One attester per issued initial pair (SPEC "Attester revocation": `addAttester`
/// MUST insert the attester's initial `type(uint64).max` pair).
#[derive(Debug, Clone, Default)]
pub struct RevocationTree {
    attesters: Vec<(Address, u64)>,
    revocation_floor: HashMap<Address, u64>,
}

impl RevocationTree {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_attester(&mut self, attester: Address) -> Result<Bytes32, MerkleError> {
        if self.attesters.iter().any(|(a, _)| *a == attester) {
            return Err(MerkleError::AttesterAlreadyExists(attester));
        }
        if self.attesters.len() >= ATTESTER_TREE_CAPACITY {
            return Err(MerkleError::RevocationTreeFull);
        }
        let floor = self.revocation_floor.get(&attester).copied().unwrap_or(0);
        let revoked_at = if floor == 0 { u64::MAX } else { floor };
        self.attesters.push((attester, revoked_at));
        Ok(self.root())
    }

    /// Swap-and-pop, mirroring the Solidity `remove`: frees the slot back to empty, so
    /// any witness for `attester`'s leaf can no longer produce an inclusion proof
    /// against the resulting root. The revocation floor is left in place.
    pub fn remove_attester(&mut self, attester: Address) -> Result<Bytes32, MerkleError> {
        let pos = self.position_of(attester)?;
        self.attesters.swap_remove(pos);
        Ok(self.root())
    }

    /// SPEC "Attester revocation": `revokedAtEpoch` is non-increasing; enforcing that
    /// monotonicity is the caller's job (mirroring the Solidity contract's timelocked
    /// governance path), not this in-memory mirror's.
    pub fn lower_revocation(
        &mut self,
        attester: Address,
        revoked_at_epoch: u64,
    ) -> Result<Bytes32, MerkleError> {
        let pos = self.position_of(attester)?;
        self.attesters[pos].1 = revoked_at_epoch;
        self.revocation_floor.insert(attester, revoked_at_epoch);
        Ok(self.root())
    }

    pub fn contains(&self, attester: Address) -> bool {
        self.attesters.iter().any(|(a, _)| *a == attester)
    }

    pub fn revoked_at_epoch_of(&self, attester: Address) -> Result<u64, MerkleError> {
        let pos = self.position_of(attester)?;
        Ok(self.attesters[pos].1)
    }

    pub fn root(&self) -> Bytes32 {
        Bytes32::from(compute_root(&self.attesters))
    }

    pub fn proof(&self, attester: Address) -> Result<MerklePath, MerkleError> {
        let pos = self.position_of(attester)?;
        Ok(compute_proof(&self.attesters, pos))
    }

    fn position_of(&self, attester: Address) -> Result<usize, MerkleError> {
        self.attesters
            .iter()
            .position(|(a, _)| *a == attester)
            .ok_or(MerkleError::AttesterNotFound(attester))
    }
}

fn leaf_at(attesters: &[(Address, u64)], i: usize) -> Fr {
    match attesters.get(i) {
        Some((attester, revoked_at)) => {
            poseidon2(Fr::from(*attester), Fr::from(*revoked_at))
        }
        None => poseidon2(Fr::from(0u64), Fr::from(0u64)),
    }
}

fn compute_root(attesters: &[(Address, u64)]) -> Fr {
    let mut nodes: Vec<Fr> = (0..ATTESTER_TREE_CAPACITY)
        .map(|i| leaf_at(attesters, i))
        .collect();
    let mut level_size = ATTESTER_TREE_CAPACITY;
    while level_size > 1 {
        let half = level_size / 2;
        for i in 0..half {
            nodes[i] = poseidon2(nodes[2 * i], nodes[2 * i + 1]);
        }
        level_size = half;
    }
    nodes[0]
}

fn compute_proof(attesters: &[(Address, u64)], leaf_index: usize) -> MerklePath {
    let mut nodes: Vec<Fr> = (0..ATTESTER_TREE_CAPACITY)
        .map(|i| leaf_at(attesters, i))
        .collect();
    let mut steps = Vec::with_capacity(ATTESTER_TREE_DEPTH);
    let mut index = leaf_index;
    let mut level_size = ATTESTER_TREE_CAPACITY;
    while level_size > 1 {
        let sibling_index = index ^ 1;
        let side = if index.is_multiple_of(2) {
            Side::Left
        } else {
            Side::Right
        };
        steps.push(PathStep {
            sibling: Bytes32::from(nodes[sibling_index]),
            side,
        });

        let half = level_size / 2;
        for i in 0..half {
            nodes[i] = poseidon2(nodes[2 * i], nodes[2 * i + 1]);
        }
        level_size = half;
        index /= 2;
    }
    MerklePath::new(steps)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> Address {
        Address::from([byte; 20])
    }

    #[test]
    fn add_attester_initializes_revoked_at_to_u64_max() {
        let mut tree = RevocationTree::new();
        tree.add_attester(addr(1)).expect("add");
        assert_eq!(tree.revoked_at_epoch_of(addr(1)).unwrap(), u64::MAX);
    }

    #[test]
    fn add_attester_rejects_a_duplicate() {
        let mut tree = RevocationTree::new();
        tree.add_attester(addr(1)).expect("first add");
        assert!(matches!(
            tree.add_attester(addr(1)),
            Err(MerkleError::AttesterAlreadyExists(_))
        ));
    }

    #[test]
    fn root_changes_when_revoked_at_epoch_is_lowered() {
        let mut tree = RevocationTree::new();
        tree.add_attester(addr(1)).expect("add");
        tree.add_attester(addr(2)).expect("add");
        let before = tree.root();
        tree.lower_revocation(addr(1), 42).expect("lower");
        let after = tree.root();
        assert_ne!(before, after);
    }

    #[test]
    fn root_is_unchanged_by_an_unrelated_read() {
        let mut tree = RevocationTree::new();
        tree.add_attester(addr(1)).expect("add");
        tree.add_attester(addr(2)).expect("add");
        let before = tree.root();
        // Reads: contains() and revoked_at_epoch_of() take &self and mutate nothing.
        let _ = tree.contains(addr(2));
        let _ = tree.revoked_at_epoch_of(addr(2)).unwrap();
        assert_eq!(before, tree.root());
    }

    #[test]
    fn empty_tree_root_is_all_empty_leaves() {
        let tree = RevocationTree::new();
        let expected = compute_root(&[]);
        assert_eq!(tree.root(), Bytes32::from(expected));
    }

    #[test]
    fn remove_frees_the_slot_so_a_later_add_reuses_the_root_shape() {
        let mut tree = RevocationTree::new();
        tree.add_attester(addr(1)).expect("add");
        let single = tree.root();
        tree.remove_attester(addr(1)).expect("remove");
        assert_eq!(tree.root(), RevocationTree::new().root());
        tree.add_attester(addr(1)).expect("re-add");
        assert_eq!(tree.root(), single);
    }

    #[test]
    fn remove_then_re_add_preserves_the_revocation_floor() {
        let mut tree = RevocationTree::new();
        tree.add_attester(addr(1)).expect("add");
        tree.lower_revocation(addr(1), 7).expect("lower");
        tree.remove_attester(addr(1)).expect("remove");
        tree.add_attester(addr(1)).expect("re-add");

        assert_eq!(tree.revoked_at_epoch_of(addr(1)).unwrap(), 7);
        assert_eq!(tree.root(), Bytes32::from(compute_root(&[(addr(1), 7)])));
    }

    #[test]
    fn revocation_tree_full_when_capacity_exceeded() {
        let mut tree = RevocationTree::new();
        for i in 0..ATTESTER_TREE_CAPACITY as u8 {
            tree.add_attester(addr(i)).expect("add within capacity");
        }
        assert!(matches!(
            tree.add_attester(addr(255)),
            Err(MerkleError::RevocationTreeFull)
        ));
    }

    #[test]
    fn proof_verifies_against_the_tree_root() {
        let mut tree = RevocationTree::new();
        tree.add_attester(addr(1)).expect("add");
        tree.add_attester(addr(2)).expect("add");
        tree.add_attester(addr(3)).expect("add");

        let leaf = poseidon2(Fr::from(addr(2)), Fr::from(u64::MAX));
        let proof = tree.proof(addr(2)).expect("proof");

        let mut node = leaf;
        for step in proof.steps() {
            let sibling = Fr::try_from(step.sibling).expect("canonical sibling");
            node = match step.side {
                Side::Left => poseidon2(node, sibling),
                Side::Right => poseidon2(sibling, node),
            };
        }
        assert_eq!(Bytes32::from(node), tree.root());
    }

    #[test]
    fn proof_for_unknown_attester_fails() {
        let tree = RevocationTree::new();
        assert!(matches!(
            tree.proof(addr(9)),
            Err(MerkleError::AttesterNotFound(_))
        ));
    }
}

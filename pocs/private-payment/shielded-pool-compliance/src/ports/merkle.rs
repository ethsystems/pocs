//! The commitment/attestation tree port. `RevocationTree` (`adapters::revocation_tree`)
//! does not implement this trait: its write model (add/remove/lower a fixed-position
//! leaf) is fundamentally different from the append-only `insert` this trait exposes,
//! and forcing it through the same interface would blur that distinction rather than
//! reuse anything real.

use crate::{
    error::MerkleError,
    types::Bytes32,
};

/// Which side of a hash pair the proved node sits on. `Right` means the node is the
/// right child and its sibling is on the left, matching `indices[i] == true` in the
/// vendored Noir `binary_merkle_root`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Left,
    Right,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathStep {
    pub sibling: Bytes32,
    pub side: Side,
}

/// A leaf position, kept distinct from `MerkleStore::size`'s `u64` so the two cannot
/// be swapped at a call site even though both are plain integers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LeafIndex(pub u64);

/// A leaf's inclusion path from a `MerkleStore`. Promoted levels (a LeanIMT node
/// lacking a right sibling) are absent, so this is shorter than the tree's maximum
/// depth for some leaves; two parallel `Vec`s whose lengths must agree would make that
/// an invariant to re-check everywhere instead of a property the type enforces.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MerklePath(Vec<PathStep>);

impl MerklePath {
    pub fn new(steps: Vec<PathStep>) -> Self {
        Self(steps)
    }

    pub fn steps(&self) -> &[PathStep] {
        &self.0
    }

    pub fn into_steps(self) -> Vec<PathStep> {
        self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// `[u32 step count]` then, per step, `[side u8][sibling 32 bytes]`. A plain
    /// canonical encoding of this type's own shape, independent of the `Prover.toml`
    /// writer, which converts a `MerklePath` into the circuit's
    /// `(proof_length, indices, siblings)` triple rather than this format.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.0.len() * 33);
        out.extend_from_slice(&(self.0.len() as u32).to_be_bytes());
        for step in &self.0 {
            out.push(match step.side {
                Side::Left => 0,
                Side::Right => 1,
            });
            out.extend_from_slice(step.sibling.as_ref());
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, MerkleError> {
        let malformed = || {
            MerkleError::Storage(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "malformed MerklePath encoding",
            )))
        };
        let count_bytes: [u8; 4] = bytes
            .get(0..4)
            .ok_or_else(malformed)?
            .try_into()
            .expect("4 bytes");
        let count = u32::from_be_bytes(count_bytes) as usize;
        // Each step needs at least 33 bytes (1-byte side + 32-byte sibling), so an
        // untrusted `count` can never plausibly exceed the remaining bytes / 33. Without
        // this cap, a crafted `count` near u32::MAX drives a multi-GB allocation before
        // any step is validated.
        let plausible_max = bytes.len().saturating_sub(4) / 33;
        let mut steps = Vec::with_capacity(count.min(plausible_max));
        let mut pos = 4;
        for _ in 0..count {
            let side_byte = *bytes.get(pos).ok_or_else(malformed)?;
            let side = match side_byte {
                0 => Side::Left,
                1 => Side::Right,
                _ => return Err(malformed()),
            };
            let sibling_bytes: [u8; 32] = bytes
                .get(pos + 1..pos + 33)
                .ok_or_else(malformed)?
                .try_into()
                .expect("32 bytes");
            steps.push(PathStep {
                sibling: Bytes32::from(sibling_bytes),
                side,
            });
            pos += 33;
        }
        Ok(Self(steps))
    }
}

/// An append-only Merkle tree the wallet owns exclusively. `Sync` is earned, not
/// reflexive: the tree adapter (`adapters::commitment_tree`) wraps `rotortree::RotorTree`,
/// which internally synchronizes `insert`, so `&self` insertion is genuinely safe to
/// share across threads even though this crate only ever calls it from one owner.
pub trait MerkleStore: Send + Sync {
    fn root(&self) -> Option<Bytes32>;
    fn size(&self) -> u64;
    fn get_proof(&self, index: LeafIndex) -> Result<MerklePath, MerkleError>;
    fn insert(&self, leaf: Bytes32) -> Result<LeafIndex, MerkleError>;
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn encode_decode_round_trips_a_fixed_path() {
        let path = MerklePath::new(vec![
            PathStep {
                sibling: Bytes32::from([1u8; 32]),
                side: Side::Left,
            },
            PathStep {
                sibling: Bytes32::from([2u8; 32]),
                side: Side::Right,
            },
        ]);
        assert_eq!(MerklePath::decode(&path.encode()).unwrap(), path);
    }

    #[test]
    fn empty_path_round_trips() {
        let path = MerklePath::default();
        assert_eq!(MerklePath::decode(&path.encode()).unwrap(), path);
    }

    #[test]
    fn decode_rejects_an_implausible_step_count_without_over_allocating() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(MerklePath::decode(&bytes).is_err());
    }

    fn arb_side() -> impl Strategy<Value = Side> {
        prop_oneof![Just(Side::Left), Just(Side::Right)]
    }

    fn arb_step() -> impl Strategy<Value = PathStep> {
        (any::<[u8; 32]>(), arb_side()).prop_map(|(bytes, side)| PathStep {
            sibling: Bytes32::from(bytes),
            side,
        })
    }

    proptest! {
        #[test]
        fn merkle_path_round_trips_through_its_encoding(steps in proptest::collection::vec(arb_step(), 0..40)) {
            let path = MerklePath::new(steps);
            prop_assert_eq!(MerklePath::decode(&path.encode()).unwrap(), path);
        }
    }
}

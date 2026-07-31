//! Mirrors `circuits/lib/src/policy.nr` one to one. `reference` is the demo
//! implementation; `commit` and `source_hash` bind a policy's identity into `STATE_TAG`.

use crate::{
    error::PolicyError,
    types::Flags,
};

pub mod commit;
pub mod reference;
pub mod source_hash;
pub mod tag_file;

/// Mirrors `circuits/lib/src/tx_facts.nr` field for field. Defined in
/// `domain::tx_facts`, which also owns the per-operation constructors; re-exported here
/// so `Policy` methods and existing call sites keep referring to `policy::TxFacts`.
pub use crate::domain::tx_facts::TxFacts;

/// Mirrors the Noir `policy` module one to one. Every method is an associated function
/// with no `self`, so no `P` value ever exists: `Send + Sync` bounds belong on `State`,
/// where values do exist and may cross into a `spawn_blocking` closure, not on the trait.
///
/// A Noir `assert` inside `advance` or `evaluate` maps to `Err(PolicyError::Blocked)`,
/// which is what lets the wallet report "no satisfying witness" locally instead of
/// panicking.
pub trait Policy {
    /// Number of state slots. Mirrors `policy::K` in Noir.
    const K: usize;

    /// The pool reads the slots directly, so `State` must expose them as `u64`.
    type State: Copy + PartialEq + AsRef<[u64]> + Send + Sync + core::fmt::Debug;

    fn zero() -> Self::State;
    fn advance(prev: Self::State, tx: &TxFacts) -> Result<Self::State, PolicyError>;
    fn evaluate(
        tx: &TxFacts,
        prev: Self::State,
        next: Self::State,
    ) -> Result<Flags, PolicyError>;
}

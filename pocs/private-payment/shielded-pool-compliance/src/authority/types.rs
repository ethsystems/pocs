/// The deployed `AttestationRegistry`'s `MIN_COHORT_SIZE`, which is a constructor
/// immutable rather than a compile-time constant, so it varies per deployment. The
/// Authority must be configured with the value of the registry it submits to: a client
/// that assumes a smaller one passes its own check and then reverts `CohortTooSmall`
/// on chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MinCohortSize(pub u64);

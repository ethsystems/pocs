#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("cohort has {size} subjects, below the minimum of {minimum}")]
    CohortTooSmall { size: u64, minimum: u64 },
}

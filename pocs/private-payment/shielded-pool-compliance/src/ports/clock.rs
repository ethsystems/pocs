//! A local wall clock. Synchronous: reading the time is not I/O in the sense that
//! justifies an async port, and a sync trait lets tests substitute a fixed instant
//! without an executor.

use crate::types::Epoch;

pub trait Clock: Send + Sync {
    fn now_unix(&self) -> u64;

    /// SPEC "Deployment Parameters": `block.timestamp / EPOCH_SECONDS` is the epoch
    /// number at the recommended `EPOCH_SECONDS = 86400` (the UTC calendar day).
    fn current_epoch(&self, epoch_seconds: u64) -> Epoch {
        Epoch(self.now_unix() / epoch_seconds)
    }
}

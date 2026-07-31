//! `ports::clock::Clock` over the OS wall clock.

use std::time::{
    SystemTime,
    UNIX_EPOCH,
};

use crate::ports::clock::Clock;

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    /// # Panics
    ///
    /// Panics if the system clock reads before the Unix epoch, which indicates a
    /// misconfigured host clock rather than a condition this crate can recover from.
    fn now_unix(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock reads before the Unix epoch")
            .as_secs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_unix_is_a_plausible_current_timestamp() {
        // 2024-01-01T00:00:00Z, a loose floor that only breaks if the host clock is
        // badly wrong.
        let clock = SystemClock;
        assert!(clock.now_unix() > 1_700_000_000);
    }

    #[test]
    fn current_epoch_divides_by_epoch_seconds() {
        let clock = SystemClock;
        let now = clock.now_unix();
        assert_eq!(
            clock.current_epoch(crate::EPOCH_SECONDS).0,
            now / crate::EPOCH_SECONDS
        );
    }
}

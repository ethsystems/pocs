//! The attester actor: batches subjects into a `Cohort` ready for
//! `addAttestations`, computing `expiresAt` off the one function the registry itself
//! uses (`Cohort::calendar_expires_at`) so a client-computed value can never diverge
//! from the deployed calendar.

use crate::{
    domain::{
        attestation::{
            Cohort,
            Generation,
        },
        keys::OwnerPubkey,
    },
    ports::clock::Clock,
};

use super::{
    error::Error,
    types::MinCohortSize,
};

#[derive(Debug, Clone, Copy)]
pub struct Authority {
    min_cohort_size: MinCohortSize,
}

impl Authority {
    /// `min_cohort_size` MUST be read from the registry this Authority submits to,
    /// since it is a per-deployment immutable rather than a protocol constant.
    pub fn new(min_cohort_size: MinCohortSize) -> Self {
        Self { min_cohort_size }
    }

    pub fn min_cohort_size(&self) -> MinCohortSize {
        self.min_cohort_size
    }

    /// # Errors
    ///
    /// Returns [`Error::CohortTooSmall`] if `subjects` has fewer entries than the
    /// registry's minimum. The deployed `AttestationRegistry` enforces that minimum
    /// on-chain; this check exists so a client fails immediately rather than spending a
    /// submission on a cohort the registry will reject anyway.
    pub fn build_cohort(
        &self,
        clock: &impl Clock,
        subjects: Vec<OwnerPubkey>,
        generation: Generation,
    ) -> Result<Cohort, Error> {
        let size = subjects.len() as u64;
        if size < self.min_cohort_size.0 {
            return Err(Error::CohortTooSmall {
                size,
                minimum: self.min_cohort_size.0,
            });
        }
        let epoch = clock.current_epoch(crate::EPOCH_SECONDS);
        let expires_at = Cohort::calendar_expires_at(
            epoch,
            crate::EPOCH_SECONDS,
            crate::MAX_ATTESTATION_EPOCHS,
        );
        Ok(Cohort::new(subjects, expires_at, generation))
    }

    /// Identical to [`Self::build_cohort`], but issues against the next period's
    /// calendar value. Only accepted by the registry inside its overlap window,
    /// which is how a new cohort can be onboarded before the current one lapses.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CohortTooSmall`] under the same condition as
    /// [`Self::build_cohort`].
    pub fn build_next_period_cohort(
        &self,
        clock: &impl Clock,
        subjects: Vec<OwnerPubkey>,
        generation: Generation,
    ) -> Result<Cohort, Error> {
        let size = subjects.len() as u64;
        if size < self.min_cohort_size.0 {
            return Err(Error::CohortTooSmall {
                size,
                minimum: self.min_cohort_size.0,
            });
        }
        let epoch = clock.current_epoch(crate::EPOCH_SECONDS);
        let expires_at = Cohort::next_period_expires_at(
            epoch,
            crate::EPOCH_SECONDS,
            crate::MAX_ATTESTATION_EPOCHS,
        );
        Ok(Cohort::new(subjects, expires_at, generation))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::keys::SpendingKey;

    struct FixedClock(u64);
    impl Clock for FixedClock {
        fn now_unix(&self) -> u64 {
            self.0
        }
    }

    fn owner(seed: u8) -> OwnerPubkey {
        let mut bytes = [0u8; 32];
        bytes[31] = seed;
        SpendingKey::from_canonical_bytes(bytes)
            .expect("small seed is canonical")
            .derive_owner_pubkey()
    }

    #[test]
    fn cohort_below_the_minimum_size_is_refused_client_side() {
        let authority = Authority::new(MinCohortSize(4));
        let clock = FixedClock(100 * crate::EPOCH_SECONDS);
        let subjects = vec![owner(1), owner(2)];

        let err = authority
            .build_cohort(&clock, subjects, Generation(1))
            .expect_err("two subjects is below the configured minimum");
        assert!(matches!(
            err,
            Error::CohortTooSmall {
                size: 2,
                minimum: 4
            }
        ));
    }

    /// The registry's `MIN_COHORT_SIZE` is a constructor immutable, so the same cohort
    /// is valid against one deployment and rejected by another. A hardcoded client-side
    /// minimum would pass here and then revert `CohortTooSmall` on chain.
    #[test]
    fn the_minimum_is_the_configured_one_not_a_fixed_constant() {
        let clock = FixedClock(100 * crate::EPOCH_SECONDS);
        let subjects: Vec<OwnerPubkey> = (1..=4u8).map(owner).collect();

        assert!(
            Authority::new(MinCohortSize(4))
                .build_cohort(&clock, subjects.clone(), Generation(1))
                .is_ok()
        );
        let err = Authority::new(MinCohortSize(10))
            .build_cohort(&clock, subjects, Generation(1))
            .expect_err("four subjects is below a registry minimum of ten");
        assert!(matches!(
            err,
            Error::CohortTooSmall {
                size: 4,
                minimum: 10
            }
        ));
    }

    #[test]
    fn cohort_expiry_matches_the_calendar_function_for_the_current_epoch() {
        let authority = Authority::new(MinCohortSize(4));
        let epoch_seconds = crate::EPOCH_SECONDS;
        let clock = FixedClock(100 * epoch_seconds);
        let subjects: Vec<OwnerPubkey> = (1..=4u8).map(owner).collect();

        let cohort = authority
            .build_cohort(&clock, subjects.clone(), Generation(2))
            .expect("cohort meets the minimum size");

        let expected = crate::domain::attestation::Cohort::calendar_expires_at(
            clock.current_epoch(epoch_seconds),
            epoch_seconds,
            crate::MAX_ATTESTATION_EPOCHS,
        );
        assert_eq!(cohort.expires_at, expected);
        assert_eq!(cohort.subjects, subjects);
        assert_eq!(cohort.generation, Generation(2));
    }
}

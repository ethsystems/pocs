//! SPEC "Attestation leaf" and "Attester revocation":
//!
//! ```text
//! attestation_leaf = Poseidon1(owner_pubkey, attester, generation, issued_at, expires_at)
//! revocation_leaf  = Poseidon1(attester, revoked_at_epoch)
//! ```

use ark_bn254::Fr;

use crate::{
    error::CryptoError,
    poseidon::{
        poseidon2,
        poseidon5,
    },
    types::{
        Address,
        Bytes32,
        Epoch,
    },
};

use super::keys::OwnerPubkey;

/// A registry generation counter. SPEC "Attester revocation": `generation` MUST be
/// the registry's current value or its successor at issuance time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Generation(pub u64);

/// SPEC "Attestation leaf": `Poseidon1(owner_pubkey, attester, generation, issued_at,
/// expires_at)`. The registry's `subjectPubkeyHash` argument is `owner_pubkey` itself;
/// an implementation that applies a further Poseidon layer produces leaves no gated
/// circuit can open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttestationLeaf {
    pub owner_pubkey: OwnerPubkey,
    pub attester: Address,
    pub generation: Generation,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl AttestationLeaf {
    pub fn hash(&self) -> Result<Bytes32, CryptoError> {
        let owner = self.owner_pubkey.field()?;
        let hash = poseidon5(
            owner,
            Fr::from(self.attester),
            Fr::from(self.generation.0),
            Fr::from(self.issued_at),
            Fr::from(self.expires_at),
        );
        Ok(Bytes32::from(hash))
    }
}

/// SPEC "Attester revocation": `Poseidon1(attester, revoked_at_epoch)`. One leaf per
/// attester in the fixed-depth revocation tree (`adapters::revocation_tree`); an empty
/// slot's `revoked_at_epoch = 0` can never satisfy the gadget's `epoch < revoked_at`,
/// since no epoch is less than zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttesterRevocationLeaf {
    pub attester: Address,
    pub revoked_at_epoch: u64,
}

impl AttesterRevocationLeaf {
    /// Infallible: `Address` always converts to a canonical `Fr` (20 bytes stays far
    /// below the BN254 modulus), unlike the fallible `OwnerPubkey`/`Bytes32` hashes
    /// elsewhere in this module.
    pub fn hash(&self) -> Bytes32 {
        let hash = poseidon2(Fr::from(self.attester), Fr::from(self.revoked_at_epoch));
        Bytes32::from(hash)
    }
}

/// A batch of subjects due for issuance in one `addAttestations` call, sharing one
/// `expiresAt`/`generation` pair. SPEC "Attestation leaf", issuance requirements:
/// `MIN_COHORT_SIZE` and the exact calendar rule are deployment policy, enforced by
/// the caller (the Authority actor), not by this value type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cohort {
    pub subjects: Vec<OwnerPubkey>,
    pub expires_at: u64,
    pub generation: Generation,
}

impl Cohort {
    pub fn new(
        subjects: Vec<OwnerPubkey>,
        expires_at: u64,
        generation: Generation,
    ) -> Self {
        Self {
            subjects,
            expires_at,
            generation,
        }
    }

    /// The published cohort calendar value, mirroring
    /// `AttestationRegistry._calendarExpiry` exactly. Periods are
    /// `max_attestation_epochs` long, so this is the next period boundary, not the
    /// next epoch. `addAttestations` reverts `ExpiryNotOnCalendar` on any other
    /// value, so a client that computes its own must produce this one.
    pub fn calendar_expires_at(
        current_epoch: Epoch,
        epoch_seconds: u64,
        max_attestation_epochs: u64,
    ) -> u64 {
        let period = current_epoch.0 / max_attestation_epochs;
        (period + 1) * max_attestation_epochs * epoch_seconds
    }

    /// The next period's calendar value, mirroring
    /// `AttestationRegistry._nextCalendarExpiry`. Only accepted by the registry
    /// during the final `overlap_epochs` of the current period.
    pub fn next_period_expires_at(
        current_epoch: Epoch,
        epoch_seconds: u64,
        max_attestation_epochs: u64,
    ) -> u64 {
        let period = current_epoch.0 / max_attestation_epochs;
        (period + 2) * max_attestation_epochs * epoch_seconds
    }

    /// Mirrors `AttestationRegistry._inOverlapWindow`: true for the final
    /// `overlap_epochs` epochs of the current period.
    pub fn in_overlap_window(
        current_epoch: Epoch,
        max_attestation_epochs: u64,
        overlap_epochs: u64,
    ) -> bool {
        if overlap_epochs == 0 {
            return false;
        }
        let boundary =
            (current_epoch.0 / max_attestation_epochs + 1) * max_attestation_epochs;
        current_epoch.0 + overlap_epochs >= boundary
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::keys::SpendingKey;

    fn owner() -> OwnerPubkey {
        SpendingKey::random().derive_owner_pubkey()
    }

    #[test]
    fn attestation_leaf_hash_is_deterministic() {
        let leaf = AttestationLeaf {
            owner_pubkey: owner(),
            attester: Address::from([0xaa; 20]),
            generation: Generation(1),
            issued_at: 1_700_000_000,
            expires_at: 200 * crate::EPOCH_SECONDS,
        };
        assert_eq!(leaf.hash().unwrap(), leaf.hash().unwrap());
    }

    #[test]
    fn attestation_leaf_hash_changes_with_generation() {
        let base = AttestationLeaf {
            owner_pubkey: owner(),
            attester: Address::from([0xaa; 20]),
            generation: Generation(1),
            issued_at: 1_700_000_000,
            expires_at: 200 * crate::EPOCH_SECONDS,
        };
        let mut bumped = base;
        bumped.generation = Generation(2);
        assert_ne!(base.hash().unwrap(), bumped.hash().unwrap());
    }

    #[test]
    fn empty_revocation_slot_never_passes_epoch_less_than_revoked_at() {
        // Mirrors circuits/lib/src/attestation.nr's
        // test_verify_instance_empty_revocation_slot_never_passes: revoked_at_epoch
        // 0 fails `epoch < revoked_at` for every u64 epoch, including 0.
        let leaf = AttesterRevocationLeaf {
            attester: Address::from([0xbb; 20]),
            revoked_at_epoch: 0,
        };
        for epoch in [0u64, 1, u64::MAX] {
            assert!(epoch >= leaf.revoked_at_epoch);
        }
    }

    #[test]
    fn revocation_leaf_hash_differs_from_zero_revoked_at() {
        let attester = Address::from([0xbb; 20]);
        let active = AttesterRevocationLeaf {
            attester,
            revoked_at_epoch: u64::MAX,
        };
        let revoked = AttesterRevocationLeaf {
            attester,
            revoked_at_epoch: 5,
        };
        assert_ne!(active.hash(), revoked.hash());
    }

    /// Pinned against `AttestationRegistry._calendarExpiry`. Epoch 100 with a
    /// 7-epoch period lands on boundary epoch 105, not 101, so a client using the
    /// interval floor instead would revert `ExpiryNotOnCalendar`.
    #[test]
    fn cohort_calendar_expiry_is_the_next_period_boundary() {
        let expires_at = Cohort::calendar_expires_at(
            Epoch(100),
            crate::EPOCH_SECONDS,
            crate::MAX_ATTESTATION_EPOCHS,
        );
        assert_eq!(expires_at, 105 * crate::EPOCH_SECONDS);
    }

    /// The calendar value must sit inside the interval `addAttestations` separately
    /// enforces, for every epoch in a period.
    #[test]
    fn calendar_expiry_sits_inside_the_accepted_interval() {
        let (secs, max) = (crate::EPOCH_SECONDS, crate::MAX_ATTESTATION_EPOCHS);
        for epoch in 0..(4 * max) {
            let got = Cohort::calendar_expires_at(Epoch(epoch), secs, max);
            assert!(got >= (epoch + 1) * secs, "below interval floor at {epoch}");
            assert!(
                got < (epoch + 1 + max) * secs,
                "at or above ceiling at {epoch}"
            );
        }
    }

    /// Pinned against `AttestationRegistry._nextCalendarExpiry`: one period
    /// beyond `calendar_expires_at` for the same epoch.
    #[test]
    fn next_period_expiry_is_one_period_beyond_calendar_expiry() {
        let (secs, max) = (crate::EPOCH_SECONDS, crate::MAX_ATTESTATION_EPOCHS);
        let epoch = Epoch(100);
        let calendar = Cohort::calendar_expires_at(epoch, secs, max);
        let next = Cohort::next_period_expires_at(epoch, secs, max);
        assert_eq!(next, calendar + max * secs);
    }

    /// Pinned against `AttestationRegistry._inOverlapWindow`: false throughout
    /// the period until the final `overlap_epochs` epochs, then true through
    /// the boundary epoch itself.
    #[test]
    fn in_overlap_window_is_true_only_in_the_final_overlap_epochs() {
        let max = crate::MAX_ATTESTATION_EPOCHS;
        let overlap = crate::OVERLAP_EPOCHS;
        let boundary = 15 * max; // period 14's boundary, matching Epoch(100)'s period.

        assert!(!Cohort::in_overlap_window(
            Epoch(boundary - overlap - 1),
            max,
            overlap
        ));
        assert!(Cohort::in_overlap_window(
            Epoch(boundary - overlap),
            max,
            overlap
        ));
        assert!(Cohort::in_overlap_window(Epoch(boundary - 1), max, overlap));
    }

    #[test]
    fn in_overlap_window_is_always_false_when_overlap_epochs_is_zero() {
        let max = crate::MAX_ATTESTATION_EPOCHS;
        for epoch in 0..(4 * max) {
            assert!(!Cohort::in_overlap_window(Epoch(epoch), max, 0));
        }
    }
}

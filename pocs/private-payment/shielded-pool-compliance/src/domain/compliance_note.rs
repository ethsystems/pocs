//! SPEC "Compliance note", "State commitment", and "Velocity nullifier":
//!
//! ```text
//! facts = Poseidon1(counterparty_0, amount_out_0, counterparty_1, amount_out_1, exit)
//! state = Poseidon1(epoch, seq, commit(s), flags, facts)
//! CN    = Poseidon1(CN_TAG, owner_pubkey, state, salt)
//! vn    = Poseidon1(VN_TAG, spending_key, epoch, seq)
//! ```
//!
//! `commit(s)` (SPEC "State commitment") is `policy::commit::commit`; its `STATE_TAG`
//! is computed by the caller from the deployed policy source (cross-track-constraints:
//! "`state::commit` takes the tag as a parameter") and passed in here as a plain
//! `Bytes32`, matching the Noir mirror's signature.

use ark_bn254::Fr;

use crate::{
    CN_TAG,
    VN_TAG,
    error::CryptoError,
    policy::{
        Policy,
        commit::commit as policy_commit,
    },
    poseidon::{
        poseidon4,
        poseidon5,
    },
    types::{
        Bytes32,
        Epoch,
        Flags,
        Seq,
    },
};

use super::keys::{
    OwnerPubkey,
    SpendingKey,
};

/// SPEC "Compliance note": the counterparty, per-output amount, and exit destination
/// the pool commits alongside `flags`. No policy state slot can hold any of these
/// (slots are `u64`, `counterparty[i]` is a field-wide pubkey, `exit` is a 160-bit
/// address), so without `facts` a decrypted chain has no answer to "who was paid".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Facts {
    pub counterparty: [Bytes32; 2],
    pub amount_out: [u64; 2],
    pub exit: Bytes32,
}

impl Facts {
    pub fn hash(&self) -> Result<Bytes32, CryptoError> {
        let c0 = Fr::try_from(self.counterparty[0])?;
        let c1 = Fr::try_from(self.counterparty[1])?;
        let exit = Fr::try_from(self.exit)?;
        let hash = poseidon5(
            c0,
            Fr::from(self.amount_out[0]),
            c1,
            Fr::from(self.amount_out[1]),
            exit,
        );
        Ok(Bytes32::from(hash))
    }
}

/// SPEC "State commitment": one gated transaction's committed slot state, flags, and
/// facts, for one `(epoch, seq)` position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateCommitment {
    pub epoch: Epoch,
    pub seq: Seq,
    pub flags: Flags,
    pub facts: Facts,
}

impl StateCommitment {
    /// `tag` is `STATE_TAG` (`policy::commit::state_tag::<P>(policy_source_hash)`),
    /// computed by the caller so this function stays free of file I/O.
    pub fn hash<P: Policy>(
        &self,
        tag: Bytes32,
        state: &P::State,
    ) -> Result<Bytes32, CryptoError> {
        let tag_fr = Fr::try_from(tag)?;
        let commit_fr = policy_commit::<P>(tag_fr, state);
        let facts_fr = Fr::try_from(self.facts.hash()?)?;
        let hash = poseidon5(
            Fr::from(self.epoch.0),
            Fr::from(self.seq.0),
            commit_fr,
            Fr::from(self.flags.as_u64()),
            facts_fr,
        );
        Ok(Bytes32::from(hash))
    }
}

/// SPEC "Compliance note": a leaf in the commitment tree carrying the subject's
/// policy state for one epoch, generic over the deployed policy's state shape.
///
/// `Clone`/`Copy`/`Debug` are implemented by hand rather than derived: a derive would
/// add `P: Clone + Copy + Debug` bounds even though only `P::State` (already bounded
/// by `Policy`) is stored, and policy marker types like `ReferencePolicy` are
/// zero-sized units with no such derives of their own.
pub struct ComplianceNote<P: Policy> {
    pub owner_pubkey: OwnerPubkey,
    pub epoch: Epoch,
    pub seq: Seq,
    /// MUST be a fresh random value per position (SPEC "Compliance note"): the
    /// attested key set is public, so an unsalted `CN` would fall to brute force.
    pub salt: Bytes32,
    pub flags: Flags,
    pub state: P::State,
    pub facts: Facts,
}

impl<P: Policy> Clone for ComplianceNote<P> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<P: Policy> Copy for ComplianceNote<P> {}

impl<P: Policy> core::fmt::Debug for ComplianceNote<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ComplianceNote")
            .field("owner_pubkey", &self.owner_pubkey)
            .field("epoch", &self.epoch)
            .field("seq", &self.seq)
            .field("salt", &self.salt)
            .field("flags", &self.flags)
            .field("state", &self.state)
            .field("facts", &self.facts)
            .finish()
    }
}

impl<P: Policy> ComplianceNote<P> {
    pub fn state_commitment(&self, tag: Bytes32) -> Result<Bytes32, CryptoError> {
        StateCommitment {
            epoch: self.epoch,
            seq: self.seq,
            flags: self.flags,
            facts: self.facts,
        }
        .hash::<P>(tag, &self.state)
    }

    /// `CN = Poseidon1(CN_TAG, owner_pubkey, state, salt)`.
    pub fn commitment(&self, tag: Bytes32) -> Result<Bytes32, CryptoError> {
        let state = self.state_commitment(tag)?;
        compliance_commitment(self.owner_pubkey, state, self.salt)
    }
}

/// `CN = Poseidon1(CN_TAG, owner_pubkey, state, salt)`, exposed standalone for callers
/// (e.g. the auditor) that already hold a recomputed `state` hash and do not need to
/// reconstruct a full `ComplianceNote`.
pub fn compliance_commitment(
    owner_pubkey: OwnerPubkey,
    state: Bytes32,
    salt: Bytes32,
) -> Result<Bytes32, CryptoError> {
    let owner = owner_pubkey.field()?;
    let state_fr = Fr::try_from(state)?;
    let salt_fr = Fr::try_from(salt)?;
    let hash = poseidon4(*CN_TAG, owner, state_fr, salt_fr);
    Ok(Bytes32::from(hash))
}

/// SPEC "Velocity nullifier": `vn = Poseidon1(VN_TAG, spending_key, epoch, seq)`. An
/// entry in the pool's nullifier mapping, making each `(epoch, seq)` position within
/// one key single-use and keeping the compliance chain linear.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VelocityNullifier(pub Bytes32);

impl VelocityNullifier {
    pub fn derive(spending_key: &SpendingKey, epoch: Epoch, seq: Seq) -> Self {
        let hash = poseidon4(
            *VN_TAG,
            spending_key.field(),
            Fr::from(epoch.0),
            Fr::from(seq.0),
        );
        Self(Bytes32::from(hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::reference::ReferencePolicy;

    fn owner() -> OwnerPubkey {
        SpendingKey::random().derive_owner_pubkey()
    }

    fn no_counterparty_facts() -> Facts {
        Facts {
            counterparty: [*crate::NO_COUNTERPARTY, *crate::NO_COUNTERPARTY]
                .map(Bytes32::from),
            amount_out: [500, 0],
            exit: Bytes32::from(*crate::NO_EXIT),
        }
    }

    #[test]
    fn facts_hash_is_deterministic() {
        let f = no_counterparty_facts();
        assert_eq!(f.hash().unwrap(), f.hash().unwrap());
    }

    #[test]
    fn compliance_note_commitment_is_deterministic() {
        let note = ComplianceNote::<ReferencePolicy> {
            owner_pubkey: owner(),
            epoch: Epoch(100),
            seq: Seq(0),
            salt: Bytes32::from([7u8; 32]),
            flags: Flags::NONE,
            state: ReferencePolicy::zero(),
            facts: no_counterparty_facts(),
        };
        let tag = Bytes32::from([9u8; 32]);
        assert_eq!(note.commitment(tag).unwrap(), note.commitment(tag).unwrap());
    }

    #[test]
    fn compliance_note_commitment_changes_with_salt() {
        let base = ComplianceNote::<ReferencePolicy> {
            owner_pubkey: owner(),
            epoch: Epoch(100),
            seq: Seq(0),
            salt: Bytes32::from([7u8; 32]),
            flags: Flags::NONE,
            state: ReferencePolicy::zero(),
            facts: no_counterparty_facts(),
        };
        let mut salted = base;
        salted.salt = Bytes32::from([8u8; 32]);
        let tag = Bytes32::from([9u8; 32]);
        assert_ne!(
            base.commitment(tag).unwrap(),
            salted.commitment(tag).unwrap()
        );
    }

    #[test]
    fn velocity_nullifier_is_deterministic() {
        let sk = SpendingKey::random();
        let a = VelocityNullifier::derive(&sk, Epoch(100), Seq(3));
        let b = VelocityNullifier::derive(&sk, Epoch(100), Seq(3));
        assert_eq!(a, b);
    }

    #[test]
    fn velocity_nullifier_differs_across_seq() {
        let sk = SpendingKey::random();
        let a = VelocityNullifier::derive(&sk, Epoch(100), Seq(0));
        let b = VelocityNullifier::derive(&sk, Epoch(100), Seq(1));
        assert_ne!(a, b);
    }
}

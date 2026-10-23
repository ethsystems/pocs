//! Notes, locks and nullifiers (SPEC, Note and Commitment, Lock, Nullifier).

use ark_bn254::Fr;

use crate::{
    domain::keys::NullifierKey,
    error::CryptoError,
    poseidon::{
        fr_to_be_bytes,
        poseidon2,
        poseidon4,
        poseidon5,
    },
    types::Bytes32,
};

pub const LOCK_FREEZE: u64 = 1;
pub const LOCK_HOLD: u64 = 2;

/// A lock's terms. The note stores only their hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockOpening {
    pub reason: u64,
    pub release_after: u64,
    pub claim_party: Fr,
}

impl LockOpening {
    pub const NONE: LockOpening = LockOpening {
        reason: 0,
        release_after: 0,
        claim_party: Fr::new(ark_ff::BigInt::zero()),
    };

    /// Never released by time; only a release through the claim path undoes it.
    pub fn freeze() -> Self {
        Self {
            reason: LOCK_FREEZE,
            release_after: u64::MAX,
            claim_party: Fr::from(0u64),
        }
    }

    /// A holding period the owner path can spend from `epoch` on.
    pub fn hold(epoch: u64) -> Self {
        Self {
            reason: LOCK_HOLD,
            release_after: epoch,
            claim_party: Fr::from(0u64),
        }
    }

    /// 0 for no lock, else Poseidon1(LOCK_TAG, reason, release_after, claim_party).
    pub fn value(&self) -> Fr {
        if self.reason == 0 {
            return Fr::from(0u64);
        }
        poseidon4(
            *crate::LOCK_TAG,
            Fr::from(self.reason),
            Fr::from(self.release_after),
            self.claim_party,
        )
    }

    /// The terms as the register feed and the recipient payload carry them:
    /// `(reason, release_after, claim_party)`, all zero for no lock.
    pub fn fields(&self) -> [Fr; 3] {
        [
            Fr::from(self.reason),
            Fr::from(self.release_after),
            self.claim_party,
        ]
    }

    /// `None` if `reason` or `release_after` is not a `u64`.
    pub fn from_fields(f: [Fr; 3]) -> Option<Self> {
        Some(Self {
            reason: small(&f[0])?,
            release_after: small(&f[1])?,
            claim_party: f[2],
        })
    }
}

/// A field element that holds a `u64`, or `None`.
fn small(f: &Fr) -> Option<u64> {
    let bytes = fr_to_be_bytes(f);
    if bytes[..24].iter().any(|b| *b != 0) {
        return None;
    }
    Some(u64::from_be_bytes(
        bytes[24..].try_into().expect("the last 8 of 32 bytes"),
    ))
}

/// A note's opening.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Note {
    pub token: Fr,
    pub units: u64,
    pub owner: Fr,
    pub salt: Fr,
    pub lock: Fr,
}

pub const NOTE_FIELDS: usize = 5;
pub const NOTE_BYTES: usize = NOTE_FIELDS * 32;

impl Note {
    pub fn fields(&self) -> [Fr; NOTE_FIELDS] {
        [
            self.token,
            Fr::from(self.units),
            self.owner,
            self.salt,
            self.lock,
        ]
    }

    /// commitment = Poseidon1(token, units, owner, salt, lock)
    pub fn commitment(&self) -> Fr {
        poseidon5(
            self.token,
            Fr::from(self.units),
            self.owner,
            self.salt,
            self.lock,
        )
    }

    /// The plaintext of a recipient payload element: the five fields, 32 bytes each.
    pub fn encode(&self) -> Vec<u8> {
        self.fields().iter().flat_map(fr_to_be_bytes).collect()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != NOTE_BYTES {
            return Err(CryptoError::MalformedCiphertext);
        }
        let mut f = [Fr::from(0u64); NOTE_FIELDS];
        for (i, chunk) in bytes.chunks_exact(32).enumerate() {
            let word: [u8; 32] =
                chunk.try_into().expect("chunks_exact(32) yields 32 bytes");
            f[i] = Fr::try_from(Bytes32::from(word))?;
        }
        Self::from_fields(f).ok_or(CryptoError::MalformedCiphertext)
    }

    /// Rebuilds a note from decrypted fields; `None` if `units` is not a `u64`,
    /// which a wrong key yields with overwhelming probability.
    pub fn from_fields(f: [Fr; NOTE_FIELDS]) -> Option<Self> {
        Some(Self {
            token: f[0],
            units: small(&f[1])?,
            owner: f[2],
            salt: f[3],
            lock: f[4],
        })
    }
}

/// nullifier = Poseidon1(commitment, nk). Identical on the owner and claim paths.
pub fn nullifier(commitment: Fr, nk: &NullifierKey) -> Fr {
    poseidon2(commitment, nk.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn note_round_trips_through_its_encoding() {
        let note = Note {
            token: Fr::from(1u64),
            units: 1_000,
            owner: Fr::from(3u64),
            salt: Fr::from(4u64),
            lock: LockOpening::freeze().value(),
        };
        assert_eq!(Note::decode(&note.encode()).unwrap(), note);
    }

    #[test]
    fn unlocked_is_zero() {
        assert_eq!(LockOpening::NONE.value(), Fr::from(0u64));
        assert_ne!(LockOpening::hold(400).value(), Fr::from(0u64));
    }
}

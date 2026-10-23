//! The register feed (SPEC, Register Feed): every new note's opening and lock
//! terms, encrypted to the transfer agent's register key `tpk` with Grumpkin
//! ECDH and a Poseidon keystream. The circuits bind it; this module builds and
//! reads it.

use ark_bn254::Fr;
use num_bigint::BigUint;
use rand::RngExt;

use crate::{
    domain::{
        grumpkin::{
            GENERATOR,
            Point,
        },
        note::{
            LockOpening,
            NOTE_FIELDS,
            Note,
        },
    },
    poseidon::{
        poseidon2,
        poseidon3,
    },
};

/// Fields per output: the note's opening, then its lock terms.
pub const FEED_FIELDS: usize = NOTE_FIELDS + 3;

/// Output j's feed fields `(token, units, owner, salt, lock, reason,
/// release_after, claim_party)`; the terms are all zero for an unlocked note.
pub fn fields(note: &Note, terms: &LockOpening) -> [Fr; FEED_FIELDS] {
    let mut f = [Fr::from(0u64); FEED_FIELDS];
    f[..NOTE_FIELDS].copy_from_slice(&note.fields());
    f[NOTE_FIELDS..].copy_from_slice(&terms.fields());
    f
}

/// The inverse of `fields`; `None` for fields a wrong key decrypted.
pub fn open(f: &[Fr; FEED_FIELDS]) -> Option<(Note, LockOpening)> {
    let note = Note::from_fields(
        f[..NOTE_FIELDS]
            .try_into()
            .expect("the feed starts with the NOTE_FIELDS of the note"),
    )?;
    let terms = LockOpening::from_fields(
        f[NOTE_FIELDS..]
            .try_into()
            .expect("the feed ends with the three lock terms"),
    )?;
    Some((note, terms))
}

/// A Grumpkin scalar as the circuits take it: two 128-bit limbs. The sender's
/// `r` is fresh per proof and MUST NOT be reused; the agent's `tk` is long-lived.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FeedSecret {
    pub lo: u128,
    pub hi: u128,
}

impl std::fmt::Debug for FeedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FeedSecret(..)")
    }
}

impl FeedSecret {
    /// A random non-zero scalar below 2^253, so below Grumpkin's group order
    /// (about 2^254): Barretenberg rejects a larger one when it solves the
    /// circuit, and the circuit rejects 0, whose feed key anyone can compute.
    pub fn random() -> Self {
        let mut rng = rand::rng();
        loop {
            let s = Self {
                lo: rng.random(),
                hi: rng.random::<u128>() >> 3,
            };
            if s.lo != 0 || s.hi != 0 {
                return s;
            }
        }
    }

    fn scalar(&self) -> BigUint {
        BigUint::from(self.lo) + (BigUint::from(self.hi) << 128u32)
    }

    /// tpk = tk * G, for the agent's register key.
    pub fn public_point(&self) -> Point {
        GENERATOR.mul(&self.scalar())
    }
}

fn key_of(shared: &Point) -> Fr {
    poseidon3(*crate::FEED_TAG, shared.x, shared.y)
}

/// The sender's side: R = r * G and k = Poseidon1(FEED_TAG, rt.x, rt.y), rt = r * tpk.
pub fn derive(r: &FeedSecret, register_key: &Point) -> (Point, Fr) {
    let big_r = r.public_point();
    let rt = register_key.mul(&r.scalar());
    (big_r, key_of(&rt))
}

/// ct[j][i] = f_i + Poseidon1(k, 8 * j + i), for output j's feed fields f.
pub fn encrypt(k: Fr, fields: &[Fr; FEED_FIELDS], j: usize) -> [Fr; FEED_FIELDS] {
    let mut ct = [Fr::from(0u64); FEED_FIELDS];
    for i in 0..FEED_FIELDS {
        ct[i] = fields[i] + poseidon2(k, Fr::from((FEED_FIELDS * j + i) as u64));
    }
    ct
}

/// The agent's side: rt = tk * R, then subtract the keystream.
pub fn decrypt(
    tk: &FeedSecret,
    feed_r: &Point,
    ct: &[Fr; FEED_FIELDS],
    j: usize,
) -> [Fr; FEED_FIELDS] {
    let k = key_of(&feed_r.mul(&tk.scalar()));
    let mut f = [Fr::from(0u64); FEED_FIELDS];
    for i in 0..FEED_FIELDS {
        f[i] = ct[i] - poseidon2(k, Fr::from((FEED_FIELDS * j + i) as u64));
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon::fr_to_be_bytes;

    fn hex_of(fr: Fr) -> String {
        format!("0x{}", hex::encode(fr_to_be_bytes(&fr)))
    }

    /// Values the circuits' `test_parity_vectors` also pins.
    #[test]
    fn derivation_matches_noir() {
        let tpk = FeedSecret {
            lo: 0x7777,
            hi: 0x1,
        }
        .public_point();
        assert_eq!(
            hex_of(tpk.x),
            "0x24764a9bca6028e77d08ce48769e78b267310826a15569a651751d602100f3bb"
        );
        assert_eq!(
            hex_of(tpk.y),
            "0x003d802df0f7a2702bf102dfd5e0e87e7d9182c73f98273fa79fa17d27324c61"
        );
        let (big_r, k) = derive(
            &FeedSecret {
                lo: 0x1234,
                hi: 0x5678,
            },
            &tpk,
        );
        assert_eq!(
            hex_of(big_r.x),
            "0x0640d0c6d4e4c4a7a1ca6810a1d70fd450c1ae737df2ed707ad5e3be60493034"
        );
        assert_eq!(
            hex_of(big_r.y),
            "0x292a33b89dece883c8c3473818365cdc3694e834d5773120a4e52660004c877c"
        );
        assert_eq!(
            hex_of(k),
            "0x178ef8f4073794f21bd872ac9442c50b9b433da511eff0c56cc7e29ff4a08a3b"
        );
    }

    /// The known answer the circuits' `test_known_answer_two_outputs` also
    /// pins: a two-output feed under the parity vectors' keys, hashed to one
    /// value. It fixes the field order and the keystream index, which a change
    /// made on both sides at once would leave every round-trip test passing.
    #[test]
    fn a_two_output_feed_matches_noir() {
        let tpk = FeedSecret {
            lo: 0x7777,
            hi: 0x1,
        }
        .public_point();
        let (_, k) = derive(
            &FeedSecret {
                lo: 0x1234,
                hi: 0x5678,
            },
            &tpk,
        );
        let hold = LockOpening::hold(400);
        let held = Note {
            token: Fr::from(1u64),
            units: 2,
            owner: Fr::from(3u64),
            salt: Fr::from(4u64),
            lock: hold.value(),
        };
        let free = Note {
            token: Fr::from(1u64),
            units: 5,
            owner: Fr::from(6u64),
            salt: Fr::from(7u64),
            lock: Fr::from(0u64),
        };
        let mut all = encrypt(k, &fields(&held, &hold), 0).to_vec();
        all.extend(encrypt(k, &fields(&free, &LockOpening::NONE), 1));
        assert_eq!(
            hex_of(crate::poseidon::sponge(&all)),
            "0x2f51828023fd41a233ed1374bb09f441a20bba5102c048c6abb2268c1746b1a9"
        );
    }

    #[test]
    fn agent_decrypts_what_the_sender_encrypts() {
        let tk = FeedSecret::random();
        let terms = LockOpening::hold(400);
        let note = Note {
            token: Fr::from(1u64),
            units: 2,
            owner: Fr::from(3u64),
            salt: Fr::from(4u64),
            lock: terms.value(),
        };
        let (big_r, k) = derive(&FeedSecret::random(), &tk.public_point());
        let ct = encrypt(k, &fields(&note, &terms), 1);
        assert_eq!(open(&decrypt(&tk, &big_r, &ct, 1)), Some((note, terms)));
        assert_eq!(open(&decrypt(&FeedSecret::random(), &big_r, &ct, 1)), None);
    }
}

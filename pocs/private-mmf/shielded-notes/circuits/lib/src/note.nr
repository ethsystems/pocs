use crate::domain;
use crate::hasher::{hash_2, hash_5};
use crate::lock::LockOpening;

// A note's opening (SPEC, Note and Commitment).
pub struct Note {
    pub token: Field,
    pub units: u64,
    pub owner: Field,
    pub salt: Field,
    pub lock: Field,
}

impl Note {
    pub fn fields(self) -> [Field; domain::NOTE_FIELDS] {
        [self.token, self.units as Field, self.owner, self.salt, self.lock]
    }

    // commitment = Poseidon1(token, units, owner, salt, lock).
    pub fn commitment(self) -> Field {
        hash_5(self.fields())
    }
}

// nullifier = Poseidon1(commitment, nk). Identical on the owner and claim paths.
pub fn nullifier(commitment: Field, nk: Field) -> Field {
    hash_2([commitment, nk])
}

// A spent note's private witnesses. The token and owner are not here: every
// input shares the circuit's token and the owner opening's owner value.
pub struct InputNote {
    pub units: u64,
    pub salt: Field,
    pub lock: Field,
    pub lock_opening: LockOpening,
    pub proof_length: u32,
    pub indices: [bool; domain::MAX_COMMITMENT_TREE_DEPTH],
    pub path: [Field; domain::MAX_COMMITMENT_TREE_DEPTH],
}

impl InputNote {
    pub fn note(self, token: Field, owner: Field) -> Note {
        Note { token, units: self.units, owner, salt: self.salt, lock: self.lock }
    }
}

#[test]
fn test_commitment_binds_every_field() {
    let n = Note { token: 1, units: 2, owner: 3, salt: 4, lock: 0 };
    let c = n.commitment();
    assert(c == hash_5([1, 2, 3, 4, 0]));
    assert(c != Note { token: 1, units: 2, owner: 3, salt: 4, lock: 5 }.commitment());
    assert(c != Note { token: 1, units: 3, owner: 3, salt: 4, lock: 0 }.commitment());
}

pub mod feed;
pub mod grumpkin;
pub mod keys;
pub mod note;
pub mod plan;
pub mod tree;
pub mod witness;

use ark_bn254::Fr;
use rand::RngExt;

use crate::types::Bytes32;

pub(crate) fn random_canonical_bytes32() -> Bytes32 {
    let mut bytes = [0u8; 32];
    loop {
        rand::rng().fill(&mut bytes);
        let candidate = Bytes32::from(bytes);
        if Fr::try_from(candidate).is_ok() {
            return candidate;
        }
    }
}

/// A fresh random field element, for salts and nullifier keys.
pub fn random_fr() -> Fr {
    Fr::try_from(random_canonical_bytes32()).expect("canonical by construction")
}

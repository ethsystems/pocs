//! Key material. `SpendingKey`/`OwnerPubkey` are the spend-authority pair (SPEC
//! "Compliance note"); the three ECIES key families decrypt the three payload
//! elements of SPEC "Audit Channel" and are kept as distinct types on purpose, since
//! mixing the compliance-viewing branch with the ordinary incoming-viewing branch is
//! exactly the correlation risk that section warns against.

use std::fmt;

use ark_bn254::Fr;
use k256::{
    PublicKey as K256PublicKey,
    SecretKey as K256SecretKey,
    elliptic_curve::sec1::ToEncodedPoint,
};
use rand::RngCore;
use zeroize::{
    Zeroize,
    ZeroizeOnDrop,
};

use crate::{
    crypto::encryption,
    error::CryptoError,
    poseidon::poseidon1,
    types::Bytes32,
};

use super::random_canonical_bytes32;

/// The master spending secret. Rejection-sampled so it always encodes a canonical
/// `Fr`, per SPEC "Compliance note": `owner_pubkey = Poseidon1(spending_key)`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SpendingKey([u8; 32]);

impl fmt::Debug for SpendingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SpendingKey(REDACTED)")
    }
}

impl SpendingKey {
    pub fn random() -> Self {
        loop {
            let mut bytes = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut bytes);
            if Fr::try_from(Bytes32::from(bytes)).is_ok() {
                return Self(bytes);
            }
        }
    }

    pub fn from_canonical_bytes(bytes: [u8; 32]) -> Result<Self, CryptoError> {
        Fr::try_from(Bytes32::from(bytes))?;
        Ok(Self(bytes))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub(crate) fn field(&self) -> Fr {
        Fr::try_from(Bytes32::from(self.0))
            .expect("constructed only from canonical bytes")
    }

    /// SPEC "Compliance note": `owner_pubkey = Poseidon1(spending_key)`.
    pub fn derive_owner_pubkey(&self) -> OwnerPubkey {
        OwnerPubkey(Bytes32::from(poseidon1(self.field())))
    }
}

/// `owner_pubkey = Poseidon1(spending_key)`. Public: the set of attested keys is
/// itself public per SPEC "Compliance note".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OwnerPubkey(Bytes32);

impl OwnerPubkey {
    pub fn from_bytes32(bytes: Bytes32) -> Self {
        Self(bytes)
    }

    pub fn as_bytes32(&self) -> Bytes32 {
        self.0
    }

    pub(crate) fn field(&self) -> Result<Fr, CryptoError> {
        Fr::try_from(self.0)
    }
}

macro_rules! ecies_keypair {
    ($secret:ident, $public:ident, $doc:expr) => {
        #[doc = $doc]
        pub struct $secret(K256SecretKey);

        impl fmt::Debug for $secret {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($secret), "(REDACTED)"))
            }
        }

        impl $secret {
            /// Uses `rand::thread_rng()`, matching the sibling `shielded-pool` PoC's
            /// key generation: `k256` 0.13 pins a `rand_core` major version that
            /// mismatches trivially against an independently-chosen `OsRng` import.
            pub fn random() -> Self {
                Self(K256SecretKey::random(&mut rand::thread_rng()))
            }

            pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
                K256SecretKey::from_slice(bytes)
                    .map(Self)
                    .map_err(|_| CryptoError::MalformedCiphertext)
            }

            pub fn public_key(&self) -> $public {
                $public(self.0.public_key())
            }

            pub fn decrypt(
                &self,
                ciphertext: &[u8],
                aad: &[u8],
            ) -> Result<Vec<u8>, CryptoError> {
                encryption::decrypt(ciphertext, &self.0, aad)
            }
        }

        #[derive(Clone, PartialEq, Eq)]
        pub struct $public(K256PublicKey);

        impl fmt::Debug for $public {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($public))
                    .field(&hex::encode(self.to_sec1_bytes()))
                    .finish()
            }
        }

        impl $public {
            pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
                K256PublicKey::from_sec1_bytes(bytes)
                    .map(Self)
                    .map_err(|_| CryptoError::MalformedCiphertext)
            }

            pub fn to_sec1_bytes(&self) -> Vec<u8> {
                self.0.to_encoded_point(true).as_bytes().to_vec()
            }

            pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
                encryption::encrypt(plaintext, &self.0, aad)
            }
        }
    };
}

ecies_keypair!(
    ViewingKey,
    ViewingPubkey,
    "Decrypts `0x01` value-note payload elements. Mirrors the parent PoC's incoming \
     viewing key."
);
ecies_keypair!(
    ComplianceViewingKey,
    ComplianceViewingPubkey,
    "Decrypts `0x02` compliance-note elements addressed to the note's own owner. SPEC \
     \"Audit Channel\": derived outside the ordinary incoming-viewing branch, since a \
     compliance note under that branch would turn any value-note grant into a \
     complete outgoing history."
);
ecies_keypair!(
    AuditViewingKey,
    AuditViewingPubkey,
    "Decrypts `0x03` compliance-note elements addressed to the audit committee. This \
     PoC uses a single key pair (`t = n = 1`) as a deliberate, documented stand-in for \
     the SPEC's `SHOULD` of Silent Threshold Encryption; see the README's \
     implementation-divergences section."
);

/// Generates a random 32-byte salt that is always a canonical field element, so
/// `Fr::try_from` on it never fails. SPEC "Compliance note": `CN` MUST be salted with
/// a fresh random `salt` per position.
pub fn random_salt() -> Bytes32 {
    random_canonical_bytes32()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spending_key_derivation_is_deterministic() {
        let sk = SpendingKey::random();
        assert_eq!(sk.derive_owner_pubkey(), sk.derive_owner_pubkey());
    }

    #[test]
    fn distinct_spending_keys_derive_distinct_pubkeys() {
        let a = SpendingKey::random();
        let b = SpendingKey::random();
        assert_ne!(a.derive_owner_pubkey(), b.derive_owner_pubkey());
    }

    #[test]
    fn spending_key_debug_is_redacted() {
        let sk = SpendingKey::random();
        assert_eq!(format!("{sk:?}"), "SpendingKey(REDACTED)");
    }

    #[test]
    fn viewing_key_round_trips_public_key_bytes() {
        let vk = ViewingKey::random();
        let pk = vk.public_key();
        let bytes = pk.to_sec1_bytes();
        let recovered = ViewingPubkey::from_sec1_bytes(&bytes).expect("valid SEC1 bytes");
        assert_eq!(pk, recovered);
    }

    #[test]
    fn compliance_and_audit_viewing_keys_are_independent_types() {
        // Same underlying k256 machinery, but distinct nominal types: a
        // ComplianceViewingPubkey cannot be passed where an AuditViewingPubkey is
        // expected, even though both wrap a k256::PublicKey.
        let cvk = ComplianceViewingKey::random();
        let avk = AuditViewingKey::random();
        assert_ne!(
            cvk.public_key().to_sec1_bytes(),
            avk.public_key().to_sec1_bytes()
        );
    }

    #[test]
    fn random_salt_is_always_canonical() {
        for _ in 0..16 {
            let salt = random_salt();
            assert!(Fr::try_from(salt).is_ok());
        }
    }
}

use alloy::primitives::B256;
use k256::elliptic_curve::Generate;
use rand::RngExt;
use serde::{
    Deserialize,
    Serialize,
};
use zeroize::{
    Zeroize,
    ZeroizeOnDrop,
};

use crate::crypto::poseidon::poseidon1;

/// Spending key - used to authorize transfers and derive nullifiers.
/// This is the master secret for spending authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendingKey(pub B256);

impl SpendingKey {
    /// Generate a random spending key.
    pub fn random() -> Self {
        let mut rng = rand::rng();
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes[5..]);
        Self(B256::from(bytes))
    }

    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(B256::from(bytes))
    }

    /// Derive the owner public key (spending pubkey) from the spending key.
    /// owner_pubkey = poseidon1(spending_key)
    pub fn derive_owner_pubkey(&self) -> OwnerPubkey {
        OwnerPubkey(poseidon1(self.0))
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_ref()
    }
}

// The spending key is the master spend secret; wipe its bytes on drop so they do
// not linger in freed memory.
impl Zeroize for SpendingKey {
    fn zeroize(&mut self) {
        self.0 .0.zeroize();
    }
}

impl ZeroizeOnDrop for SpendingKey {}

impl Drop for SpendingKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Owner public key - derived from spending key, used in note commitments.
/// owner_pubkey = poseidon1(spending_key)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OwnerPubkey(pub B256);

impl OwnerPubkey {
    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(B256::from(bytes))
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_ref()
    }
}

/// Viewing key - used for decrypting notes and enabling audit access.
/// Separate from spending key for selective disclosure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewingKey(pub k256::SecretKey);

impl ViewingKey {
    /// Generate a random viewing key.
    pub fn random() -> Self {
        Self(k256::SecretKey::generate_from_rng(&mut rand::rng()))
    }

    /// Create from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, k256::elliptic_curve::Error> {
        Ok(Self(k256::SecretKey::from_slice(bytes)?))
    }

    /// Derive the viewing public key.
    pub fn derive_viewing_pubkey(&self) -> ViewingPubkey {
        ViewingPubkey(self.0.public_key())
    }

    /// Get the secret key reference.
    pub fn secret_key(&self) -> &k256::SecretKey {
        &self.0
    }
}

/// Viewing public key - used for encrypting notes to recipients.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewingPubkey(#[serde(with = "viewing_pubkey_serde")] pub k256::PublicKey);

impl ViewingPubkey {
    /// Create from raw compressed bytes (33 bytes).
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, k256::elliptic_curve::Error> {
        Ok(Self(k256::PublicKey::from_sec1_bytes(bytes)?))
    }

    /// Get the public key reference.
    pub fn public_key(&self) -> &k256::PublicKey {
        &self.0
    }

    /// Serialize to compressed SEC1 format (33 bytes).
    pub fn to_sec1_bytes(&self) -> Vec<u8> {
        use k256::elliptic_curve::sec1::ToSec1Point;
        self.0.to_sec1_point(true).as_bytes().to_vec()
    }
}

mod viewing_pubkey_serde {
    use k256::elliptic_curve::sec1::ToSec1Point;
    use serde::{
        Deserialize,
        Deserializer,
        Serializer,
    };

    pub fn serialize<S>(key: &k256::PublicKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = key.to_sec1_point(true);
        serializer.serialize_bytes(bytes.as_bytes())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<k256::PublicKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        k256::PublicKey::from_sec1_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spending_key_derivation() {
        let sk = SpendingKey::random();
        let pk1 = sk.derive_owner_pubkey();
        let pk2 = sk.derive_owner_pubkey();
        assert_eq!(pk1, pk2, "Derivation should be deterministic");
    }

    #[test]
    fn test_viewing_key_derivation() {
        let vk = ViewingKey::random();
        let vpk1 = vk.derive_viewing_pubkey();
        let vpk2 = vk.derive_viewing_pubkey();
        assert_eq!(vpk1, vpk2, "Derivation should be deterministic");
    }

    #[test]
    fn test_viewing_pubkey_roundtrip() {
        let vk = ViewingKey::random();
        let vpk = vk.derive_viewing_pubkey();
        let bytes = vpk.to_sec1_bytes();
        let vpk2 = ViewingPubkey::from_sec1_bytes(&bytes).unwrap();
        assert_eq!(vpk, vpk2);
    }
}

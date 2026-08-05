use ff::PrimeField;
use num_bigint::BigUint;
use poseidon_rs::{Fr, Poseidon};
use rand::{self, RngExt};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ShieldedKeys {
    seed: [u8; 32],
    private_spending_key_hex: String,
    pub public_spending_key_hex: String,
    private_viewing_key: [u8; 32],
    pub public_viewing_key: [u8; 32],
}

impl ShieldedKeys {
    /// Generate new shielded keys from a random seed
    pub fn generate() -> Self {
        let seed = rand::rng().random::<[u8; 32]>();
        Self::from_seed(seed)
    }

    /// Derive shielded keys from a seed
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let private_spending_key = Self::derive_spending_key(&seed);
        let private_spending_key_hex = format!("{}", private_spending_key);

        let hasher = Poseidon::new();
        let public_spending_key = hasher
            .hash(vec![private_spending_key])
            .expect("Failed to hash private spending key");
        let public_spending_key_hex = format!("{}", public_spending_key);

        // Derive viewing keys for encryption (X25519)
        let (private_viewing_key, public_viewing_key) = Self::derive_public_viewing_key(&seed);

        ShieldedKeys {
            seed,
            private_spending_key_hex,
            public_spending_key_hex,
            private_viewing_key,
            public_viewing_key,
        }
    }

    /// Derive spending keys from seed using Keccak256
    fn derive_spending_key(seed: &[u8; 32]) -> Fr {
        let mut hasher = Keccak256::new();
        hasher.update(seed);
        hasher.update(b"spending_key");
        let derived = hasher.finalize();

        // Convert first 8 bytes to u64 then to string for Fr::from_str
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&derived[..8]);
        let num = u64::from_le_bytes(bytes);
        Fr::from_str(&num.to_string()).expect("Failed to create Fr from derived key")
    }

    /// Derive X25519 private key from seed and return public key
    fn derive_public_viewing_key(seed: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        let viewing_secret = StaticSecret::from(*seed);
        let viewing_public = PublicKey::from(&viewing_secret);
        (*viewing_secret.as_bytes(), *viewing_public.as_bytes())
    }

    /// Parse hex string in Fr(0x...) format to Fr
    fn parse_fr_hex(hex_str: &str) -> Fr {
        // Strip "Fr(0x" prefix and ")" suffix
        let clean = hex_str
            .trim_start_matches("Fr(0x")
            .trim_start_matches("Fr(")
            .trim_start_matches("0x")
            .trim_end_matches(')');
        
        // Parse hex to big integer, then to Fr
        // Fr::from_str expects decimal, so we convert hex to decimal
        let bytes = match hex::decode(clean) {
            Ok(b) => b,
            Err(_) => {
                // If hex decode fails, try parsing as decimal string
                return Fr::from_str(clean).unwrap_or(Fr::from_str("0").unwrap());
            }
        };
        
        if bytes.is_empty() {
            // Fallback: try parsing as decimal string
            return Fr::from_str(clean).unwrap_or(Fr::from_str("0").unwrap());
        }
        
        // Convert bytes to BigUint, then to decimal string for Fr::from_str
        let num = BigUint::from_bytes_be(&bytes);
        Fr::from_str(&num.to_string()).unwrap_or(Fr::from_str("0").unwrap())
    }

    /// Reconstruct the private spending key Fr from stored hex
    pub fn get_private_spending_key(&self) -> Fr {
        Self::parse_fr_hex(&self.private_spending_key_hex)
    }

    /// Reconstruct the public spending key Fr from stored hex
    fn get_public_spending_key(&self) -> Fr {
        Self::parse_fr_hex(&self.public_spending_key_hex)
    }

    /// Get the public spending key
    pub fn public_spending_key(&self) -> Fr {
        self.get_public_spending_key()
    }

    /// Get the public viewing key as bytes
    pub fn public_viewing_key(&self) -> &[u8; 32] {
        &self.public_viewing_key
    }

    /// Get the seed (for storage)
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    /// Sign a message (nullifier) using the private spending key
    pub fn sign_nullifier(&self, salt: u64) -> Fr {
        let f_salt = Fr::from_str(&salt.to_string()).expect("Salt conversion failed");
        let hasher = Poseidon::new();
        hasher
            .hash(vec![f_salt, self.get_private_spending_key()])
            .expect("Failed to compute nullifier")
    }
}

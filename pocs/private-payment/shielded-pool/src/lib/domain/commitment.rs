use alloy::primitives::{
    keccak256,
    B256,
};
use ark_bn254::Fr;
use ark_ff::{
    BigInteger,
    PrimeField,
};
use serde::{
    Deserialize,
    Serialize,
};

use crate::{
    crypto::poseidon::poseidon2,
    domain::nullifier::Nullifier,
};

use super::keys::SpendingKey;

/// A commitment is the on-chain representation of a note.
/// It hides all note contents while allowing proof of ownership.
/// commitment = poseidon4(token, amount, owner_pubkey, salt)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Commitment(pub B256);

impl Commitment {
    /// Create a commitment from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(B256::from(bytes))
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_ref()
    }

    /// Compute the nullifier for this commitment given the spending key.
    /// nullifier = poseidon2(commitment, spending_key)
    pub fn nullifier(&self, spending_key: &SpendingKey) -> Nullifier {
        let hash = poseidon2(self.0, spending_key.0);
        Nullifier(hash)
    }
}

/// Commitment to an encrypted payload, bound into deposit and transfer proofs as a
/// public input: `keccak256(payload) mod p` (BN254 scalar field), matching
/// `ShieldedPool.payloadCommitment`. The contract recomputes it from the submitted
/// bytes, so a relayer cannot garble the payload after the proof is made.
pub fn payload_commitment(payload: &[u8]) -> B256 {
    let reduced = Fr::from_be_bytes_mod_order(keccak256(payload).as_slice());
    B256::from_slice(&reduced.into_bigint().to_bytes_be())
}

impl From<B256> for Commitment {
    fn from(value: B256) -> Self {
        Self(value)
    }
}

impl From<Commitment> for B256 {
    fn from(value: Commitment) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_commitment_is_canonical_and_binding() {
        // Known value: keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        let empty = payload_commitment(b"");
        let raw = alloy::primitives::U256::from_be_slice(keccak256(b"").as_slice());
        let p = alloy::primitives::U256::from_str_radix(
            "21888242871839275222246405745257275088548364400416034343698204186575808495617",
            10,
        )
        .unwrap();
        assert_eq!(alloy::primitives::U256::from_be_slice(empty.as_slice()), raw % p);
        assert_ne!(payload_commitment(b"original"), payload_commitment(b"garbled!"));
    }

    #[test]
    fn test_commitment_nullifier_deterministic() {
        let commitment = Commitment(B256::repeat_byte(0x42));
        let sk = SpendingKey::from_bytes([0x01; 32]);

        let nullifier1 = commitment.nullifier(&sk);
        let nullifier2 = commitment.nullifier(&sk);

        assert_eq!(nullifier1, nullifier2);
    }

    #[test]
    fn test_commitment_nullifier_different_keys() {
        let commitment = Commitment(B256::repeat_byte(0x42));
        let sk1 = SpendingKey::from_bytes([0x01; 32]);
        let sk2 = SpendingKey::from_bytes([0x02; 32]);

        let nullifier1 = commitment.nullifier(&sk1);
        let nullifier2 = commitment.nullifier(&sk2);

        assert_ne!(nullifier1, nullifier2);
    }
}

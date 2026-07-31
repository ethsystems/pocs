use std::fmt;

use ark_bn254::Fr;
use num_bigint::BigUint;

use crate::error::CryptoError;

/// The crate's port currency for every field-element-shaped value crossing a module
/// boundary. Construct from untrusted bytes only through `TryFrom<Bytes32> for Fr`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bytes32([u8; 32]);

impl From<[u8; 32]> for Bytes32 {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Bytes32 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Bytes32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bytes32(0x{})", hex::encode(self.0))
    }
}

impl fmt::Display for Bytes32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

/// The one total decode function from untrusted bytes to a field element. Rejects any
/// value at or above `BN254_MODULUS`; `ark_ff::PrimeField::from_be_bytes_mod_order`
/// would silently reduce it instead, letting `x + p` and `x` collide.
impl TryFrom<Bytes32> for Fr {
    type Error = CryptoError;

    fn try_from(value: Bytes32) -> Result<Self, Self::Error> {
        let n = BigUint::from_bytes_be(value.as_ref());
        if n >= *crate::BN254_MODULUS {
            return Err(CryptoError::NotCanonical(value));
        }
        Ok(Fr::from(n))
    }
}

impl From<Fr> for Bytes32 {
    fn from(value: Fr) -> Self {
        Self(crate::poseidon::fr_to_be_bytes(&value))
    }
}

/// A transaction hash: the keccak of a signed transaction, not a field element.
/// `ports::chain::ChainWriter` returns this rather than `Bytes32`, since a keccak
/// digest routinely exceeds the BN254 modulus and `Bytes32`'s `Fr` conversion would
/// reject it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TxHash(pub [u8; 32]);

impl From<[u8; 32]> for TxHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for TxHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for TxHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TxHash(0x{})", hex::encode(self.0))
    }
}

impl fmt::Display for TxHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Epoch(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Seq(pub u64);

/// A bitfield of policy outcome flags, the return type of `Policy::evaluate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Flags(u64);

impl Flags {
    pub const NONE: Self = Self(0);
    pub const FLAG_SINGLE_TX: Self = Self(1);
    pub const FLAG_AGGREGATE: Self = Self(2);

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }

    /// The bitfield value as it enters the hash preimage.
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// An Ethereum address. Always below `2^160`, so the field-element conversion the SPEC
/// calls `token < 2^160` is infallible: 20 bytes never reach the BN254 modulus.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address([u8; 20]);

impl From<[u8; 20]> for Address {
    fn from(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address(0x{})", hex::encode(self.0))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl From<Address> for Fr {
    fn from(value: Address) -> Self {
        Fr::from(BigUint::from_bytes_be(value.as_ref()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes32_round_trips_through_fr_below_modulus() {
        let bytes = Bytes32::from([0u8; 32]);
        let fr = Fr::try_from(bytes).expect("zero is canonical");
        assert_eq!(Bytes32::from(fr), bytes);
    }

    #[test]
    fn bytes32_at_modulus_is_rejected() {
        let modulus_bytes: [u8; 32] = crate::BN254_MODULUS
            .to_bytes_be()
            .try_into()
            .expect("BN254 modulus is exactly 32 bytes");
        let bytes = Bytes32::from(modulus_bytes);
        assert!(matches!(
            Fr::try_from(bytes),
            Err(CryptoError::NotCanonical(_))
        ));
    }

    #[test]
    fn bytes32_one_below_modulus_is_canonical() {
        let mut below = crate::BN254_MODULUS.to_bytes_be();
        *below.last_mut().expect("nonempty") -= 1;
        let bytes = Bytes32::from(
            <[u8; 32]>::try_from(below).expect("BN254 modulus is exactly 32 bytes"),
        );
        assert!(Fr::try_from(bytes).is_ok());
    }

    #[test]
    fn flags_union_and_contains() {
        let flags = Flags::NONE.union(Flags::FLAG_SINGLE_TX);
        assert!(flags.contains(Flags::FLAG_SINGLE_TX));
        assert!(!flags.contains(Flags::FLAG_AGGREGATE));
        assert_eq!(flags.as_u64(), 1);
    }

    #[test]
    fn flags_insert_is_idempotent_and_additive() {
        let mut flags = Flags::NONE;
        flags.insert(Flags::FLAG_SINGLE_TX);
        flags.insert(Flags::FLAG_AGGREGATE);
        assert_eq!(flags.as_u64(), 3);
    }

    #[test]
    fn largest_address_stays_below_two_to_160() {
        let fr = Fr::from(Address::from([0xffu8; 20]));
        let two_to_160 = Fr::from(BigUint::from(1u8) << 160u32);
        assert_eq!(fr + Fr::from(1u64), two_to_160);
    }
}

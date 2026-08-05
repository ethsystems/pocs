//! Domain types shared across actors.
//!
//! Design Z prime: per-recipient commitments + cross-circuit M binding via
//! `claim_nullifier` preimage + balance-based residual. There is NO
//! `PoolNote`, NO spending material, NO batch-withdraw witness anywhere in
//! this file.

use ark_bn254::Fr;
use serde::{
    Deserialize,
    Serialize,
};

/// 20-byte Ethereum address.
pub type Address = [u8; 20];

/// 32-byte word.
pub type Bytes32 = [u8; 32];

/// secp256k1 affine public key in uncompressed `(x, y)` form, big-endian.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecpPubkey {
    pub x: Bytes32,
    pub y: Bytes32,
}

impl SecpPubkey {
    pub fn new(x: Bytes32, y: Bytes32) -> Self {
        Self { x, y }
    }
}

/// secp256k1 ECDSA signature (`r`, `s`), canonical-s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcdsaSignature {
    pub r: Bytes32,
    pub s: Bytes32,
}

/// 256-bit unsigned integer wrapper. Uses big-endian bytes for serialization
/// to match the on-chain representation in the SPEC voucher preimage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct U256Be(pub Bytes32);

impl U256Be {
    pub const fn zero() -> Self {
        Self([0u8; 32])
    }
    pub fn from_u128(v: u128) -> Self {
        let mut out = [0u8; 32];
        out[16..32].copy_from_slice(&v.to_be_bytes());
        Self(out)
    }
    pub fn from_u64(v: u64) -> Self {
        let mut out = [0u8; 32];
        out[24..32].copy_from_slice(&v.to_be_bytes());
        Self(out)
    }
    pub fn as_bytes(&self) -> &Bytes32 {
        &self.0
    }
    pub fn into_bytes(self) -> Bytes32 {
        self.0
    }
    /// Decompose into `(hi, lo)` 128-bit big-endian limbs (each is itself a
    /// 16-byte big-endian integer fitted into a `u128`).
    pub fn to_limbs_128(&self) -> (u128, u128) {
        let mut hi_bytes = [0u8; 16];
        hi_bytes.copy_from_slice(&self.0[0..16]);
        let mut lo_bytes = [0u8; 16];
        lo_bytes.copy_from_slice(&self.0[16..32]);
        (u128::from_be_bytes(hi_bytes), u128::from_be_bytes(lo_bytes))
    }
}

/// Round header. Mirrors the Solidity struct exactly. Does NOT include
/// `firstPoolLeafIndex` (set atomically by the factory; out of band of
/// `H_header`).
///
/// `close_time` is a unix timestamp in seconds (uint64).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundHeader {
    pub round_id: Bytes32,
    pub cohort_version: u64,
    pub cohort_root: Bytes32,
    pub per_recipient_amount: U256Be,
    pub cohort_size: u64,
    pub token: Address,
    pub close_time: u64,
    pub claim_contract_address: Address,
    pub chain_id: U256Be,
}

/// Funder-signed envelope around a `RoundHeader`. The signature byte layout
/// is opaque here; production deployments use a multisig-aggregated
/// signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedHeader {
    pub header: RoundHeader,
    pub signature: Vec<u8>,
}

/// Companion-supplied APDU payload for `SIGN_VOUCHER`. The card consumes
/// these fields plus its own master key to build the 308-byte preimage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoucherContext {
    pub round_id: Bytes32,
    pub cohort_root: Bytes32,
    pub claim_contract: Address,
    pub per_recipient_amount: U256Be,
    pub chain_id: U256Be,
}

/// Plaintext voucher returned by the smartcard and post-processed by the
/// companion before encryption. Crucially does NOT carry `leaf_index`,
/// `cohort_position`, or any spending material.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedVoucher {
    pub m: SecpPubkey,
    pub derived_pubkey: SecpPubkey,
    pub signature: EcdsaSignature,
    pub context: VoucherContext,
    pub claim_nullifier: Bytes32,
    pub destination: Address,
}

/// Encrypted voucher envelope (sealring X25519 suite v1). `relay_id` is
/// routing metadata carried alongside the self-framed envelope and doubles
/// as its AAD.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedVoucher {
    pub envelope: Vec<u8>,
    pub relay_id: Bytes32,
}

/// Cohort merkle path (depth 20), LeanIMT-shaped. `siblings.len() ==
/// indices.len()` and `<= COHORT_DEPTH`. The proof may be shorter than the
/// max depth when the tree has an odd count at the top level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CohortMerklePath {
    pub siblings: Vec<Bytes32>,
    pub indices: Vec<u8>,
}

/// Pool sub-tree merkle path (depth 32), LeanIMT-shaped.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolMerklePath {
    pub siblings: Vec<Bytes32>,
    pub indices: Vec<u8>,
}

/// Witness for the claim circuit. Public inputs first, then privates. Field
/// names mirror `circuits/claim/src/main.nr`.
#[derive(Debug, Clone)]
pub struct ClaimWitness {
    // Public
    pub round_id_hi: Fr,
    pub round_id_lo: Fr,
    pub cohort_root: Fr,
    pub chain_id_hi: Fr,
    pub chain_id_lo: Fr,
    pub destination: Fr,
    pub amount: Fr,
    pub nullifier: Fr,
    pub claim_contract_address: Fr,
    pub relay_submitter: Fr,
    // Private
    pub derived_pubkey_x_hi: Fr,
    pub derived_pubkey_x_lo: Fr,
    pub derived_pubkey_y_hi: Fr,
    pub derived_pubkey_y_lo: Fr,
    pub m_x_hi: Fr,
    pub m_x_lo: Fr,
    pub m_y_hi: Fr,
    pub m_y_lo: Fr,
    pub signature_r: Bytes32,
    pub signature_s: Bytes32,
    pub merkle_path: CohortMerklePath,
}

/// Witness for the pool-withdraw circuit. Public inputs first. Field names
/// mirror `circuits/withdraw/src/main.nr`.
#[derive(Debug, Clone)]
pub struct PoolWithdrawWitness {
    // Public
    pub pool_root: Fr,
    pub claim_nullifier: Fr,
    pub token: Fr,
    pub amount: Fr,
    pub recipient: Fr,
    // Private
    pub m_x_hi: Fr,
    pub m_x_lo: Fr,
    pub m_y_hi: Fr,
    pub m_y_lo: Fr,
    pub derived_pubkey_x_hi: Fr,
    pub derived_pubkey_x_lo: Fr,
    pub derived_pubkey_y_hi: Fr,
    pub derived_pubkey_y_lo: Fr,
    pub round_id_hi: Fr,
    pub round_id_lo: Fr,
    pub chain_id_hi: Fr,
    pub chain_id_lo: Fr,
    pub claim_contract: Fr,
    pub merkle_path: PoolMerklePath,
}

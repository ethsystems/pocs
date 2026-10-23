//! The investor's keys (SPEC, Key Model): a spend key held by a custody signer,
//! a nullifier key and a viewing key held by the wallet, and the owner value
//! that binds the first two.

use std::fmt;

use alloy::primitives::keccak256;
use ark_bn254::Fr;
use k256::{
    PublicKey as K256PublicKey,
    SecretKey as K256SecretKey,
    ecdsa::{
        Signature,
        SigningKey,
        VerifyingKey,
        signature::hazmat::{
            PrehashSigner,
            PrehashVerifier,
        },
    },
};
use num_bigint::BigUint;

use crate::{
    crypto::encryption,
    domain::{
        note::Note,
        plan::Plan,
        random_fr,
    },
    error::CryptoError,
    poseidon::{
        fr_to_be_bytes,
        poseidon2,
        poseidon3,
        poseidon4,
    },
    types::Address,
};

/// An ECDSA secp256k1 public key as a custody signer exports it: two 32-byte
/// big-endian coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicSpendKey {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

fn limb(bytes: &[u8]) -> Fr {
    Fr::from(BigUint::from_bytes_be(bytes))
}

impl PublicSpendKey {
    /// pk_hash = Poseidon1(pk_x_hi, pk_x_lo, pk_y_hi, pk_y_lo), over 128-bit limbs.
    /// Also the claim key's hash, which the pool stores as `claimKeyHash`.
    pub fn key_hash(&self) -> Fr {
        poseidon4(
            limb(&self.x[..16]),
            limb(&self.x[16..]),
            limb(&self.y[..16]),
            limb(&self.y[16..]),
        )
    }
}

/// The custody signer's interface (SPEC, Transaction Plan). It is handed the
/// plan's fields and its output openings, never a bare digest: it rebuilds the
/// digest itself (`Plan::rebuild`) and signs its 32 bytes as a raw message
/// hash, without exporting the key. An HSM or MPC platform implements this in
/// the policy layer in front of its sign-only key, which is also where it
/// checks the owners and units against what it approves; `SpendKey` is the
/// software stand-in.
pub trait PlanSigner: Send + Sync {
    fn public_key(&self) -> PublicSpendKey;
    /// Refuses with `CryptoError::PlanMismatch` if the openings do not match
    /// the plan's output commitments.
    fn sign_plan(&self, plan: &Plan, outputs: &[Note]) -> Result<[u8; 64], CryptoError>;
    /// Signs an onboarding registration, rebuilding its digest from the
    /// fields, which carry `nk`'s hash and never `nk`. Refuses with
    /// `CryptoError::RegistrationKeyMismatch` one for another key.
    fn sign_registration(
        &self,
        registration: &Registration,
    ) -> Result<[u8; 64], CryptoError>;
}

/// What the custody signer signs at onboarding (SPEC, Onboarding, step 2), for
/// one pool. It carries `nk`'s hash, not `nk`: the signer rebuilds the message
/// from these fields, and `nk` stays with the wallet and the transfer agent
/// (SPEC, Key Model), which receives it alongside and checks it against
/// `nk_hash`. The signature shows that the investor controls `sk` for this
/// `pk`, and binds the `nk` and `vpk` it registers with it, for the investor ID
/// the agent assigned it, so the registration cannot be presented under
/// another investor's ID; the agent then computes the owner value itself.
#[derive(Debug, Clone)]
pub struct Registration {
    pub chain_id: u64,
    pub pool: Address,
    /// The pseudonymous investor ID the agent assigned at verification (SPEC,
    /// Onboarding, step 1).
    pub investor_id: String,
    pub pk: PublicSpendKey,
    /// `NullifierKey::hash`, as in the owner value. It reveals no nullifier,
    /// which takes `nk` itself.
    pub nk_hash: Fr,
    pub vpk: ViewingPubkey,
}

impl Registration {
    /// keccak256 over a domain string, the chain, the pool, the investor ID's
    /// keccak256, `pk`, `nk_hash` and `vpk`. Used off-chain only, and unlike
    /// any plan digest, which is a Poseidon sponge.
    pub fn digest(&self) -> [u8; 32] {
        let mut bytes = b"shielded-notes registration".to_vec();
        bytes.extend(self.chain_id.to_be_bytes());
        bytes.extend(self.pool.as_ref());
        bytes.extend(keccak256(self.investor_id.as_bytes()).0);
        bytes.extend(self.pk.x);
        bytes.extend(self.pk.y);
        bytes.extend(fr_to_be_bytes(&self.nk_hash));
        bytes.extend(self.vpk.to_sec1_bytes());
        keccak256(bytes).0
    }

    /// Checks a signature by `pk` over `digest`.
    pub fn verify(&self, signature: &[u8; 64]) -> Result<(), CryptoError> {
        let mut sec1 = vec![0x04];
        sec1.extend(self.pk.x);
        sec1.extend(self.pk.y);
        let key =
            VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| CryptoError::InvalidKey)?;
        let signature =
            Signature::from_slice(signature).map_err(|_| CryptoError::BadSignature)?;
        key.verify_prehash(&self.digest(), &signature)
            .map_err(|_| CryptoError::BadSignature)
    }
}

pub struct SpendKey(SigningKey);

impl fmt::Debug for SpendKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SpendKey({:?})", self.public_key())
    }
}

impl SpendKey {
    pub fn random() -> Self {
        let secret = K256SecretKey::generate_from_rng(&mut rand::rng());
        Self(SigningKey::from(secret))
    }

    pub fn from_secret(bytes: &[u8]) -> Result<Self, CryptoError> {
        SigningKey::from_slice(bytes)
            .map(Self)
            .map_err(|_| CryptoError::InvalidKey)
    }
}

impl PlanSigner for SpendKey {
    fn public_key(&self) -> PublicSpendKey {
        let point = self.0.verifying_key().to_sec1_point(false);
        PublicSpendKey {
            x: point
                .x()
                .expect("an uncompressed SEC1 point carries both coordinates")
                .as_slice()
                .try_into()
                .expect("a secp256k1 coordinate is 32 bytes"),
            y: point
                .y()
                .expect("an uncompressed SEC1 point carries both coordinates")
                .as_slice()
                .try_into()
                .expect("a secp256k1 coordinate is 32 bytes"),
        }
    }

    /// Deterministic (RFC 6979) and low-s.
    fn sign_plan(&self, plan: &Plan, outputs: &[Note]) -> Result<[u8; 64], CryptoError> {
        Ok(self.sign_digest(&plan.rebuild(outputs)?))
    }

    fn sign_registration(
        &self,
        registration: &Registration,
    ) -> Result<[u8; 64], CryptoError> {
        if registration.pk != self.public_key() {
            return Err(CryptoError::RegistrationKeyMismatch);
        }
        Ok(self.sign_digest(&registration.digest()))
    }
}

impl SpendKey {
    fn sign_digest(&self, digest: &[u8; 32]) -> [u8; 64] {
        let signature: Signature = self
            .0
            .sign_prehash(digest)
            .expect("signing a 32-byte prehash with a valid key cannot fail");
        signature
            .to_bytes()
            .as_slice()
            .try_into()
            .expect("an ECDSA signature is 64 bytes")
    }
}

/// The nullifier key `nk`: reveals when a note is spent, but cannot spend it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NullifierKey(pub Fr);

impl fmt::Debug for NullifierKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NullifierKey(..)")
    }
}

impl NullifierKey {
    pub fn random() -> Self {
        Self(random_fr())
    }

    /// nk_hash = Poseidon1(NK_TAG, nk)
    pub fn hash(&self) -> Fr {
        poseidon2(*crate::NK_TAG, self.0)
    }
}

/// owner = Poseidon1(OWNER_TAG, pk_hash, nk_hash)
pub fn owner_value(pk: &PublicSpendKey, nk: &NullifierKey) -> Fr {
    poseidon3(*crate::OWNER_TAG, pk.key_hash(), nk.hash())
}

/// The viewing key `(vk, vpk)`: decrypts the note openings sent to `vpk`.
#[derive(Clone)]
pub struct ViewingKey(K256SecretKey);

impl fmt::Debug for ViewingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ViewingKey(..)")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewingPubkey(K256PublicKey);

impl ViewingKey {
    pub fn random() -> Self {
        Self(K256SecretKey::generate_from_rng(&mut rand::rng()))
    }

    pub fn public_key(&self) -> ViewingPubkey {
        ViewingPubkey(self.0.public_key())
    }

    pub fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        encryption::decrypt(ciphertext, &self.0, aad)
    }
}

impl ViewingPubkey {
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        encryption::encrypt(plaintext, &self.0, aad)
    }

    /// The SEC1 encoding, as the registration digest takes it.
    pub fn to_sec1_bytes(&self) -> Vec<u8> {
        self.0.to_sec1_bytes().to_vec()
    }
}

/// A holder's keys under one owner value, as generated. They are held apart:
/// `split` gives the spend key to the custody signer and the rest to the
/// wallet. Only the agent keeps all three together, for its padding values.
pub struct OwnerKeys {
    pub spend: SpendKey,
    pub nk: NullifierKey,
    pub view: ViewingKey,
}

impl fmt::Debug for OwnerKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OwnerKeys({:?})", self.spend.public_key())
    }
}

impl OwnerKeys {
    pub fn random() -> Self {
        Self {
            spend: SpendKey::random(),
            nk: NullifierKey::random(),
            view: ViewingKey::random(),
        }
    }

    pub fn owner(&self) -> Fr {
        owner_value(&self.spend.public_key(), &self.nk)
    }

    /// The spend key for the custody signer, and the wallet's keys, which hold
    /// only the spend key's public half.
    pub fn split(self) -> (SpendKey, WalletKeys) {
        let pk = self.spend.public_key();
        (
            self.spend,
            WalletKeys {
                pk,
                nk: self.nk,
                view: self.view,
            },
        )
    }
}

/// What the wallet holds under one owner value: `pk`, `nk` and the viewing
/// key. Never `sk`, which stays in the custody signer (SPEC, Key Model).
pub struct WalletKeys {
    pub pk: PublicSpendKey,
    pub nk: NullifierKey,
    pub view: ViewingKey,
}

impl fmt::Debug for WalletKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WalletKeys({:?})", self.pk)
    }
}

impl WalletKeys {
    pub fn owner(&self) -> Fr {
        owner_value(&self.pk, &self.nk)
    }
}

use k256::elliptic_curve::Generate as _;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon::fr_to_be_bytes;

    fn hex_of(fr: Fr) -> String {
        format!("0x{}", hex::encode(fr_to_be_bytes(&fr)))
    }

    fn secret(byte: u8) -> SpendKey {
        let mut bytes = [0u8; 32];
        bytes[31] = byte;
        SpendKey::from_secret(&bytes).expect("valid secret")
    }

    /// Values the circuits' `test_parity_vectors` also pins: test secrets
    /// 0x0b (owner) and 0x0c (claim key), nk = 0x6e6b.
    #[test]
    fn owner_value_and_key_hash_match_noir() {
        let nk = NullifierKey(Fr::from(0x6e6bu64));
        assert_eq!(
            hex_of(owner_value(&secret(0x0b).public_key(), &nk)),
            "0x0d67dadf84418a242db346ed0bf55de2b2723fee773bf40ba3369e54c8e82c0a"
        );
        assert_eq!(
            hex_of(secret(0x0c).public_key().key_hash()),
            "0x1c0f6c4f661cfb481dd3351cdb68f7e9c9573bcb46a21344e356b8eed3ca3f3d"
        );
    }

    /// The custody signer signs a registration of its own key only, and a
    /// registration whose fields change no longer verifies.
    #[test]
    fn a_registration_is_signed_for_its_own_key() {
        let signer = secret(0x0b);
        let registration = Registration {
            chain_id: 31337,
            pool: Address::from([1; 20]),
            investor_id: "INV-ALICE".to_string(),
            pk: signer.public_key(),
            nk_hash: NullifierKey(Fr::from(0x6e6bu64)).hash(),
            vpk: ViewingKey::random().public_key(),
        };
        let signature = signer.sign_registration(&registration).unwrap();
        assert!(registration.verify(&signature).is_ok());

        let other_nk = Registration {
            nk_hash: NullifierKey(Fr::from(1u64)).hash(),
            ..registration.clone()
        };
        assert!(matches!(
            other_nk.verify(&signature),
            Err(CryptoError::BadSignature)
        ));
        let other_investor = Registration {
            investor_id: "INV-MALLORY".to_string(),
            ..registration.clone()
        };
        assert!(matches!(
            other_investor.verify(&signature),
            Err(CryptoError::BadSignature)
        ));
        assert!(matches!(
            secret(0x0c).sign_registration(&registration),
            Err(CryptoError::RegistrationKeyMismatch)
        ));
    }

    #[test]
    fn viewing_key_round_trips() {
        let vk = ViewingKey::random();
        let ct = vk.public_key().encrypt(b"opening", b"aad");
        assert_eq!(vk.decrypt(&ct, b"aad").unwrap(), b"opening");
        assert!(ViewingKey::random().decrypt(&ct, b"aad").is_err());
    }
}

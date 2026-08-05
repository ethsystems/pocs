//! Companion device. Drives the smartcard through APDUs and packages an
//! encrypted voucher for a relay.
//!
//! The companion is stateless w.r.t. cohort position: relays derive each
//! recipient's pool leaf index from `pool.commitmentIndex(claim_contract,
//! commitment)` at submission time, so the companion never needs to track
//! per-cohort positions across rounds.

use std::sync::Arc;

use sha2::{
    Digest,
    Sha256,
};
use x25519_dalek::PublicKey;

use crate::{
    DOMAIN_HEADER,
    DOMAIN_ROSTER,
    clock::Clock,
    companion::{
        error::CompanionError,
        types::{
            HeaderBundle,
            RelayDescriptor,
            RelayRoster,
        },
    },
    crypto::{
        aead::encrypt_to_relay,
        hmac::derive_auth_token,
        multisig::{
            decode_threshold,
            verify_threshold,
        },
        stealth::destination_from_derived_pubkey,
    },
    ports::smartcard::Smartcard,
    poseidon::{
        fr_from_be_bytes,
        hash_claim_nullifier,
        hash_derived_pubkey_packed,
        hash_m_packed,
        pack_chain_id,
        pack_round_id,
    },
    smartcard::apdu::{
        decode_sign_voucher_response,
        encode_sign_voucher,
        serialize_round_header,
    },
    types::{
        Address,
        Bytes32,
        EncryptedVoucher,
        RoundHeader,
        SignedVoucher,
        VoucherContext,
    },
};

/// Roster freshness window: 48 hours per SPEC.
const ROSTER_STALENESS_SECS: u64 = 48 * 3600;

pub struct Companion<S: Smartcard> {
    pub card: S,
    pub companion_pre_key: Bytes32,
    pub roster: RelayRoster,
    /// k-of-n EOA owner addresses authorized to sign round headers and
    /// rosters. Mirrors the on-chain Multisig deployment.
    pub funder_owners: Vec<Address>,
    pub funder_threshold: usize,
    /// Wall-clock for roster staleness checks.
    pub clock: Arc<dyn Clock>,
}

impl<S: Smartcard> Companion<S> {
    pub fn new(
        card: S,
        companion_pre_key: Bytes32,
        roster: RelayRoster,
        funder_owners: Vec<Address>,
        funder_threshold: usize,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            card,
            companion_pre_key,
            roster,
            funder_owners,
            funder_threshold,
            clock,
        }
    }

    /// Pick the first relay in the roster. Production deployments MUST
    /// rotate selection per round (SPEC Limitations: cross-round per-relay
    /// linkability).
    fn pick_relay(&self) -> Result<&RelayDescriptor, CompanionError> {
        self.roster
            .relays
            .first()
            .ok_or(CompanionError::NoRelaysAvailable)
    }

    /// `H_header = SHA-256(domain_digest || serialize_round_header(h))`.
    /// Domain digest is `SHA-256(DOMAIN_HEADER)`. The card recomputes the
    /// same value over its own copy of the serialized header carried in the
    /// SIGN_VOUCHER APDU.
    pub fn h_header(header: &RoundHeader) -> Bytes32 {
        let serialized = serialize_round_header(header);
        let mut domain_digest = [0u8; 32];
        domain_digest.copy_from_slice(&Sha256::digest(DOMAIN_HEADER));
        let mut hasher = Sha256::new();
        hasher.update(domain_digest);
        hasher.update(serialized);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }

    /// `roster_digest = SHA-256(DOMAIN_ROSTER || count_be(u32) || for each
    /// relay { relay_id (32) || x25519_pub (32) || rotation_epoch_be(u64) }
    /// || signed_at_unix_be(u64))`. Funder signs this; companion verifies
    /// k-of-n on it.
    fn roster_digest(roster: &RelayRoster) -> Bytes32 {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN_ROSTER);
        let count = roster.relays.len() as u32;
        hasher.update(count.to_be_bytes());
        for r in &roster.relays {
            hasher.update(r.relay_id);
            hasher.update(r.static_pub_x25519);
            hasher.update(r.rotation_epoch.to_be_bytes());
        }
        hasher.update(roster.signed_at_unix.to_be_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }

    /// Build, sign, and encrypt a voucher. Returns the AEAD envelope ready
    /// to hand to the mesh transport.
    pub fn build_voucher(
        &mut self,
        bundle: &HeaderBundle,
    ) -> Result<EncryptedVoucher, CompanionError> {
        // 1. Roster freshness via injected clock (SPEC: 48h window).
        let now = self.clock.now_unix();
        if now < self.roster.signed_at_unix {
            return Err(CompanionError::FutureRoster);
        }
        if now - self.roster.signed_at_unix > ROSTER_STALENESS_SECS {
            return Err(CompanionError::StaleRoster);
        }

        // 2. Roster k-of-n signature verification.
        let roster_digest = Self::roster_digest(&self.roster);
        let roster_sigs = decode_threshold(&self.roster.signature, self.funder_threshold)
            .map_err(CompanionError::BadRosterSig)?;
        verify_threshold(
            &roster_digest,
            &roster_sigs,
            &self.funder_owners,
            self.funder_threshold,
        )
        .map_err(CompanionError::BadRosterSig)?;

        // 3. Header k-of-n signature verification over h_header.
        let header = &bundle.signed.header;
        let h_header = Self::h_header(header);
        let header_sigs =
            decode_threshold(&bundle.signed.signature, self.funder_threshold)
                .map_err(CompanionError::BadFunderSig)?;
        verify_threshold(
            &h_header,
            &header_sigs,
            &self.funder_owners,
            self.funder_threshold,
        )
        .map_err(CompanionError::BadFunderSig)?;

        // 4. Build voucher context + auth token; drive SIGN_VOUCHER.
        let auth_token = derive_auth_token(&self.companion_pre_key, &h_header);
        let ctx = VoucherContext {
            round_id: header.round_id,
            cohort_root: header.cohort_root,
            claim_contract: header.claim_contract_address,
            per_recipient_amount: header.per_recipient_amount,
            chain_id: header.chain_id,
        };
        let serialized_header = serialize_round_header(header);
        let apdu = encode_sign_voucher(auth_token, &serialized_header, &ctx);
        let resp = self.card.transmit(&apdu)?;
        let (m_pub, derived_pub, signature) = decode_sign_voucher_response(&resp)?;

        // 5. Companion-side derived metadata.
        let destination = destination_from_derived_pubkey(&derived_pub);

        // claim_nullifier = Poseidon(NULL_DOMAIN_TAG, M_packed,
        // derivedPubkey_packed, roundId_packed, claim_contract,
        // chainId_packed).
        let m_x_hi = fr_from_be_bytes(&m_pub.x[..16]);
        let m_x_lo = fr_from_be_bytes(&m_pub.x[16..32]);
        let m_y_hi = fr_from_be_bytes(&m_pub.y[..16]);
        let m_y_lo = fr_from_be_bytes(&m_pub.y[16..32]);
        let m_packed = hash_m_packed(m_x_hi, m_x_lo, m_y_hi, m_y_lo);
        let derived_pubkey_packed = hash_derived_pubkey_packed(
            fr_from_be_bytes(&derived_pub.x[..16]),
            fr_from_be_bytes(&derived_pub.x[16..32]),
            fr_from_be_bytes(&derived_pub.y[..16]),
            fr_from_be_bytes(&derived_pub.y[16..32]),
        );
        let r_packed = pack_round_id(
            fr_from_be_bytes(&header.round_id[..16]),
            fr_from_be_bytes(&header.round_id[16..32]),
        );
        let c_packed = pack_chain_id(
            fr_from_be_bytes(&header.chain_id.as_bytes()[..16]),
            fr_from_be_bytes(&header.chain_id.as_bytes()[16..32]),
        );
        let claim_contract_fr = {
            let mut padded = [0u8; 32];
            padded[12..].copy_from_slice(&header.claim_contract_address);
            fr_from_be_bytes(&padded)
        };
        let nullifier_fr = hash_claim_nullifier(
            m_packed,
            derived_pubkey_packed,
            r_packed,
            claim_contract_fr,
            c_packed,
        );
        let claim_nullifier: Bytes32 = {
            use ark_ff::{
                BigInteger,
                PrimeField,
            };
            let le = nullifier_fr.into_bigint().to_bytes_le();
            let mut be = [0u8; 32];
            for i in 0..32 {
                be[i] = le[31 - i];
            }
            be
        };

        let voucher = SignedVoucher {
            m: m_pub,
            derived_pubkey: derived_pub,
            signature,
            context: ctx,
            claim_nullifier,
            destination,
        };

        // Serialize and encrypt.
        let plaintext = serde_json::to_vec(&voucher)
            .map_err(|e| CompanionError::Serialization(e.to_string()))?;
        let relay = self.pick_relay()?;
        let pk = PublicKey::from(relay.static_pub_x25519);
        let env = encrypt_to_relay(&pk, relay.relay_id, &plaintext)?;
        Ok(env)
    }
}

#[cfg(test)]
mod tests {
    use k256::{
        SecretKey,
        ecdsa::SigningKey,
        elliptic_curve::rand_core::OsRng,
    };
    use sha3::{
        Digest as Sha3Digest,
        Keccak256,
    };

    use super::*;
    use crate::{
        adapters::software_smartcard::SoftwareSmartcard,
        clock::MockClock,
        crypto::{
            aead::decrypt_from_companion,
            multisig::{
                MultiSignature,
                encode_threshold,
                sign_digest,
            },
        },
        types::{
            RoundHeader,
            SignedHeader,
            U256Be,
        },
    };

    /// secp256k1 SecretKey + Ethereum address pair.
    fn fresh_signer() -> (SecretKey, Address) {
        let sk = SecretKey::random(&mut OsRng);
        let signing = SigningKey::from(sk.clone());
        let ep = signing.verifying_key().to_encoded_point(false);
        let bytes = ep.as_bytes();
        let digest = Keccak256::digest(&bytes[1..]);
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&digest[12..]);
        (sk, addr)
    }

    fn fresh_x25519() -> (x25519_dalek::StaticSecret, x25519_dalek::PublicKey) {
        use rand::Rng;
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        let sk = x25519_dalek::StaticSecret::from(seed);
        let pk = x25519_dalek::PublicKey::from(&sk);
        (sk, pk)
    }

    fn sample_header() -> RoundHeader {
        RoundHeader {
            round_id: [0x42; 32],
            cohort_version: 1,
            cohort_root: [0xab; 32],
            per_recipient_amount: U256Be::from_u64(1_000_000),
            cohort_size: 4,
            token: [0xcc; 20],
            close_time: 1_700_000_000,
            claim_contract_address: [0xee; 20],
            chain_id: U256Be::from_u64(11_155_111),
        }
    }

    /// Sign `digest` from the first `threshold` signers and serialize via
    /// the multisig wire format.
    fn sign_with(
        signers: &[(SecretKey, Address)],
        threshold: usize,
        digest: &Bytes32,
    ) -> Vec<u8> {
        let sigs: Vec<MultiSignature> = signers
            .iter()
            .take(threshold)
            .map(|(sk, _)| sign_digest(sk, digest))
            .collect();
        encode_threshold(&sigs)
    }

    /// Build a fully-signed roster and bundle, ready to hand to a Companion
    /// constructed against the matching `funder_owners`.
    fn build_signed_world(
        signers: &[(SecretKey, Address)],
        threshold: usize,
        clock_now: u64,
    ) -> (RelayRoster, HeaderBundle, x25519_dalek::StaticSecret) {
        let (relay_sk, relay_pk) = fresh_x25519();
        let mut roster = RelayRoster {
            relays: vec![RelayDescriptor {
                relay_id: [0x11; 32],
                static_pub_x25519: *relay_pk.as_bytes(),
                rotation_epoch: 0,
            }],
            signed_at_unix: clock_now,
            signature: vec![],
        };
        // Compute roster digest, then sign.
        let digest = {
            let mut hasher = Sha256::new();
            hasher.update(DOMAIN_ROSTER);
            hasher.update((roster.relays.len() as u32).to_be_bytes());
            for r in &roster.relays {
                hasher.update(r.relay_id);
                hasher.update(r.static_pub_x25519);
                hasher.update(r.rotation_epoch.to_be_bytes());
            }
            hasher.update(roster.signed_at_unix.to_be_bytes());
            let mut out = [0u8; 32];
            out.copy_from_slice(&hasher.finalize());
            out
        };
        roster.signature = sign_with(signers, threshold, &digest);

        let header = sample_header();
        let h_header = Companion::<SoftwareSmartcard>::h_header(&header);
        let header_sig = sign_with(signers, threshold, &h_header);
        let bundle = HeaderBundle {
            signed: SignedHeader {
                header,
                signature: header_sig,
            },
            first_pool_leaf_index: 0,
        };
        (roster, bundle, relay_sk)
    }

    #[test]
    fn test_companion_builds_decryptable_voucher() {
        // Given: a 2-of-3 funder multisig, fresh roster and signed header,
        // a clock pinned at the same instant the roster was signed.
        let signers: Vec<(SecretKey, Address)> = (0..3).map(|_| fresh_signer()).collect();
        let owners: Vec<Address> = signers.iter().map(|(_, a)| *a).collect();
        let threshold = 2;
        let now = 1_700_000_000u64;
        let (roster, bundle, relay_sk) = build_signed_world(&signers, threshold, now);

        // Card with auth-token enforcement enabled (production default).
        // The companion holds the same pre-key.
        let pre_key = [0xabu8; 32];
        let mut card = SoftwareSmartcard::new(Some(pre_key), true);
        let _ = card
            .transmit(&crate::smartcard::apdu::encode_generate_key())
            .unwrap();

        let clock = Arc::new(MockClock::new(now));
        let mut companion =
            Companion::new(card, pre_key, roster, owners, threshold, clock.clone());

        // When: build_voucher is invoked.
        let env = companion.build_voucher(&bundle).unwrap();

        // Then: relay decrypts and parses the voucher cleanly.
        let plain = decrypt_from_companion(&relay_sk, &env).unwrap();
        let voucher: SignedVoucher = serde_json::from_slice(&plain).unwrap();
        assert_eq!(voucher.context.round_id, [0x42; 32]);
        assert_ne!(voucher.derived_pubkey.x, [0u8; 32]);
        assert_ne!(voucher.claim_nullifier, [0u8; 32]);
    }

    #[test]
    fn test_tampered_header_signature_rejected() {
        // Given: a valid 2-of-3 setup, then a single byte in the header
        // signature is flipped.
        let signers: Vec<(SecretKey, Address)> = (0..3).map(|_| fresh_signer()).collect();
        let owners: Vec<Address> = signers.iter().map(|(_, a)| *a).collect();
        let threshold = 2;
        let now = 1_700_000_000u64;
        let (roster, mut bundle, _relay_sk) =
            build_signed_world(&signers, threshold, now);
        // Tamper the first signature byte after the count prefix; this
        // disturbs the (r, s, v) of signer 0 → BadSignature on recovery.
        bundle.signed.signature[1 + 20 + 5] ^= 0x01;

        let pre_key = [0xabu8; 32];
        let mut card = SoftwareSmartcard::new(Some(pre_key), true);
        let _ = card
            .transmit(&crate::smartcard::apdu::encode_generate_key())
            .unwrap();
        let clock = Arc::new(MockClock::new(now));
        let mut companion =
            Companion::new(card, pre_key, roster, owners, threshold, clock);

        // When + Then: build_voucher returns BadFunderSig.
        let err = companion.build_voucher(&bundle).unwrap_err();
        assert!(matches!(err, CompanionError::BadFunderSig(_)));
    }

    #[test]
    fn test_future_roster_rejected() {
        // Given: a roster signed `1000` seconds in the future relative to
        // the local clock.
        let signers: Vec<(SecretKey, Address)> = (0..3).map(|_| fresh_signer()).collect();
        let owners: Vec<Address> = signers.iter().map(|(_, a)| *a).collect();
        let threshold = 2;
        let signed_at = 1_700_000_000u64;
        let (roster, bundle, _relay_sk) =
            build_signed_world(&signers, threshold, signed_at);

        let pre_key = [0xabu8; 32];
        let mut card = SoftwareSmartcard::new(Some(pre_key), true);
        let _ = card
            .transmit(&crate::smartcard::apdu::encode_generate_key())
            .unwrap();
        let clock = Arc::new(MockClock::new(signed_at - 1_000));
        let mut companion =
            Companion::new(card, pre_key, roster, owners, threshold, clock);

        // When + Then: build_voucher returns FutureRoster.
        let err = companion.build_voucher(&bundle).unwrap_err();
        assert!(matches!(err, CompanionError::FutureRoster));
    }

    #[test]
    fn test_stale_roster_rejected() {
        // Given: a roster signed > 48 hours before the local clock.
        let signers: Vec<(SecretKey, Address)> = (0..3).map(|_| fresh_signer()).collect();
        let owners: Vec<Address> = signers.iter().map(|(_, a)| *a).collect();
        let threshold = 2;
        let signed_at = 1_700_000_000u64;
        let (roster, bundle, _relay_sk) =
            build_signed_world(&signers, threshold, signed_at);

        let pre_key = [0xabu8; 32];
        let mut card = SoftwareSmartcard::new(Some(pre_key), true);
        let _ = card
            .transmit(&crate::smartcard::apdu::encode_generate_key())
            .unwrap();
        // 49 hours later.
        let clock = Arc::new(MockClock::new(signed_at + 49 * 3600));
        let mut companion =
            Companion::new(card, pre_key, roster, owners, threshold, clock);

        let err = companion.build_voucher(&bundle).unwrap_err();
        assert!(matches!(err, CompanionError::StaleRoster));
    }

    #[test]
    fn test_tampered_roster_signature_rejected() {
        // Given: roster signed correctly, then a signature byte is flipped.
        let signers: Vec<(SecretKey, Address)> = (0..3).map(|_| fresh_signer()).collect();
        let owners: Vec<Address> = signers.iter().map(|(_, a)| *a).collect();
        let threshold = 2;
        let now = 1_700_000_000u64;
        let (mut roster, bundle, _relay_sk) =
            build_signed_world(&signers, threshold, now);
        roster.signature[1 + 20 + 5] ^= 0x01;

        let pre_key = [0xabu8; 32];
        let mut card = SoftwareSmartcard::new(Some(pre_key), true);
        let _ = card
            .transmit(&crate::smartcard::apdu::encode_generate_key())
            .unwrap();
        let clock = Arc::new(MockClock::new(now));
        let mut companion =
            Companion::new(card, pre_key, roster, owners, threshold, clock);

        let err = companion.build_voucher(&bundle).unwrap_err();
        assert!(matches!(err, CompanionError::BadRosterSig(_)));
    }
}

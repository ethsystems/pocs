//! Integration tests for the high-level `Prover` / `Verifier` API.
//!
//! These tests exercise the full compile-prove-verify round trip and
//! a few rejection cases. The KAT-backed positive paths are slow
//! (compile dominates), so each test compiles its own `Prover` /
//! `Verifier` exactly once and reuses them across assertions where
//! possible.

#![deny(unsafe_code)]

mod common;

use binius_mayo::{
    Commitment, DOMAIN_TAG_C, DOMAIN_TAG_PK, Proof, ProofBundle, Prover, SignedMessage, Verifier,
    compute_c, compute_c_from_digest, compute_commitments, compute_pk_id,
};
use common::kat;

const KAT_PATH: &str = "tests/kat/mayo2.rsp";
const SIG_BYTES: usize = 186;
const CPK_BYTES: usize = 4912;

/// Pull the first KAT entry's `(cpk, sig, msg)` triple.
fn first_kat() -> ([u8; CPK_BYTES], [u8; SIG_BYTES], Vec<u8>) {
    let entries = kat::load_rsp(KAT_PATH);
    assert!(!entries.is_empty(), "no KAT entries parsed");
    let e = &entries[0];
    let cpk: [u8; CPK_BYTES] = e.pk.as_slice().try_into().expect("pk size");
    let sig: [u8; SIG_BYTES] = e.signature().try_into().expect("sig size");
    (cpk, sig, e.message().to_vec())
}

#[test]
fn given_first_kat_when_prove_then_verify_succeeds() {
    // Given: the first KAT entry and freshly-compiled prover/verifier.
    let (cpk, sig, msg) = first_kat();
    let prover = Prover::compile().expect("prover compile");
    let verifier = Verifier::compile().expect("verifier compile");
    let signed = SignedMessage {
        payload: &msg,
        cpk: &cpk,
        sig: &sig,
    };

    // When: we prove the signature.
    let bundle = prover.prove(&signed).expect("prove");

    // Then: the verifier accepts it.
    verifier.verify(&bundle).expect("verify");
}

#[test]
fn given_same_input_when_proved_twice_then_zk_proofs_differ() {
    // Given: one KAT entry and a compiled prover/verifier.
    let (cpk, sig, msg) = first_kat();
    let prover = Prover::compile().expect("prover compile");
    let verifier = Verifier::compile().expect("verifier compile");
    let signed = SignedMessage {
        payload: &msg,
        cpk: &cpk,
        sig: &sig,
    };

    // When: we prove the same statement twice with independent blinding.
    let a = prover.prove(&signed).expect("prove a");
    let b = prover.prove(&signed).expect("prove b");

    // Then: both verify, the public commitments match, but the ZK proof bytes
    // differ because each call draws fresh blinding randomness.
    verifier.verify(&a).expect("verify a");
    verifier.verify(&b).expect("verify b");
    assert_eq!(a.c, b.c);
    assert_eq!(a.pk_id, b.pk_id);
    assert_ne!(
        a.proof.as_slice(),
        b.proof.as_slice(),
        "ZK proofs over identical input must not be byte-identical"
    );
}

#[test]
fn given_proof_when_proof_byte_flipped_then_verify_rejects() {
    // Given: a valid proof bundle.
    let (cpk, sig, msg) = first_kat();
    let prover = Prover::compile().expect("prover compile");
    let verifier = Verifier::compile().expect("verifier compile");
    let signed = SignedMessage {
        payload: &msg,
        cpk: &cpk,
        sig: &sig,
    };
    let mut bundle = prover.prove(&signed).expect("prove");

    // When: we flip a single byte in the SNARK proof transcript.
    assert!(!bundle.proof.is_empty());
    bundle.proof.as_mut_slice()[0] ^= 1;

    // Then: verification rejects.
    let r = verifier.verify(&bundle);
    assert!(r.is_err(), "tampered proof must be rejected");
}

#[test]
fn given_proof_when_c_replaced_then_verify_rejects() {
    // Given: a valid proof bundle whose `c` we replace with a commitment
    // to a different message.
    let (cpk, sig, msg) = first_kat();
    let prover = Prover::compile().expect("prover compile");
    let verifier = Verifier::compile().expect("verifier compile");
    let signed = SignedMessage {
        payload: &msg,
        cpk: &cpk,
        sig: &sig,
    };
    let mut bundle = prover.prove(&signed).expect("prove");

    // When: we substitute a commitment to a foreign message.
    let foreign = compute_c(b"a different message");
    assert_ne!(bundle.c, foreign, "fixture must change c");
    bundle.c = foreign;

    // Then: verification rejects (the public input no longer matches the
    // bound transcript).
    let r = verifier.verify(&bundle);
    assert!(r.is_err(), "wrong c must be rejected");
}

#[test]
fn given_proof_when_pk_id_zeroed_then_verify_rejects() {
    // Given: a valid proof bundle with `pk_id` overwritten by zeros.
    let (cpk, sig, msg) = first_kat();
    let prover = Prover::compile().expect("prover compile");
    let verifier = Verifier::compile().expect("verifier compile");
    let signed = SignedMessage {
        payload: &msg,
        cpk: &cpk,
        sig: &sig,
    };
    let mut bundle = prover.prove(&signed).expect("prove");

    // When: we substitute an obviously-bogus pk_id.
    let bogus = binius_mayo::PkId::from([0u8; 32]);
    assert_ne!(bundle.pk_id, bogus, "fixture must change pk_id");
    bundle.pk_id = bogus;

    // Then: verification rejects.
    let r = verifier.verify(&bundle);
    assert!(r.is_err(), "wrong pk_id must be rejected");
}

#[test]
fn given_signed_message_when_compute_commitments_then_matches_prove_output() {
    // Given: the first KAT entry and a freshly-compiled prover.
    let (cpk, sig, msg) = first_kat();
    let prover = Prover::compile().expect("prover compile");
    let signed = SignedMessage {
        payload: &msg,
        cpk: &cpk,
        sig: &sig,
    };

    // When: we compute (c, pk_id) off-circuit AND extract them from a
    // freshly-produced proof bundle.
    let (c_local, pk_id_local) = compute_commitments(&msg, &cpk);
    let c_alone = compute_c(&msg);
    let pk_id_alone = compute_pk_id(&cpk);
    let bundle = prover.prove(&signed).expect("prove");

    // Then: the off-circuit helpers agree with what `prove` returns.
    assert_eq!(c_local, c_alone, "compute_c vs compute_commitments");
    assert_eq!(
        pk_id_local, pk_id_alone,
        "compute_pk_id vs compute_commitments"
    );
    assert_eq!(bundle.c, c_local, "prove(c) vs compute_c");
    assert_eq!(bundle.pk_id, pk_id_local, "prove(pk_id) vs compute_pk_id");

    // And: a non-trivial commitment never collides with the empty-message one.
    let empty = Commitment::from([0u8; 32]);
    assert_ne!(c_local, empty, "c must not be zero");
}

/// Domain tags for `c` and `pk_id` must be distinct, otherwise the algebraic
/// separation between the two commitments collapses.
#[test]
fn given_domain_tags_when_compared_then_they_differ() {
    assert_ne!(DOMAIN_TAG_C, DOMAIN_TAG_PK);
}

/// `compute_c_from_digest` and `compute_c` agree when the caller has manually
/// SHAKE-pre-hashed the payload to a 32-byte digest. This pins the contract
/// that `compute_c(payload) == compute_c_from_digest(SHAKE(payload, 32))`.
#[test]
fn given_payload_when_compute_c_then_matches_compute_c_from_digest() {
    use sha3::{
        Shake256,
        digest::{ExtendableOutput, Update, XofReader},
    };

    let payload = b"the quick brown fox jumps over the lazy dog";
    let mut hasher = Shake256::default();
    hasher.update(payload);
    let mut reader = hasher.finalize_xof();
    let mut digest = [0u8; 32];
    reader.read(&mut digest);

    let c_via_payload = compute_c(payload);
    let c_via_digest = compute_c_from_digest(&digest);
    assert_eq!(c_via_payload, c_via_digest);
}

/// Substituting a *legitimately-derived* `pk_id` from a different KAT entry
/// must be rejected by the verifier. This is a stronger negative test than
/// the zeroed-pk_id case, because the substituted value is structurally
/// well-formed.
#[test]
fn given_proof_when_pk_id_swapped_with_foreign_kat_then_verify_rejects() {
    let entries = kat::load_rsp(KAT_PATH);
    assert!(entries.len() >= 2, "need at least 2 KAT entries");

    let cpk0: [u8; CPK_BYTES] = entries[0].pk.as_slice().try_into().expect("pk size");
    let sig0: [u8; SIG_BYTES] = entries[0].signature().try_into().expect("sig size");
    let msg0 = entries[0].message().to_vec();
    let cpk1: [u8; CPK_BYTES] = entries[1].pk.as_slice().try_into().expect("pk size");

    let prover = Prover::compile().expect("prover compile");
    let verifier = Verifier::compile().expect("verifier compile");

    let signed = SignedMessage {
        payload: &msg0,
        cpk: &cpk0,
        sig: &sig0,
    };
    let mut bundle = prover.prove(&signed).expect("prove");
    bundle.pk_id = compute_pk_id(&cpk1);

    let r = verifier.verify(&bundle);
    assert!(r.is_err(), "foreign pk_id must be rejected");
}

/// A garbage `Proof` blob must be rejected without panicking. Exercises the
/// `Verifier::try_verify` panic-shield contract.
#[test]
fn given_garbage_proof_when_try_verify_then_returns_err_without_panic() {
    let verifier = Verifier::compile().expect("verifier compile");

    for proof_bytes in [
        Vec::<u8>::new(),
        vec![0u8; 1],
        vec![0xFFu8; 4096],
        (0..1024).map(|i| (i & 0xFF) as u8).collect::<Vec<_>>(),
    ] {
        let bundle = ProofBundle {
            c: Commitment::from([0u8; 32]),
            pk_id: binius_mayo::PkId::from([0u8; 32]),
            proof: Proof::from(proof_bytes),
        };
        let r = verifier.try_verify(&bundle);
        assert!(r.is_err(), "garbage proof must not be accepted");
    }
}

/// Golden-value regression test for `compute_pk_id` and `compute_c` against
/// KAT[0]. Pin the bytes to catch any silent shift in the keccak/AES expansion
/// path (e.g., a hypothetical `cargo update` to a `sha3 0.10.x` patch with a
/// behavior change). Values were captured against `sha3 = "=0.10.9"`,
/// `aes = "=0.8.4"`, and the domain-tag layout in this commit; if you bump
/// either dependency or change the domain tags, regenerate these expectations.
#[test]
fn given_kat0_when_compute_commitments_then_matches_golden_hex() {
    let (cpk, _sig, msg) = first_kat();

    let c = compute_c(&msg);
    let pk_id = compute_pk_id(&cpk);

    // Pinned hex against `sha3 = "=0.10.9"`, `aes = "=0.8.4"`, the domain-tag
    // layout in `src/api.rs::DOMAIN_TAG_C` / `DOMAIN_TAG_PK`, and KAT[0] of
    // the vendored `tests/kat/mayo2.rsp`.
    const KAT0_C_HEX: &str = "0efdaf717fc8bab983711d6d9e55a28b302f895f966f3307c74b0bbefb29846e";
    const KAT0_PK_ID_HEX: &str = "fbbb19e357481cd8492cdc9b2ab65a8a59194f2a81973146d33d3845f077e8e7";
    assert_eq!(hex::encode(c.as_bytes()), KAT0_C_HEX, "KAT[0] c shifted");
    assert_eq!(
        hex::encode(pk_id.as_bytes()),
        KAT0_PK_ID_HEX,
        "KAT[0] pk_id shifted"
    );

    // Determinism: back-to-back invocations must produce identical bytes.
    assert_eq!(c, compute_c(&msg), "compute_c must be deterministic");
    assert_eq!(
        pk_id,
        compute_pk_id(&cpk),
        "compute_pk_id must be deterministic"
    );

    // Sanity: domain-tagged outputs must differ from the un-tagged keccak
    // (catches accidental removal of the domain tag).
    use sha3::{Digest, Keccak256};
    let mut k = Keccak256::new();
    sha3::Digest::update(&mut k, &shake256_oracle(&msg));
    let untagged_c: [u8; 32] = k.finalize().into();
    assert_ne!(
        c.into_bytes(),
        untagged_c,
        "c must include DOMAIN_TAG_C; untagged hash must differ"
    );
}

fn shake256_oracle(payload: &[u8]) -> [u8; 32] {
    use sha3::{
        Shake256,
        digest::{ExtendableOutput, Update, XofReader},
    };
    let mut s = Shake256::default();
    s.update(payload);
    let mut r = s.finalize_xof();
    let mut out = [0u8; 32];
    r.read(&mut out);
    out
}

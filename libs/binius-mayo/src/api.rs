//! High-level public API for the MAYO-2 verifier SNARK.
//!
//! This module hides `binius64` entirely behind a small set of newtypes and
//! the [`Prover`] / [`Verifier`] structs. Most consumers should use this API
//! rather than touching [`crate::Mayo2Verify`] directly.
//!
//! # Quickstart
//!
//! ```no_run
//! use binius_mayo::{Prover, Verifier, SignedMessage};
//!
//! let prover = Prover::compile().expect("setup");
//! let verifier = Verifier::compile().expect("setup");
//!
//! # let cpk: [u8; 4912] = [0; 4912];
//! # let sig: [u8; 186] = [0; 186];
//! # let payload: &[u8] = b"";
//! let signed = SignedMessage { payload, cpk: &cpk, sig: &sig };
//! let bundle = prover.prove(&signed).expect("prove");
//! // For untrusted bundles use `try_verify` instead (see [`Verifier::verify`]).
//! verifier.try_verify(&bundle).expect("verify");
//! ```
//!
//! ## Soundness note
//!
//! The SNARK alone proves "I know a MAYO-2 signature binding the digest
//! commitment `c` to the public-key fingerprint `pk_id`". It does **not**
//! prove that those values are correct on their own. The application must
//! compare `bundle.c` and `bundle.pk_id` against locally-derived values
//! ([`compute_c`] / [`compute_pk_id`]) **before** calling [`Verifier::verify`].

use std::fmt;

use aes::Aes128;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use binius_core::word::Word;
use binius_frontend::{Circuit, CircuitBuilder};
use binius_hash::sha256::Sha256HashSuite;
use binius_prover::{OptimalPackedB128, zk_config::ZKProver as BiniusProver};
use binius_transcript::{ProverTranscript, VerifierTranscript};
use binius_verifier::{config::StdChallenger, zk_config::ZKVerifier as BiniusVerifier};
use rand::CryptoRng;
use sha3::Shake256;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Keccak256};

use crate::gf16::scalar;
use crate::params::{
    CPK_BYTES, M, M_VEC_BYTES, P1_ENTRIES, P2_ENTRIES, P3_ENTRIES, PK_SEED_BYTES, SIG_BYTES,
};
use crate::verify::Mayo2Verify;

/// 32-byte commitment to the application payload:
/// `keccak256(DOMAIN_C ‖ SHAKE-256(payload, 32))`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Commitment([u8; 32]);

/// 32-byte fingerprint of the public key:
/// `keccak256(DOMAIN_PK ‖ canonical_packed(P^1, P^2, P^3))`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct PkId([u8; 32]);

/// Opaque SNARK proof bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Proof(Vec<u8>);

/// What the prover sends and what the verifier consumes.
#[derive(Clone, Debug)]
pub struct ProofBundle {
    pub c: Commitment,
    pub pk_id: PkId,
    pub proof: Proof,
}

/// Inputs to [`Prover::prove`]. The MAYO-2 signature `sig` was produced over
/// `payload` under the compact public key `cpk`.
///
/// `payload` is hashed to the 32-byte MAYO digest off-circuit via
/// `m = SHAKE-256(payload, 32)`. It may be any
/// length; pass an already-32-byte digest at your own risk (it will be
/// SHAKE-pre-hashed again, use [`compute_c_from_digest`] if you need to
/// re-derive `c` from a digest you have in hand).
#[derive(Clone, Copy, Debug)]
pub struct SignedMessage<'a> {
    pub payload: &'a [u8],
    pub cpk: &'a [u8; CPK_BYTES],
    pub sig: &'a [u8; SIG_BYTES],
}

impl Commitment {
    /// View the commitment as a 32-byte array.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consume `self` and return the inner 32 bytes.
    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl From<[u8; 32]> for Commitment {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Commitment {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for Commitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.0)
    }
}

impl PkId {
    /// View the fingerprint as a 32-byte array.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consume `self` and return the inner 32 bytes.
    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl From<[u8; 32]> for PkId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for PkId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for PkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.0)
    }
}

impl Proof {
    /// View the proof as a byte slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Mutable view, mainly for negative tests that tamper with the bytes.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// Consume `self` and return the inner `Vec<u8>`.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Number of bytes in the serialized proof.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the proof is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<u8>> for Proof {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Proof {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

fn write_hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for b in bytes {
        write!(f, "{b:02x}")?;
    }
    Ok(())
}

/// Library-level error.
#[derive(Debug)]
pub enum Error {
    /// Wraps any failure during `compile()` (constraint-system or proving-key setup).
    Setup(Box<dyn std::error::Error + Send + Sync>),
    /// Wraps any failure during `prove()`. Typically a bad witness fill.
    ///
    /// **Information-leakage warning.** The wrapped error is produced by the
    /// underlying binius prover and may contain wire IDs or witness-derived
    /// metadata that depend on which signature byte was malformed. Consumers
    /// that produce proofs over secret signatures should not log
    /// `format!("{e:?}")` of this variant in adversarial settings.
    Prove(Box<dyn std::error::Error + Send + Sync>),
    /// Wraps any failure during `verify()`.
    Verify(Box<dyn std::error::Error + Send + Sync>),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Setup(e) => write!(f, "setup error: {e}"),
            Error::Prove(e) => write!(f, "prove error: {e}"),
            Error::Verify(e) => write!(f, "verify error: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Setup(e) | Error::Prove(e) | Error::Verify(e) => Some(&**e),
        }
    }
}

#[derive(Debug)]
struct LayoutError {
    offset_inout: usize,
    offset_witness: usize,
    constants_len: usize,
    detail: &'static str,
}

impl fmt::Display for LayoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "binius value-vec layout invariant violated ({}): \
             offset_inout={}, offset_witness={}, constants.len()={}",
            self.detail, self.offset_inout, self.offset_witness, self.constants_len,
        )
    }
}

impl std::error::Error for LayoutError {}

#[derive(Debug)]
struct PanicError(String);

impl fmt::Display for PanicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "binius backend panicked: {}", self.0)
    }
}

impl std::error::Error for PanicError {}

impl Error {
    fn from_caught_panic(payload: Box<dyn std::any::Any + Send + 'static>) -> Self {
        let msg = if let Some(s) = payload.downcast_ref::<&'static str>() {
            (*s).to_owned()
        } else if let Some(s) = payload.downcast_ref::<String>() {
            s.clone()
        } else {
            "non-string panic payload".to_owned()
        };
        Error::Verify(Box::new(PanicError(msg)))
    }
}

/// Library-level result type.
pub type Result<T> = std::result::Result<T, Error>;

/// Compute `c = keccak256(DOMAIN_C ‖ SHAKE-256(payload, 32))`.
///
/// This is the commitment to the application payload that the SNARK exposes
/// as a public input. The application re-derives it from `payload` to compare
/// against `bundle.c` returned by the prover.
///
/// The 8-byte domain tag [`DOMAIN_TAG_C`] is prepended to keep `c` algebraically
/// distinct from any other 32-byte keccak256 commitment a future protocol
/// might introduce; see [`compute_pk_id`].
///
/// `payload` may be of any length and is SHAKE-256-pre-hashed to the 32-byte
/// MAYO digest the signature actually authenticates. Callers already in
/// possession of a 32-byte digest should use [`compute_c_from_digest`] to
/// avoid a redundant round of pre-hashing.
#[must_use]
pub fn compute_c(payload: &[u8]) -> Commitment {
    compute_c_from_digest(&shake256_32(payload))
}

/// Compute `c = keccak256(DOMAIN_C ‖ m)` for a caller-supplied 32-byte digest.
#[must_use]
pub fn compute_c_from_digest(m: &[u8; 32]) -> Commitment {
    let mut hasher = Keccak256::new();
    sha3::Digest::update(&mut hasher, DOMAIN_TAG_C);
    sha3::Digest::update(&mut hasher, m);
    Commitment(hasher.finalize().into())
}

/// Compute `pk_id = keccak256(DOMAIN_PK ‖ canonical_packed(expand(cpk)))`.
#[must_use]
pub fn compute_pk_id(cpk: &[u8; CPK_BYTES]) -> PkId {
    let (p1, p2, p3) = expand_pk_to_lanes(cpk);
    pk_id_from_lanes(&p1, &p2, &p3)
}

/// Hot-path variant of [`compute_pk_id`] for callers that already hold the
/// expanded lane arrays. Streams the canonical packing directly into keccak.
pub(crate) fn pk_id_from_lanes(p1: &[[u8; M]], p2: &[[u8; M]], p3: &[[u8; M]]) -> PkId {
    assert_eq!(p1.len(), P1_ENTRIES, "p1 entry count");
    assert_eq!(p2.len(), P2_ENTRIES, "p2 entry count");
    assert_eq!(p3.len(), P3_ENTRIES, "p3 entry count");

    let mut hasher = Keccak256::new();
    sha3::Digest::update(&mut hasher, DOMAIN_TAG_PK);

    let mut entry_bytes = [0u8; M_VEC_BYTES];
    for lanes in p1.iter().chain(p2.iter()).chain(p3.iter()) {
        let packed = scalar::pack_lanes(lanes);
        for (j, word) in packed.iter().enumerate() {
            entry_bytes[j * 8..(j + 1) * 8].copy_from_slice(&word.to_le_bytes());
        }
        sha3::Digest::update(&mut hasher, entry_bytes);
    }

    PkId(hasher.finalize().into())
}

/// Convenience: returns both [`compute_c`] and [`compute_pk_id`] outputs.
#[must_use]
pub fn compute_commitments(payload: &[u8], cpk: &[u8; CPK_BYTES]) -> (Commitment, PkId) {
    (compute_c(payload), compute_pk_id(cpk))
}

/// Length of the per-commitment domain-separation tag (one Word).
pub const DOMAIN_TAG_LEN: usize = 8;

/// Domain-separation tag prepended to the keccak256 preimage of `c`.
///
/// Layout: 1 distinguishing byte, then 7 zero bytes (Word-aligned). The
/// 8-byte width matches the natural 64-bit Word lane of the in-circuit
/// keccak gadget.
pub const DOMAIN_TAG_C: [u8; DOMAIN_TAG_LEN] = [0x01, 0, 0, 0, 0, 0, 0, 0];

/// Domain-separation tag prepended to the keccak256 preimage of `pk_id`.
pub const DOMAIN_TAG_PK: [u8; DOMAIN_TAG_LEN] = [0x02, 0, 0, 0, 0, 0, 0, 0];

/// `DOMAIN_TAG_C` packed as a little-endian `u64` for in-circuit use.
pub(crate) const DOMAIN_TAG_C_WORD: u64 = u64::from_le_bytes(DOMAIN_TAG_C);

/// `DOMAIN_TAG_PK` packed as a little-endian `u64` for in-circuit use.
pub(crate) const DOMAIN_TAG_PK_WORD: u64 = u64::from_le_bytes(DOMAIN_TAG_PK);

/// Log of the inverse Reed-Solomon rate for the binius prover/verifier.
///
/// Soundness is fixed by binius's `SECURITY_BITS` (96), not by this value
const LOG_INV_RATE: usize = 3;

/// Compiled SNARK prover for the MAYO-2 verifier circuit.
///
/// Compile once with [`Prover::compile`] (around 3 s in release mode) and
/// reuse the same instance across many [`Prover::prove`] calls.
#[must_use = "a `Prover` is the result of an expensive compile step; drop it only when you're done proving"]
pub struct Prover {
    inner: Mayo2Verify,
    circuit: Circuit,
    binius_prover: BiniusProver<OptimalPackedB128, Sha256HashSuite>,
}

/// Compiled SNARK verifier for the MAYO-2 verifier circuit.
///
/// Compile once with [`Verifier::compile`] and reuse across many
/// [`Verifier::verify`] calls.
#[must_use = "a `Verifier` is the result of an expensive compile step; drop it only when you're done verifying"]
pub struct Verifier {
    binius_verifier: BiniusVerifier<Sha256HashSuite>,
    /// Constants from the constraint system, copied into the public-input
    /// slice prefix at verify time.
    constants: Vec<Word>,
    offset_inout: usize,
    offset_witness: usize,
}

impl Prover {
    /// Compile the verifier circuit and prepare the proving key.
    ///
    /// Takes ~3 s in release mode. Reuse the resulting `Prover` across
    /// many `prove()` calls.
    #[must_use = "compile() is the expensive setup step; capture the result"]
    pub fn compile() -> Result<Self> {
        let builder = CircuitBuilder::new();
        let inner = Mayo2Verify::new(&builder);
        let circuit = builder.build();
        let cs = circuit.constraint_system();

        let binius_verifier = BiniusVerifier::<Sha256HashSuite>::setup(cs.clone(), LOG_INV_RATE)
            .map_err(|e| Error::Setup(Box::new(e)))?;
        let binius_prover =
            BiniusProver::<OptimalPackedB128, Sha256HashSuite>::setup(binius_verifier)
                .map_err(|e| Error::Setup(Box::new(e)))?;

        Ok(Self {
            inner,
            circuit,
            binius_prover,
        })
    }

    /// Produce a proof bundle for the signed message, drawing zero-knowledge
    /// blinding randomness from the OS CSPRNG.
    ///
    /// The proof is zero-knowledge: it reveals nothing about the witness beyond
    /// what the public commitments `c` and `pk_id` already commit to. Each call
    /// draws fresh randomness, so proofs over identical input differ byte-wise.
    #[must_use = "the returned `ProofBundle` is the only output; dropping it discards the proof"]
    pub fn prove(&self, signed: &SignedMessage<'_>) -> Result<ProofBundle> {
        self.prove_with_rng(signed, rand::rng())
    }

    /// Like [`Prover::prove`] but draws the zero-knowledge blinding randomness
    /// from a caller-supplied source. Use this for reproducible proofs in tests
    /// or to bind a specific entropy source.
    ///
    /// The RNG must be cryptographically secure. Low-entropy or reused blinding
    /// randomness breaks the zero-knowledge property.
    #[must_use = "the returned `ProofBundle` is the only output; dropping it discards the proof"]
    pub fn prove_with_rng(
        &self,
        signed: &SignedMessage<'_>,
        rng: impl CryptoRng,
    ) -> Result<ProofBundle> {
        // 1. Off-circuit: lift the variable-length payload to the 32-byte
        //    MAYO digest the signature actually authenticates.
        let m = shake256_32(signed.payload);

        // 2. Off-circuit: AES-128-CTR expansion of the compact pk into lanes.
        let (p1, p2, p3) = expand_pk_to_lanes(signed.cpk);

        // 3. Allocate witness, populate, and run the in-circuit evaluator.
        let mut w = self.circuit.new_witness_filler();
        self.inner.populate(&mut w, &m, &p1, &p2, &p3, signed.sig);
        self.circuit
            .populate_wire_witness(&mut w)
            .map_err(|e| Error::Prove(Box::new(e)))?;

        // 4. Run the binius64 ZK prover and finalize the transcript. The RNG
        //    supplies the masking randomness that hides the witness.
        let value_vec = w.into_value_vec();
        let mut transcript = ProverTranscript::new(StdChallenger::default());
        self.binius_prover
            .prove(value_vec, rng, &mut transcript)
            .map_err(|e| Error::Prove(Box::new(e)))?;
        let proof_bytes = transcript.finalize();

        // 5. Compute the matching public-input commitments off-circuit. Reuse
        //    the expanded lanes from step 2 instead of calling
        //    `compute_pk_id(signed.cpk)`, which would re-run the AES expansion
        //    and re-allocate the canonical preimage.
        let c = compute_c_from_digest(&m);
        let pk_id = pk_id_from_lanes(&p1, &p2, &p3);

        Ok(ProofBundle {
            c,
            pk_id,
            proof: Proof(proof_bytes),
        })
    }
}

impl Verifier {
    /// Compile the verifier circuit and prepare the verifying key.
    #[must_use = "compile() is the expensive setup step; capture the result"]
    pub fn compile() -> Result<Self> {
        let builder = CircuitBuilder::new();
        // The `Mayo2Verify::new` call emits the constraint system into `builder`;
        // we don't keep the wire handles because the verifier only needs the
        // compiled constraint system and the public-input layout below.
        Mayo2Verify::new(&builder);
        let circuit = builder.build();
        let cs = circuit.constraint_system();

        let binius_verifier = BiniusVerifier::<Sha256HashSuite>::setup(cs.clone(), LOG_INV_RATE)
            .map_err(|e| Error::Setup(Box::new(e)))?;

        let constants = cs.constants.clone();
        let offset_inout = cs.value_vec_layout.offset_inout;
        let offset_witness = cs.value_vec_layout.offset_witness;

        // Defensive layout validation: `verify()` writes 8 inout Words (4 for
        // `c`, 4 for `pk_id`) starting at `offset_inout` into a buffer of
        // length `offset_witness`. If a future binius upgrade ever changes the
        // layout so these no longer fit, surface it here as a Setup error
        // rather than as an OOB panic on every verify call.
        if offset_witness < offset_inout + 8 {
            return Err(Error::Setup(Box::new(LayoutError {
                offset_inout,
                offset_witness,
                constants_len: constants.len(),
                detail: "offset_witness must be >= offset_inout + 8 for c/pk_id slots",
            })));
        }
        if constants.len() > offset_inout {
            return Err(Error::Setup(Box::new(LayoutError {
                offset_inout,
                offset_witness,
                constants_len: constants.len(),
                detail: "constants must fit in the [0, offset_inout) prefix",
            })));
        }

        Ok(Self {
            binius_verifier,
            constants,
            offset_inout,
            offset_witness,
        })
    }

    /// Verify a proof bundle. Returns `Ok(())` iff the SNARK accepts.
    ///
    /// The SNARK only proves "I know a sig binding to (`c`, `pk_id`)".
    /// The application must compare `bundle.c` and `bundle.pk_id` against
    /// the values it expects **before** calling this method.
    ///
    /// # Panic surface
    ///
    /// `bundle.proof` carries arbitrary attacker-controlled bytes (the
    /// `Proof::from(Vec<u8>)` constructor accepts any length). The wrapped
    /// `binius_verifier::verify` and `transcript.finalize` calls map their
    /// `Result`s through [`Error::Verify`], but a malformed proof can in
    /// principle still trigger a panic inside the pinned binius backend
    /// (`unwrap()` / slice-OOB on bytes whose layout the backend assumed
    /// well-formed). Consumers exposed to untrusted bundles should use
    /// [`Verifier::try_verify`], which catches such panics and folds them
    /// into a regular [`Error::Verify`].
    #[must_use = "verify() returns Ok(()) only when the proof is valid; ignoring the result silently accepts invalid proofs"]
    pub fn verify(&self, bundle: &ProofBundle) -> Result<()> {
        // Build the public-input slice the binius verifier consumes:
        // [constants ... | padding | inout (c, pk_id) | padding].
        let mut public = vec![Word(0); self.offset_witness];
        for (i, c) in self.constants.iter().enumerate() {
            public[i] = *c;
        }
        // Inout layout: `c[0..4]` then `pk_id[0..4]`, matching the
        // `add_inout` order in `Mayo2Verify::new`.
        for (i, chunk) in bundle.c.0.chunks_exact(8).enumerate() {
            let arr: [u8; 8] = chunk.try_into().expect("chunks_exact(8) yields 8 bytes");
            public[self.offset_inout + i] = Word(u64::from_le_bytes(arr));
        }
        for (i, chunk) in bundle.pk_id.0.chunks_exact(8).enumerate() {
            let arr: [u8; 8] = chunk.try_into().expect("chunks_exact(8) yields 8 bytes");
            public[self.offset_inout + 4 + i] = Word(u64::from_le_bytes(arr));
        }

        let mut transcript =
            VerifierTranscript::new(StdChallenger::default(), bundle.proof.0.clone());
        self.binius_verifier
            .verify(&public, &mut transcript)
            .map_err(|e| Error::Verify(Box::new(e)))?;
        transcript
            .finalize()
            .map_err(|e| Error::Verify(Box::new(e)))?;
        Ok(())
    }

    /// Like [`Verifier::verify`], but catches panics from the underlying
    /// binius backend and folds them into [`Error::Verify`].
    ///
    /// Use this when verifying bundles whose `proof` bytes come from an
    /// untrusted source (network, attacker-controlled blob) and the
    /// process must remain alive on a malformed input.
    ///
    /// # Caveat: panic strategy
    ///
    /// `try_verify` relies on `std::panic::catch_unwind`, which has no effect
    /// when the binary is built with `panic = "abort"`. Under that profile
    /// setting both `verify` and `try_verify` will abort the process on a
    /// malformed proof. Callers exposed to untrusted input must build with
    /// the default `panic = "unwind"` strategy.
    #[must_use = "try_verify() returns Ok(()) only when the proof is valid; ignoring the result silently accepts invalid proofs"]
    pub fn try_verify(&self, bundle: &ProofBundle) -> Result<()> {
        // `AssertUnwindSafe` is sound here because every panic-recovery path
        // ends by returning `Err(_)` to the caller, we do not continue
        // using any partially-mutated state after a caught panic. Both
        // `&self` and `&ProofBundle` are read-only references.
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.verify(bundle)));
        match res {
            Ok(r) => r,
            Err(payload) => Err(Error::from_caught_panic(payload)),
        }
    }
}

/// `SHAKE-256(input, 32)` as a 32-byte digest.
fn shake256_32(input: &[u8]) -> [u8; 32] {
    let mut shake = Shake256::default();
    shake.update(input);
    let mut reader = shake.finalize_xof();
    let mut out = [0u8; 32];
    reader.read(&mut out);
    out
}

/// AES-128-CTR-expand the compact public key into nibble-lane arrays for
/// `P^(1)`, `P^(2)`, `P^(3)`. Each entry is a `[u8; 64]` of GF(16) nibbles
/// (low-then-high unpack of the matching MAYO-C packed bytes).
///
/// Encrypts directly into the per-entry buffer (no intermediate keystream
/// Vec). Each entry consumes two consecutive AES-CTR blocks; the BE 32-bit
/// counter advances by 1 per block, so for entry index `i` (in concatenated
/// p1‖p2 order) we encrypt counters `2i, 2i+1`. This matches MAYO-C's
/// `AES_128_CTR(key=pk_seed, IV=0)` byte-for-byte.
fn expand_pk_to_lanes(cpk: &[u8; CPK_BYTES]) -> (Vec<[u8; M]>, Vec<[u8; M]>, Vec<[u8; M]>) {
    debug_assert_eq!(M_VEC_BYTES % 16, 0, "AES block must tile each m-vec evenly");
    let blocks_per_entry = M_VEC_BYTES / 16;

    let pk_seed: &[u8; PK_SEED_BYTES] = (&cpk[..PK_SEED_BYTES])
        .try_into()
        .expect("CPK_BYTES >= PK_SEED_BYTES");
    let p3_packed = &cpk[PK_SEED_BYTES..CPK_BYTES];

    let cipher = Aes128::new(GenericArray::from_slice(pk_seed));
    let mut counter: u32 = 0;

    let mut fill_entry = |entry: &mut [u8; M]| {
        for half in 0..blocks_per_entry {
            let mut block = [0u8; 16];
            block[12..16].copy_from_slice(&counter.to_be_bytes());
            counter = counter.wrapping_add(1);
            let mut blk = GenericArray::clone_from_slice(&block);
            cipher.encrypt_block(&mut blk);
            let off = half * 32;
            for b in 0..16 {
                let byte = blk[b];
                entry[off + 2 * b] = byte & 0x0F;
                entry[off + 2 * b + 1] = byte >> 4;
            }
        }
    };

    let mut p1: Vec<[u8; M]> = Vec::with_capacity(P1_ENTRIES);
    let mut p2: Vec<[u8; M]> = Vec::with_capacity(P2_ENTRIES);
    for _ in 0..P1_ENTRIES {
        let mut e = [0u8; M];
        fill_entry(&mut e);
        p1.push(e);
    }
    for _ in 0..P2_ENTRIES {
        let mut e = [0u8; M];
        fill_entry(&mut e);
        p2.push(e);
    }

    let p3 = unpack_m_vec_array(p3_packed, P3_ENTRIES);

    (p1, p2, p3)
}

/// Unpack `n_entries * (M/2)` packed bytes into nibble lanes (low-then-high),
/// one `[u8; M]` per entry.
fn unpack_m_vec_array(packed: &[u8], n_entries: usize) -> Vec<[u8; M]> {
    assert_eq!(
        packed.len(),
        n_entries * (M / 2),
        "unpack_m_vec_array: expected {} bytes, got {}",
        n_entries * (M / 2),
        packed.len(),
    );
    let mut out = Vec::with_capacity(n_entries);
    for i in 0..n_entries {
        let mut e = [0u8; M];
        let off = i * (M / 2);
        for b in 0..(M / 2) {
            let byte = packed[off + b];
            e[2 * b] = byte & 0x0f;
            e[2 * b + 1] = byte >> 4;
        }
        out.push(e);
    }
    out
}

#[cfg(test)]
mod soundness {
    use super::LOG_INV_RATE;

    #[test]
    fn binius_security_target_is_at_least_96_bits() {
        assert!(
            binius_verifier::SECURITY_BITS >= 96,
            "binius soundness target dropped to {} bits",
            binius_verifier::SECURITY_BITS,
        );
        let n_queries = binius_verifier::fri::calculate_n_test_queries(
            binius_verifier::SECURITY_BITS,
            LOG_INV_RATE,
        );
        assert!(n_queries >= binius_verifier::SECURITY_BITS);
    }
}

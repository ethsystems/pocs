# binius-mayo

A Binius64 zk-circuit library that proves a [MAYO-2](https://pqmayo.org/) post-quantum signature verifies for a 32-byte committed message under a hidden* public key.

> Proof of concept. Not audited, not production-ready. See [Limitations](#limitations).

## What this proves

The SNARK statement implemented by `Mayo2Verify`:

```text
public input:
  c     = keccak256(DOMAIN_C  ‖ m)                                // 32 B commitment to message
  pk_id = keccak256(DOMAIN_PK ‖ canonical_packed(P^1, P^2, P^3))  // 32 B fingerprint of the (hidden) pk

private witness:
  m            : 32-byte message digest
  P^(1), P^(2), P^(3) : expanded MAYO-2 public-key matrices (bitsliced GF(16))
  s_1..s_4, salt      : the MAYO signature

prove:
  keccak256(DOMAIN_C  ‖ m)                    == c
  keccak256(DOMAIN_PK ‖ canonical_packed(P))  == pk_id
  t = SHAKE-256(m ‖ salt, 32)           ∈ GF(16)^64
  y = MayoEvalPublicMap(P, s)           ∈ GF(16)^64
  y == t
```

The counterparty receives `(c, pk_id, π)` and verifies the SNARK. They learn that the prover knows a valid MAYO-2 signature on the message committed to in `c`, without learning the public key (only its fingerprint `pk_id`).

`pk_id` is bound to the **expanded** matrices, not the 4912-byte compact public key. The AES-128-CTR pk-expansion is performed off-circuit. See [Limitations](#limitations).

**All 100 NIST MAYO-2 KAT vectors verify in-circuit.**

## Who sees what

| Field                              | Prover (signer) | Verifier         | Public observer |
| ---------------------------------- | :-------------: | :--------------: | :-------------: |
| MAYO-2 secret key `sk`             |        ✓        |        ❌         |        ❌        |
| Compact public key `cpk` (4912 B)  |        ✓        |        ❌         |        ❌        |
| Expanded `(P¹, P², P³)`            |        ✓        |        ❌         |        ❌        |
| `payload` / `m = SHAKE(payload)`   |        ✓        | application-dep. |        ❌        |
| Signature `(s, salt)` (186 B)      |        ✓        |        ❌         |        ❌        |
| `pk_id` (32 B, published OOB once) |        ✓        |   ✓ (pinned)     |   ✓ (bundle)    |
| `c` (32 B commitment)              |        ✓        |   ✓ (recomputed) |   ✓ (bundle)    |
| SNARK proof `π`                    |        ✓        |        ✓         |   ✓ (bundle)    |

The verifier's view of `payload` is application-dependent: in an attestation flow they know it (and recompute `c` locally); in a blinded flow they only know `c`. The SNARK proof `π` is zero-knowledge (binius64's ZK prover/verifier): it reveals nothing about `cpk`, `sig`, or `payload` beyond what `c` and `pk_id` already commit to. Those two commitments are binding but not hiding, so an observer who can guess `payload`, or who holds a candidate `cpk`, can confirm the guess by recomputing them; see [Limitations](#limitations).

## Build & test

The crate pins [`binius-zk/binius64`](https://github.com/binius-zk/binius64) at commit `3bc7451`, which includes binius64's zero-knowledge prover/verifier. Toolchain: **Rust ≥ 1.95**, edition 2024.

```bash
# Build the library
cargo build --release

cargo test
```

Recommended: `RUSTFLAGS="-C target-cpu=native"` for the prover.

## API overview

The high-level surface hides Binius64 entirely behind a small set of newtypes. Compile a `Prover` (or `Verifier`) once, then reuse it across many proofs.

```rust
use binius_mayo::{Prover, Verifier, SignedMessage, compute_commitments};

// Compile once: reuse across many proofs.
let prover = Prover::compile()?;
let verifier = Verifier::compile()?;

// Inputs the prover takes (the SNARK contracts that `sig` was produced by
// MAYO-2 over `msg` under the public key `cpk`).
let signed = SignedMessage { payload, cpk: &cpk, sig: &sig };
let bundle = prover.prove(&signed)?;
// `bundle` carries (c, pk_id, proof). Send it to the verifier.

// Application-level binding: re-derive the values the verifier expects
// and compare BEFORE calling `verify`. The SNARK alone only proves
// that *some* signature exists for the (c, pk_id) carried in the bundle.
let (c_local, pk_id_local) = compute_commitments(payload, &cpk);
assert_eq!(bundle.c, c_local);
assert_eq!(bundle.pk_id, pk_id_local);

verifier.verify(&bundle)?;
```

Proofs are zero-knowledge and randomized: each `prove` call draws fresh blinding randomness from the OS CSPRNG, so proofs over identical input are not byte-identical. Use `prove_with_rng` to supply your own cryptographically-secure RNG (for reproducible test vectors, say).

The example at `examples/mayo2_e2e.rs` walks through the full flow end-to-end against the first NIST KAT entry.

### Advanced: low-level escape hatch

`Mayo2Verify` is the underlying circuit-builder primitive used by `Prover` / `Verifier`. Reach for it only if you need to embed the MAYO-2 verifier inside a larger Binius64 circuit, or to drive the prover/verifier yourself for benchmarking. Most consumers should stick to the high-level API above.

```rust
use binius_frontend::CircuitBuilder;
use binius_mayo::Mayo2Verify;

let builder = CircuitBuilder::new();
let v = Mayo2Verify::new(&builder);
let circuit = builder.build();

let mut w = circuit.new_witness_filler();
v.populate(&mut w, &m, &p1, &p2, &p3, &sig);
circuit.populate_wire_witness(&mut w)?;
// ... prove / verify per the binius64 prover/verifier scaffold
```

## Why Binius?

MAYO-2 verification is dominated by GF(16) arithmetic, bit-level packing, and Keccak / SHAKE hashing. Binius64 is a SNARK over binary fields with 64-bit wires and AND-count as the dominant cost metric, which lines up with this workload:

1. **Native binary fields.** GF(16) is a subfield of GF(2^64), so nibble multiplication, addition, and the whipping reduction over `f(z)` map directly onto the prover's native arithmetic. There is no field-emulation tax of the kind a BN254/BLS12-381 SNARK would pay.
2. **Bitsliced parallelism is free.** The 64-bit wire model lets us pack 64 GF(16) lanes per `[Wire; 4]` and amortize each Karatsuba AND across all of them, giving ~0.14 ANDs per scalar GF(16) multiply.
3. **Cheap XOR, expensive AND.** XOR (linear in GF(2)) is essentially free; only nonlinear gates count. MAYO-2's bilinear form is mostly XOR with a thin layer of multiplications, so the AND budget stays small (~120k for the dominant `P · S` pass).
4. **Keccak / SHAKE are bit-oriented.** The in-circuit `t = SHAKE-256(m ‖ salt)` and the two `keccak256` commitments are natural fits for a binary-field circuit; in a prime-field SNARK they would be the most expensive component by far.

Concretely this is what lets us keep a full MAYO-2 verifier (including SHAKE and two Keccaks) under a budget where in-circuit AES expansion of the compact pk would have been the single largest cost.

## Design choices

Highlights:

1. **AES-128-CTR pk expansion is performed off-circuit.** The signer canonicalises their expanded pk once and publishes `pk_id = keccak256(canonical_packed(P))`. This is the same shape as Ethereum's address-as-`keccak256(pk)`. AES-128-CTR over the full pk-expansion would dominate the AND budget if done in-circuit (rough order-of-magnitude estimate: tens of millions of ANDs); skipping it is the single largest cost savings in this design. The figure is not benchmarked in-tree.

2. **GF(16) is bitsliced.** Each length-64 m-vector is stored as `[Wire; 4]`, one bit-plane per nibble bit. Componentwise GF(16) multiplication is a 2-level Karatsuba at **9 ANDs per 64-lane parallel mul** (~0.14 ANDs per scalar mul).

3. **The bilinear form uses the 2-pass schedule** from MAYO-C `m_calculate_PS_SPS`: first `PS[j][col] = (P · s_col)[j]`, then `SPS[row][col] = s_row^T · PS[:, col]`. PS is the dominant cost (~120k ANDs).

4. **Whipping** reduces 16 SPS values mod `f(z) = z^M + 8 + 2z^2 + 8z^3` via 10 iterations of multiply-by-z-and-fold. Constant-multiply by F_TAIL coefficients is pure XOR; the whole reduction costs only **151 ANDs**.

5. **message digest.** The in-circuit hash chain skips the redundant `digest = SHAKE-256(m, 32)` step: `m` is treated as already a 32-byte MAYO digest, and the only in-circuit SHAKE-256 call is `t = SHAKE-256(m ‖ salt, 32)`. Callers wrap their actual messages by computing `m = SHAKE-256(payload, 32)` off-circuit.

## Limitations

This is a **proof of concept** for research and evaluation. Known limitations:

1. **The proof is zero-knowledge; the public commitments are not hiding.** The SNARK uses binius64's zero-knowledge prover/verifier (`zk_config::{ZKProver, ZKVerifier}`: a Spartan ZK wrapper over a blinded FRI-Binius commitment with masked sumcheck, per Diamond, [eprint 2025/1015](https://eprint.iacr.org/2025/1015)). The proof transcript reveals nothing about the witness data (the expanded pk, the signature, or the message digest). The residual exposure is the two public inputs: `c = keccak256(DOMAIN_C ‖ m)` and `pk_id = keccak256(DOMAIN_PK ‖ canonical_packed(P))` are binding but not hiding, so an adversary who can enumerate candidate payloads, or who holds a candidate `cpk`, can confirm a guess by recomputing them. For payload confidentiality against enumeration, fold a high-entropy salt into `payload` before proving (it flows into `c` with no circuit change); `pk_id` is a public identifier. Soundness is binius64's 96-bit target (`SECURITY_BITS`); see the `soundness` test.

2. **`pk_id` binds the expanded pk, not the 4912-byte compact form.** Off-circuit AES-128-CTR expansion is required by the signer once at keypair publication. Any external system holding "the prover's MAYO-2 pk" must hash the expanded form, not the cpk.

3. **Fixed 32-byte messages.** Variable-length / longer-message support is not in scope; callers should pre-hash arbitrary payloads.

4. **No in-circuit AES.** The SNARK proves knowledge of the **expanded** `(P^1, P^2, P^3)` matching `pk_id`, not of a 4912-byte `cpk` whose first 16 bytes AES-CTR-expand to `(P^1, P^2)`. Soundness rests on AES-128-CTR being a PRF: finding two distinct `cpk` values that AES-expand to the same `(P^1, P^2)` is computationally infeasible. Any external system that holds the prover's `cpk` and wants to bind it to `pk_id` must re-run the AES expansion locally and call `compute_pk_id(cpk)`. In exchange, prover cost is roughly an order of magnitude lower than an in-circuit AES variant would be (figure not benchmarked).

## Vendored sources

- `tests/kat/mayo2.{req,rsp}`: NIST KAT files for MAYO-2, copied verbatim from [`PQCMayo/MAYO-C`](https://github.com/PQCMayo/MAYO-C).

## License

MIT / APACHE 2.0

use rpi_lib::hasher;

use noir_bigcurve::BigCurve;
use noir_bigcurve::curves::bn254::{BN254, BN254_Fq, BN254Scalar};
use noir_bigcurve::ScalarField;

// Link proof (pi_link): proves that a blinded OPRF request and an identity
// commitment derive from the same user_id, AND that G_id is correctly
// derived from user_id_hash via Fouque-Tibouchi (SVDW) hash-to-curve.
//
// Public inputs:
//   identity_commitment -- Poseidon hash binding user_id_hash and salt
//   blinded_request_x, blinded_request_y -- the blinded point B = r * G_id
//   g_id_x, g_id_y -- the identity base point G_id
//
// Private inputs:
//   user_id_hash -- hash of the user's identifier
//   salt -- random salt used in the identity commitment
//   r -- blinding scalar (must be nonzero)
//   svdw_index -- which SVDW candidate was selected (0, 1, or 2)
//   svdw_w -- division witness: w = sqrt(-3) * t / (4 + t^2)
//   svdw_inv_w2 -- inverse witness: 1 / w^2
//   non_qr_witness_0, non_qr_witness_1 -- non-QR proofs for earlier candidates
//
// Security properties:
//   - sqrt(-3) and C1 are hardcoded constants (prevents root-choice attack)
//   - y-coordinate is canonicalized to even parity (prevents y-negation attack)
//   - Non-QR witnesses enforce canonical candidate selection

// Hardcoded SVDW constants for BN254 Fq.
// SQRT_NEG3 = sqrt(-3) mod q, even-parity canonical root
// C1 = (SQRT_NEG3 - 1) / 2 mod q
global SQRT_NEG3: Field = 21888242871839275217838484774961031245859103671646299620740479376884814904650;
global C1: Field = 21888242871839275220042445260109153167277707414472061641714758635765020556616;

fn main(
    // Public inputs
    identity_commitment: pub Field,
    blinded_request_x: pub Field,
    blinded_request_y: pub Field,
    g_id_x: pub Field,
    g_id_y: pub Field,
    // Private inputs
    user_id_hash: Field,
    salt: Field,
    r: Field,
    svdw_index: u8,
    svdw_w: Field,
    svdw_inv_w2: Field,
    non_qr_witness_0: Field,
    non_qr_witness_1: Field,
) {
    // 1. Verify identity commitment: H(DOMAIN_LINK, user_id_hash, salt)
    let computed_commitment = hasher::hash_link(user_id_hash, salt);
    assert(identity_commitment == computed_commitment);

    // 2. Compute t = H(DOMAIN_H2C, user_id_hash) -- single Poseidon hash
    let t_field = hasher::hash_h2c(user_id_hash);
    assert(t_field != 0, "t must be nonzero");
    let t: BN254_Fq = BN254_Fq::from(t_field);

    // 3. Load hardcoded SVDW constants
    let sqrt_neg3: BN254_Fq = BN254_Fq::from(SQRT_NEG3);
    let c1: BN254_Fq = BN254_Fq::from(C1);
    let one: BN254_Fq = BN254_Fq::from(1);
    let zero: BN254_Fq = BN254_Fq::from(0);
    let three: BN254_Fq = BN254_Fq::from(3);
    let four: BN254_Fq = BN254_Fq::from(4);

    // 4. Verify division witness: w * (4 + t^2) == sqrt(-3) * t
    let w: BN254_Fq = BN254_Fq::from(svdw_w);
    let t2 = t * t;
    let denom = four + t2;
    assert(w * denom == sqrt_neg3 * t, "w verification failed");

    // 5. Verify inverse witness: inv_w2 * w^2 == 1
    let inv_w2: BN254_Fq = BN254_Fq::from(svdw_inv_w2);
    assert(inv_w2 * w * w == one, "inv_w2 verification failed");

    // 6. Compute SVDW candidate x-coordinates
    let x1 = c1 - t * w;
    let x2 = zero - one - x1;
    let x3 = one + inv_w2;

    // 7. Select candidate by index and verify G_id.x matches
    let g_id_fq_x: BN254_Fq = BN254_Fq::from(g_id_x);
    assert(svdw_index < 3, "svdw_index must be 0, 1, or 2");

    if svdw_index == 0 {
        assert(x1 == g_id_fq_x, "candidate x1 mismatch");
    } else if svdw_index == 1 {
        assert(x2 == g_id_fq_x, "candidate x2 mismatch");
    } else {
        assert(x3 == g_id_fq_x, "candidate x3 mismatch");
    }

    // 8. Non-QR proofs for earlier candidates
    //    For non-QR rhs: -rhs is QR (since -1 is non-QR in BN254 Fq, q = 3 mod 4)
    //    Witness wi satisfies: wi^2 == -rhs
    if svdw_index > 0 {
        let rhs_0 = x1 * x1 * x1 + three;
        let neg_rhs_0 = zero - rhs_0;
        let w0: BN254_Fq = BN254_Fq::from(non_qr_witness_0);
        assert(w0 * w0 == neg_rhs_0, "non-QR witness 0 failed");
    }
    if svdw_index > 1 {
        let rhs_1 = x2 * x2 * x2 + three;
        let neg_rhs_1 = zero - rhs_1;
        let w1: BN254_Fq = BN254_Fq::from(non_qr_witness_1);
        assert(w1 * w1 == neg_rhs_1, "non-QR witness 1 failed");
    }

    // 9. Y-canonicalization: enforce even parity (LSB == 0)
    //    This prevents the y-negation attack where (x, -y) gives a different OPRF output.
    let g_id_y_bits: [bool; 254] = g_id_y.to_le_bits();
    assert(!g_id_y_bits[0], "g_id_y must have even parity");

    // 10. Validate G_id is on the BN254 curve (y^2 = x^3 + 3)
    let g_id_fq_y: BN254_Fq = BN254_Fq::from(g_id_y);
    let g_id: BN254 = BN254::from_coordinates(g_id_fq_x, g_id_fq_y, false);
    g_id.validate_on_curve();

    // 11. Verify blinded_request = r * G_id
    assert(r != 0, "blinding factor r must not be zero");
    let scalar: BN254Scalar = ScalarField::from(r);
    let computed_blinded: BN254 = g_id.mul(scalar);

    let br_fq_x: BN254_Fq = BN254_Fq::from(blinded_request_x);
    let br_fq_y: BN254_Fq = BN254_Fq::from(blinded_request_y);
    let blinded_request: BN254 = BN254::from_coordinates(br_fq_x, br_fq_y, false);
    blinded_request.validate_on_curve();

    assert(computed_blinded == blinded_request, "r * G_id != blinded_request");
}

use rdr_lib::ecdsa_secp256k1;
use rdr_lib::hasher;
use rdr_lib::keccak;
use rdr_lib::limbs;
use rdr_lib::merkle;
use rdr_lib::sha256_voucher;

// SHA-256("RDR/voucher/v1"); pinned constant matches off-chain Rust.
global DOMAIN_VOUCHER: [u8; 32] = [
    0x55, 0xb4, 0xfe, 0x97, 0x03, 0x48, 0x58, 0x5b, 0x05, 0x54, 0xf6, 0x94, 0x59, 0x43, 0x76, 0x93,
    0x98, 0xa8, 0xed, 0x6a, 0xb6, 0x0c, 0x65, 0x89, 0x3e, 0xd8, 0xe7, 0xf4, 0x48, 0xf6, 0xc0, 0x95,
];

fn main(
    round_id_hi: pub Field,
    round_id_lo: pub Field,
    cohort_root: pub Field,
    chain_id_hi: pub Field,
    chain_id_lo: pub Field,
    destination: pub Field,
    amount: pub Field,
    nullifier: pub Field,
    claim_contract_address: pub Field,
    relay_submitter: pub Field,
    derived_pubkey_x_hi: Field,
    derived_pubkey_x_lo: Field,
    derived_pubkey_y_hi: Field,
    derived_pubkey_y_lo: Field,
    m_x_hi: Field,
    m_x_lo: Field,
    m_y_hi: Field,
    m_y_lo: Field,
    signature_r: [u8; 32],
    signature_s: [u8; 32],
    proof_length: u32,
    leaf_index_bits: [bool; 20],
    merkle_path: [Field; 20],
) {
    limbs::assert_lt_2_128(round_id_hi);
    limbs::assert_lt_2_128(round_id_lo);
    limbs::assert_lt_2_128(chain_id_hi);
    limbs::assert_lt_2_128(chain_id_lo);
    limbs::assert_lt_2_128(m_x_hi);
    limbs::assert_lt_2_128(m_x_lo);
    limbs::assert_lt_2_128(m_y_hi);
    limbs::assert_lt_2_128(m_y_lo);
    // derivedPubkey limbs are range-checked < 2^128 each (so the assembled
    // 32-byte BE values are < 2^256). On-curve and canonical-form (< p_secp)
    // checks are NOT enforced in-circuit; they are delegated to the on-card
    // SHA-256 voucher signature, whose preimage commits to derived_x_bytes ||
    // derived_y_bytes, plus the chip-platform honesty assumption that the
    // card derives derivedPubkey via standard secp256k1 base-point mul. A
    // tampered card supplying a non-curve dpk loses funds for that user (the
    // resulting EOA has no known private key) but does not break system
    // soundness for other cards.
    limbs::assert_lt_2_128(derived_pubkey_x_hi);
    limbs::assert_lt_2_128(derived_pubkey_x_lo);
    limbs::assert_lt_2_128(derived_pubkey_y_hi);
    limbs::assert_lt_2_128(derived_pubkey_y_lo);
    limbs::assert_lt_2_160(destination);
    limbs::assert_lt_2_160(claim_contract_address);
    limbs::assert_lt_2_160(relay_submitter);

    let m_packed = hasher::hash_m_packed(m_x_hi, m_x_lo, m_y_hi, m_y_lo);
    merkle::verify_membership_cohort(
        m_packed,
        cohort_root,
        proof_length,
        leaf_index_bits,
        merkle_path,
    );

    let m_x_bytes = limbs::limbs_to_be_bytes_32(m_x_hi, m_x_lo);
    let m_y_bytes = limbs::limbs_to_be_bytes_32(m_y_hi, m_y_lo);
    let derived_x_bytes = limbs::limbs_to_be_bytes_32(derived_pubkey_x_hi, derived_pubkey_x_lo);
    let derived_y_bytes = limbs::limbs_to_be_bytes_32(derived_pubkey_y_hi, derived_pubkey_y_lo);
    let round_id_bytes = limbs::limbs_to_be_bytes_32(round_id_hi, round_id_lo);
    let chain_id_bytes = limbs::limbs_to_be_bytes_32(chain_id_hi, chain_id_lo);
    let cohort_root_bytes: [u8; 32] = cohort_root.to_be_bytes();
    let amount_bytes: [u8; 32] = amount.to_be_bytes();
    let claim_contract_bytes: [u8; 20] = claim_contract_address.to_be_bytes();

    let mut preimage: [u8; 308] = [0; 308];
    for i in 0..32 {
        preimage[i] = DOMAIN_VOUCHER[i];
    }
    for i in 0..32 {
        preimage[32 + i] = round_id_bytes[i];
    }
    for i in 0..32 {
        preimage[64 + i] = cohort_root_bytes[i];
    }
    for i in 0..32 {
        preimage[96 + i] = chain_id_bytes[i];
    }
    for i in 0..32 {
        preimage[128 + i] = m_x_bytes[i];
    }
    for i in 0..32 {
        preimage[160 + i] = m_y_bytes[i];
    }
    for i in 0..32 {
        preimage[192 + i] = derived_x_bytes[i];
    }
    for i in 0..32 {
        preimage[224 + i] = derived_y_bytes[i];
    }
    for i in 0..32 {
        preimage[256 + i] = amount_bytes[i];
    }
    for i in 0..20 {
        preimage[288 + i] = claim_contract_bytes[i];
    }

    let h_msg = sha256_voucher::sha256_308(preimage);

    ecdsa_secp256k1::verify_ecdsa(m_x_bytes, m_y_bytes, h_msg, signature_r, signature_s);

    let mut dpk_concat: [u8; 64] = [0; 64];
    for i in 0..32 {
        dpk_concat[i] = derived_x_bytes[i];
    }
    for i in 0..32 {
        dpk_concat[32 + i] = derived_y_bytes[i];
    }
    let dpk_keccak: [u8; 32] = keccak::keccak256_64(dpk_concat);
    let mut dest_acc: Field = 0;
    for i in 0..20 {
        dest_acc = dest_acc * 256 + dpk_keccak[12 + i] as Field;
    }
    assert(destination == dest_acc, "destination mismatch");

    let derived_pubkey_packed = hasher::hash_derived_pubkey_packed(
        derived_pubkey_x_hi,
        derived_pubkey_x_lo,
        derived_pubkey_y_hi,
        derived_pubkey_y_lo,
    );
    let round_id_packed = hasher::pack_round_id(round_id_hi, round_id_lo);
    let chain_id_packed = hasher::pack_chain_id(chain_id_hi, chain_id_lo);
    let computed_nullifier = hasher::hash_claim_nullifier(
        m_packed,
        derived_pubkey_packed,
        round_id_packed,
        claim_contract_address,
        chain_id_packed,
    );
    assert(nullifier == computed_nullifier, "nullifier mismatch");

    // relay_submitter is constrained on-chain to msg.sender; expose as
    // public input by reading it. Force the prover to commit to the value.
    let _ = relay_submitter;
}

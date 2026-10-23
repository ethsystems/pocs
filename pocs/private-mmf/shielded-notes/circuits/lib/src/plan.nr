use crate::domain;
use crate::hasher::sponge;
use crate::owner::SpendKey;

// The values a custody signer approves (SPEC, Transaction Plan). Unused slots
// are zero, so every operation absorbs the same 12 elements. The register feed
// is not in the plan: the circuit derives it from the output openings the
// signer approves, so a register-key rotation voids proofs but not signatures.
pub struct Plan {
    pub chain_id: Field,
    pub pool: Field,
    pub op: Field,
    pub path: Field,
    pub nullifiers: [Field; 2],
    pub outputs: [Field; 2],
    pub public_units: Field,
    pub recipient: Field,
    pub expiry: u64,
}

pub fn digest(p: Plan) -> Field {
    sponge([
        domain::PLAN_TAG,
        p.chain_id,
        p.pool,
        p.op,
        p.path,
        p.nullifiers[0],
        p.nullifiers[1],
        p.outputs[0],
        p.outputs[1],
        p.public_units,
        p.recipient,
        p.expiry as Field,
    ])
}

// `expiry` is private; it is checked against the public epoch, which the pool
// pins to the current one. A signature is usable through the last epoch that
// ends by `expiry`, so an expiry between midnights counts as the midnight
// before it.
pub fn check_expiry(epoch: u64, expiry: u64) {
    assert((epoch + 1) * domain::EPOCH_SECONDS <= expiry, "plan expired");
}

// The signer signs the digest's 32 big-endian bytes as a raw message hash.
pub fn verify_signature(key: SpendKey, signature: [u8; 64], plan_digest: Field) {
    let message = plan_digest.to_be_bytes::<32>();
    assert(
        std::ecdsa_secp256k1::verify_signature(key.x, key.y, signature, message),
        "invalid plan signature",
    );
}

#[test]
fn test_digest_binds_op_and_path() {
    let p = Plan {
        chain_id: 31337,
        pool: 0x5,
        op: domain::OP_TRANSFER,
        path: domain::PATH_OWNER,
        nullifiers: [1, 2],
        outputs: [3, 4],
        public_units: 0,
        recipient: 0,
        expiry: 8,
    };
    let d = digest(p);
    let mut q = p;
    q.path = domain::PATH_CLAIM;
    assert(d != digest(q));
    let mut r = p;
    r.op = domain::OP_WITHDRAW;
    assert(d != digest(r));
}

#[test]
fn test_expiry_at_the_end_of_the_epoch_passes() {
    check_expiry(100, 101 * domain::EPOCH_SECONDS);
}

#[test(should_fail_with = "plan expired")]
fn test_expiry_before_the_end_of_the_epoch_fails() {
    check_expiry(100, 101 * domain::EPOCH_SECONDS - 1);
}

#[test]
fn test_expiry_between_midnights_counts_as_the_midnight_before() {
    // One hour past the midnight that ends epoch 100: usable in epoch 100,
    // like that midnight, and not in epoch 101.
    check_expiry(100, 101 * domain::EPOCH_SECONDS + 3600);
}

#[test(should_fail_with = "plan expired")]
fn test_expiry_between_midnights_does_not_reach_the_next_epoch() {
    check_expiry(101, 101 * domain::EPOCH_SECONDS + 3600);
}

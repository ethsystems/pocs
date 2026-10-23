// Shared test fixtures for the circuits' Noir tests. Nothing here is used by
// a circuit's main function.
use crate::owner::SpendKey;

// secp256k1 public key for secret 0x0b: an investor's spend key in tests.
pub fn owner_key() -> SpendKey {
    SpendKey {
        x: [
            119, 74, 231, 248, 88, 169, 65, 30, 94, 244, 36, 107, 112, 198, 90, 172, 86, 73, 152,
            11, 229, 193, 120, 145, 187, 236, 23, 137, 93, 160, 8, 203,
        ],
        y: [
            217, 132, 160, 50, 235, 107, 94, 25, 2, 67, 221, 86, 215, 183, 179, 101, 55, 45, 177,
            226, 223, 249, 214, 168, 48, 29, 116, 201, 201, 83, 198, 27,
        ],
    }
}

// secp256k1 public key for secret 0x0c: the transfer agent's claim key in tests.
pub fn claim_key() -> SpendKey {
    SpendKey {
        x: [
            208, 17, 21, 213, 72, 231, 86, 27, 21, 195, 143, 0, 77, 115, 70, 51, 104, 124, 244, 65,
            150, 32, 9, 91, 197, 176, 244, 112, 112, 175, 232, 90,
        ],
        y: [
            169, 243, 79, 253, 200, 21, 224, 215, 168, 182, 69, 55, 225, 123, 216, 21, 121, 35, 140,
            93, 217, 168, 109, 82, 107, 5, 27, 19, 244, 6, 35, 39,
        ],
    }
}

pub global OWNER_NK: Field = 0x6e6b;
pub global TOKEN: Field = 0x1234567890abcdef1234567890abcdef12345678;
pub global POOL: Field = 0x5fbdb2315678afecb367f032d93f642f64180aa3;
pub global CHAIN_ID: Field = 31337;
pub global EPOCH: u64 = 100;
// A midnight UTC, as plan expiries SHOULD be.
pub global EXPIRY: u64 = 2_000_073_600;

// Reference values, pinned here and in the Rust implementation's parity tests
// (`src/domain`, `src/poseidon.rs`), so a change on either side fails a test.
// `nargo test --show-output test_parity_vectors` prints them.
#[test]
fn test_parity_vectors() {
    let six = crate::hasher::sponge([1, 2, 3, 4, 5, 6]);
    let fifteen = crate::hasher::sponge([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    let owner = crate::owner::owner_value(owner_key(), OWNER_NK);
    let claim_key_hash = crate::owner::key_hash(claim_key());
    let tpk = crate::feed::register_key_of(crate::feed::FeedSecret { lo: 0x7777, hi: 0x1 });
    let (r, k) = crate::feed::derive(crate::feed::FeedSecret { lo: 0x1234, hi: 0x5678 }, tpk);
    std::println([six, fifteen, owner, claim_key_hash]);
    std::println([tpk, r]);
    std::println(k);
    assert(six == 0x04c1bd93fcc11f3e42dd9814a64bedae53baad244b8664eec7f4bd1e421f507c);
    assert(fifteen == 0x09295d73b719cc1a82c8b3f5ca7c3b5bb94ca4db1605637510651e7435fd5567);
    assert(owner == 0x0d67dadf84418a242db346ed0bf55de2b2723fee773bf40ba3369e54c8e82c0a);
    assert(claim_key_hash == 0x1c0f6c4f661cfb481dd3351cdb68f7e9c9573bcb46a21344e356b8eed3ca3f3d);
    assert(tpk[0] == 0x24764a9bca6028e77d08ce48769e78b267310826a15569a651751d602100f3bb);
    assert(tpk[1] == 0x003d802df0f7a2702bf102dfd5e0e87e7d9182c73f98273fa79fa17d27324c61);
    assert(r[0] == 0x0640d0c6d4e4c4a7a1ca6810a1d70fd450c1ae737df2ed707ad5e3be60493034);
    assert(r[1] == 0x292a33b89dece883c8c3473818365cdc3694e834d5773120a4e52660004c877c);
    assert(k == 0x178ef8f4073794f21bd872ac9442c50b9b433da511eff0c56cc7e29ff4a08a3b);
}

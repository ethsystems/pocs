//! Signs a plan digest with a test key, for the circuits' Noir test fixtures.
//! Noir cannot sign, so each fixture's signature is produced here once and
//! pasted into the test. Signing is deterministic (RFC 6979), so rerunning
//! reproduces the same bytes.
//!
//! Usage: cargo run --example sign_digest -- <secret key hex> <digest hex>
//! Prints the public key's coordinates and the 64-byte signature (r || s) as
//! Noir arrays.

use k256::ecdsa::{
    Signature,
    SigningKey,
    signature::hazmat::PrehashSigner,
};

fn parse_32(hex_str: &str) -> [u8; 32] {
    let digits = hex_str.trim_start_matches("0x");
    let padded = format!("{digits:0>64}");
    let bytes = hex::decode(padded).expect("hex input");
    bytes.try_into().expect("at most 32 bytes")
}

fn noir_array(bytes: &[u8]) -> String {
    let items: Vec<String> = bytes.iter().map(|b| b.to_string()).collect();
    format!("[{}]", items.join(", "))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(
        args.len(),
        3,
        "usage: sign_digest <secret key hex> <digest hex>"
    );
    let secret = parse_32(&args[1]);
    let digest = parse_32(&args[2]);

    let key = SigningKey::from_slice(&secret).expect("valid secret key");
    let signature: Signature = key.sign_prehash(&digest).expect("signing succeeds");
    let point = key.verifying_key().to_sec1_point(false);

    println!("x: {}", noir_array(point.x().expect("uncompressed point")));
    println!("y: {}", noir_array(point.y().expect("uncompressed point")));
    println!("signature: {}", noir_array(&signature.to_bytes()));
}

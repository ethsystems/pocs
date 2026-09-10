use alloy::primitives::{Address, B256, U256};
use private_payment_shielded_pool::domain::{keys::OwnerPubkey, note::Note};

#[path = "core_deposit/proof_checks.rs"]
mod proof_checks;

/// The Noir fixture and the Rust client must derive the same commitment.
#[test]
fn core_fixture_matches_rust_primitives() {
    let fixture: toml::Table = include_str!("core_deposit/circuit/Prover.toml")
        .parse()
        .unwrap();
    let field = |key: &str| fixture[key].as_str().unwrap();
    let note = Note::with_salt(
        field("token").parse::<Address>().unwrap(),
        field("amount").parse::<U256>().unwrap(),
        OwnerPubkey(field("owner_pubkey").parse::<B256>().unwrap()),
        field("salt").parse::<B256>().unwrap(),
    );
    assert_eq!(note.commitment().0.to_string(), field("commitment"));
}

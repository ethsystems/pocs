//! The four public-input ABI orderings. SPEC "Circuit Constraints (diff)" fixes these
//! exactly: Noir `main` parameter order, `contracts/src/PublicInputs.sol` index for
//! index, and here. `compliance_commitment_out` sits at index 5 on deposit and index 6
//! on transfer and gated withdraw; that asymmetry is fixed by the SPEC, not a bug to
//! "correct".

use ark_bn254::Fr;

use crate::{
    error::CryptoError,
    types::{
        Bytes32,
        Epoch,
    },
};

fn u64_to_bytes32(v: u64) -> Bytes32 {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&v.to_be_bytes());
    Bytes32::from(bytes)
}

/// The Solidity twin of this function is `PublicInputs.requireCanonical`: `2^256 / p`
/// is about 5.29, so a prover submitting `x + p` for any field-typed input presents
/// the same field element to the verifier and an unseen key to whatever mapping reads
/// the raw bytes (e.g. `nullifiers`), forking state at a value that should be unique.
pub fn require_canonical(inputs: &[Bytes32]) -> Result<(), CryptoError> {
    for &input in inputs {
        Fr::try_from(input)?;
    }
    Ok(())
}

/// Indexes into the deposit circuit's 13 public inputs. Mirrors
/// `contracts/src/PublicInputs.sol::DepositPublicInputs`.
pub mod deposit {
    use super::*;

    pub const COMMITMENT: usize = 0;
    pub const TOKEN: usize = 1;
    pub const AMOUNT: usize = 2;
    pub const ATTESTATION_ROOT: usize = 3;
    pub const VELOCITY_NULLIFIER: usize = 4;
    pub const COMPLIANCE_COMMITMENT_OUT: usize = 5;
    pub const EPOCH: usize = 6;
    pub const EPOCH_SECONDS: usize = 7;
    pub const POLICY_SOURCE_HASH: usize = 8;
    pub const COMMITMENT_ROOT: usize = 9;
    pub const ATTESTER_REVOCATION_ROOT: usize = 10;
    pub const MIN_ACCEPTED_GENERATION: usize = 11;
    pub const PAYLOAD_COMMITMENT: usize = 12;
    pub const LENGTH: usize = 13;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Fields {
        pub commitment: Bytes32,
        pub token: Bytes32,
        pub amount: u64,
        pub attestation_root: Bytes32,
        pub velocity_nullifier: Bytes32,
        pub compliance_commitment_out: Bytes32,
        pub epoch: Epoch,
        pub epoch_seconds: u64,
        pub policy_source_hash: Bytes32,
        pub commitment_root: Bytes32,
        pub attester_revocation_root: Bytes32,
        pub min_accepted_generation: u64,
        pub payload_commitment: Bytes32,
    }

    impl Fields {
        pub fn ordered(&self) -> [Bytes32; LENGTH] {
            [
                self.commitment,
                self.token,
                u64_to_bytes32(self.amount),
                self.attestation_root,
                self.velocity_nullifier,
                self.compliance_commitment_out,
                u64_to_bytes32(self.epoch.0),
                u64_to_bytes32(self.epoch_seconds),
                self.policy_source_hash,
                self.commitment_root,
                self.attester_revocation_root,
                u64_to_bytes32(self.min_accepted_generation),
                self.payload_commitment,
            ]
        }
    }
}

/// Indexes into the transfer circuit's 14 public inputs. Mirrors
/// `contracts/src/PublicInputs.sol::TransferPublicInputs`.
pub mod transfer {
    use super::*;

    pub const NULLIFIER_0: usize = 0;
    pub const NULLIFIER_1: usize = 1;
    pub const COMMITMENT_OUT_0: usize = 2;
    pub const COMMITMENT_OUT_1: usize = 3;
    pub const COMMITMENT_ROOT: usize = 4;
    pub const VELOCITY_NULLIFIER: usize = 5;
    pub const COMPLIANCE_COMMITMENT_OUT: usize = 6;
    pub const EPOCH: usize = 7;
    pub const EPOCH_SECONDS: usize = 8;
    pub const POLICY_SOURCE_HASH: usize = 9;
    pub const ATTESTATION_ROOT: usize = 10;
    pub const ATTESTER_REVOCATION_ROOT: usize = 11;
    pub const MIN_ACCEPTED_GENERATION: usize = 12;
    pub const PAYLOAD_COMMITMENT: usize = 13;
    pub const LENGTH: usize = 14;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Fields {
        pub nullifier_0: Bytes32,
        pub nullifier_1: Bytes32,
        pub commitment_out_0: Bytes32,
        pub commitment_out_1: Bytes32,
        pub commitment_root: Bytes32,
        pub velocity_nullifier: Bytes32,
        pub compliance_commitment_out: Bytes32,
        pub epoch: Epoch,
        pub epoch_seconds: u64,
        pub policy_source_hash: Bytes32,
        pub attestation_root: Bytes32,
        pub attester_revocation_root: Bytes32,
        pub min_accepted_generation: u64,
        pub payload_commitment: Bytes32,
    }

    impl Fields {
        pub fn ordered(&self) -> [Bytes32; LENGTH] {
            [
                self.nullifier_0,
                self.nullifier_1,
                self.commitment_out_0,
                self.commitment_out_1,
                self.commitment_root,
                self.velocity_nullifier,
                self.compliance_commitment_out,
                u64_to_bytes32(self.epoch.0),
                u64_to_bytes32(self.epoch_seconds),
                self.policy_source_hash,
                self.attestation_root,
                self.attester_revocation_root,
                u64_to_bytes32(self.min_accepted_generation),
                self.payload_commitment,
            ]
        }
    }
}

/// Indexes into the gated withdraw circuit's 14 public inputs. Mirrors
/// `contracts/src/PublicInputs.sol::WithdrawPublicInputs`.
pub mod gated_withdraw {
    use super::*;

    pub const NULLIFIER: usize = 0;
    pub const TOKEN: usize = 1;
    pub const AMOUNT: usize = 2;
    pub const RECIPIENT: usize = 3;
    pub const COMMITMENT_ROOT: usize = 4;
    pub const VELOCITY_NULLIFIER: usize = 5;
    pub const COMPLIANCE_COMMITMENT_OUT: usize = 6;
    pub const EPOCH: usize = 7;
    pub const EPOCH_SECONDS: usize = 8;
    pub const POLICY_SOURCE_HASH: usize = 9;
    pub const ATTESTATION_ROOT: usize = 10;
    pub const ATTESTER_REVOCATION_ROOT: usize = 11;
    pub const MIN_ACCEPTED_GENERATION: usize = 12;
    pub const PAYLOAD_COMMITMENT: usize = 13;
    pub const LENGTH: usize = 14;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Fields {
        pub nullifier: Bytes32,
        pub token: Bytes32,
        pub amount: u64,
        pub recipient: Bytes32,
        pub commitment_root: Bytes32,
        pub velocity_nullifier: Bytes32,
        pub compliance_commitment_out: Bytes32,
        pub epoch: Epoch,
        pub epoch_seconds: u64,
        pub policy_source_hash: Bytes32,
        pub attestation_root: Bytes32,
        pub attester_revocation_root: Bytes32,
        pub min_accepted_generation: u64,
        pub payload_commitment: Bytes32,
    }

    impl Fields {
        pub fn ordered(&self) -> [Bytes32; LENGTH] {
            [
                self.nullifier,
                self.token,
                u64_to_bytes32(self.amount),
                self.recipient,
                self.commitment_root,
                self.velocity_nullifier,
                self.compliance_commitment_out,
                u64_to_bytes32(self.epoch.0),
                u64_to_bytes32(self.epoch_seconds),
                self.policy_source_hash,
                self.attestation_root,
                self.attester_revocation_root,
                u64_to_bytes32(self.min_accepted_generation),
                self.payload_commitment,
            ]
        }
    }
}

/// Indexes into the ungated withdraw circuit's 5 public inputs, the parent's
/// unchanged. Mirrors `contracts/src/PublicInputs.sol::UngatedWithdrawPublicInputs`.
/// `amount` is `Field`-typed here (`circuits/withdraw_ungated/src/main.nr` ports the
/// parent circuit unchanged in statement), unlike the gated circuits' `u64` `amount`.
pub mod ungated_withdraw {
    use super::*;

    pub const NULLIFIER: usize = 0;
    pub const TOKEN: usize = 1;
    pub const AMOUNT: usize = 2;
    pub const RECIPIENT: usize = 3;
    pub const COMMITMENT_ROOT: usize = 4;
    pub const LENGTH: usize = 5;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Fields {
        pub nullifier: Bytes32,
        pub token: Bytes32,
        pub amount: Bytes32,
        pub recipient: Bytes32,
        pub commitment_root: Bytes32,
    }

    impl Fields {
        pub fn ordered(&self) -> [Bytes32; LENGTH] {
            [
                self.nullifier,
                self.token,
                self.amount,
                self.recipient,
                self.commitment_root,
            ]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compliance_commitment_out_sits_at_the_spec_fixed_indices() {
        // SPEC-fixed indices: 5 on deposit, 6 on transfer and gated withdraw.
        assert_eq!(deposit::COMPLIANCE_COMMITMENT_OUT, 5);
        assert_eq!(transfer::COMPLIANCE_COMMITMENT_OUT, 6);
        assert_eq!(gated_withdraw::COMPLIANCE_COMMITMENT_OUT, 6);
    }

    #[test]
    fn lengths_match_the_spec_input_counts() {
        assert_eq!(deposit::LENGTH, 13);
        assert_eq!(transfer::LENGTH, 14);
        assert_eq!(gated_withdraw::LENGTH, 14);
        assert_eq!(ungated_withdraw::LENGTH, 5);
    }

    #[test]
    fn deposit_fields_order_matches_the_index_constants() {
        let f = deposit::Fields {
            commitment: Bytes32::from([1u8; 32]),
            token: Bytes32::from([2u8; 32]),
            amount: 1000,
            attestation_root: Bytes32::from([3u8; 32]),
            velocity_nullifier: Bytes32::from([4u8; 32]),
            compliance_commitment_out: Bytes32::from([5u8; 32]),
            epoch: Epoch(100),
            epoch_seconds: 86400,
            policy_source_hash: Bytes32::from([6u8; 32]),
            commitment_root: Bytes32::from([7u8; 32]),
            attester_revocation_root: Bytes32::from([8u8; 32]),
            min_accepted_generation: 1,
            payload_commitment: Bytes32::from([9u8; 32]),
        };
        let ordered = f.ordered();
        assert_eq!(ordered[deposit::COMMITMENT], f.commitment);
        assert_eq!(ordered[deposit::TOKEN], f.token);
        assert_eq!(
            ordered[deposit::COMPLIANCE_COMMITMENT_OUT],
            f.compliance_commitment_out
        );
        assert_eq!(ordered[deposit::MIN_ACCEPTED_GENERATION], u64_to_bytes32(1));
        assert_eq!(ordered[deposit::PAYLOAD_COMMITMENT], f.payload_commitment);
    }

    #[test]
    fn require_canonical_rejects_a_value_at_the_modulus() {
        let modulus_bytes: [u8; 32] = crate::BN254_MODULUS
            .to_bytes_be()
            .try_into()
            .expect("32 bytes");
        let inputs = [Bytes32::from([0u8; 32]), Bytes32::from(modulus_bytes)];
        assert!(require_canonical(&inputs).is_err());
    }

    #[test]
    fn require_canonical_accepts_values_below_the_modulus() {
        let inputs = [Bytes32::from([0u8; 32]), Bytes32::from([1u8; 32])];
        assert!(require_canonical(&inputs).is_ok());
    }
}

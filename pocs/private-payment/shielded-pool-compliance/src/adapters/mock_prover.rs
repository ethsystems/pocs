//! A complete mock `Prover`: deterministic, no real circuit backend. `prove` mints a
//! 32-byte tag over the circuit and its public inputs; `verify` recomputes the same
//! tag and compares. This gives `verify` a real ability to reject a tampered proof
//! (unlike a stub that always returns `Ok(true)`), without any dependency on
//! `nargo`/`bb`.
#![cfg(any(test, feature = "test-mocks"))]

use sha2::{
    Digest,
    Sha256,
};

use crate::{
    error::ProverError,
    ports::prover::{
        Circuit,
        CircuitProof,
        ProofRequest,
        Prover,
    },
    types::Bytes32,
};

const PROOF_LEN: usize = 32;

fn circuit_tag(circuit: Circuit) -> u8 {
    match circuit {
        Circuit::Deposit => 0,
        Circuit::Transfer => 1,
        Circuit::Withdraw => 2,
        Circuit::WithdrawBlocked => 3,
    }
}

fn mock_proof_bytes(circuit: Circuit, public_inputs: &[Bytes32]) -> [u8; PROOF_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(b"mock-prover-v1");
    hasher.update([circuit_tag(circuit)]);
    hasher.update((public_inputs.len() as u32).to_be_bytes());
    for input in public_inputs {
        hasher.update(input.as_ref());
    }
    hasher.finalize().into()
}

/// Test double for `Prover`. `prove` and `verify` are inverses of each other over the
/// same `(circuit, public_inputs)`, so a test can assert both acceptance and
/// rejection without a real backend.
#[derive(Debug, Clone, Copy, Default)]
pub struct MockProver;

impl Prover for MockProver {
    fn prove(&self, request: &ProofRequest) -> Result<CircuitProof, ProverError> {
        let public_inputs = request.public_inputs();
        let proof = mock_proof_bytes(request.circuit(), &public_inputs).to_vec();
        Ok(CircuitProof {
            proof,
            public_inputs,
        })
    }

    fn verify(
        &self,
        circuit: Circuit,
        proof: &CircuitProof,
    ) -> Result<bool, ProverError> {
        if proof.proof.len() != PROOF_LEN {
            return Err(ProverError::MalformedProof {
                expected: PROOF_LEN,
                actual: proof.proof.len(),
            });
        }
        let expected = mock_proof_bytes(circuit, &proof.public_inputs);
        Ok(proof.proof == expected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        domain::{
            attestation::Generation,
            keys::SpendingKey,
            public_inputs::deposit,
            witness::{
                AttestationWitness,
                ComplianceWitness,
                DepositWitness,
            },
        },
        policy::{
            Policy,
            reference::ReferencePolicy,
        },
        ports::merkle::MerklePath,
        types::{
            Address,
            Epoch,
            Seq,
        },
    };

    fn deposit_request() -> ProofRequest {
        let witness = DepositWitness {
            public: deposit::Fields {
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
            },
            spending_key: SpendingKey::random(),
            note_salt: Bytes32::from([9u8; 32]),
            attestation: AttestationWitness {
                attester: Address::from([0xaa; 20]),
                generation: Generation(1),
                issued_at: 1,
                expires_at: 2,
                attestation_proof: MerklePath::new(vec![]),
                revoked_at: u64::MAX,
                revocation_proof: MerklePath::new(vec![]),
            },
            compliance: ComplianceWitness {
                seq: Seq(0),
                epoch_in: Epoch(100),
                prev: ReferencePolicy::zero(),
                flags_in: 0,
                cp_in: [Bytes32::from([0u8; 32]); 2],
                amt_in: [0, 0],
                exit_in: Bytes32::from([0u8; 32]),
                salt_in: Bytes32::from([0u8; 32]),
                salt_out: Bytes32::from([0u8; 32]),
                cn_proof: MerklePath::new(vec![]),
            },
        };
        ProofRequest::Deposit(Box::new(witness))
    }

    #[test]
    fn prove_then_verify_accepts() {
        let prover = MockProver;
        let request = deposit_request();
        let proof = prover.prove(&request).expect("mock prove never fails");
        let ok = prover
            .verify(request.circuit(), &proof)
            .expect("mock verify runs");
        assert!(ok);
    }

    #[test]
    fn verify_rejects_a_proof_with_tampered_public_inputs() {
        let prover = MockProver;
        let request = deposit_request();
        let mut proof = prover.prove(&request).expect("mock prove never fails");
        proof.public_inputs[0] = Bytes32::from([0xffu8; 32]);
        let ok = prover
            .verify(request.circuit(), &proof)
            .expect("mock verify runs");
        assert!(!ok);
    }

    #[test]
    fn verify_rejects_a_proof_checked_against_the_wrong_circuit() {
        let prover = MockProver;
        let request = deposit_request();
        let proof = prover.prove(&request).expect("mock prove never fails");
        let ok = prover
            .verify(Circuit::Transfer, &proof)
            .expect("mock verify runs");
        assert!(!ok);
    }

    #[test]
    fn verify_errors_on_a_malformed_proof_length() {
        let prover = MockProver;
        let proof = CircuitProof {
            proof: vec![0u8; 4],
            public_inputs: vec![],
        };
        assert!(matches!(
            prover.verify(Circuit::Deposit, &proof),
            Err(ProverError::MalformedProof {
                expected: PROOF_LEN,
                actual: 4
            })
        ));
    }
}

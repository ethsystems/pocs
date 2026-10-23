//! A complete mock `Prover`: deterministic, no real circuit backend. `prove` mints a
//! 32-byte proof over the circuit and its public inputs; `verify` recomputes it and
//! compares. The on-chain `BindingMockVerifier` recomputes the same proof from the
//! inputs the pool assembles, so under mocks a public input that Rust and the pool
//! lay out or fill in differently is refused, as the generated verifier would refuse
//! it. No dependency on `nargo`/`bb`.
#![cfg(any(test, feature = "test-mocks"))]

use alloy::primitives::keccak256;

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
    }
}

/// keccak256("shielded-notes mock proof" ‖ circuit ‖ public inputs), which
/// `BindingMockVerifier.sol` computes as `abi.encodePacked` of the same.
fn mock_proof_bytes(circuit: Circuit, public_inputs: &[Bytes32]) -> [u8; PROOF_LEN] {
    let mut bytes = b"shielded-notes mock proof".to_vec();
    bytes.push(circuit_tag(circuit));
    for input in public_inputs {
        bytes.extend_from_slice(input.as_ref());
    }
    keccak256(bytes).0
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
    use ark_bn254::Fr;

    use super::*;
    use crate::{
        domain::{
            keys::{
                PlanSigner,
                SpendKey,
            },
            tree::MerkleProof,
            witness::{
                AttestationWitness,
                InputWitness,
                WithdrawWitness,
            },
        },
        types::Address,
    };

    fn withdraw_request() -> ProofRequest {
        let attestation = AttestationWitness {
            attester: Address::from([0xaa; 20]),
            generation: 0,
            issued_at: 1,
            expires_at: 2,
            path: MerkleProof::default(),
        };
        ProofRequest::Withdraw(Box::new(WithdrawWitness {
            nullifier: Fr::from(1u64),
            token: Address::from([2; 20]),
            units: 1000,
            recipient: Address::from([3; 20]),
            commitment_root: Fr::from(4u64),
            attestation_root: Fr::from(5u64),
            min_accepted_generation: 0,
            epoch: 100,
            chain_id: 31337,
            pool: Address::from([6; 20]),
            expiry: 7,
            owner_key: SpendKey::random().public_key(),
            nk: Fr::from(8u64),
            signature: [0; 64],
            input: InputWitness::padding(Fr::from(9u64)),
            attestation,
        }))
    }

    #[test]
    fn prove_then_verify_accepts() {
        let prover = MockProver;
        let request = withdraw_request();
        let proof = prover.prove(&request).expect("mock prove never fails");
        let ok = prover
            .verify(request.circuit(), &proof)
            .expect("mock verify runs");
        assert!(ok);
    }

    #[test]
    fn verify_rejects_a_proof_with_tampered_public_inputs() {
        let prover = MockProver;
        let request = withdraw_request();
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
        let request = withdraw_request();
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

    /// The proof `BindingMockVerifier.t.sol` pins: the withdraw circuit over the
    /// public inputs 1 to 10.
    #[test]
    fn a_mock_proof_matches_the_binding_verifier() {
        let inputs: Vec<Bytes32> =
            (1..=10u64).map(|i| Bytes32::from(Fr::from(i))).collect();
        assert_eq!(
            hex::encode(mock_proof_bytes(Circuit::Withdraw, &inputs)),
            "26e0c7ad3a714fd2d4f1a046f2ac4ca65a023f715edf4090c0cf2501c6f0c3e5"
        );
    }
}

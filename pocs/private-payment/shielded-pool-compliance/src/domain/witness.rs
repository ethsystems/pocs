//! The private witness records the four circuits need, one type per circuit. Field
//! names and grouping mirror each `circuits/*/src/main.nr`'s parameter list; the
//! `BbProver` adapter is what flattens these into `Prover.toml`.
//!
//! Concrete to `policy::reference::ReferencePolicy`, not generic over `Policy`: this
//! deployment has exactly one policy (`policy::K = 1`), and `ports::prover::ProofRequest`
//! is a plain enum over these four types, which a generic parameter would infect.

use crate::{
    policy::{
        Policy,
        reference::ReferencePolicy,
    },
    ports::merkle::MerklePath,
    types::{
        Address,
        Bytes32,
        Epoch,
        Seq,
    },
};

use super::{
    attestation::Generation,
    keys::{
        OwnerPubkey,
        SpendingKey,
    },
    public_inputs::{
        deposit,
        gated_withdraw,
        transfer,
        ungated_withdraw,
    },
};

/// The concrete policy state shape for this deployment's single reference policy.
pub type PolicyState = <ReferencePolicy as Policy>::State;

/// Mirrors `spc_lib::attestation::AttestationWitness`. `attestation_proof`'s length is
/// the circuit's `att_proof_length`; `revocation_proof` is always the full
/// `ATTESTER_TREE_DEPTH`, since the revocation tree never promotes.
#[derive(Debug, Clone)]
pub struct AttestationWitness {
    pub attester: Address,
    pub generation: Generation,
    pub issued_at: u64,
    pub expires_at: u64,
    pub attestation_proof: MerklePath,
    pub revoked_at: u64,
    pub revocation_proof: MerklePath,
}

/// Mirrors `circuits/lib/src/compliance.nr::ComplianceInputs`'s fields that are not
/// already one of the circuit's own public inputs: the predecessor compliance note's
/// opening and its Merkle inclusion proof (empty for the `seq == 0` base case).
#[derive(Debug, Clone)]
pub struct ComplianceWitness {
    pub seq: Seq,
    pub epoch_in: Epoch,
    pub prev: PolicyState,
    pub flags_in: u64,
    pub cp_in: [Bytes32; 2],
    pub amt_in: [u64; 2],
    pub exit_in: Bytes32,
    pub salt_in: Bytes32,
    pub salt_out: Bytes32,
    pub cn_proof: MerklePath,
}

/// Mirrors `circuits/deposit/src/main.nr::main`.
#[derive(Debug, Clone)]
pub struct DepositWitness {
    pub public: deposit::Fields,
    pub spending_key: SpendingKey,
    pub note_salt: Bytes32,
    pub attestation: AttestationWitness,
    pub compliance: ComplianceWitness,
}

impl DepositWitness {
    pub fn public_inputs(&self) -> Vec<Bytes32> {
        self.public.ordered().to_vec()
    }
}

/// One spent or padded input note. A zero-value padding note (`amount == 0`) carries
/// an empty `proof`, since a zero note is never inserted into the tree (SPEC "TxFacts
/// construction").
#[derive(Debug, Clone)]
pub struct InputNoteWitness {
    pub amount: u64,
    pub salt: Bytes32,
    pub proof: MerklePath,
}

/// One minted output note.
#[derive(Debug, Clone, Copy)]
pub struct OutputNoteWitness {
    pub amount: u64,
    pub owner: OwnerPubkey,
    pub salt: Bytes32,
}

/// Mirrors `circuits/transfer/src/main.nr::main`. `token` is one field, not four: the
/// circuit asserts all of `token_in_0/token_in_1/token_out_0/token_out_1` equal, so a
/// single field makes a mismatched-token witness unconstructible instead of a runtime
/// check the builder must remember to make.
#[derive(Debug, Clone)]
pub struct TransferWitness {
    pub public: transfer::Fields,
    pub spending_key: SpendingKey,
    pub token: Address,
    pub inputs: [InputNoteWitness; 2],
    pub outputs: [OutputNoteWitness; 2],
    pub subject_attestation: AttestationWitness,
    pub output_attestations: [AttestationWitness; 2],
    pub compliance: ComplianceWitness,
}

impl TransferWitness {
    pub fn public_inputs(&self) -> Vec<Bytes32> {
        self.public.ordered().to_vec()
    }
}

/// Mirrors `circuits/withdraw/src/main.nr::main` (the gated path).
#[derive(Debug, Clone)]
pub struct WithdrawWitness {
    pub public: gated_withdraw::Fields,
    pub spending_key: SpendingKey,
    pub note_salt: Bytes32,
    pub note_proof: MerklePath,
    pub attestation: AttestationWitness,
    pub compliance: ComplianceWitness,
}

impl WithdrawWitness {
    pub fn public_inputs(&self) -> Vec<Bytes32> {
        self.public.ordered().to_vec()
    }
}

/// Mirrors `circuits/withdraw_ungated/src/main.nr::main`, the parent's circuit routed
/// through `ShieldedPool::withdrawBlocked` once a subject's attestation lapses. No
/// attestation or compliance witness: this path stays provable specifically because it
/// carries neither.
#[derive(Debug, Clone)]
pub struct BlockedWithdrawWitness {
    pub public: ungated_withdraw::Fields,
    pub spending_key: SpendingKey,
    pub note_salt: Bytes32,
    pub note_proof: MerklePath,
}

impl BlockedWithdrawWitness {
    pub fn public_inputs(&self) -> Vec<Bytes32> {
        self.public.ordered().to_vec()
    }
}

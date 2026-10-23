//! The proving port. Callers run `prove` inside `tokio::task::spawn_blocking`,
//! since proving blocks a thread for seconds.

use crate::{
    domain::witness::{
        DepositWitness,
        TransferWitness,
        WithdrawWitness,
    },
    error::ProverError,
    types::Bytes32,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Circuit {
    Deposit,
    Transfer,
    Withdraw,
}

#[derive(Debug)]
pub enum ProofRequest {
    Deposit(Box<DepositWitness>),
    Transfer(Box<TransferWitness>),
    Withdraw(Box<WithdrawWitness>),
}

impl ProofRequest {
    pub fn circuit(&self) -> Circuit {
        match self {
            Self::Deposit(_) => Circuit::Deposit,
            Self::Transfer(_) => Circuit::Transfer,
            Self::Withdraw(_) => Circuit::Withdraw,
        }
    }

    pub fn public_inputs(&self) -> Vec<Bytes32> {
        match self {
            Self::Deposit(w) => w.public_inputs(),
            Self::Transfer(w) => w.public_inputs(),
            Self::Withdraw(w) => w.public_inputs(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CircuitProof {
    pub proof: Vec<u8>,
    pub public_inputs: Vec<Bytes32>,
}

pub trait Prover: Send + Sync {
    fn prove(&self, request: &ProofRequest) -> Result<CircuitProof, ProverError>;
    /// `Ok(false)` means the proof was checked and rejected; `Err` means the
    /// backend itself failed.
    fn verify(&self, circuit: Circuit, proof: &CircuitProof)
    -> Result<bool, ProverError>;
}

//! The proving port. Deliberately not `Provable` (a witness does not know how to
//! prove itself; proving needs the Barretenberg backend and a `nargo execute`
//! subprocess, which inverts the port boundary). `Prover: Send + Sync` is earned by
//! exactly one thing: callers run `prove` inside a `tokio::task::spawn_blocking`
//! closure, since proving blocks a thread for seconds and must not run on an async
//! runtime worker; the closure must be `Send`.

use crate::{
    domain::witness::{
        BlockedWithdrawWitness,
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
    WithdrawBlocked,
}

/// Every variant boxed: `TransferWitness` alone is over a kilobyte (three
/// `AttestationWitness`es, each carrying two `MerklePath`s), and an unboxed enum pays
/// its largest variant's size for every variant, including the much smaller
/// `WithdrawBlocked`. Boxing uniformly keeps the enum one pointer wide regardless of
/// which witness grows next.
#[derive(Debug)]
pub enum ProofRequest {
    Deposit(Box<DepositWitness>),
    Transfer(Box<TransferWitness>),
    Withdraw(Box<WithdrawWitness>),
    WithdrawBlocked(Box<BlockedWithdrawWitness>),
}

impl ProofRequest {
    pub fn circuit(&self) -> Circuit {
        match self {
            Self::Deposit(_) => Circuit::Deposit,
            Self::Transfer(_) => Circuit::Transfer,
            Self::Withdraw(_) => Circuit::Withdraw,
            Self::WithdrawBlocked(_) => Circuit::WithdrawBlocked,
        }
    }

    pub fn public_inputs(&self) -> Vec<Bytes32> {
        match self {
            Self::Deposit(w) => w.public_inputs(),
            Self::Transfer(w) => w.public_inputs(),
            Self::Withdraw(w) => w.public_inputs(),
            Self::WithdrawBlocked(w) => w.public_inputs(),
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

    /// `Ok(false)` means the proof was checked and rejected; `Err` means the backend
    /// itself failed (subprocess error, malformed input) and answers neither way.
    /// Callers must not conflate the two: retrying on `Err` may succeed, retrying on
    /// `Ok(false)` never will.
    fn verify(&self, circuit: Circuit, proof: &CircuitProof)
    -> Result<bool, ProverError>;
}

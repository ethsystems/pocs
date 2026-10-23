//! Proving on the owner's side, and reading and submitting on an account's.
//! The owner of an operation proves it and hands over only a `Submission`, so
//! a relayer never sees the witness. Proving runs on a blocking thread, since
//! it holds a CPU for seconds.

use std::sync::Arc;

use alloy::{
    providers::DynProvider,
    rpc::types::TransactionReceipt,
};

use crate::{
    chain::{
        self,
        ChainView,
        Deployment,
        PoolEnv,
        Submission,
    },
    domain::witness::{
        DepositWitness,
        WithdrawWitness,
    },
    error::{
        ChainError,
        ClientError,
    },
    ports::prover::{
        CircuitProof,
        ProofRequest,
        Prover,
    },
    wallet::BuiltTransfer,
};

/// Reads the chain and submits proved operations for one account: a relayer,
/// or an owner submitting its own.
#[derive(Clone)]
pub struct Client {
    pub provider: DynProvider,
    pub deployment: Deployment,
}

impl Client {
    pub async fn view(&self) -> Result<ChainView, ChainError> {
        ChainView::sync(&self.provider, &self.deployment).await
    }

    pub async fn env(&self) -> Result<PoolEnv, ChainError> {
        PoolEnv::fetch(&self.provider, &self.deployment).await
    }

    pub async fn submit(
        &self,
        submission: &Submission,
    ) -> Result<TransactionReceipt, ChainError> {
        chain::submit(&self.provider, &self.deployment, submission).await
    }
}

async fn prove(
    prover: &Arc<dyn Prover>,
    request: ProofRequest,
) -> Result<CircuitProof, ClientError> {
    let prover = Arc::clone(prover);
    Ok(tokio::task::spawn_blocking(move || prover.prove(&request)).await??)
}

pub async fn prove_deposit(
    prover: &Arc<dyn Prover>,
    witness: &DepositWitness,
    payload: &[u8],
) -> Result<Submission, ClientError> {
    let proof = prove(prover, ProofRequest::Deposit(Box::new(witness.clone()))).await?;
    Ok(Submission::deposit(witness, &proof, payload))
}

pub async fn prove_transfer(
    prover: &Arc<dyn Prover>,
    built: &BuiltTransfer,
) -> Result<Submission, ClientError> {
    let proof = prove(
        prover,
        ProofRequest::Transfer(Box::new(built.witness.clone())),
    )
    .await?;
    Ok(Submission::transfer(&built.witness, &proof, &built.payload))
}

pub async fn prove_withdraw(
    prover: &Arc<dyn Prover>,
    witness: &WithdrawWitness,
) -> Result<Submission, ClientError> {
    let proof = prove(prover, ProofRequest::Withdraw(Box::new(witness.clone()))).await?;
    Ok(Submission::withdraw(witness, &proof))
}

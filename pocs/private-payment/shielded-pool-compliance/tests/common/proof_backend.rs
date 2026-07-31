//! Runtime prover selection. `VCCM_USE_MOCK_PROOFS` picks `MockProver` over `BbProver`,
//! and `AnvilHarness` passes the same variable to the deploy script as
//! `USE_MOCK_VERIFIER`, so the in-process prover and the deployed verifier can never
//! disagree. A cargo feature could not do this: it is fixed at compile time and the same
//! test binary has to run both ways.

use std::{
    path::PathBuf,
    sync::OnceLock,
};

#[cfg(feature = "test-mocks")]
use shielded_pool_compliance::adapters::mock_prover::MockProver;
use shielded_pool_compliance::{
    adapters::bb_prover::BbProver,
    error::ProverError,
    ports::prover::{
        Circuit,
        CircuitProof,
        ProofRequest,
        Prover,
    },
};

pub fn use_mock_proofs() -> bool {
    matches!(
        std::env::var("VCCM_USE_MOCK_PROOFS").as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE")
    )
}

pub enum TestProver {
    #[cfg(feature = "test-mocks")]
    Mock(MockProver),
    Real(Box<BbProver>),
}

#[cfg(feature = "test-mocks")]
fn mock_prover() -> TestProver {
    TestProver::Mock(MockProver)
}

#[cfg(not(feature = "test-mocks"))]
fn mock_prover() -> TestProver {
    panic!(
        "VCCM_USE_MOCK_PROOFS is set but this binary was built without \
         --features test-mocks, so adapters::mock_prover is not compiled in"
    )
}

fn tool_path(var: &str, home_relative: &str) -> PathBuf {
    match std::env::var(var) {
        Ok(path) => PathBuf::from(path),
        Err(_) => PathBuf::from(std::env::var("HOME").expect("HOME")).join(home_relative),
    }
}

fn real_prover() -> TestProver {
    let prover = BbProver::new(
        &tool_path("BB_PATH", ".bb/bb"),
        tool_path("NARGO_PATH", ".nargo/bin/nargo"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")),
    )
    .expect("start bb");
    TestProver::Real(Box::new(prover))
}

/// One prover per test process. `nargo execute` writes the workspace-shared
/// `circuits/target/witness.gz` whichever circuit it runs, and `BbProver` serializes
/// that behind its own mutex, so two independent instances in one process would race on
/// that file. Sharing one also shares the verification-key cache.
pub fn prover() -> &'static TestProver {
    static PROVER: OnceLock<TestProver> = OnceLock::new();
    PROVER.get_or_init(|| {
        if use_mock_proofs() {
            mock_prover()
        } else {
            real_prover()
        }
    })
}

impl Prover for TestProver {
    fn prove(&self, request: &ProofRequest) -> Result<CircuitProof, ProverError> {
        match self {
            #[cfg(feature = "test-mocks")]
            Self::Mock(p) => p.prove(request),
            Self::Real(p) => p.prove(request),
        }
    }

    fn verify(
        &self,
        circuit: Circuit,
        proof: &CircuitProof,
    ) -> Result<bool, ProverError> {
        match self {
            #[cfg(feature = "test-mocks")]
            Self::Mock(p) => p.verify(circuit, proof),
            Self::Real(p) => p.verify(circuit, proof),
        }
    }
}

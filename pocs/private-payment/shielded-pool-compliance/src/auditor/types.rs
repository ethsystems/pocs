use crate::{
    domain::witness::PolicyState,
    types::{
        Bytes32,
        Flags,
        Seq,
    },
};

/// One position in a subject's decrypted compliance chain: the facts the pool
/// committed at that `seq`, the resulting policy state, and the recomputed leaf value
/// (`commitment`) that must appear in the on-chain commitment tree if the ciphertext is
/// genuine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditedTx {
    pub seq: Seq,
    pub counterparty: [Bytes32; 2],
    pub amount_out: [u64; 2],
    pub exit: Bytes32,
    pub state: PolicyState,
    pub flags: Flags,
    pub commitment: Bytes32,
}

/// `Auditor::reconstruct_chain`'s result: the verified chain plus the two counted,
/// legitimate skip categories (SPEC "Audit Channel"). Neither count is an error: an
/// element of another kind is ordinary payload traffic, and a stale `committeeVersion`
/// is the expected shape of a ciphertext from before a committee rotation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChainReconstruction {
    pub txs: Vec<AuditedTx>,
    pub skipped_other_kind: usize,
    pub skipped_stale_version: usize,
}

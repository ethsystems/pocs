//! Demo traces in `crates/trace-recorder/SPEC.md` form. A scenario brackets itself
//! with `Stage::begin_trace` and `Tracer::finish`; the harness helpers record each step
//! in between. Pool calls bypass `ChainWriter`, so recording sits at those helpers
//! rather than at a port. Every run records and checks its trace; only
//! `--features trace` writes it.

use std::collections::BTreeMap;

use alloy::{
    consensus::Transaction as _,
    primitives::{
        Address as AlloyAddress,
        B256,
    },
    providers::{
        DynProvider,
        Provider,
    },
    rpc::types::TransactionReceipt,
    sol_types::SolError,
};
use serde_json::json;
use shielded_pool_compliance::{
    NO_COUNTERPARTY,
    NO_EXIT,
    auditor::ChainReconstruction,
    domain::{
        attestation::Cohort,
        keys::{
            AuditViewingKey,
            ComplianceViewingKey,
            OwnerPubkey,
            SpendingKey,
            ViewingKey,
        },
        payload::{
            Payload,
            PayloadElement,
            PayloadKind,
        },
        public_inputs::{
            deposit as deposit_idx,
            gated_withdraw as withdraw_idx,
            transfer as transfer_idx,
            ungated_withdraw as ungated_idx,
        },
    },
    ports::prover::CircuitProof,
    types::{
        Bytes32,
        Epoch,
    },
    wallet::{
        CompliancePlaintext,
        ValueNotePlaintext,
    },
};
use tokio::sync::Mutex;
use trace_recorder::{
    ActionDef,
    Artifact,
    Asset,
    Balance,
    BalanceKind,
    Cell,
    Chain,
    CircuitDef,
    Codec,
    Event,
    Field,
    FieldType,
    Header,
    Hex,
    Kem,
    Key,
    LayoutField,
    Level,
    MapRefs,
    Note,
    NoteDomain,
    NoteLayout,
    Observer,
    ObserverRole,
    Persona,
    Proof,
    Recorder,
    Sealed,
    State,
    Step,
    Str,
    Tx,
    TxOutcome,
};

use super::{
    BLOCKED_FUNDS,
    DEPLOYER,
    IAttestationRegistry,
    IMockERC20,
    IShieldedPool,
    PAYEE,
    ProvedBlockedWithdraw,
    ProvedDeposit,
    ProvedTransfer,
    ProvedWithdraw,
    SANCTIONED,
    Stage,
    b256,
    project_root,
    proof_backend::use_mock_proofs,
};

/// A shielded-wallet persona with fixed keys, so the header prints the keys that open
/// its notes. Spending-key bytes stay below the BN254 modulus (`0x3064...`).
pub struct ShieldedPersona {
    pub id: &'static str,
    pub label: &'static str,
    spending: [u8; 32],
    viewing: [u8; 32],
    compliance: [u8; 32],
}

pub const ALICE: ShieldedPersona = ShieldedPersona {
    id: "alice",
    label: "Alice",
    spending: [0x11; 32],
    viewing: [0x12; 32],
    compliance: [0x13; 32],
};

pub const BOB: ShieldedPersona = ShieldedPersona {
    id: "bob",
    label: "Bob",
    spending: [0x21; 32],
    viewing: [0x22; 32],
    compliance: [0x23; 32],
};

const SHIELDED: [&ShieldedPersona; 2] = [&ALICE, &BOB];

impl ShieldedPersona {
    pub fn spending_key(&self) -> SpendingKey {
        SpendingKey::from_canonical_bytes(self.spending).expect("canonical persona key")
    }

    pub fn viewing_key(&self) -> ViewingKey {
        ViewingKey::from_bytes(&self.viewing).expect("valid k256 scalar")
    }

    pub fn compliance_viewing_key(&self) -> ComplianceViewingKey {
        ComplianceViewingKey::from_bytes(&self.compliance).expect("valid k256 scalar")
    }
}

static AUDIT_KEY: [u8; 32] = [0x31; 32];

/// The committee key every `Stage` uses, traced or not.
pub fn audit_key() -> AuditViewingKey {
    AuditViewingKey::from_bytes(&AUDIT_KEY).expect("valid k256 scalar")
}

/// An anvil account playing a persona.
struct Account {
    id: &'static str,
    label: &'static str,
    role: &'static str,
    index: usize,
}

const ACCOUNTS: [Account; 4] = [
    Account {
        id: "operator",
        label: "Operator",
        role: "deployer, attester, blocklist curator, and relayer of every pool call in this run",
        index: DEPLOYER,
    },
    Account {
        id: "blocked_funds",
        label: "Blocked-funds account",
        role: "receives exits through the blocked-funds path",
        index: BLOCKED_FUNDS,
    },
    Account {
        id: "payee",
        label: "Payee",
        role: "withdrawal destination",
        index: PAYEE,
    },
    Account {
        id: "sanctioned",
        label: "Blocked destination",
        role: "an address on the pool's blocklist",
        index: SANCTIONED,
    },
];

const AUDITOR: &str = "auditor";
const AUDITOR_LABEL: &str = "Audit committee";
const OBSERVERS: [&str; 3] = ["public", "counterparty", AUDITOR];
/// Key ids, scoped to the persona that holds them.
const VIEWING: &str = "viewing";
const COMPLIANCE: &str = "compliance";
const AUDIT: &str = "audit";
const DOMAIN: &str = "spc-ecies-v1";
const DOMAIN_TAG: &str = "shielded-pool-compliance-ecies-v1";
const VALUE_NOTE: &str = "value-note";
const COMPLIANCE_NOTE: &str = "compliance-note";
const ASSET: &str = "musdc";
const CHAIN_ID: u64 = 31337;

const FIELDS: [(&str, &str); 6] = [
    ("sender", "Sender"),
    ("recipient", "Recipient"),
    ("amount", "Amount"),
    ("asset", "Asset"),
    ("linkage", "Linkage"),
    ("policy_state", "Policy state"),
];

const ONE_TOKEN: &str = "The pool accepts one token, fixed at deployment.";
const POOL_LINKAGE: &str = "The pool holds only this run's notes, so a chain reader can tie this call to the run's other pool calls by elimination, or by public amounts that add up.";
const COHORT_SENDER: &str =
    "The proof hides which attested key spent; the anonymity set is the attested cohort.";
const AUDIT_SENDER: &str = "The 0x03 compliance note names the subject's owner_pubkey.";
const AUDIT_POLICY: &str = "The 0x03 note carries the running total and the flags.";
const SEALED_POLICY: &str = "The compliance note is a commitment and two ciphertexts.";

type Row = BTreeMap<Str<'static>, Cell<'static>>;
type Observations = BTreeMap<Str<'static>, Row>;
/// One `(level, why)` per field, in `FIELDS` order.
type Cells = [(Level, &'static str); 6];

#[derive(Default)]
pub struct Tracer(Mutex<Option<Session>>);

struct Session {
    recorder: Recorder<'static>,
    scenario: &'static str,
    provider: DynProvider,
    pool: AlloyAddress,
    token: AlloyAddress,
    accounts: [AlloyAddress; 4],
    owners: [OwnerPubkey; 2],
}

/// A pool entry point the harness called.
pub enum PoolCall<'a> {
    Deposit(&'a ProvedDeposit),
    Transfer(&'a ProvedTransfer, &'a [u8]),
    Withdraw(&'a ProvedWithdraw),
    WithdrawBlocked(&'a ProvedBlockedWithdraw),
    Claim { caller: usize },
    BlockDestination(AlloyAddress),
}

/// The ids a gated operation's observations cite.
struct Cited {
    tx: u32,
    /// `0x01` notes with their recipient.
    value_notes: Vec<(u32, &'static str)>,
    audit_note: u32,
}

impl Stage {
    /// Starts recording this scenario, which `Tracer::finish` checks and, under
    /// `--features trace`, writes to `traces/<test>.jsonl`.
    pub async fn begin_trace(&self, title: &'static str, summary: &'static str) {
        let scenario = env!("CARGO_CRATE_NAME");
        let accounts = ACCOUNTS.map(|a| self.harness.account(a.index));
        let owners = SHIELDED.map(|p| p.spending_key().derive_owner_pubkey());
        *self.harness.trace.0.lock().await = Some(Session {
            recorder: Recorder::new(header(
                self, scenario, title, summary, &accounts, &owners,
            )),
            scenario,
            provider: self.harness.provider(DEPLOYER),
            pool: self.deployment.pool,
            token: self.deployment.token,
            accounts,
            owners,
        });
    }
}

impl Tracer {
    /// Checks the trace as a consumer would. Under `--features trace` it then writes
    /// it; otherwise it fails if the words differ from the committed trace, which is
    /// then stale. Off the async workers, since it is file I/O.
    pub async fn finish(&self) {
        let Some(session) = self.0.lock().await.take() else {
            return;
        };
        let path = project_root()
            .join("traces")
            .join(format!("{}.jsonl", session.scenario));
        tokio::task::spawn_blocking(move || {
            if !cfg!(feature = "trace") {
                session.recorder.check(open).expect("the trace checks");
                assert_same_words(&session.recorder, &path);
                return;
            }
            assert!(
                !use_mock_proofs(),
                "traces/ takes real proofs only; unset VCCM_USE_MOCK_PROOFS to record"
            );
            session
                .recorder
                .finish(&path, open)
                .expect("the trace checks and writes");
        })
        .await
        .expect("the trace writer does not panic");
    }

    pub async fn onboard(&self, receipt: &TransactionReceipt, cohort: &Cohort) {
        self.record(|s| s.onboard(receipt, cohort)).await;
    }

    pub async fn fund(&self, mint: &TransactionReceipt, approve: &TransactionReceipt) {
        self.record(|s| s.fund(mint, approve)).await;
    }

    /// Records the audit committee decrypting `subject`'s `0x03` notes for `epoch`.
    pub async fn disclose(
        &self,
        subject: &ShieldedPersona,
        epoch: Epoch,
        committee_version: u64,
        reconstruction: &ChainReconstruction,
    ) {
        self.record(|s| s.disclose(subject, epoch, committee_version, reconstruction))
            .await;
    }

    pub async fn pool_call(
        &self,
        call: PoolCall<'_>,
        outcome: &Result<TransactionReceipt, alloy::contract::Error>,
    ) {
        self.record(|s| match outcome {
            Ok(receipt) => s.accepted(&call, receipt),
            Err(error) => s.rejected(&call, error),
        })
        .await;
    }

    /// Holds the lock across the wallet scan's RPCs, which read the recorded notes in
    /// place. A scenario records one step at a time, so nothing waits on it.
    async fn record(&self, step: impl FnOnce(&mut Session) -> Step<'static>) {
        let mut guard = self.0.lock().await;
        let Some(session) = guard.as_mut() else {
            return;
        };
        let mut step = step(session);
        session.calldata(&mut step.artifacts).await;
        step.wallets = session.wallets(&step.artifacts).await;
        session.recorder.push(step);
    }
}

impl Session {
    fn onboard(
        &mut self,
        receipt: &TransactionReceipt,
        cohort: &Cohort,
    ) -> Step<'static> {
        let tx = self.confirmed(receipt, "addAttestations");
        let tx_id = tx.id();
        let members: Vec<&str> = cohort
            .subjects
            .iter()
            .filter_map(|subject| self.shielded_of(*subject))
            .map(|p| p.label)
            .collect();
        let subjects: Vec<_> = cohort
            .subjects
            .iter()
            .map(|subject| {
                json!({
                    "owner_pubkey": subject.as_bytes32().to_string(),
                    "persona": self.shielded_of(*subject).map(|p| p.id),
                })
            })
            .collect();
        let state = Artifact::State(State {
            id: self.recorder.next_id(),
            label: "Attested cohort".into(),
            data: json!({
                "generation": cohort.generation.0,
                "expires_at": cohort.expires_at,
                "subjects": subjects,
            }),
        });
        Step {
            actor: "operator".into(),
            action: "onboard".into(),
            title: format!(
                "Operator attests a cohort of {} keys, {} among them",
                cohort.subjects.len(),
                members.join(" and ")
            )
            .into(),
            roles: BTreeMap::new(),
            artifacts: vec![tx, state],
            observations: same_for_all(
                &[tx_id],
                [
                    (
                        Level::Visible,
                        "addAttestations is sent by the attester in the clear.",
                    ),
                    (
                        Level::Visible,
                        "AttestationAdded lists each subject's owner_pubkey, a pseudonym. Only the Compliance Authority maps it to an identity.",
                    ),
                    (Level::NotApplicable, "Issuing attestations moves no value."),
                    (Level::NotApplicable, "Issuing attestations moves no value."),
                    (
                        Level::NotApplicable,
                        "There is no shielded activity to link.",
                    ),
                    (
                        Level::Visible,
                        "Each attestation's generation and expiry are public.",
                    ),
                ],
            ),
            wallets: BTreeMap::new(),
        }
    }

    fn fund(
        &mut self,
        mint: &TransactionReceipt,
        approve: &TransactionReceipt,
    ) -> Step<'static> {
        let mint = self.confirmed(mint, "mint");
        let approve = self.confirmed(approve, "approve");
        let tx_id = mint.id();
        Step {
            actor: "operator".into(),
            action: "fund".into(),
            title: "Operator mints mUSDC and approves the pool to pull it".into(),
            roles: BTreeMap::new(),
            artifacts: vec![mint, approve],
            observations: same_for_all(
                &[tx_id],
                [
                    (
                        Level::Visible,
                        "Mint and approve are sent from the operator in the clear.",
                    ),
                    (
                        Level::Visible,
                        "The mint names the operator; the approval names the pool.",
                    ),
                    (
                        Level::Visible,
                        "The ERC-20 Transfer and Approval events carry the amount.",
                    ),
                    (Level::Visible, "The token contract is the call target."),
                    (
                        Level::NotApplicable,
                        "There is no shielded activity to link.",
                    ),
                    (
                        Level::NotApplicable,
                        "No policy runs on a plain ERC-20 call.",
                    ),
                ],
            ),
            wallets: BTreeMap::new(),
        }
    }

    fn accepted(
        &mut self,
        call: &PoolCall<'_>,
        receipt: &TransactionReceipt,
    ) -> Step<'static> {
        let (method, actor) = method_and_actor(call);
        let size_flag = receipt
            .inner
            .logs()
            .iter()
            .any(|log| log.log_decode::<IShieldedPool::SizeFlag>().is_ok());
        let tx = self.confirmed(receipt, method);
        let tx_id = tx.id();
        let mut roles = BTreeMap::new();

        let (action, title, artifacts, observations): (_, String, _, _) = match call {
            PoolCall::Deposit(proved) => {
                let proof = self.proof(&proved.proof, "deposit", Some(tx_id));
                let (notes, cited) = self.notes(
                    proved.payload.elements(),
                    tx_id,
                    actor,
                    &[proved.note.owner_pubkey],
                );
                (
                    "deposit",
                    format!("{} deposits", label(actor)),
                    [proof, tx].into_iter().chain(notes).collect(),
                    deposit_cells(&cited, size_flag),
                )
            }
            PoolCall::Transfer(proved, encrypted_notes) => {
                let payload =
                    Payload::decode(encrypted_notes).expect("well-formed payload");
                let owners = proved.outputs.map(|note| note.owner_pubkey);
                let proof = self.proof(&proved.proof, "transfer", Some(tx_id));
                let (notes, cited) =
                    self.notes(payload.elements(), tx_id, actor, &owners);
                let counterparty = owners
                    .iter()
                    .filter_map(|owner| self.shielded_of(*owner))
                    .map(|p| p.id)
                    .find(|id| *id != actor);
                let title = match counterparty {
                    Some(to) => {
                        roles.insert("counterparty".into(), to.into());
                        format!("{} transfers to {}", label(actor), label(to))
                    }
                    None => format!("{} transfers to themselves", label(actor)),
                };
                (
                    "transfer",
                    title,
                    [proof, tx].into_iter().chain(notes).collect(),
                    transfer_cells(&cited, counterparty),
                )
            }
            PoolCall::Withdraw(proved) => {
                let to = self.withdraw_recipient(&proved.proof);
                roles.insert("counterparty".into(), to.into());
                let proof = self.proof(&proved.proof, "withdraw", Some(tx_id));
                let (notes, cited) =
                    self.notes(proved.payload.elements(), tx_id, actor, &[]);
                (
                    "withdraw",
                    format!("{} withdraws to {}", label(actor), label(to)),
                    [proof, tx].into_iter().chain(notes).collect(),
                    withdraw_cells(&cited, size_flag),
                )
            }
            PoolCall::WithdrawBlocked(proved) => {
                let proof = self.proof(&proved.proof, "withdraw_ungated", Some(tx_id));
                (
                    "withdraw-blocked",
                    format!("{} exits through the blocked-funds path", label(actor)),
                    vec![proof, tx],
                    same_for_all(
                        &[tx_id],
                        [
                            (
                                Level::Hidden,
                                "The ungated proof hides which note was spent.",
                            ),
                            (
                                Level::Visible,
                                "The call names the recipient; the pool credits blockedBalance for the blocked-funds account.",
                            ),
                            (
                                Level::Visible,
                                "The WithdrawBlocked event carries the amount.",
                            ),
                            (Level::Visible, ONE_TOKEN),
                            (Level::Inferable, POOL_LINKAGE),
                            (Level::NotApplicable, "This path mints no compliance note."),
                        ],
                    ),
                )
            }
            PoolCall::Claim { .. } => (
                "claim-blocked",
                format!("{} claims blocked funds", label(actor)),
                vec![tx],
                same_for_all(
                    &[tx_id],
                    [
                        (
                            Level::Visible,
                            "claimBlocked is sent by the blocked-funds account in the clear.",
                        ),
                        (
                            Level::Visible,
                            "The token Transfer event names the blocked-funds account.",
                        ),
                        (Level::Visible, "BlockedFundsClaimed carries the amount."),
                        (Level::Visible, ONE_TOKEN),
                        (
                            Level::Visible,
                            "The nullifier in BlockedFundsClaimed matches the earlier WithdrawBlocked event.",
                        ),
                        (Level::NotApplicable, "No policy runs on this path."),
                    ],
                ),
            ),
            PoolCall::BlockDestination(destination) => (
                "block-destination",
                format!(
                    "Operator adds the {} to the blocklist",
                    label(self.account_of(*destination)).to_lowercase()
                ),
                vec![tx],
                same_for_all(
                    &[tx_id],
                    [
                        (
                            Level::Visible,
                            "setBlockedDestination is sent by the curator in the clear.",
                        ),
                        (Level::Visible, "DestinationBlocked names the address."),
                        (Level::NotApplicable, "Blocking moves no value."),
                        (Level::NotApplicable, "Blocking moves no value."),
                        (
                            Level::NotApplicable,
                            "There is no shielded activity to link.",
                        ),
                        (Level::Visible, "The blocklist is public contract state."),
                    ],
                ),
            ),
        };

        Step {
            actor: actor.into(),
            action: action.into(),
            title: title.into(),
            roles,
            artifacts,
            observations,
            wallets: BTreeMap::new(),
        }
    }

    /// The node refused the call while estimating gas, so it was never broadcast: no
    /// hash, no notes, and nothing for any observer to see.
    fn rejected(
        &mut self,
        call: &PoolCall<'_>,
        error: &alloy::contract::Error,
    ) -> Step<'static> {
        let (method, actor) = method_and_actor(call);
        let revert = revert_name(error);
        let from = match call {
            PoolCall::Claim { caller } => self.accounts[*caller],
            _ => self.accounts[DEPLOYER],
        };
        let proof = match call {
            PoolCall::Deposit(p) => Some(self.proof(&p.proof, "deposit", None)),
            PoolCall::Transfer(p, _) => Some(self.proof(&p.proof, "transfer", None)),
            PoolCall::Withdraw(p) => Some(self.proof(&p.proof, "withdraw", None)),
            PoolCall::WithdrawBlocked(p) => {
                Some(self.proof(&p.proof, "withdraw_ungated", None))
            }
            PoolCall::Claim { .. } | PoolCall::BlockDestination(_) => None,
        };
        let to = match call {
            PoolCall::Withdraw(proved) => Some(self.withdraw_recipient(&proved.proof)),
            _ => None,
        };
        let title = match to {
            Some(to) => format!(
                "The pool refuses {}'s {method} to the {}: {revert}",
                label(actor),
                label(to).to_lowercase()
            ),
            None => format!("The pool refuses {}'s {method}: {revert}", label(actor)),
        };
        let tx_id = self.recorder.next_id();
        let tx = Artifact::Tx(Tx {
            id: tx_id,
            chain_id: CHAIN_ID,
            from: owned(from.as_slice()),
            to: owned(self.pool.as_slice()),
            method: method.into(),
            outcome: TxOutcome::Rejected {
                revert: revert.into(),
            },
            events: Vec::new(),
            input: None,
        });
        Step {
            actor: actor.into(),
            action: "reject".into(),
            title: title.into(),
            roles: to
                .map(|to| ("counterparty".into(), to.into()))
                .into_iter()
                .collect(),
            artifacts: proof.into_iter().chain([tx]).collect(),
            observations: same_for_all(
                &[tx_id],
                [(
                    Level::Hidden,
                    "The wallet simulates before it broadcasts, so the refused call never left it; only the RPC node that ran the simulation saw it. A call that reverts on-chain publishes its calldata.",
                ); 6],
            ),
            wallets: BTreeMap::new(),
        }
    }

    fn disclose(
        &mut self,
        subject: &ShieldedPersona,
        epoch: Epoch,
        committee_version: u64,
        reconstruction: &ChainReconstruction,
    ) -> Step<'static> {
        let owner = self.owners[shielded_index(subject.id)];
        let key = audit_key();
        let aad = PayloadKind::ComplianceNoteToCommittee { committee_version }.aad();
        let notes: Vec<u32> = self
            .recorded_notes(&[])
            .filter(|(_, sealed)| *sealed.aad == *aad)
            .filter(|(_, sealed)| {
                let bytes = key
                    .decrypt(&sealed.ciphertext, &sealed.aad)
                    .expect("0x03 notes open under the audit key");
                let plaintext =
                    CompliancePlaintext::decode(&bytes).expect("compliance note");
                plaintext.owner_pubkey == owner && plaintext.epoch == epoch
            })
            .map(|(note, _)| note.id)
            .collect();
        assert!(!notes.is_empty(), "no 0x03 notes for {}", subject.id);

        let txs: Vec<_> = reconstruction
            .txs
            .iter()
            .map(|tx| {
                json!({
                    "seq": tx.seq.0,
                    "counterparty": tx.counterparty.map(|word| self.name_of(word)),
                    "amount_out": tx.amount_out.map(|amount| amount.to_string()),
                    "exit": self.name_of(tx.exit),
                    "running_total": tx.state[0].to_string(),
                    "flags": tx.flags.as_u64(),
                    "commitment": tx.commitment.to_string(),
                })
            })
            .collect();
        let state_id = self.recorder.next_id();
        let state = Artifact::State(State {
            id: state_id,
            label: format!("{}'s reconstructed compliance chain", subject.label).into(),
            data: json!({
                "subject": subject.id,
                "epoch": epoch.0,
                "committee_version": committee_version,
                "txs": txs,
                "skipped_other_kind": reconstruction.skipped_other_kind,
                "skipped_stale_version": reconstruction.skipped_stale_version,
            }),
        });

        let off_chain = [(
            Level::Hidden,
            "Off-chain decryption by the audit committee; nothing is published.",
        ); 6];
        let opened: Vec<u32> = notes.iter().copied().chain([state_id]).collect();
        let auditor = row(
            &opened,
            [
                (
                    Level::KeyGated,
                    "Each 0x03 note names the subject's owner_pubkey.",
                ),
                (
                    Level::KeyGated,
                    "Each note's facts name the counterparties and the exit address.",
                ),
                (
                    Level::KeyGated,
                    "Each note's facts carry every output amount.",
                ),
                (Level::Visible, ONE_TOKEN),
                (
                    Level::KeyGated,
                    "seq orders the subject's transactions within the epoch.",
                ),
                (
                    Level::KeyGated,
                    "Each note carries the running total and the flags.",
                ),
            ],
        );
        Step {
            actor: AUDITOR.into(),
            action: "disclose".into(),
            title: format!(
                "Audit committee reconstructs {}'s epoch from on-chain ciphertexts",
                subject.label
            )
            .into(),
            roles: BTreeMap::new(),
            artifacts: vec![state],
            observations: BTreeMap::from([
                ("public".into(), row(&notes, off_chain)),
                ("counterparty".into(), row(&notes, off_chain)),
                (AUDITOR.into(), auditor),
            ]),
            wallets: BTreeMap::new(),
        }
    }

    fn confirmed(
        &mut self,
        receipt: &TransactionReceipt,
        method: &'static str,
    ) -> Artifact<'static> {
        assert!(receipt.status(), "{method} reverted");
        Artifact::Tx(Tx {
            id: self.recorder.next_id(),
            chain_id: CHAIN_ID,
            from: owned(receipt.from.as_slice()),
            to: owned(receipt.to.expect("a call, not a deployment").as_slice()),
            method: method.into(),
            outcome: TxOutcome::Confirmed {
                hash: owned(receipt.transaction_hash.as_slice()),
                block_number: receipt.block_number.expect("a mined receipt"),
                gas_used: receipt.gas_used,
            },
            events: events(receipt),
            input: None,
        })
    }

    /// Each confirmed transaction's calldata, which a verified proof must sit in.
    async fn calldata(&self, artifacts: &mut [Artifact<'static>]) {
        for artifact in artifacts {
            if let Artifact::Tx(Tx {
                outcome: TxOutcome::Confirmed { hash, .. },
                input,
                ..
            }) = artifact
            {
                let tx = self
                    .provider
                    .get_transaction_by_hash(B256::from_slice(hash))
                    .await
                    .expect("eth_getTransactionByHash")
                    .expect("a mined transaction");
                *input = Some(owned(tx.input()));
            }
        }
    }

    fn proof(
        &mut self,
        proof: &CircuitProof,
        circuit: &'static str,
        verified_by: Option<u32>,
    ) -> Artifact<'static> {
        Artifact::Proof(Proof {
            id: self.recorder.next_id(),
            system: if use_mock_proofs() {
                "mock"
            } else {
                "ultrahonk"
            }
            .into(),
            circuit: circuit.into(),
            public_inputs: proof
                .public_inputs
                .iter()
                .map(|word| owned(word.as_ref()))
                .collect(),
            bytes: owned(&proof.proof),
            precomputed: false,
            verified_by,
        })
    }

    /// One note artifact per payload element, each checked to open under the key the
    /// header names for it. `value_owners` names each `0x01` recipient, in order.
    fn notes(
        &mut self,
        elements: &[PayloadElement],
        tx: u32,
        actor: &'static str,
        value_owners: &[OwnerPubkey],
    ) -> (Vec<Artifact<'static>>, Cited) {
        let mut artifacts = Vec::with_capacity(elements.len());
        let mut value_notes = Vec::new();
        let mut audit_note = None;
        let mut owners = value_owners.iter();
        for (element_index, element) in elements.iter().enumerate() {
            let id = self.recorder.next_id();
            let aad = element.kind.aad();
            let (recipient, key, layout, label, opens) = match element.kind {
                PayloadKind::ValueNote => {
                    let owner = owners.next().expect("one owner per value note");
                    let persona = self
                        .shielded_of(*owner)
                        .expect("value notes go to personas");
                    value_notes.push((id, persona.id));
                    (
                        persona.id,
                        VIEWING,
                        VALUE_NOTE,
                        "Value note (0x01)",
                        persona
                            .viewing_key()
                            .decrypt(&element.ciphertext, &aad)
                            .is_ok(),
                    )
                }
                PayloadKind::ComplianceNoteToOwner => {
                    let persona = SHIELDED[shielded_index(actor)];
                    (
                        persona.id,
                        COMPLIANCE,
                        COMPLIANCE_NOTE,
                        "Compliance note to the owner (0x02)",
                        persona
                            .compliance_viewing_key()
                            .decrypt(&element.ciphertext, &aad)
                            .is_ok(),
                    )
                }
                PayloadKind::ComplianceNoteToCommittee { .. } => {
                    audit_note = Some(id);
                    (
                        AUDITOR,
                        AUDIT,
                        COMPLIANCE_NOTE,
                        "Compliance note to the audit committee (0x03)",
                        audit_key().decrypt(&element.ciphertext, &aad).is_ok(),
                    )
                }
            };
            assert!(
                opens,
                "note {id} does not open under {recipient}'s {key} key"
            );
            artifacts.push(Artifact::Note(Note {
                id,
                label: label.into(),
                recipient: recipient.into(),
                carried_by: tx,
                element: u32::try_from(element_index).expect("payloads are short"),
                sealed: Some(Sealed {
                    domain: DOMAIN.into(),
                    layout: layout.into(),
                    key: key.into(),
                    aad: aad.into(),
                    ciphertext: owned(&element.ciphertext),
                }),
                opened: None,
            }));
        }
        assert!(owners.next().is_none(), "more owners than value notes");
        let cited = Cited {
            tx,
            value_notes,
            audit_note: audit_note.expect("a gated operation carries a 0x03 note"),
        };
        (artifacts, cited)
    }

    /// Every sealed note recorded so far, then those in `current`.
    fn recorded_notes<'s>(
        &'s self,
        current: &'s [Artifact<'static>],
    ) -> impl Iterator<Item = (&'s Note<'static>, &'s Sealed<'static>)> {
        self.recorder
            .steps()
            .iter()
            .flat_map(|step| &step.artifacts)
            .chain(current)
            .filter_map(|artifact| match artifact {
                Artifact::Note(
                    note @ Note {
                        sealed: Some(sealed),
                        ..
                    },
                ) => Some((note, sealed)),
                _ => None,
            })
    }

    /// A shielded persona holds what its wallet finds by scanning: every `0x01` note
    /// addressed to it whose nullifier the pool has not recorded.
    async fn wallets(
        &self,
        current: &[Artifact<'static>],
    ) -> BTreeMap<Str<'static>, Vec<Balance<'static>>> {
        let pool = IShieldedPool::new(self.pool, &self.provider);
        let token = IMockERC20::new(self.token, &self.provider);
        let mut wallets = BTreeMap::new();

        for persona in SHIELDED {
            let viewing_key = persona.viewing_key();
            let spending_key = persona.spending_key();
            let mut amount = 0u128;
            let mut notes = Vec::new();
            let held = self.recorded_notes(current).filter(|(note, sealed)| {
                &*sealed.layout == VALUE_NOTE && &*note.recipient == persona.id
            });
            for (note, sealed) in held {
                let bytes = viewing_key
                    .decrypt(&sealed.ciphertext, &sealed.aad)
                    .expect("a value note opens under its recipient's key");
                let value = ValueNotePlaintext::decode(&bytes)
                    .expect("value note plaintext")
                    .into_note();
                let nullifier = value.nullifier(&spending_key).expect("nullifier");
                if !pool
                    .nullifiers(b256(nullifier))
                    .call()
                    .await
                    .expect("nullifiers")
                {
                    amount += u128::from(value.amount);
                    notes.push(note.id);
                }
            }
            wallets.insert(
                persona.id.into(),
                vec![Balance {
                    asset: ASSET.into(),
                    kind: BalanceKind::Confidential,
                    amount: amount.to_string().into(),
                    notes,
                }],
            );
        }

        for (account, address) in ACCOUNTS.iter().zip(self.accounts) {
            let balance = token.balanceOf(address).call().await.expect("balanceOf");
            wallets.insert(
                account.id.into(),
                vec![Balance {
                    asset: ASSET.into(),
                    kind: BalanceKind::Public,
                    amount: balance.to_string().into(),
                    notes: Vec::new(),
                }],
            );
        }

        wallets.insert(AUDITOR.into(), Vec::new());
        wallets
    }

    fn shielded_of(&self, owner: OwnerPubkey) -> Option<&'static ShieldedPersona> {
        self.owners
            .iter()
            .position(|o| *o == owner)
            .map(|i| SHIELDED[i])
    }

    fn account_of(&self, address: AlloyAddress) -> &'static str {
        let i = self
            .accounts
            .iter()
            .position(|a| *a == address)
            .unwrap_or_else(|| panic!("{address} is not a persona"));
        ACCOUNTS[i].id
    }

    fn withdraw_recipient(&self, proof: &CircuitProof) -> &'static str {
        let word = proof.public_inputs[withdraw_idx::RECIPIENT];
        let raw = word.as_ref();
        assert!(
            raw[..12].iter().all(|b| *b == 0),
            "recipient is not an address: {word}"
        );
        self.account_of(AlloyAddress::from_slice(&raw[12..]))
    }

    /// A decrypted compliance-note word as a persona id (an owner_pubkey, or an address
    /// as a field element), a sentinel's name, or hex.
    fn name_of(&self, word: Bytes32) -> Str<'static> {
        if let Some(persona) = self.shielded_of(OwnerPubkey::from_bytes32(word)) {
            return persona.id.into();
        }
        if word == Bytes32::from(*NO_COUNTERPARTY) {
            return "no counterparty".into();
        }
        if word == Bytes32::from(*NO_EXIT) {
            return "no exit".into();
        }
        let raw = word.as_ref();
        if raw[..12].iter().all(|b| *b == 0) {
            let address = AlloyAddress::from_slice(&raw[12..]);
            if let Some(i) = self.accounts.iter().position(|a| *a == address) {
                return ACCOUNTS[i].id.into();
            }
        }
        word.to_string().into()
    }
}

/// Bytes the trace must own, because their source does not outlive the recorder.
fn owned(bytes: &[u8]) -> Hex<'static> {
    bytes.to_vec().into()
}

/// Opens a sealed note for the checks of SPEC Section 4.3. Every key in this PoC is
/// a k256 key under the one domain, and all three key types decrypt alike.
pub fn open(
    domain: &NoteDomain<'_>,
    key: &Key<'_>,
    sealed: &Sealed<'_>,
) -> Option<Vec<u8>> {
    if &*domain.tag != DOMAIN_TAG {
        return None;
    }
    ViewingKey::from_bytes(&key.secret)
        .ok()?
        .decrypt(&sealed.ciphertext, &sealed.aad)
        .ok()
}

/// The words a re-record would change: titles, the summary, the simplifications and
/// every cell. The data around them changes on every run.
fn words(header: &Header<'_>, steps: &[Step<'_>]) -> Vec<String> {
    let mut words = vec![header.title.to_string(), header.summary.to_string()];
    words.extend(header.simplifications.iter().map(ToString::to_string));
    for step in steps {
        words.push(step.title.to_string());
        for (observer, row) in &step.observations {
            for (field, cell) in row {
                words.push(format!("{observer}.{field}: {:?} {}", cell.level, cell.why));
            }
        }
    }
    words
}

/// Fails when `tests/common/trace.rs` no longer says what the committed trace says.
fn assert_same_words(recorder: &Recorder<'_>, path: &std::path::Path) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    let committed = trace_recorder::parse(&text).expect("the committed trace parses");
    assert_eq!(
        words(recorder.header(), recorder.steps()),
        words(&committed.header, &committed.steps),
        "{} is stale: re-record it with --features trace",
        path.display()
    );
}

fn cell(level: Level, why: &'static str, evidence: &[u32]) -> Cell<'static> {
    Cell {
        level,
        why: why.into(),
        evidence: match level {
            Level::NotApplicable => Vec::new(),
            _ => evidence.to_vec(),
        },
    }
}

/// One cell per field, each citing `evidence`.
fn row(evidence: &[u32], cells: Cells) -> Row {
    FIELDS
        .iter()
        .zip(cells)
        .map(|((field, _), (level, why))| ((*field).into(), cell(level, why, evidence)))
        .collect()
}

/// Every observer learns the same: nothing beyond the chain.
fn same_for_all(evidence: &[u32], cells: Cells) -> Observations {
    OBSERVERS
        .into_iter()
        .map(|observer| (observer.into(), row(evidence, cells)))
        .collect()
}

/// The chain's view for every observer, with `audited` fields key-gated for the
/// auditor through the `0x03` note.
fn with_auditor(
    cited: &Cited,
    cells: Cells,
    audited: &[(&'static str, &'static str)],
) -> Observations {
    let mut observations = same_for_all(&[cited.tx], cells);
    let auditor = observations
        .get_mut(AUDITOR)
        .expect("every observer has a row");
    for (field, why) in audited {
        auditor.insert(
            (*field).into(),
            cell(Level::KeyGated, why, &[cited.audit_note]),
        );
    }
    observations
}

/// `SizeFlag` publishes that an amount crossed `singleTxThreshold`, a sliver of policy
/// state; without it the compliance note shows nothing.
fn policy_cell(size_flag: bool, flagged: &'static str) -> (Level, &'static str) {
    if size_flag {
        (Level::Inferable, flagged)
    } else {
        (Level::Hidden, SEALED_POLICY)
    }
}

fn deposit_cells(cited: &Cited, size_flag: bool) -> Observations {
    with_auditor(
        cited,
        [
            (
                Level::Visible,
                "The deposit is sent from the operator, and the pool pulls the tokens from it.",
            ),
            (
                Level::Hidden,
                "The new note's owner sits inside a Poseidon commitment.",
            ),
            (Level::Visible, "The Deposit event carries the amount."),
            (Level::Visible, ONE_TOKEN),
            (Level::Inferable, POOL_LINKAGE),
            policy_cell(
                size_flag,
                "A SizeFlag event says this deposit crossed singleTxThreshold.",
            ),
        ],
        &[
            ("sender", AUDIT_SENDER),
            (
                "recipient",
                "The minted note belongs to the subject the 0x03 compliance note names.",
            ),
            (
                "linkage",
                "The 0x03 note's epoch and seq place this deposit in the subject's chain.",
            ),
            ("policy_state", AUDIT_POLICY),
        ],
    )
}

fn transfer_cells(cited: &Cited, counterparty: Option<&str>) -> Observations {
    let mut observations = with_auditor(
        cited,
        [
            (Level::Hidden, COHORT_SENDER),
            (
                Level::Hidden,
                "Output owners sit inside Poseidon commitments.",
            ),
            (
                Level::Hidden,
                "Amounts sit inside commitments and ciphertexts.",
            ),
            (Level::Visible, ONE_TOKEN),
            (Level::Inferable, POOL_LINKAGE),
            (Level::Hidden, SEALED_POLICY),
        ],
        &[
            ("sender", AUDIT_SENDER),
            (
                "recipient",
                "The 0x03 note's facts name both output owners.",
            ),
            ("amount", "The 0x03 note's facts carry each output amount."),
            (
                "linkage",
                "The 0x03 note's epoch and seq place this transfer in the subject's chain.",
            ),
            ("policy_state", AUDIT_POLICY),
        ],
    );
    if let Some(persona) = counterparty {
        let notes: Vec<u32> = cited
            .value_notes
            .iter()
            .filter(|(_, recipient)| *recipient == persona)
            .map(|(id, _)| *id)
            .collect();
        let row = observations
            .get_mut("counterparty")
            .expect("every observer has a row");
        row.extend([
            (
                "sender".into(),
                cell(
                    Level::Hidden,
                    "The value note carries token, amount, owner and salt, but not the sender.",
                    &notes,
                ),
            ),
            (
                "recipient".into(),
                cell(
                    Level::KeyGated,
                    "The counterparty's viewing key opens the 0x01 note addressed to it.",
                    &notes,
                ),
            ),
            (
                "amount".into(),
                cell(Level::KeyGated, "The opened 0x01 note carries the amount.", &notes),
            ),
            (
                "policy_state".into(),
                cell(
                    Level::Hidden,
                    "The compliance notes go to the sender's compliance key and the audit committee.",
                    &[cited.tx],
                ),
            ),
        ]);
    }
    observations
}

fn withdraw_cells(cited: &Cited, size_flag: bool) -> Observations {
    with_auditor(
        cited,
        [
            (Level::Hidden, COHORT_SENDER),
            (
                Level::Visible,
                "The Withdraw event names the destination address.",
            ),
            (Level::Visible, "The Withdraw event carries the amount."),
            (Level::Visible, ONE_TOKEN),
            (Level::Inferable, POOL_LINKAGE),
            policy_cell(
                size_flag,
                "A SizeFlag event says this withdrawal crossed singleTxThreshold.",
            ),
        ],
        &[
            ("sender", AUDIT_SENDER),
            (
                "linkage",
                "The 0x03 note's epoch and seq place this withdrawal in the subject's chain.",
            ),
            ("policy_state", AUDIT_POLICY),
        ],
    )
}

fn method_and_actor(call: &PoolCall<'_>) -> (&'static str, &'static str) {
    match call {
        PoolCall::Deposit(p) => ("deposit", p.actor),
        PoolCall::Transfer(p, _) => ("transfer", p.actor),
        PoolCall::Withdraw(p) => ("withdraw", p.actor),
        PoolCall::WithdrawBlocked(p) => ("withdrawBlocked", p.actor),
        PoolCall::Claim { caller } => (
            "claimBlocked",
            ACCOUNTS
                .iter()
                .find(|a| a.index == *caller)
                .expect("caller is a persona")
                .id,
        ),
        PoolCall::BlockDestination(_) => ("setBlockedDestination", "operator"),
    }
}

fn revert_name(error: &alloy::contract::Error) -> String {
    use IShieldedPool::IShieldedPoolErrors as E;
    let signature = match error.as_decoded_interface_error::<E>() {
        Some(E::BlockedDestination(_)) => IShieldedPool::BlockedDestination::SIGNATURE,
        Some(E::WrongEpoch(_)) => IShieldedPool::WrongEpoch::SIGNATURE,
        Some(E::UnknownRoot(_)) => IShieldedPool::UnknownRoot::SIGNATURE,
        Some(E::NullifierSpent(_)) => IShieldedPool::NullifierSpent::SIGNATURE,
        Some(E::NotBlockedFundsAccount(_)) => {
            IShieldedPool::NotBlockedFundsAccount::SIGNATURE
        }
        Some(E::InvalidProof(_)) => IShieldedPool::InvalidProof::SIGNATURE,
        Some(E::PayloadMismatch(_)) => IShieldedPool::PayloadMismatch::SIGNATURE,
        None => return error.to_string(),
    };
    signature.into()
}

/// The receipt's logs, decoded for the events a demo shows. `encryptedNotes` is left
/// out: the note artifacts carry it element by element.
fn events(receipt: &TransactionReceipt) -> Vec<Event<'static>> {
    let b = |v: B256| Hex::from(v.as_slice()).to_string();
    let a = |v: AlloyAddress| Hex::from(v.as_slice()).to_string();
    receipt
        .inner
        .logs()
        .iter()
        .filter_map(|log| {
            let (name, args): (&'static str, Vec<(&'static str, String)>) = if let Ok(e) =
                log.log_decode::<IShieldedPool::Deposit>()
            {
                let e = e.inner.data;
                (
                    "Deposit",
                    vec![
                        ("commitment", b(e.commitment)),
                        ("amount", e.amount.to_string()),
                        ("velocityNullifier", b(e.velocityNullifier)),
                        ("complianceCommitment", b(e.complianceCommitment)),
                    ],
                )
            } else if let Ok(e) = log.log_decode::<IShieldedPool::Transfer>() {
                let e = e.inner.data;
                (
                    "Transfer",
                    vec![
                        ("nullifier0", b(e.nullifier0)),
                        ("nullifier1", b(e.nullifier1)),
                        ("commitmentOut0", b(e.commitmentOut0)),
                        ("commitmentOut1", b(e.commitmentOut1)),
                        ("velocityNullifier", b(e.velocityNullifier)),
                        ("complianceCommitment", b(e.complianceCommitment)),
                    ],
                )
            } else if let Ok(e) = log.log_decode::<IShieldedPool::Withdraw>() {
                let e = e.inner.data;
                (
                    "Withdraw",
                    vec![
                        ("nullifier", b(e.nullifier)),
                        ("recipient", a(e.recipient)),
                        ("amount", e.amount.to_string()),
                        ("velocityNullifier", b(e.velocityNullifier)),
                        ("complianceCommitment", b(e.complianceCommitment)),
                    ],
                )
            } else if let Ok(e) = log.log_decode::<IShieldedPool::WithdrawBlocked>() {
                let e = e.inner.data;
                (
                    "WithdrawBlocked",
                    vec![
                        ("nullifier", b(e.nullifier)),
                        ("amount", e.amount.to_string()),
                    ],
                )
            } else if let Ok(e) = log.log_decode::<IShieldedPool::BlockedFundsClaimed>() {
                let e = e.inner.data;
                (
                    "BlockedFundsClaimed",
                    vec![
                        ("nullifier", b(e.nullifier)),
                        ("amount", e.amount.to_string()),
                    ],
                )
            } else if let Ok(e) = log.log_decode::<IShieldedPool::SizeFlag>() {
                let e = e.inner.data;
                (
                    "SizeFlag",
                    vec![
                        ("velocityNullifier", b(e.velocityNullifier)),
                        ("op", e.op.to_string()),
                        ("amount", e.amount.to_string()),
                    ],
                )
            } else if let Ok(e) = log.log_decode::<IShieldedPool::DestinationBlocked>() {
                let e = e.inner.data;
                (
                    "DestinationBlocked",
                    vec![
                        ("destination", a(e.destination)),
                        ("blocked", e.blocked.to_string()),
                    ],
                )
            } else if let Ok(e) =
                log.log_decode::<IAttestationRegistry::AttestationAdded>()
            {
                let e = e.inner.data;
                (
                    "AttestationAdded",
                    vec![
                        ("leaf", b(e.leaf)),
                        ("subjectPubkeyHash", b(e.subjectPubkeyHash)),
                        ("attester", a(e.attester)),
                        ("generation", e.generation.to_string()),
                        ("issuedAt", e.issuedAt.to_string()),
                        ("expiresAt", e.expiresAt.to_string()),
                    ],
                )
            } else if let Ok(e) = log.log_decode::<IMockERC20::Transfer>() {
                let e = e.inner.data;
                (
                    "ERC20.Transfer",
                    vec![
                        ("from", a(e.from)),
                        ("to", a(e.to)),
                        ("value", e.value.to_string()),
                    ],
                )
            } else if let Ok(e) = log.log_decode::<IMockERC20::Approval>() {
                let e = e.inner.data;
                (
                    "ERC20.Approval",
                    vec![
                        ("owner", a(e.owner)),
                        ("spender", a(e.spender)),
                        ("value", e.value.to_string()),
                    ],
                )
            } else {
                return None;
            };
            Some(Event {
                name: name.into(),
                args: args
                    .into_iter()
                    .map(|(k, v)| (k.into(), v.into()))
                    .collect(),
            })
        })
        .collect()
}

fn header(
    stage: &Stage,
    scenario: &'static str,
    title: &'static str,
    summary: &'static str,
    accounts: &[AlloyAddress; 4],
    owners: &[OwnerPubkey; 2],
) -> Header<'static> {
    let shielded = SHIELDED.into_iter().zip(owners).map(|(p, owner)| Persona {
        id: p.id.into(),
        label: p.label.into(),
        role: "attested account holder with a shielded wallet".into(),
        address: None,
        owner_pubkey: Some(owned(owner.as_bytes32().as_ref())),
        keys: vec![
            Key {
                id: VIEWING.into(),
                secret: p.viewing.as_slice().into(),
                opens: "value notes addressed to this persona (0x01)".into(),
            },
            Key {
                id: COMPLIANCE.into(),
                secret: p.compliance.as_slice().into(),
                opens: "this persona's own compliance notes (0x02)".into(),
            },
        ],
    });
    let eoas = ACCOUNTS.iter().zip(accounts).map(|(a, address)| Persona {
        id: a.id.into(),
        label: a.label.into(),
        role: a.role.into(),
        address: Some(owned(address.as_slice())),
        owner_pubkey: None,
        keys: Vec::new(),
    });
    let auditor = Persona {
        id: AUDITOR.into(),
        label: AUDITOR_LABEL.into(),
        role: "regulator quorum that holds the audit key".into(),
        address: None,
        owner_pubkey: None,
        keys: vec![Key {
            id: AUDIT.into(),
            secret: AUDIT_KEY.as_slice().into(),
            opens: "compliance notes to the audit committee (0x03)".into(),
        }],
    };

    let field = |name: &'static str, offset: u32, ty: FieldType| LayoutField {
        name: name.into(),
        offset,
        ty,
        labels: BTreeMap::new(),
    };
    let sentinel =
        |name: &'static str, offset: u32, value: Bytes32, label: &'static str| {
            LayoutField {
                labels: BTreeMap::from([(owned(value.as_ref()), label.into())]),
                ..field(name, offset, FieldType::Bytes32)
            }
        };
    let no_counterparty = Bytes32::from(*NO_COUNTERPARTY);

    Header {
        schema: trace_recorder::SCHEMA_VERSION,
        poc: "pocs/private-payment/shielded-pool-compliance".into(),
        scenario: scenario.into(),
        title: title.into(),
        summary: summary.into(),
        simplifications: [
            "One operator account deploys the contracts, attests the cohort, curates the blocklist, funds the deposits and relays every pool call. The spec gives these roles to separate parties.",
            "The pool holds only this run's notes, so its anonymity set is far smaller than a busy pool's.",
            "The audit committee is a single key (t = n = 1).",
            "The wallet simulates each pool call and does not broadcast one that the pool refuses.",
            "The chain is a local Anvil node.",
        ]
        .map(Str::from)
        .into(),
        mock_proofs: use_mock_proofs(),
        source: format!("tests/{scenario}.rs").into(),
        map: MapRefs {
            use_case: "private-payments".into(),
            approach: "approach-private-payments".into(),
            patterns: [
                "pattern-shielding",
                "pattern-compliance-monitoring",
                "pattern-regulatory-disclosure-keys-proofs",
                "pattern-verifiable-attestation",
            ]
            .map(Str::from)
            .into(),
        },
        chains: vec![Chain {
            chain_id: CHAIN_ID,
            name: "Anvil (local)".into(),
        }],
        assets: vec![Asset {
            id: ASSET.into(),
            symbol: "mUSDC".into(),
            decimals: 6,
            chain_id: CHAIN_ID,
            address: owned(stage.deployment.token.as_slice()),
        }],
        personas: shielded.chain(eoas).chain([auditor]).collect(),
        observers: [
            ("public", ObserverRole::Public, "Chain observer"),
            ("counterparty", ObserverRole::Counterparty, "Counterparty"),
            (AUDITOR, ObserverRole::Regulator, AUDITOR_LABEL),
        ]
        .map(|(id, role, label)| Observer {
            id: id.into(),
            role,
            label: label.into(),
        })
        .into(),
        fields: FIELDS
            .map(|(id, label)| Field {
                id: id.into(),
                label: label.into(),
            })
            .into(),
        actions: [
            ("fund", "Fund"),
            ("withdraw-blocked", "Blocked-funds exit"),
            ("block-destination", "Block a destination"),
            ("claim-blocked", "Claim blocked funds"),
        ]
        .map(|(id, label)| ActionDef {
            id: id.into(),
            label: label.into(),
        })
        .into(),
        circuits: circuits(),
        note_domains: vec![NoteDomain {
            id: DOMAIN.into(),
            kem: Kem::K256,
            tag: DOMAIN_TAG.into(),
        }],
        note_layouts: vec![
            NoteLayout {
                id: VALUE_NOTE.into(),
                label: "Value note".into(),
                codec: Codec::Fixed {
                    len: 104,
                    fields: vec![
                        field("token", 0, FieldType::Address),
                        field("amount", 32, FieldType::U64),
                        field("owner_pubkey", 40, FieldType::Bytes32),
                        field("salt", 72, FieldType::Bytes32),
                    ],
                },
            },
            NoteLayout {
                id: COMPLIANCE_NOTE.into(),
                label: "Compliance note".into(),
                codec: Codec::Fixed {
                    len: 208,
                    fields: vec![
                        field("owner_pubkey", 0, FieldType::Bytes32),
                        field("epoch", 32, FieldType::U64),
                        field("seq", 40, FieldType::U64),
                        field("salt", 48, FieldType::Bytes32),
                        field("flags", 80, FieldType::U64),
                        field("running_total", 88, FieldType::U64),
                        sentinel(
                            "counterparty_0",
                            96,
                            no_counterparty,
                            "no counterparty",
                        ),
                        sentinel(
                            "counterparty_1",
                            128,
                            no_counterparty,
                            "no counterparty",
                        ),
                        field("amount_out_0", 160, FieldType::U64),
                        field("amount_out_1", 168, FieldType::U64),
                        sentinel("exit", 176, Bytes32::from(*NO_EXIT), "no exit"),
                    ],
                },
            },
        ],
    }
}

/// Each circuit's public-input names, placed by the index constants in
/// `src/domain/public_inputs.rs`, so the two cannot drift apart.
fn circuits() -> Vec<CircuitDef<'static>> {
    fn named(
        id: &'static str,
        length: usize,
        names: &[(usize, &'static str)],
    ) -> CircuitDef<'static> {
        let mut slots = vec![None; length];
        for &(index, name) in names {
            assert!(
                slots[index].replace(name).is_none(),
                "{id} input {index} named twice"
            );
        }
        CircuitDef {
            id: id.into(),
            public_inputs: slots
                .into_iter()
                .enumerate()
                .map(|(i, name)| {
                    name.unwrap_or_else(|| panic!("{id} input {i} is unnamed"))
                        .into()
                })
                .collect(),
        }
    }
    use deposit_idx as d;
    use transfer_idx as t;
    use ungated_idx as u;
    use withdraw_idx as w;
    vec![
        named(
            "deposit",
            d::LENGTH,
            &[
                (d::COMMITMENT, "commitment"),
                (d::TOKEN, "token"),
                (d::AMOUNT, "amount"),
                (d::ATTESTATION_ROOT, "attestation_root"),
                (d::VELOCITY_NULLIFIER, "velocity_nullifier"),
                (d::COMPLIANCE_COMMITMENT_OUT, "compliance_commitment_out"),
                (d::EPOCH, "epoch"),
                (d::EPOCH_SECONDS, "epoch_seconds"),
                (d::POLICY_SOURCE_HASH, "policy_source_hash"),
                (d::COMMITMENT_ROOT, "commitment_root"),
                (d::ATTESTER_REVOCATION_ROOT, "attester_revocation_root"),
                (d::MIN_ACCEPTED_GENERATION, "min_accepted_generation"),
                (d::PAYLOAD_COMMITMENT, "payload_commitment"),
            ],
        ),
        named(
            "transfer",
            t::LENGTH,
            &[
                (t::NULLIFIER_0, "nullifier_0"),
                (t::NULLIFIER_1, "nullifier_1"),
                (t::COMMITMENT_OUT_0, "commitment_out_0"),
                (t::COMMITMENT_OUT_1, "commitment_out_1"),
                (t::COMMITMENT_ROOT, "commitment_root"),
                (t::VELOCITY_NULLIFIER, "velocity_nullifier"),
                (t::COMPLIANCE_COMMITMENT_OUT, "compliance_commitment_out"),
                (t::EPOCH, "epoch"),
                (t::EPOCH_SECONDS, "epoch_seconds"),
                (t::POLICY_SOURCE_HASH, "policy_source_hash"),
                (t::ATTESTATION_ROOT, "attestation_root"),
                (t::ATTESTER_REVOCATION_ROOT, "attester_revocation_root"),
                (t::MIN_ACCEPTED_GENERATION, "min_accepted_generation"),
                (t::PAYLOAD_COMMITMENT, "payload_commitment"),
            ],
        ),
        named(
            "withdraw",
            w::LENGTH,
            &[
                (w::NULLIFIER, "nullifier"),
                (w::TOKEN, "token"),
                (w::AMOUNT, "amount"),
                (w::RECIPIENT, "recipient"),
                (w::COMMITMENT_ROOT, "commitment_root"),
                (w::VELOCITY_NULLIFIER, "velocity_nullifier"),
                (w::COMPLIANCE_COMMITMENT_OUT, "compliance_commitment_out"),
                (w::EPOCH, "epoch"),
                (w::EPOCH_SECONDS, "epoch_seconds"),
                (w::POLICY_SOURCE_HASH, "policy_source_hash"),
                (w::ATTESTATION_ROOT, "attestation_root"),
                (w::ATTESTER_REVOCATION_ROOT, "attester_revocation_root"),
                (w::MIN_ACCEPTED_GENERATION, "min_accepted_generation"),
                (w::PAYLOAD_COMMITMENT, "payload_commitment"),
            ],
        ),
        named(
            "withdraw_ungated",
            u::LENGTH,
            &[
                (u::NULLIFIER, "nullifier"),
                (u::TOKEN, "token"),
                (u::AMOUNT, "amount"),
                (u::RECIPIENT, "recipient"),
                (u::COMMITMENT_ROOT, "commitment_root"),
            ],
        ),
    ]
}

fn shielded_index(id: &str) -> usize {
    SHIELDED
        .iter()
        .position(|p| p.id == id)
        .unwrap_or_else(|| panic!("{id} is not a shielded persona"))
}

fn label(id: &str) -> &'static str {
    SHIELDED
        .iter()
        .map(|p| (p.id, p.label))
        .chain(ACCOUNTS.iter().map(|a| (a.id, a.label)))
        .chain([(AUDITOR, AUDITOR_LABEL)])
        .find(|(candidate, _)| *candidate == id)
        .map(|(_, label)| label)
        .unwrap_or_else(|| panic!("{id} is not a persona"))
}

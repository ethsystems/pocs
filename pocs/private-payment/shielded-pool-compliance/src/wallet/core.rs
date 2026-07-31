//! The wallet actor. Owns two `MerkleStore`s as local state (a mirror of the pool's
//! on-chain commitment and attestation trees, kept in sync by `observe_*` and by every
//! `build_*` call's own inserts) and its subject's compliance chain; every other
//! capability (`ChainReader`, `Clock`, `AuditEncryptor`, `AttestationSource`) is a
//! call-time parameter per CONTRIBUTING's "pass dependencies as parameters" rule.

use ark_bn254::Fr;

use crate::{
    domain::{
        compliance_note::{
            ComplianceNote,
            Facts,
            VelocityNullifier,
        },
        keys::{
            OwnerPubkey,
            ViewingPubkey,
            random_salt,
        },
        note::Note,
        payload::{
            Payload,
            PayloadElement,
            PayloadKind,
        },
        public_inputs::{
            deposit,
            gated_withdraw,
            require_canonical,
            transfer,
            ungated_withdraw,
        },
        tx_facts,
        witness::{
            AttestationWitness,
            BlockedWithdrawWitness,
            ComplianceWitness,
            DepositWitness,
            InputNoteWitness,
            OutputNoteWitness,
            PolicyState,
            TransferWitness,
            WithdrawWitness,
        },
    },
    policy::{
        Policy,
        commit::state_tag,
        reference::ReferencePolicy,
    },
    ports::{
        audit::AuditEncryptor,
        chain::{
            ChainReader,
            PolicyPair,
            RegistrySnapshot,
        },
        clock::Clock,
        merkle::{
            MerklePath,
            MerkleStore,
        },
        prover::ProofRequest,
        registry::AttestationSource,
    },
    types::{
        Bytes32,
        Epoch,
        Seq,
    },
};

use super::{
    error::Error,
    types::{
        BuiltDeposit,
        BuiltTransfer,
        BuiltWithdraw,
        BuiltWithdrawBlocked,
        CompliancePlaintext,
        DepositRequest,
        OwnedNote,
        TransferRequest,
        ValueNotePlaintext,
        WalletKeys,
        WithdrawRequest,
    },
};

/// Two tree parameters, not one: the commitment tree is `MAX_COMMITMENT_TREE_DEPTH`
/// deep and the attestation tree `MAX_ATTESTATION_TREE_DEPTH`, and the circuits size
/// their path arrays accordingly. Collapsing them to a single `M` would let an
/// attestation tree accept leaves whose paths no gated circuit can carry.
pub struct Wallet<C: MerkleStore, A: MerkleStore> {
    commitments: C,
    attestations: A,
    current_note: Option<ComplianceNote<ReferencePolicy>>,
    current_note_leaf: Option<crate::ports::merkle::LeafIndex>,
    keys: WalletKeys,
}

struct ChainContext {
    registry: RegistrySnapshot,
    policy: PolicyPair,
}

async fn read_chain_context(
    chain: &impl ChainReader,
    local_epoch: Epoch,
) -> Result<ChainContext, Error> {
    let chain_epoch = chain.current_epoch().await?;
    if chain_epoch != local_epoch {
        return Err(Error::EpochMismatch {
            local: local_epoch,
            chain: chain_epoch,
        });
    }
    let registry = chain.registry_values().await?;
    let policy = chain.effective_policy().await?;
    Ok(ChainContext { registry, policy })
}

fn state_tag_bytes(policy_source_hash: Bytes32) -> Result<Bytes32, Error> {
    let hash_fr = Fr::try_from(policy_source_hash)?;
    Ok(Bytes32::from(state_tag::<ReferencePolicy>(hash_fr)))
}

impl<C: MerkleStore, A: MerkleStore> Wallet<C, A> {
    pub fn new(commitments: C, attestations: A, keys: WalletKeys) -> Self {
        Self {
            commitments,
            attestations,
            current_note: None,
            current_note_leaf: None,
            keys,
        }
    }

    pub fn owner_pubkey(&self) -> OwnerPubkey {
        self.keys.owner_pubkey()
    }

    /// The half of `viewing_key` this subject hands to a prospective sender out of
    /// band, the same way `owner_pubkey` already travels for attestation lookup. A
    /// `TransferOutput`/deposit output addressed to this subject encrypts its `0x01`
    /// value-note element to this key.
    pub fn viewing_pubkey(&self) -> ViewingPubkey {
        self.keys.viewing_key.public_key()
    }

    /// The subject's current policy accumulator, if any compliance note has been built
    /// yet. Exposed for callers (tests, the auditor's cross-check) that want to compare
    /// the wallet's own view against a reconstructed one.
    pub fn current_state(&self) -> Option<PolicyState> {
        self.current_note.as_ref().map(|note| note.state)
    }

    /// Folds a leaf observed on chain (someone else's deposit or transfer output, or an
    /// attestation the wallet does not itself hold) into the local commitment tree.
    pub fn observe_commitment(
        &self,
        leaf: Bytes32,
    ) -> Result<crate::ports::merkle::LeafIndex, Error> {
        Ok(self.commitments.insert(leaf)?)
    }

    /// Same as [`Self::observe_commitment`] for the attestation tree.
    pub fn observe_attestation(
        &self,
        leaf: Bytes32,
    ) -> Result<crate::ports::merkle::LeafIndex, Error> {
        Ok(self.attestations.insert(leaf)?)
    }

    fn commitment_root(&self) -> Bytes32 {
        self.commitments.root().unwrap_or(Bytes32::from([0u8; 32]))
    }

    /// The accumulator this transaction advances from. It resets across an epoch
    /// boundary for the same reason `next_seq` does: the reset chain starts at `seq 0`,
    /// whose in-circuit branch asserts `prev == policy::zero()`.
    fn prev_state(&self, epoch: Epoch) -> PolicyState {
        match &self.current_note {
            Some(note) if note.epoch == epoch => note.state,
            _ => ReferencePolicy::zero(),
        }
    }

    /// This transaction's `seq`, which `compliance.nr` asserts equals `tx.seq` and uses
    /// for the predecessor note's own commitment. A note committed at `seq = k` is
    /// consumed by the transaction whose `seq` is also `k`, which then commits its
    /// successor at `k + 1` (`compliance.nr`'s `state_out` hashes `inp.seq + 1`). So the
    /// next transaction's `seq` is the stored note's `seq`, not one past it.
    ///
    /// It resets to 0 across an epoch boundary: `compliance.nr` asserts
    /// `epoch_in == epoch` unconditionally, so a predecessor committed in an earlier
    /// epoch can never be opened, and the chain restarts at the base case.
    fn next_seq(&self, epoch: Epoch) -> Seq {
        match &self.current_note {
            Some(note) if note.epoch == epoch => note.seq,
            _ => Seq(0),
        }
    }

    /// The `seq` a note produced by a transaction at `tx_seq` is committed with.
    fn committed_seq(tx_seq: Seq) -> Seq {
        Seq(tx_seq.0 + 1)
    }

    /// `epoch` is this transaction's epoch, not the predecessor's. The predecessor
    /// branch is taken only when the stored note sits in that same epoch: the circuit's
    /// `seq == 0` branch asserts `prev == policy::zero()` and `flags_in == 0`, so
    /// carrying a previous epoch's accumulator into a reset chain cannot prove.
    fn compliance_witness(
        &self,
        epoch: Epoch,
        salt_out: Bytes32,
    ) -> Result<ComplianceWitness, Error> {
        match (&self.current_note, self.current_note_leaf) {
            (Some(note), Some(leaf_index)) if note.epoch == epoch => {
                let cn_proof = self.commitments.get_proof(leaf_index)?;
                Ok(ComplianceWitness {
                    seq: note.seq,
                    epoch_in: note.epoch,
                    prev: note.state,
                    flags_in: note.flags.as_u64(),
                    cp_in: note.facts.counterparty,
                    amt_in: note.facts.amount_out,
                    exit_in: note.facts.exit,
                    salt_in: note.salt,
                    salt_out,
                    cn_proof,
                })
            }
            _ => Ok(ComplianceWitness {
                seq: Seq(0),
                epoch_in: epoch,
                prev: ReferencePolicy::zero(),
                flags_in: 0,
                cp_in: [Bytes32::from(*crate::NO_COUNTERPARTY); 2],
                amt_in: [0, 0],
                exit_in: Bytes32::from(*crate::NO_EXIT),
                salt_in: Bytes32::from([0u8; 32]),
                salt_out,
                cn_proof: MerklePath::new(vec![]),
            }),
        }
    }

    /// Fetches the current attestation instance covering `owner`, its inclusion proof,
    /// and its attester's revocation status.
    async fn attestation_witness(
        &self,
        attestation_source: &impl AttestationSource,
        owner: OwnerPubkey,
    ) -> Result<AttestationWitness, Error> {
        let record = attestation_source
            .current_attestation(owner)
            .await?
            .ok_or(Error::NoAttestation(owner))?;
        let attestation_proof = self.attestations.get_proof(record.leaf_index)?;
        Ok(AttestationWitness {
            attester: record.attester,
            generation: record.generation,
            issued_at: record.issued_at,
            expires_at: record.expires_at,
            attestation_proof,
            revoked_at: record.revoked_at,
            revocation_proof: record.revocation_proof,
        })
    }

    fn input_note_witness(&self, slot: OwnedNote) -> Result<InputNoteWitness, Error> {
        let proof = if slot.note.is_zero() {
            MerklePath::new(vec![])
        } else {
            self.commitments.get_proof(slot.leaf_index)?
        };
        Ok(InputNoteWitness {
            amount: slot.note.amount,
            salt: slot.note.salt,
            proof,
        })
    }

    /// Assembles a gated operation's full `encryptedNotes` payload: one `0x01`
    /// value-note element per output (SPEC:449), in output order, followed by the two
    /// compliance-note elements. Every element's AEAD is bound to its own cleartext
    /// kind (and, for the committee element, its `committeeVersion`) via
    /// `PayloadKind::aad`.
    fn build_payload(
        &self,
        audit: &impl AuditEncryptor,
        note: &ComplianceNote<ReferencePolicy>,
        value_notes: &[(ViewingPubkey, ValueNotePlaintext)],
    ) -> Result<Payload, Error> {
        let mut elements = Vec::with_capacity(value_notes.len() + 2);
        let value_note_kind = PayloadKind::ValueNote;
        for (viewing_pubkey, plaintext) in value_notes {
            elements.push(PayloadElement {
                kind: value_note_kind,
                ciphertext: viewing_pubkey
                    .encrypt(&plaintext.encode(), &value_note_kind.aad()),
            });
        }

        let plaintext = CompliancePlaintext::from_note(note).encode();
        let to_owner_kind = PayloadKind::ComplianceNoteToOwner;
        let to_owner = self
            .keys
            .compliance_viewing_key
            .public_key()
            .encrypt(&plaintext, &to_owner_kind.aad());
        let to_committee_kind = PayloadKind::ComplianceNoteToCommittee {
            committee_version: audit.committee_version(),
        };
        let to_committee = audit
            .encrypt(&plaintext, &to_committee_kind.aad())
            .map_err(Error::Audit)?;
        elements.push(PayloadElement {
            kind: to_owner_kind,
            ciphertext: to_owner,
        });
        elements.push(PayloadElement {
            kind: to_committee_kind,
            ciphertext: to_committee,
        });
        Ok(Payload::new(elements))
    }

    /// The viewing pubkey a `0x01` value-note element for `owner` is encrypted to.
    /// Self-owned outputs (a deposit's minted note, or a transfer's change) always use
    /// the wallet's own `viewing_key`, regardless of what a caller-supplied
    /// `TransferOutput::viewing_pubkey` says, so a caller cannot lock the wallet out of
    /// its own note by supplying the wrong key.
    fn viewing_pubkey_for(
        &self,
        owner: OwnerPubkey,
        supplied: &ViewingPubkey,
    ) -> ViewingPubkey {
        if owner == self.keys.owner_pubkey() {
            self.keys.viewing_key.public_key()
        } else {
            supplied.clone()
        }
    }

    /// Decrypts a `0x01` value-note element addressed to this wallet's own
    /// `viewing_key`, recovering a note learned only from chain data (SPEC:449). The
    /// counterpart to `build_payload`'s value-note elements.
    pub fn accept_value_note(&self, element: &PayloadElement) -> Result<Note, Error> {
        if element.kind != PayloadKind::ValueNote {
            return Err(Error::WrongElementKind);
        }
        let plaintext_bytes = self
            .keys
            .viewing_key
            .decrypt(&element.ciphertext, &element.kind.aad())?;
        Ok(ValueNotePlaintext::decode(&plaintext_bytes)?.into_note())
    }

    pub async fn build_deposit(
        &mut self,
        chain: &impl ChainReader,
        clock: &impl Clock,
        audit: &impl AuditEncryptor,
        attestation_source: &impl AttestationSource,
        req: DepositRequest,
    ) -> Result<BuiltDeposit, Error> {
        let subject = self.keys.owner_pubkey();
        let local_epoch = clock.current_epoch(crate::EPOCH_SECONDS);
        let new_seq = self.next_seq(local_epoch);

        let tx = tx_facts::deposit(local_epoch, new_seq, req.token, subject, req.amount)?;
        let prev_state = self.prev_state(local_epoch);
        let next_state =
            ReferencePolicy::advance(prev_state, &tx).map_err(Error::PolicyBlocked)?;
        let flags = ReferencePolicy::evaluate(&tx, prev_state, next_state)
            .map_err(Error::PolicyBlocked)?;

        let ctx = read_chain_context(chain, local_epoch).await?;
        let tag = state_tag_bytes(ctx.policy.policy_source_hash)?;

        let output_note = Note::new(req.token, req.amount, subject);
        let commitment = output_note.commitment()?;
        let velocity_nullifier =
            VelocityNullifier::derive(&self.keys.spending_key, local_epoch, new_seq).0;

        // `circuits/deposit/src/main.nr` calls `compliance::run(.., amount, 0)`,
        // so the committed `facts_out` binds the amount in slot 0.
        let facts = Facts {
            counterparty: [
                Bytes32::from(tx.counterparty[0]),
                Bytes32::from(tx.counterparty[1]),
            ],
            amount_out: [req.amount, 0],
            exit: Bytes32::from(tx.exit),
        };
        let new_salt = random_salt();
        let new_note = ComplianceNote::<ReferencePolicy> {
            owner_pubkey: subject,
            epoch: local_epoch,
            seq: Self::committed_seq(new_seq),
            salt: new_salt,
            flags,
            state: next_state,
            facts,
        };
        let compliance_commitment_out = new_note.commitment(tag)?;
        let compliance = self.compliance_witness(local_epoch, new_salt)?;

        // The payload MUST be built before `public` below: `payload_commitment` is a
        // public input the contract checks against `keccak256(encryptedNotes) mod r`,
        // so it has to be derived from the payload that ships, not the reverse.
        let value_notes = [(
            self.keys.viewing_key.public_key(),
            ValueNotePlaintext::from_note(&output_note),
        )];
        let payload = self.build_payload(audit, &new_note, &value_notes)?;

        let public = deposit::Fields {
            commitment,
            token: Bytes32::from(tx.token),
            amount: req.amount,
            attestation_root: ctx.registry.attestation_root,
            velocity_nullifier,
            compliance_commitment_out,
            epoch: local_epoch,
            epoch_seconds: crate::EPOCH_SECONDS,
            policy_source_hash: ctx.policy.policy_source_hash,
            commitment_root: self.commitment_root(),
            attester_revocation_root: ctx.registry.attester_revocation_root,
            min_accepted_generation: ctx.registry.min_accepted_generation,
            payload_commitment: payload.commitment(),
        };
        require_canonical(&public.ordered())?;

        let attestation = self
            .attestation_witness(attestation_source, subject)
            .await?;

        let witness = DepositWitness {
            public,
            spending_key: self.keys.spending_key.clone(),
            note_salt: output_note.salt,
            attestation,
            compliance,
        };

        let output_index = self.commitments.insert(commitment)?;
        let cn_leaf_index = self.commitments.insert(compliance_commitment_out)?;
        self.current_note = Some(new_note);
        self.current_note_leaf = Some(cn_leaf_index);

        Ok(BuiltDeposit {
            request: ProofRequest::Deposit(Box::new(witness)),
            payload,
            note: output_note,
            output_index,
        })
    }

    pub async fn build_transfer(
        &mut self,
        chain: &impl ChainReader,
        clock: &impl Clock,
        audit: &impl AuditEncryptor,
        attestation_source: &impl AttestationSource,
        req: TransferRequest,
    ) -> Result<BuiltTransfer, Error> {
        let subject = self.keys.owner_pubkey();
        let local_epoch = clock.current_epoch(crate::EPOCH_SECONDS);
        let new_seq = self.next_seq(local_epoch);

        let have: u64 = req.inputs.iter().map(|slot| slot.note.amount).sum();
        let need: u64 = req.outputs.iter().map(|out| out.amount).sum();
        if have < need {
            return Err(Error::InsufficientValue { have, need });
        }

        let owner_out = [req.outputs[0].owner, req.outputs[1].owner];
        let amount_out = [req.outputs[0].amount, req.outputs[1].amount];
        let tx = tx_facts::transfer(
            local_epoch,
            new_seq,
            req.token,
            subject,
            owner_out,
            amount_out,
        )?;

        let prev_state = self.prev_state(local_epoch);
        let next_state =
            ReferencePolicy::advance(prev_state, &tx).map_err(Error::PolicyBlocked)?;
        let flags = ReferencePolicy::evaluate(&tx, prev_state, next_state)
            .map_err(Error::PolicyBlocked)?;

        let ctx = read_chain_context(chain, local_epoch).await?;
        let tag = state_tag_bytes(ctx.policy.policy_source_hash)?;

        let output_notes = [
            Note::new(req.token, req.outputs[0].amount, req.outputs[0].owner),
            Note::new(req.token, req.outputs[1].amount, req.outputs[1].owner),
        ];
        let output_viewing_pubkeys = [
            self.viewing_pubkey_for(req.outputs[0].owner, &req.outputs[0].viewing_pubkey),
            self.viewing_pubkey_for(req.outputs[1].owner, &req.outputs[1].viewing_pubkey),
        ];
        let commitment_out =
            [output_notes[0].commitment()?, output_notes[1].commitment()?];
        let velocity_nullifier =
            VelocityNullifier::derive(&self.keys.spending_key, local_epoch, new_seq).0;

        let facts = Facts {
            counterparty: [
                Bytes32::from(tx.counterparty[0]),
                Bytes32::from(tx.counterparty[1]),
            ],
            amount_out,
            exit: Bytes32::from(tx.exit),
        };
        let new_salt = random_salt();
        let new_note = ComplianceNote::<ReferencePolicy> {
            owner_pubkey: subject,
            epoch: local_epoch,
            seq: Self::committed_seq(new_seq),
            salt: new_salt,
            flags,
            state: next_state,
            facts,
        };
        let compliance_commitment_out = new_note.commitment(tag)?;
        let compliance = self.compliance_witness(local_epoch, new_salt)?;

        let nullifier_0 = req.inputs[0].note.nullifier(&self.keys.spending_key)?;
        let nullifier_1 = req.inputs[1].note.nullifier(&self.keys.spending_key)?;

        // The payload MUST be built before `public` below: `payload_commitment` is a
        // public input the contract checks against `keccak256(encryptedNotes) mod r`,
        // so it has to be derived from the payload that ships, not the reverse.
        let value_notes = [
            (
                output_viewing_pubkeys[0].clone(),
                ValueNotePlaintext::from_note(&output_notes[0]),
            ),
            (
                output_viewing_pubkeys[1].clone(),
                ValueNotePlaintext::from_note(&output_notes[1]),
            ),
        ];
        let payload = self.build_payload(audit, &new_note, &value_notes)?;

        let public = transfer::Fields {
            nullifier_0,
            nullifier_1,
            commitment_out_0: commitment_out[0],
            commitment_out_1: commitment_out[1],
            commitment_root: self.commitment_root(),
            velocity_nullifier,
            compliance_commitment_out,
            epoch: local_epoch,
            epoch_seconds: crate::EPOCH_SECONDS,
            policy_source_hash: ctx.policy.policy_source_hash,
            attestation_root: ctx.registry.attestation_root,
            attester_revocation_root: ctx.registry.attester_revocation_root,
            min_accepted_generation: ctx.registry.min_accepted_generation,
            payload_commitment: payload.commitment(),
        };
        require_canonical(&public.ordered())?;

        let inputs = [
            self.input_note_witness(req.inputs[0])?,
            self.input_note_witness(req.inputs[1])?,
        ];
        let outputs = [
            OutputNoteWitness {
                amount: output_notes[0].amount,
                owner: output_notes[0].owner_pubkey,
                salt: output_notes[0].salt,
            },
            OutputNoteWitness {
                amount: output_notes[1].amount,
                owner: output_notes[1].owner_pubkey,
                salt: output_notes[1].salt,
            },
        ];

        let subject_attestation = self
            .attestation_witness(attestation_source, subject)
            .await?;
        let output_attestations = [
            self.attestation_witness(attestation_source, req.outputs[0].owner)
                .await?,
            self.attestation_witness(attestation_source, req.outputs[1].owner)
                .await?,
        ];

        let witness = TransferWitness {
            public,
            spending_key: self.keys.spending_key.clone(),
            token: req.token,
            inputs,
            outputs,
            subject_attestation,
            output_attestations,
            compliance,
        };

        let output_indices = [
            self.commitments.insert(commitment_out[0])?,
            self.commitments.insert(commitment_out[1])?,
        ];
        let cn_leaf_index = self.commitments.insert(compliance_commitment_out)?;
        self.current_note = Some(new_note);
        self.current_note_leaf = Some(cn_leaf_index);

        Ok(BuiltTransfer {
            request: ProofRequest::Transfer(Box::new(witness)),
            payload,
            outputs: output_notes,
            output_indices,
        })
    }

    pub async fn build_withdraw(
        &mut self,
        chain: &impl ChainReader,
        clock: &impl Clock,
        audit: &impl AuditEncryptor,
        attestation_source: &impl AttestationSource,
        req: WithdrawRequest,
    ) -> Result<BuiltWithdraw, Error> {
        let subject = self.keys.owner_pubkey();
        let local_epoch = clock.current_epoch(crate::EPOCH_SECONDS);
        let new_seq = self.next_seq(local_epoch);

        let tx = tx_facts::gated_withdraw(
            local_epoch,
            new_seq,
            req.token,
            subject,
            req.amount,
            req.recipient,
        )?;
        let prev_state = self.prev_state(local_epoch);
        let next_state =
            ReferencePolicy::advance(prev_state, &tx).map_err(Error::PolicyBlocked)?;
        let flags = ReferencePolicy::evaluate(&tx, prev_state, next_state)
            .map_err(Error::PolicyBlocked)?;

        let ctx = read_chain_context(chain, local_epoch).await?;
        let tag = state_tag_bytes(ctx.policy.policy_source_hash)?;

        let nullifier = req.input.note.nullifier(&self.keys.spending_key)?;
        let velocity_nullifier =
            VelocityNullifier::derive(&self.keys.spending_key, local_epoch, new_seq).0;

        // `circuits/withdraw/src/main.nr` calls `compliance::run(.., amount, 0)`,
        // so the committed `facts_out` binds the amount in slot 0.
        let facts = Facts {
            counterparty: [
                Bytes32::from(tx.counterparty[0]),
                Bytes32::from(tx.counterparty[1]),
            ],
            amount_out: [req.amount, 0],
            exit: Bytes32::from(tx.exit),
        };
        let new_salt = random_salt();
        let new_note = ComplianceNote::<ReferencePolicy> {
            owner_pubkey: subject,
            epoch: local_epoch,
            seq: Self::committed_seq(new_seq),
            salt: new_salt,
            flags,
            state: next_state,
            facts,
        };
        let compliance_commitment_out = new_note.commitment(tag)?;
        let compliance = self.compliance_witness(local_epoch, new_salt)?;

        // The payload MUST be built before `public` below: `payload_commitment` is a
        // public input the contract checks against `keccak256(encryptedNotes) mod r`,
        // so it has to be derived from the payload that ships, not the reverse. A
        // gated withdraw pays out to a plain address: the funds leave the shielded
        // pool entirely, so there is no output note to address a value-note element to.
        let payload = self.build_payload(audit, &new_note, &[])?;

        let public = gated_withdraw::Fields {
            nullifier,
            token: Bytes32::from(tx.token),
            amount: req.amount,
            recipient: Bytes32::from(Fr::from(req.recipient)),
            commitment_root: self.commitment_root(),
            velocity_nullifier,
            compliance_commitment_out,
            epoch: local_epoch,
            epoch_seconds: crate::EPOCH_SECONDS,
            policy_source_hash: ctx.policy.policy_source_hash,
            attestation_root: ctx.registry.attestation_root,
            attester_revocation_root: ctx.registry.attester_revocation_root,
            min_accepted_generation: ctx.registry.min_accepted_generation,
            payload_commitment: payload.commitment(),
        };
        require_canonical(&public.ordered())?;

        let note_proof = if req.input.note.is_zero() {
            MerklePath::new(vec![])
        } else {
            self.commitments.get_proof(req.input.leaf_index)?
        };
        let attestation = self
            .attestation_witness(attestation_source, subject)
            .await?;

        let witness = WithdrawWitness {
            public,
            spending_key: self.keys.spending_key.clone(),
            note_salt: req.input.note.salt,
            note_proof,
            attestation,
            compliance,
        };

        let cn_leaf_index = self.commitments.insert(compliance_commitment_out)?;
        self.current_note = Some(new_note);
        self.current_note_leaf = Some(cn_leaf_index);

        Ok(BuiltWithdraw {
            request: ProofRequest::Withdraw(Box::new(witness)),
            payload,
        })
    }

    /// The ungated path: no compliance note, no attestation. Still checked against
    /// `chain.is_known_commitment_root` so the wallet never hands the prover a witness
    /// built against a root the pool would reject outright.
    pub async fn build_withdraw_blocked(
        &self,
        chain: &impl ChainReader,
        req: WithdrawRequest,
    ) -> Result<BuiltWithdrawBlocked, Error> {
        let root = self.commitment_root();
        if !chain.is_known_commitment_root(root).await? {
            return Err(Error::UnknownCommitmentRoot(root));
        }

        let nullifier = req.input.note.nullifier(&self.keys.spending_key)?;
        let public = ungated_withdraw::Fields {
            nullifier,
            token: Bytes32::from(Fr::from(req.token)),
            amount: Bytes32::from(Fr::from(req.amount)),
            recipient: Bytes32::from(Fr::from(req.recipient)),
            commitment_root: root,
        };
        require_canonical(&public.ordered())?;

        let note_proof = if req.input.note.is_zero() {
            MerklePath::new(vec![])
        } else {
            self.commitments.get_proof(req.input.leaf_index)?
        };

        let witness = BlockedWithdrawWitness {
            public,
            spending_key: self.keys.spending_key.clone(),
            note_salt: req.input.note.salt,
            note_proof,
        };

        Ok(BuiltWithdrawBlocked {
            request: ProofRequest::WithdrawBlocked(Box::new(witness)),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        future::Future,
        sync::atomic::{
            AtomicUsize,
            Ordering,
        },
    };

    use tempfile::TempDir;

    use super::*;
    use crate::{
        adapters::{
            commitment_tree::RotorMerkleTree,
            mock_prover::MockProver,
            revocation_tree::RevocationTree,
        },
        domain::{
            attestation::{
                AttestationLeaf,
                Generation,
            },
            keys::{
                AuditViewingKey,
                AuditViewingPubkey,
                ComplianceViewingKey,
                SpendingKey,
                ViewingKey,
            },
        },
        error::{
            ChainError,
            CryptoError,
        },
        policy::reference::ReferencePolicy,
        ports::{
            chain::{
                ChainReader,
                PolicyPair,
                RegistrySnapshot,
            },
            merkle::LeafIndex,
            prover::{
                Circuit,
                Prover,
            },
            registry::AttestationRecord,
        },
        types::{
            Address,
            Flags,
        },
        wallet::types::TransferOutput,
    };

    // Depth 20 rather than the production `MAX_COMMITMENT_TREE_DEPTH` of 32: rotortree's
    // depth-32 path overflows a debug test thread's 2 MiB stack, though it is fine in
    // release. The distinct types are the point here, not the depths.
    type CommitmentTestTree = RotorMerkleTree<20>;
    type AttestationTestTree = RotorMerkleTree<20>;

    fn open_commitments() -> (TempDir, CommitmentTestTree) {
        let dir = tempfile::tempdir().expect("create tmp dir");
        let tree = CommitmentTestTree::open(dir.path()).expect("open tree");
        (dir, tree)
    }

    fn open_attestations() -> (TempDir, AttestationTestTree) {
        let dir = tempfile::tempdir().expect("create tmp dir");
        let tree = AttestationTestTree::open(dir.path()).expect("open tree");
        (dir, tree)
    }

    struct FixedClock(u64);

    impl Clock for FixedClock {
        fn now_unix(&self) -> u64 {
            self.0
        }
    }

    /// Counts reads so the blocked-transfer test can assert that a policy rejection
    /// costs no chain round trip: `build_*` runs the policy before `read_chain_context`.
    struct FakeChainReader {
        epoch: Epoch,
        registry: RegistrySnapshot,
        policy: PolicyPair,
        reads: AtomicUsize,
    }

    impl ChainReader for FakeChainReader {
        fn current_epoch(
            &self,
        ) -> impl Future<Output = Result<Epoch, ChainError>> + Send {
            self.reads.fetch_add(1, Ordering::SeqCst);
            let epoch = self.epoch;
            async move { Ok(epoch) }
        }

        async fn commitment_root(&self) -> Result<Bytes32, ChainError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            Ok(Bytes32::from([0u8; 32]))
        }

        async fn is_known_commitment_root(
            &self,
            _root: Bytes32,
        ) -> Result<bool, ChainError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            Ok(true)
        }

        fn registry_values(
            &self,
        ) -> impl Future<Output = Result<RegistrySnapshot, ChainError>> + Send {
            self.reads.fetch_add(1, Ordering::SeqCst);
            let registry = self.registry;
            async move { Ok(registry) }
        }

        fn effective_policy(
            &self,
        ) -> impl Future<Output = Result<PolicyPair, ChainError>> + Send {
            self.reads.fetch_add(1, Ordering::SeqCst);
            let policy = self.policy;
            async move { Ok(policy) }
        }

        async fn is_nullifier_spent(
            &self,
            _nullifier: Bytes32,
        ) -> Result<bool, ChainError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            Ok(false)
        }
    }

    struct FakeAttestationSource(HashMap<[u8; 32], AttestationRecord>);

    impl AttestationSource for FakeAttestationSource {
        fn current_attestation(
            &self,
            owner_pubkey: OwnerPubkey,
        ) -> impl Future<Output = Result<Option<AttestationRecord>, ChainError>> + Send
        {
            let record = self.0.get(&owner_key(owner_pubkey)).cloned();
            async move { Ok(record) }
        }
    }

    fn owner_key(owner: OwnerPubkey) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(owner.as_bytes32().as_ref());
        bytes
    }

    struct FakeAuditEncryptor {
        pubkey: AuditViewingPubkey,
        version: u64,
    }

    impl AuditEncryptor for FakeAuditEncryptor {
        fn committee_version(&self) -> u64 {
            self.version
        }

        fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
            Ok(self.pubkey.encrypt(plaintext, aad))
        }
    }

    fn register_attestation(
        attestations: &AttestationTestTree,
        revocations: &RevocationTree,
        owner: OwnerPubkey,
        attester: Address,
    ) -> AttestationRecord {
        let generation = Generation(1);
        let issued_at = 0;
        let expires_at = u64::MAX;
        let leaf = AttestationLeaf {
            owner_pubkey: owner,
            attester,
            generation,
            issued_at,
            expires_at,
        }
        .hash()
        .expect("canonical owner pubkey");
        let leaf_index = attestations.insert(leaf).expect("insert attestation leaf");
        AttestationRecord {
            attester,
            generation,
            issued_at,
            expires_at,
            leaf_index,
            revoked_at: revocations
                .revoked_at_epoch_of(attester)
                .expect("attester is registered"),
            revocation_proof: revocations
                .proof(attester)
                .expect("attester is registered"),
        }
    }

    fn small_bytes32(v: u8) -> Bytes32 {
        let mut bytes = [0u8; 32];
        bytes[31] = v;
        Bytes32::from(bytes)
    }

    struct Fixture {
        _commitments_dir: TempDir,
        _attestations_dir: TempDir,
        wallet: Wallet<CommitmentTestTree, AttestationTestTree>,
        chain: FakeChainReader,
        clock: FixedClock,
        audit: FakeAuditEncryptor,
        attestation_source: FakeAttestationSource,
        bob: OwnerPubkey,
        token: Address,
    }

    fn fixture() -> Fixture {
        let (commitments_dir, commitments) = open_commitments();
        let (attestations_dir, attestations) = open_attestations();
        let alice_sk = SpendingKey::random();
        let alice = alice_sk.derive_owner_pubkey();
        let bob = SpendingKey::random().derive_owner_pubkey();
        let attester = Address::from([0xaa; 20]);

        let mut revocations = RevocationTree::new();
        revocations.add_attester(attester).expect("tree has room");
        let attester_revocation_root = revocations.root();

        let alice_record =
            register_attestation(&attestations, &revocations, alice, attester);
        let bob_record = register_attestation(&attestations, &revocations, bob, attester);
        let attestation_root = attestations.root().expect("nonempty attestation tree");

        let mut records = HashMap::new();
        records.insert(owner_key(alice), alice_record);
        records.insert(owner_key(bob), bob_record);

        let chain = FakeChainReader {
            epoch: Epoch(100),
            registry: RegistrySnapshot {
                attestation_root,
                attester_revocation_root,
                min_accepted_generation: 1,
            },
            policy: PolicyPair {
                verifier: Address::from([0u8; 20]),
                policy_source_hash: small_bytes32(7),
            },
            reads: AtomicUsize::new(0),
        };
        let clock = FixedClock(100 * crate::EPOCH_SECONDS);
        let audit_secret = AuditViewingKey::random();
        let audit = FakeAuditEncryptor {
            pubkey: audit_secret.public_key(),
            version: 1,
        };

        let wallet = Wallet::new(
            commitments,
            attestations,
            WalletKeys {
                spending_key: alice_sk,
                compliance_viewing_key: ComplianceViewingKey::random(),
                viewing_key: ViewingKey::random(),
            },
        );

        Fixture {
            _commitments_dir: commitments_dir,
            _attestations_dir: attestations_dir,
            wallet,
            chain,
            clock,
            audit,
            attestation_source: FakeAttestationSource(records),
            bob,
            token: Address::from([0x11; 20]),
        }
    }

    #[tokio::test]
    async fn three_transfers_in_one_epoch_accumulate_the_running_total() {
        let mut fx = fixture();
        let alice = fx.wallet.owner_pubkey();
        let prover = MockProver;

        let note = Note::new(fx.token, 10_000, alice);
        let leaf_index = fx
            .wallet
            .observe_commitment(note.commitment().unwrap())
            .unwrap();
        let mut current = OwnedNote { note, leaf_index };

        let mut running_total = 0u64;
        for amount in [100u64, 200, 300] {
            let remainder = current.note.amount - amount;
            let req = TransferRequest {
                token: fx.token,
                inputs: [
                    current,
                    OwnedNote {
                        note: Note::zero(fx.token, alice),
                        leaf_index: LeafIndex(0),
                    },
                ],
                outputs: [
                    TransferOutput {
                        owner: fx.bob,
                        amount,
                        viewing_pubkey: ViewingKey::random().public_key(),
                    },
                    TransferOutput {
                        owner: alice,
                        amount: remainder,
                        viewing_pubkey: ViewingKey::random().public_key(),
                    },
                ],
            };

            let built = fx
                .wallet
                .build_transfer(
                    &fx.chain,
                    &fx.clock,
                    &fx.audit,
                    &fx.attestation_source,
                    req,
                )
                .await
                .expect("transfer builds a valid witness");

            let proof = prover
                .prove(&built.request)
                .expect("mock prove never fails");
            assert!(
                prover
                    .verify(built.request.circuit(), &proof)
                    .expect("mock verify runs")
            );

            running_total += amount;
            assert_eq!(fx.wallet.current_state(), Some([running_total]));

            current = OwnedNote {
                note: built.outputs[1],
                leaf_index: built.output_indices[1],
            };
        }
    }

    #[tokio::test]
    async fn policy_blocked_transfer_errors_before_reaching_the_chain_or_mutating_state()
    {
        let mut fx = fixture();
        let alice = fx.wallet.owner_pubkey();

        // Seed the subject's aggregate accumulator at u64::MAX so any further
        // value_out overflows `checked_add` inside `ReferencePolicy::advance`: the
        // reference policy only blocks via `PolicyError::SlotOverflow`, never via the
        // threshold flags (those just set bits and still succeed).
        let overflow_leaf = fx.wallet.observe_commitment(small_bytes32(1)).unwrap();
        fx.wallet.current_note = Some(ComplianceNote::<ReferencePolicy> {
            owner_pubkey: alice,
            epoch: Epoch(100),
            seq: Seq(0),
            salt: Bytes32::from([0u8; 32]),
            flags: Flags::NONE,
            state: [u64::MAX],
            facts: Facts {
                counterparty: [Bytes32::from(*crate::NO_COUNTERPARTY); 2],
                amount_out: [0, 0],
                exit: Bytes32::from(*crate::NO_EXIT),
            },
        });
        fx.wallet.current_note_leaf = Some(overflow_leaf);

        let note = Note::new(fx.token, 100, alice);
        let leaf_index = fx
            .wallet
            .observe_commitment(note.commitment().unwrap())
            .unwrap();
        let req = TransferRequest {
            token: fx.token,
            inputs: [
                OwnedNote { note, leaf_index },
                OwnedNote {
                    note: Note::zero(fx.token, alice),
                    leaf_index: LeafIndex(0),
                },
            ],
            outputs: [
                TransferOutput {
                    owner: fx.bob,
                    amount: 1,
                    viewing_pubkey: ViewingKey::random().public_key(),
                },
                TransferOutput {
                    owner: alice,
                    amount: 99,
                    viewing_pubkey: ViewingKey::random().public_key(),
                },
            ],
        };

        let before = fx.wallet.current_state();
        let before_leaf = fx.wallet.current_note_leaf;
        let before_size = fx.wallet.commitments.size();
        fx.chain.reads.store(0, Ordering::SeqCst);

        let err = fx
            .wallet
            .build_transfer(&fx.chain, &fx.clock, &fx.audit, &fx.attestation_source, req)
            .await
            .expect_err("an overflowing accumulator must block");

        assert!(matches!(err, Error::PolicyBlocked(_)));
        // No `ProofRequest` exists to prove, and the rejection cost no round trip:
        // the policy runs before `read_chain_context`.
        assert_eq!(fx.chain.reads.load(Ordering::SeqCst), 0);
        // A blocked attempt must leave the chain resumable, so nothing advances.
        assert_eq!(fx.wallet.current_state(), before);
        assert_eq!(fx.wallet.current_note_leaf, before_leaf);
        assert_eq!(fx.wallet.commitments.size(), before_size);
    }

    #[tokio::test]
    async fn deposit_mints_a_note_and_starts_the_compliance_chain() {
        let mut fx = fixture();
        let alice = fx.wallet.owner_pubkey();

        let built = fx
            .wallet
            .build_deposit(
                &fx.chain,
                &fx.clock,
                &fx.audit,
                &fx.attestation_source,
                DepositRequest {
                    token: fx.token,
                    amount: 500,
                },
            )
            .await
            .expect("deposit builds");

        assert_eq!(built.request.circuit(), Circuit::Deposit);
        assert_eq!(built.note.owner_pubkey, alice);
        assert_eq!(fx.wallet.current_state(), Some([0]));
        // Keeps the blocked-transfer test's `reads == 0` honest: a build that gets
        // past the policy does read the chain, so the counter is live.
        assert!(fx.chain.reads.load(Ordering::SeqCst) > 0);
    }
}

//! The audit committee actor: decrypts `0x03` payload elements addressed to the
//! committee and reconstructs a subject's compliance chain from them, without ever
//! touching the subject's own keys.

use std::collections::BTreeSet;

use ark_bn254::Fr;

use crate::{
    domain::{
        keys::{
            AuditViewingKey,
            OwnerPubkey,
        },
        payload::{
            PayloadElement,
            PayloadKind,
        },
    },
    policy::{
        Policy,
        TxFacts,
        reference::ReferencePolicy,
    },
    types::{
        Bytes32,
        Epoch,
    },
    wallet::CompliancePlaintext,
};

use super::{
    error::Error,
    types::{
        AuditedTx,
        ChainReconstruction,
    },
};

pub struct Auditor {
    audit_key: AuditViewingKey,
}

impl Auditor {
    pub fn new(audit_key: AuditViewingKey) -> Self {
        Self { audit_key }
    }

    /// Decrypts one `0x03` element into its opening and the `committeeVersion` it
    /// claims. Returns [`Error::WrongElementKind`] for any other element kind, so a
    /// caller iterating a mixed payload can distinguish "not for me" from "corrupt".
    /// The element's own cleartext kind (tag and `committeeVersion`) is the AEAD's
    /// additional data, so a flipped framing byte fails the Poly1305 tag rather than
    /// silently decrypting.
    pub fn decrypt_committee_element(
        &self,
        element: &PayloadElement,
    ) -> Result<(CompliancePlaintext, u64), Error> {
        let PayloadKind::ComplianceNoteToCommittee { committee_version } = element.kind
        else {
            return Err(Error::WrongElementKind);
        };
        let plaintext_bytes = self
            .audit_key
            .decrypt(&element.ciphertext, &element.kind.aad())?;
        let plaintext = CompliancePlaintext::decode(&plaintext_bytes)?;
        Ok((plaintext, committee_version))
    }

    /// Reconstructs one subject's compliance chain for one epoch from a stream of
    /// payload elements observed on chain, and checks it against `anchors`: the set of
    /// compliance commitments the pool actually recorded (SPEC "Audit Channel").
    ///
    /// Decryption policy, in order:
    /// - An element of another kind is skipped and counted in `skipped_other_kind`.
    /// - A `0x03` element whose `committeeVersion` differs from `current_committee_version`
    ///   is skipped and counted in `skipped_stale_version`: a committee key rotation
    ///   invalidates decryption of older ciphertexts under a real threshold scheme, so
    ///   this crate's `t = n = 1` stand-in still enforces the version check even though
    ///   the same key happens to decrypt regardless.
    ///   A `0x03` element whose version matches MUST decrypt; a failure here returns
    ///   [`Error::UndecryptableElement`] rather than a silent skip, since a forged or
    ///   corrupted current-version element is not a legitimate absence.
    /// - An element addressed to a different subject or epoch is skipped uncounted:
    ///   this is ordinary payload traffic from someone else, not the subject's chain.
    ///
    /// Once decrypted, every entry MUST anchor to a commitment in `anchors`
    /// ([`Error::UnanchoredNote`]), sit at a contiguous `seq` with no gap
    /// ([`Error::SeqGap`]), and re-derive the same `flags` the reference policy would
    /// compute from the state delta between consecutive entries
    /// ([`Error::FlagMismatch`]). An account holder who addresses an element to an
    /// unused `committeeVersion` still causes it to be skipped rather than rejected;
    /// if that element is the epoch's final operation, no `SeqGap` appears either.
    /// `skipped_other_kind`/`skipped_stale_version` make that case visible to a reader
    /// rather than invisible, per SPEC:705.
    pub fn reconstruct_chain(
        &self,
        state_tag: Bytes32,
        current_committee_version: u64,
        elements: &[PayloadElement],
        subject: OwnerPubkey,
        epoch: Epoch,
        anchors: &BTreeSet<Bytes32>,
    ) -> Result<ChainReconstruction, Error> {
        let mut txs = Vec::new();
        let mut skipped_other_kind = 0usize;
        let mut skipped_stale_version = 0usize;

        for (index, element) in elements.iter().enumerate() {
            let committee_version = match element.kind {
                PayloadKind::ComplianceNoteToCommittee { committee_version } => {
                    committee_version
                }
                _ => {
                    skipped_other_kind += 1;
                    continue;
                }
            };
            if committee_version != current_committee_version {
                skipped_stale_version += 1;
                continue;
            }

            let (plaintext, _) = self
                .decrypt_committee_element(element)
                .map_err(|_| Error::UndecryptableElement { index })?;
            if plaintext.owner_pubkey != subject || plaintext.epoch != epoch {
                continue;
            }
            let commitment = plaintext.recompute_commitment(state_tag)?;
            txs.push(AuditedTx {
                seq: plaintext.seq,
                counterparty: plaintext.facts.counterparty,
                amount_out: plaintext.facts.amount_out,
                exit: plaintext.facts.exit,
                state: plaintext.state,
                flags: plaintext.flags,
                commitment,
            });
        }
        txs.sort_by_key(|tx| tx.seq.0);

        let mut prev_total = 0u64;
        for (position, tx) in txs.iter().enumerate() {
            if !anchors.contains(&tx.commitment) {
                return Err(Error::UnanchoredNote { seq: tx.seq.0 });
            }
            // Committed seqs start at 1: `compliance.nr` commits the successor note at
            // `inp.seq + 1`, and the reset chain's base case starts at `inp.seq == 0`.
            let expected_seq = position as u64 + 1;
            if tx.seq.0 != expected_seq {
                return Err(Error::SeqGap {
                    expected: expected_seq,
                    found: tx.seq.0,
                });
            }

            let total = tx.state[0];
            let value_out = total
                .checked_sub(prev_total)
                .ok_or(Error::FlagMismatch { seq: tx.seq.0 })?;
            let facts = TxFacts {
                epoch: epoch.0,
                seq: tx.seq.0,
                token: Fr::from(0u64),
                subject: Fr::from(0u64),
                counterparty: [Fr::from(0u64); 2],
                value_in: 0,
                value_out,
                exit: Fr::from(0u64),
            };
            let expected_flags =
                ReferencePolicy::evaluate(&facts, [prev_total], tx.state)
                    .expect("the reference policy's evaluate never blocks");
            if expected_flags != tx.flags {
                return Err(Error::FlagMismatch { seq: tx.seq.0 });
            }
            prev_total = total;
        }

        Ok(ChainReconstruction {
            txs,
            skipped_other_kind,
            skipped_stale_version,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        future::Future,
    };

    use ark_bn254::Fr;
    use tempfile::TempDir;

    use super::*;
    use crate::{
        adapters::commitment_tree::RotorMerkleTree,
        domain::{
            attestation::{
                AttestationLeaf,
                Generation,
            },
            keys::{
                AuditViewingPubkey,
                ComplianceViewingKey,
                SpendingKey,
                ViewingKey,
            },
            note::Note,
        },
        error::{
            ChainError,
            CryptoError,
        },
        policy::{
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
                LeafIndex,
                MerklePath,
                MerkleStore,
            },
            registry::{
                AttestationRecord,
                AttestationSource,
            },
        },
        types::{
            Address,
            Flags,
            Seq,
        },
        wallet::{
            OwnedNote,
            TransferOutput,
            TransferRequest,
            Wallet,
            WalletKeys,
        },
    };

    type TestTree = RotorMerkleTree<20>;

    fn open_tree() -> (TempDir, TestTree) {
        let dir = tempfile::tempdir().expect("create tmp dir");
        let tree = TestTree::open(dir.path()).expect("open tree");
        (dir, tree)
    }

    struct FixedClock(u64);
    impl Clock for FixedClock {
        fn now_unix(&self) -> u64 {
            self.0
        }
    }

    #[derive(Clone, Copy)]
    struct FakeChainReader {
        epoch: Epoch,
        registry: RegistrySnapshot,
        policy: PolicyPair,
    }
    impl ChainReader for FakeChainReader {
        fn current_epoch(
            &self,
        ) -> impl Future<Output = Result<Epoch, ChainError>> + Send {
            let epoch = self.epoch;
            async move { Ok(epoch) }
        }
        async fn commitment_root(&self) -> Result<Bytes32, ChainError> {
            Ok(Bytes32::from([0u8; 32]))
        }
        async fn is_known_commitment_root(
            &self,
            _root: Bytes32,
        ) -> Result<bool, ChainError> {
            Ok(true)
        }
        fn registry_values(
            &self,
        ) -> impl Future<Output = Result<RegistrySnapshot, ChainError>> + Send {
            let registry = self.registry;
            async move { Ok(registry) }
        }
        fn effective_policy(
            &self,
        ) -> impl Future<Output = Result<PolicyPair, ChainError>> + Send {
            let policy = self.policy;
            async move { Ok(policy) }
        }
        async fn is_nullifier_spent(
            &self,
            _nullifier: Bytes32,
        ) -> Result<bool, ChainError> {
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
        attestations: &TestTree,
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
            revoked_at: u64::MAX,
            revocation_proof: MerklePath::new(vec![]),
        }
    }

    fn small_bytes32(v: u8) -> Bytes32 {
        let mut bytes = [0u8; 32];
        bytes[31] = v;
        Bytes32::from(bytes)
    }

    #[tokio::test]
    async fn reconstructs_a_subjects_chain_from_committee_ciphertexts_alone() {
        let (_c_dir, commitments) = open_tree();
        let (_a_dir, attestations) = open_tree();
        let alice_sk = SpendingKey::random();
        let alice = alice_sk.derive_owner_pubkey();
        let bob = SpendingKey::random().derive_owner_pubkey();
        let attester = Address::from([0xaa; 20]);

        let alice_record = register_attestation(&attestations, alice, attester);
        let bob_record = register_attestation(&attestations, bob, attester);
        let attestation_root = attestations.root().expect("nonempty attestation tree");

        let mut records = HashMap::new();
        records.insert(owner_key(alice), alice_record);
        records.insert(owner_key(bob), bob_record);
        let attestation_source = FakeAttestationSource(records);

        let policy_source_hash = small_bytes32(7);
        let chain = FakeChainReader {
            epoch: Epoch(200),
            registry: RegistrySnapshot {
                attestation_root,
                attester_revocation_root: Bytes32::from([0u8; 32]),
                min_accepted_generation: 1,
            },
            policy: PolicyPair {
                verifier: Address::from([0u8; 20]),
                policy_source_hash,
            },
        };
        let clock = FixedClock(200 * crate::EPOCH_SECONDS);
        let audit_secret = AuditViewingKey::random();
        let committee_version = 3;
        let audit = FakeAuditEncryptor {
            pubkey: audit_secret.public_key(),
            version: committee_version,
        };

        let token = Address::from([0x11; 20]);
        let mut wallet = Wallet::new(
            commitments,
            attestations,
            WalletKeys {
                spending_key: alice_sk,
                compliance_viewing_key: ComplianceViewingKey::random(),
                viewing_key: ViewingKey::random(),
            },
        );

        let note = Note::new(token, 10_000, alice);
        let leaf_index = wallet
            .observe_commitment(note.commitment().unwrap())
            .unwrap();
        let mut current = OwnedNote { note, leaf_index };

        let mut payload_elements = Vec::new();
        for amount in [400u64, 600] {
            let remainder = current.note.amount - amount;
            let req = TransferRequest {
                token,
                inputs: [
                    current,
                    OwnedNote {
                        note: Note::zero(token, alice),
                        leaf_index: LeafIndex(0),
                    },
                ],
                outputs: [
                    TransferOutput {
                        owner: bob,
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
            let built = wallet
                .build_transfer(&chain, &clock, &audit, &attestation_source, req)
                .await
                .expect("transfer builds");
            payload_elements.extend(built.payload.elements().iter().cloned());
            current = OwnedNote {
                note: built.outputs[1],
                leaf_index: built.output_indices[1],
            };
        }

        let auditor = Auditor::new(audit_secret);
        let tag = Bytes32::from(state_tag::<ReferencePolicy>(
            Fr::try_from(policy_source_hash).unwrap(),
        ));

        // No chain exists in this unit test, so the anchor set is built the same way
        // the elements themselves decrypt: every current-version committee element's
        // recomputed commitment is a leaf the wallet genuinely inserted.
        let mut anchors = BTreeSet::new();
        for element in &payload_elements {
            if let Ok((plaintext, version)) = auditor.decrypt_committee_element(element)
                && version == committee_version
            {
                anchors.insert(plaintext.recompute_commitment(tag).unwrap());
            }
        }

        let chain_of_txs = auditor
            .reconstruct_chain(
                tag,
                committee_version,
                &payload_elements,
                alice,
                Epoch(200),
                &anchors,
            )
            .expect("reconstructs from ciphertexts alone")
            .txs;

        assert_eq!(chain_of_txs.len(), 2);
        // Committed seqs, not transaction seqs: `compliance.nr` hashes `inp.seq + 1`
        // into `state_out`, so the transaction at seq k commits its note at k + 1.
        assert_eq!(chain_of_txs[0].seq, Seq(1));
        assert_eq!(chain_of_txs[1].seq, Seq(2));
        assert_eq!(chain_of_txs[0].amount_out[0], 400);
        assert_eq!(chain_of_txs[0].counterparty[0], bob.as_bytes32());
        assert_eq!(chain_of_txs[1].amount_out[0], 600);
        assert_eq!(chain_of_txs[1].counterparty[0], bob.as_bytes32());

        let final_state = chain_of_txs.last().expect("two entries").state;
        assert_eq!(final_state, [400 + 600]);
        assert_eq!(Some(final_state), wallet.current_state());
    }

    #[test]
    fn decrypt_committee_element_rejects_the_wrong_kind() {
        let audit_secret = AuditViewingKey::random();
        let auditor = Auditor::new(audit_secret);
        let element = PayloadElement {
            kind: PayloadKind::ValueNote,
            ciphertext: vec![0u8; 4],
        };
        assert!(matches!(
            auditor.decrypt_committee_element(&element),
            Err(Error::WrongElementKind)
        ));
    }

    /// A ciphertext genuinely encrypted under committee version 1's AAD, then
    /// relabeled on the wire as version 2. Version 2 is what `reconstruct_chain` is
    /// told is current, so the relabeled element is not a stale-version skip; the AAD
    /// binding means it still fails to decrypt, and that failure must be a hard error.
    #[test]
    fn reconstruct_chain_errors_on_a_relabeled_committee_version_matching_current() {
        let audit_secret = AuditViewingKey::random();
        let audit_pubkey = audit_secret.public_key();
        let auditor = Auditor::new(audit_secret);

        let subject = SpendingKey::random().derive_owner_pubkey();
        let epoch = Epoch(1);
        let plaintext = CompliancePlaintext {
            owner_pubkey: subject,
            epoch,
            seq: Seq(1),
            salt: Bytes32::from([1u8; 32]),
            flags: Flags::NONE,
            state: [0],
            facts: crate::domain::compliance_note::Facts {
                counterparty: [Bytes32::from([0u8; 32]); 2],
                amount_out: [0, 0],
                exit: Bytes32::from([0u8; 32]),
            },
        };

        let ciphertext_under_v1 = {
            let kind = PayloadKind::ComplianceNoteToCommittee {
                committee_version: 1,
            };
            audit_pubkey.encrypt(&plaintext.encode(), &kind.aad())
        };
        let relabeled_as_v2 = PayloadElement {
            kind: PayloadKind::ComplianceNoteToCommittee {
                committee_version: 2,
            },
            ciphertext: ciphertext_under_v1,
        };

        let err = auditor
            .reconstruct_chain(
                Bytes32::from([0u8; 32]),
                2,
                &[relabeled_as_v2],
                subject,
                epoch,
                &BTreeSet::new(),
            )
            .expect_err("a version-2 label over a version-1 ciphertext must not decrypt");
        assert!(matches!(err, Error::UndecryptableElement { index: 0 }));
    }

    /// A two-transfer chain (seq 1, seq 2), plus the material a test needs to mutate
    /// one element or the anchor set before calling `reconstruct_chain` again.
    struct TestChain {
        auditor: Auditor,
        audit_pubkey: AuditViewingPubkey,
        elements: Vec<PayloadElement>,
        tag: Bytes32,
        committee_version: u64,
        anchors: BTreeSet<Bytes32>,
        subject: OwnerPubkey,
        epoch: Epoch,
    }

    async fn build_two_transfer_chain() -> TestChain {
        let (_c_dir, commitments) = open_tree();
        let (_a_dir, attestations) = open_tree();
        let alice_sk = SpendingKey::random();
        let alice = alice_sk.derive_owner_pubkey();
        let bob = SpendingKey::random().derive_owner_pubkey();
        let attester = Address::from([0xaa; 20]);

        let alice_record = register_attestation(&attestations, alice, attester);
        let bob_record = register_attestation(&attestations, bob, attester);
        let attestation_root = attestations.root().expect("nonempty attestation tree");

        let mut records = HashMap::new();
        records.insert(owner_key(alice), alice_record);
        records.insert(owner_key(bob), bob_record);
        let attestation_source = FakeAttestationSource(records);

        let policy_source_hash = small_bytes32(7);
        let chain_reader = FakeChainReader {
            epoch: Epoch(200),
            registry: RegistrySnapshot {
                attestation_root,
                attester_revocation_root: Bytes32::from([0u8; 32]),
                min_accepted_generation: 1,
            },
            policy: PolicyPair {
                verifier: Address::from([0u8; 20]),
                policy_source_hash,
            },
        };
        let clock = FixedClock(200 * crate::EPOCH_SECONDS);
        let audit_secret = AuditViewingKey::random();
        let audit_pubkey = audit_secret.public_key();
        let committee_version = 3;
        let audit = FakeAuditEncryptor {
            pubkey: audit_pubkey.clone(),
            version: committee_version,
        };

        let token = Address::from([0x11; 20]);
        let mut wallet = Wallet::new(
            commitments,
            attestations,
            WalletKeys {
                spending_key: alice_sk,
                compliance_viewing_key: ComplianceViewingKey::random(),
                viewing_key: ViewingKey::random(),
            },
        );

        let note = Note::new(token, 10_000, alice);
        let leaf_index = wallet
            .observe_commitment(note.commitment().unwrap())
            .unwrap();
        let mut current = OwnedNote { note, leaf_index };

        let mut elements = Vec::new();
        for amount in [400u64, 600u64] {
            let remainder = current.note.amount - amount;
            let req = TransferRequest {
                token,
                inputs: [
                    current,
                    OwnedNote {
                        note: Note::zero(token, alice),
                        leaf_index: LeafIndex(0),
                    },
                ],
                outputs: [
                    TransferOutput {
                        owner: bob,
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
            let built = wallet
                .build_transfer(&chain_reader, &clock, &audit, &attestation_source, req)
                .await
                .expect("transfer builds");
            elements.extend(built.payload.elements().iter().cloned());
            current = OwnedNote {
                note: built.outputs[1],
                leaf_index: built.output_indices[1],
            };
        }

        let auditor = Auditor::new(audit_secret);
        let tag = Bytes32::from(state_tag::<ReferencePolicy>(
            Fr::try_from(policy_source_hash).unwrap(),
        ));

        let mut anchors = BTreeSet::new();
        for element in &elements {
            if let Ok((plaintext, version)) = auditor.decrypt_committee_element(element)
                && version == committee_version
            {
                anchors.insert(plaintext.recompute_commitment(tag).unwrap());
            }
        }

        TestChain {
            auditor,
            audit_pubkey,
            elements,
            tag,
            committee_version,
            anchors,
            subject: alice,
            epoch: Epoch(200),
        }
    }

    #[tokio::test]
    async fn a_commitment_absent_from_anchors_is_rejected() {
        let chain = build_two_transfer_chain().await;
        let err = chain
            .auditor
            .reconstruct_chain(
                chain.tag,
                chain.committee_version,
                &chain.elements,
                chain.subject,
                chain.epoch,
                &BTreeSet::new(),
            )
            .expect_err("no anchors are observed, so nothing anchors");
        assert!(matches!(err, Error::UnanchoredNote { seq: 1 }));
    }

    #[tokio::test]
    async fn a_missing_middle_seq_is_rejected_as_a_gap() {
        let mut chain = build_two_transfer_chain().await;
        chain.elements.retain(|element| {
            !matches!(
                chain.auditor.decrypt_committee_element(element),
                Ok((plaintext, _)) if plaintext.seq == Seq(1)
            )
        });
        let err = chain
            .auditor
            .reconstruct_chain(
                chain.tag,
                chain.committee_version,
                &chain.elements,
                chain.subject,
                chain.epoch,
                &chain.anchors,
            )
            .expect_err("seq 1 is missing, seq 2 alone leaves a gap at position 0");
        assert!(matches!(
            err,
            Error::SeqGap {
                expected: 1,
                found: 2
            }
        ));
    }

    #[tokio::test]
    async fn a_tampered_flags_value_is_rejected() {
        let mut chain = build_two_transfer_chain().await;
        let (index, plaintext, version) = chain
            .elements
            .iter()
            .enumerate()
            .find_map(|(i, element)| {
                let (plaintext, version) =
                    chain.auditor.decrypt_committee_element(element).ok()?;
                (plaintext.seq == Seq(1)).then_some((i, plaintext, version))
            })
            .expect("seq 1's committee element exists");

        let original_commitment = plaintext.recompute_commitment(chain.tag).unwrap();
        let mut tampered = plaintext;
        tampered.flags = tampered.flags.union(Flags::FLAG_AGGREGATE);
        let tampered_commitment = tampered.recompute_commitment(chain.tag).unwrap();

        // The tampered note is the one this test says the pool accepted: only its
        // stated flags are dishonest, not its anchoring.
        chain.anchors.remove(&original_commitment);
        chain.anchors.insert(tampered_commitment);

        let kind = PayloadKind::ComplianceNoteToCommittee {
            committee_version: version,
        };
        chain.elements[index] = PayloadElement {
            kind,
            ciphertext: chain.audit_pubkey.encrypt(&tampered.encode(), &kind.aad()),
        };

        let err = chain
            .auditor
            .reconstruct_chain(
                chain.tag,
                chain.committee_version,
                &chain.elements,
                chain.subject,
                chain.epoch,
                &chain.anchors,
            )
            .expect_err("a 400-unit transfer cannot honestly flag FLAG_AGGREGATE");
        assert!(matches!(err, Error::FlagMismatch { seq: 1 }));
    }

    #[tokio::test]
    async fn a_retired_committee_version_is_a_counted_skip_not_a_rejection() {
        let mut chain = build_two_transfer_chain().await;
        chain.elements.push(PayloadElement {
            kind: PayloadKind::ComplianceNoteToCommittee {
                committee_version: chain.committee_version + 1,
            },
            // Never decrypted: the version check runs before decryption is attempted.
            ciphertext: vec![0u8; 4],
        });

        let reconstruction = chain
            .auditor
            .reconstruct_chain(
                chain.tag,
                chain.committee_version,
                &chain.elements,
                chain.subject,
                chain.epoch,
                &chain.anchors,
            )
            .expect("the retired-version element is skipped, not rejected");
        assert_eq!(reconstruction.txs.len(), 2);
        assert_eq!(reconstruction.skipped_stale_version, 1);
    }
}

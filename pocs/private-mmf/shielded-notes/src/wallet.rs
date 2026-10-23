//! The investor's wallet: finds its notes by trial-decrypting recipient payloads,
//! and builds owner-path deposits, transfers and withdrawals. The building blocks
//! here are shared with the transfer agent, whose claim path differs only in who
//! signs and which checks the circuit runs.

use ark_bn254::Fr;

use crate::{
    chain::{
        ChainView,
        PoolEnv,
    },
    domain::{
        feed::{
            self,
            FEED_FIELDS,
            FeedSecret,
        },
        keys::{
            NullifierKey,
            PlanSigner,
            PublicSpendKey,
            Registration,
            ViewingKey,
            ViewingPubkey,
            WalletKeys,
            owner_value,
        },
        note::{
            self,
            LockOpening,
            NOTE_BYTES,
            Note,
        },
        plan::{
            OP_DEPOSIT,
            OP_TRANSFER,
            OP_WITHDRAW,
            PATH_CLAIM,
            PATH_OWNER,
            Plan,
        },
        random_fr,
        tree::MerkleProof,
        witness::{
            AttestationWitness,
            DepositWitness,
            InputWitness,
            TransferWitness,
            WithdrawWitness,
        },
    },
    error::ActorError,
    poseidon::fr_to_be_bytes,
    types::{
        Address,
        Bytes32,
    },
};

// ========== Recipient payload ==========

const PAYLOAD_AAD: &[u8] = b"shielded-notes-payload";

fn aad(j: usize) -> Vec<u8> {
    let mut a = PAYLOAD_AAD.to_vec();
    a.push(j as u8);
    a
}

/// The plaintext for output `j`: the note's five fields, then its lock opening,
/// so the recipient can spend a note whose holding period has ended.
fn plaintext(note: &Note, opening: &LockOpening) -> Vec<u8> {
    let mut p = note.encode();
    p.extend(opening.fields().iter().flat_map(fr_to_be_bytes));
    p
}

/// Concatenates one ciphertext per output, each prefixed with its length.
pub fn encrypt_payload(outputs: &[(Note, LockOpening, &ViewingPubkey)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (j, (note, opening, vpk)) in outputs.iter().enumerate() {
        let ct = vpk.encrypt(&plaintext(note, opening), &aad(j));
        out.extend((ct.len() as u32).to_be_bytes());
        out.extend(ct);
    }
    out
}

fn payload_element(payload: &[u8], j: usize) -> Option<&[u8]> {
    let mut rest = payload;
    for i in 0..=j {
        let len = u32::from_be_bytes(rest.get(..4)?.try_into().ok()?) as usize;
        let element = rest.get(4..4 + len)?;
        if i == j {
            return Some(element);
        }
        rest = &rest[4 + len..];
    }
    None
}

/// Trial decryption of output `j`'s element. `None` if it is not for `vk`.
pub fn decrypt_payload(
    vk: &ViewingKey,
    payload: &[u8],
    j: usize,
) -> Option<(Note, LockOpening)> {
    let bytes = vk.decrypt(payload_element(payload, j)?, &aad(j)).ok()?;
    if bytes.len() != NOTE_BYTES + 96 {
        return None;
    }
    let note = Note::decode(&bytes[..NOTE_BYTES]).ok()?;
    let word = |i: usize| -> Option<Fr> {
        let w: [u8; 32] = bytes[NOTE_BYTES + 32 * i..NOTE_BYTES + 32 * (i + 1)]
            .try_into()
            .ok()?;
        Fr::try_from(Bytes32::from(w)).ok()
    };
    let opening = LockOpening::from_fields([word(0)?, word(1)?, word(2)?])?;
    Some((note, opening))
}

// ========== Shared building blocks ==========

/// The attestation witness for `owner`, from the registry's events.
pub fn attestation_witness(
    view: &ChainView,
    env: &PoolEnv,
    owner: Fr,
) -> Option<AttestationWitness> {
    let r = view.attestation_of(owner, env.epoch, env.min_accepted_generation)?;
    Some(AttestationWitness {
        attester: r.attester,
        generation: r.generation,
        issued_at: r.issued_at,
        expires_at: r.expires_at,
        path: view.attestations.proof(r.leaf_index)?,
    })
}

/// A witness the circuit never checks: the claim path's input owner, and its
/// outputs that stay with that owner.
fn unchecked_attestation() -> AttestationWitness {
    AttestationWitness {
        attester: Address::from([0; 20]),
        generation: 0,
        issued_at: 0,
        expires_at: 0,
        path: MerkleProof::default(),
    }
}

fn require_attestation(
    view: &ChainView,
    env: &PoolEnv,
    owner: Fr,
) -> Result<AttestationWitness, ActorError> {
    attestation_witness(view, env, owner)
        .ok_or(ActorError::NotAttested(Bytes32::from(owner)))
}

/// A note this actor can spend: its opening, lock terms and leaf.
#[derive(Debug, Clone, Copy)]
pub struct OwnedNote {
    pub note: Note,
    pub opening: LockOpening,
    pub commitment: Fr,
    pub leaf_index: usize,
    pub spent: bool,
}

impl OwnedNote {
    /// Fails if the view lacks the note at its leaf: a view older than the
    /// note, or a wrong leaf index, which would otherwise prove a wrong path.
    fn input(&self, view: &ChainView) -> Result<InputWitness, ActorError> {
        let path = view
            .commitments
            .proof(self.leaf_index)
            .filter(|_| view.commitments.leaf(self.leaf_index) == self.commitment)
            .ok_or(ActorError::UnknownNote(Bytes32::from(self.commitment)))?;
        Ok(InputWitness {
            units: self.note.units,
            salt: self.note.salt,
            lock: self.note.lock,
            lock_opening: self.opening,
            path,
        })
    }
}

/// One output of a transfer: the note, its lock terms, and who can read it.
#[derive(Debug, Clone)]
pub struct Output {
    pub owner: Fr,
    pub units: u64,
    pub opening: LockOpening,
    pub vpk: ViewingPubkey,
}

/// Everything a transfer needs that differs between the owner path and the claim path.
pub struct TransferSpec {
    pub claim: bool,
    pub owner_key: PublicSpendKey,
    pub nk: NullifierKey,
    pub claim_key: PublicSpendKey,
    pub inputs: Vec<OwnedNote>,
    pub outputs: [Output; 2],
}

/// A built transfer: the witness, the recipient payload, and the output notes.
#[derive(Clone)]
pub struct BuiltTransfer {
    pub witness: TransferWitness,
    pub payload: Vec<u8>,
    pub outputs: [Note; 2],
}

// ========== Prepare, sign, finish ==========
//
// A spend is built in three steps (SPEC, Transaction Plan). `prepare_*` fixes
// the plan from the notes alone. The custody signer then approves it, which can
// take hours. `finish` takes the roots, the Merkle paths and the register key
// from the chain as it is at that moment, and builds the register feed and the
// witness. Roots taken before the signature would show how long the approval
// took, and could leave the pool's root window. None of them is in the plan,
// so taking them late needs no new signature.

/// The circuit accepts the plan only while `(epoch + 1) * EPOCH_SECONDS <= expiry`.
fn require_unexpired(plan: &Plan, env: &PoolEnv) -> Result<(), ActorError> {
    if (env.epoch + 1) * crate::EPOCH_SECONDS > plan.expiry {
        return Err(ActorError::PlanExpired {
            expiry: plan.expiry,
            epoch: env.epoch,
        });
    }
    Ok(())
}

/// A transfer whose plan is fixed, awaiting the custody signer.
#[derive(Clone)]
pub struct PendingTransfer {
    pub plan: Plan,
    /// The output openings the signer checks the plan against.
    pub outputs: [Note; 2],
    output_locks: [LockOpening; 2],
    claim: bool,
    owner_key: PublicSpendKey,
    nk: NullifierKey,
    claim_key: PublicSpendKey,
    inputs: Vec<OwnedNote>,
    /// The zero-unit input of a one-input transfer. Its salt is fixed here,
    /// since it sets the second nullifier, which the plan covers.
    padding: Option<InputWitness>,
    payload: Vec<u8>,
}

pub fn prepare_transfer(
    spec: TransferSpec,
    env: &PoolEnv,
) -> Result<PendingTransfer, ActorError> {
    if spec.inputs.is_empty() || spec.inputs.len() > 2 {
        return Err(ActorError::InputCount(spec.inputs.len()));
    }
    let owner_in = owner_value(&spec.owner_key, &spec.nk);
    let token = Fr::from(env.token);

    let padding = (spec.inputs.len() == 1).then(|| InputWitness::padding(random_fr()));
    let second = match &padding {
        Some(p) => Note {
            token,
            units: p.units,
            owner: owner_in,
            salt: p.salt,
            lock: p.lock,
        }
        .commitment(),
        None => spec.inputs[1].commitment,
    };
    let nullifiers = [
        note::nullifier(spec.inputs[0].commitment, &spec.nk),
        note::nullifier(second, &spec.nk),
    ];

    let outputs = spec.outputs.clone().map(|o| Note {
        token,
        units: o.units,
        owner: o.owner,
        salt: random_fr(),
        lock: o.opening.value(),
    });
    let output_locks = [spec.outputs[0].opening, spec.outputs[1].opening];
    let payload = encrypt_payload(&[
        (outputs[0], output_locks[0], &spec.outputs[0].vpk),
        (outputs[1], output_locks[1], &spec.outputs[1].vpk),
    ]);

    let plan = Plan {
        chain_id: env.chain_id,
        pool: env.pool,
        op: OP_TRANSFER,
        path: if spec.claim { PATH_CLAIM } else { PATH_OWNER },
        nullifiers,
        outputs: [outputs[0].commitment(), outputs[1].commitment()],
        public_units: 0,
        recipient: Fr::from(0u64),
        expiry: env.expiry(),
    };
    Ok(PendingTransfer {
        plan,
        outputs,
        output_locks,
        claim: spec.claim,
        owner_key: spec.owner_key,
        nk: spec.nk,
        claim_key: spec.claim_key,
        inputs: spec.inputs,
        padding,
        payload,
    })
}

impl PendingTransfer {
    /// Builds the witness from the chain as it is now, with the custody
    /// signer's signature over `plan`.
    pub fn finish(
        self,
        signature: [u8; 64],
        view: &ChainView,
        env: &PoolEnv,
    ) -> Result<BuiltTransfer, ActorError> {
        require_unexpired(&self.plan, env)?;
        let owner_in = owner_value(&self.owner_key, &self.nk);

        let mut inputs: Vec<InputWitness> = self
            .inputs
            .iter()
            .map(|n| n.input(view))
            .collect::<Result<_, _>>()?;
        inputs.extend(self.padding);

        let input_attestation = if self.claim {
            unchecked_attestation()
        } else {
            require_attestation(view, env, owner_in)?
        };
        let mut output_attestations = Vec::with_capacity(2);
        for out in &self.outputs {
            let needed = !self.claim || out.owner != owner_in;
            output_attestations.push(if needed {
                require_attestation(view, env, out.owner)?
            } else {
                attestation_witness(view, env, out.owner)
                    .unwrap_or_else(unchecked_attestation)
            });
        }

        let feed_secret = FeedSecret::random();
        let (feed_r, k) = feed::derive(&feed_secret, &env.register_key);
        let mut feed_ct = [Fr::from(0u64); 2 * FEED_FIELDS];
        for (j, out) in self.outputs.iter().enumerate() {
            feed_ct[FEED_FIELDS * j..FEED_FIELDS * (j + 1)].copy_from_slice(
                &feed::encrypt(k, &feed::fields(out, &self.output_locks[j]), j),
            );
        }

        let witness = TransferWitness {
            nullifiers: self.plan.nullifiers,
            commitments_out: self.plan.outputs,
            commitment_root: view.commitments.root(),
            attestation_root: view.attestations.root(),
            min_accepted_generation: env.min_accepted_generation,
            epoch: env.epoch,
            chain_id: env.chain_id,
            pool: env.pool,
            claim_key_hash: env.claim_key_hash,
            register_key: env.register_key,
            feed_r,
            feed_ct,
            payload_commitment: payload_commitment(&self.payload),
            claim: self.claim,
            token: env.token,
            owner_key: self.owner_key,
            nk: self.nk.0,
            claim_key: self.claim_key,
            signature,
            expiry: self.plan.expiry,
            inputs: [inputs[0].clone(), inputs[1].clone()],
            outputs: self.outputs,
            output_locks: self.output_locks,
            input_attestation,
            output_attestations: [
                output_attestations[0].clone(),
                output_attestations[1].clone(),
            ],
            feed_secret,
        };
        Ok(BuiltTransfer {
            witness,
            payload: self.payload,
            outputs: self.outputs,
        })
    }
}

/// Prepares, signs and finishes at once, from one view of the chain, for a
/// signer that answers at once.
pub fn build_transfer(
    spec: TransferSpec,
    signer: &dyn PlanSigner,
    view: &ChainView,
    env: &PoolEnv,
) -> Result<BuiltTransfer, ActorError> {
    let pending = prepare_transfer(spec, env)?;
    let signature = signer.sign_plan(&pending.plan, &pending.outputs)?;
    pending.finish(signature, view, env)
}

/// A deposit whose plan is fixed, awaiting the custody signer.
#[derive(Clone)]
pub struct PendingDeposit {
    pub plan: Plan,
    /// The new note, which the signer checks the plan against.
    pub note: Note,
    owner_key: PublicSpendKey,
    nk: NullifierKey,
    funder: Address,
    payload: Vec<u8>,
}

impl PendingDeposit {
    /// Builds the witness from the chain as it is now, with the custody
    /// signer's signature over `plan`. Returns it with the recipient payload.
    pub fn finish(
        self,
        signature: [u8; 64],
        view: &ChainView,
        env: &PoolEnv,
    ) -> Result<(DepositWitness, Vec<u8>), ActorError> {
        require_unexpired(&self.plan, env)?;
        let attestation =
            require_attestation(view, env, owner_value(&self.owner_key, &self.nk))?;
        let feed_secret = FeedSecret::random();
        let (feed_r, k) = feed::derive(&feed_secret, &env.register_key);
        let feed_ct = feed::encrypt(k, &feed::fields(&self.note, &LockOpening::NONE), 0);
        let witness = DepositWitness {
            commitment: self.note.commitment(),
            token: env.token,
            units: self.note.units,
            funding_address: self.funder,
            attestation_root: view.attestations.root(),
            min_accepted_generation: env.min_accepted_generation,
            epoch: env.epoch,
            chain_id: env.chain_id,
            pool: env.pool,
            register_key: env.register_key,
            feed_r,
            feed_ct,
            payload_commitment: payload_commitment(&self.payload),
            owner_key: self.owner_key,
            nk: self.nk.0,
            signature,
            expiry: self.plan.expiry,
            salt: self.note.salt,
            attestation,
            feed_secret,
        };
        Ok((witness, self.payload))
    }
}

/// A withdrawal whose plan is fixed, awaiting the custody signer.
#[derive(Clone)]
pub struct PendingWithdraw {
    pub plan: Plan,
    owned: OwnedNote,
    owner_key: PublicSpendKey,
    nk: NullifierKey,
    recipient: Address,
}

impl PendingWithdraw {
    /// Builds the witness from the chain as it is now, with the custody
    /// signer's signature over `plan`.
    pub fn finish(
        self,
        signature: [u8; 64],
        view: &ChainView,
        env: &PoolEnv,
    ) -> Result<WithdrawWitness, ActorError> {
        require_unexpired(&self.plan, env)?;
        let attestation =
            require_attestation(view, env, owner_value(&self.owner_key, &self.nk))?;
        Ok(WithdrawWitness {
            nullifier: self.plan.nullifiers[0],
            token: env.token,
            units: self.owned.note.units,
            recipient: self.recipient,
            commitment_root: view.commitments.root(),
            attestation_root: view.attestations.root(),
            min_accepted_generation: env.min_accepted_generation,
            epoch: env.epoch,
            chain_id: env.chain_id,
            pool: env.pool,
            owner_key: self.owner_key,
            nk: self.nk.0,
            signature,
            expiry: self.plan.expiry,
            input: self.owned.input(view)?,
            attestation,
        })
    }
}

/// keccak256 of the payload, reduced into the field, as the pool computes it.
pub fn payload_commitment(payload: &[u8]) -> Fr {
    use ark_ff::PrimeField;
    Fr::from_be_bytes_mod_order(alloy::primitives::keccak256(payload).as_slice())
}

// ========== The wallet ==========

/// Holds `pk`, `nk` and the viewing key, never `sk`: every plan goes to the
/// custody signer, a `PlanSigner` the holder keeps apart (SPEC, Key Model).
#[derive(Debug)]
pub struct Wallet {
    pub keys: WalletKeys,
    pub notes: Vec<OwnedNote>,
}

impl Wallet {
    pub fn new(keys: WalletKeys) -> Self {
        Self {
            keys,
            notes: Vec::new(),
        }
    }

    pub fn owner(&self) -> Fr {
        self.keys.owner()
    }

    pub fn vpk(&self) -> ViewingPubkey {
        self.keys.view.public_key()
    }

    /// The registration the investor sends the transfer agent for this pool
    /// (SPEC, Onboarding, step 2), under the investor ID the agent assigned it,
    /// for its custody signer to sign. It carries `nk`'s hash; the wallet sends
    /// `nk` itself to the agent alongside, and never to the signer.
    pub fn registration(&self, env: &PoolEnv, investor_id: &str) -> Registration {
        Registration {
            chain_id: env.chain_id,
            pool: env.pool,
            investor_id: investor_id.to_string(),
            pk: self.keys.pk,
            nk_hash: self.keys.nk.hash(),
            vpk: self.vpk(),
        }
    }

    /// Finds new notes by trial-decrypting every recipient payload, and marks
    /// spent the ones whose nullifiers the pool has recorded.
    pub fn scan(&mut self, view: &ChainView) {
        let owner = self.owner();
        for record in &view.notes {
            if self.notes.iter().any(|n| n.commitment == record.commitment) {
                continue;
            }
            let Some((note, opening)) =
                decrypt_payload(&self.keys.view, &record.payload, record.output)
            else {
                continue;
            };
            if note.owner == owner && note.commitment() == record.commitment {
                self.notes.push(OwnedNote {
                    note,
                    opening,
                    commitment: record.commitment,
                    leaf_index: record.leaf_index,
                    spent: false,
                });
            }
        }
        for n in &mut self.notes {
            n.spent = view
                .nullifiers
                .contains(&note::nullifier(n.commitment, &self.keys.nk));
        }
    }

    /// Unspent notes the owner path can move at `epoch`.
    pub fn spendable(&self, epoch: u64) -> Vec<OwnedNote> {
        self.notes
            .iter()
            .filter(|n| {
                !n.spent
                    && n.note.units > 0
                    && (n.note.lock == Fr::from(0u64) || epoch >= n.opening.release_after)
            })
            .copied()
            .collect()
    }

    pub fn balance(&self, epoch: u64) -> u64 {
        self.spendable(epoch).iter().map(|n| n.note.units).sum()
    }

    /// Step one of a deposit of `units` into this wallet's own owner value,
    /// paid by `funder`: the plan, for the custody signer.
    pub fn prepare_deposit(
        &self,
        env: &PoolEnv,
        units: u64,
        funder: Address,
    ) -> PendingDeposit {
        let note = Note {
            token: Fr::from(env.token),
            units,
            owner: self.owner(),
            salt: random_fr(),
            lock: Fr::from(0u64),
        };
        let payload = encrypt_payload(&[(note, LockOpening::NONE, &self.vpk())]);
        let plan = Plan {
            chain_id: env.chain_id,
            pool: env.pool,
            op: OP_DEPOSIT,
            path: PATH_OWNER,
            nullifiers: [Fr::from(0u64); 2],
            outputs: [note.commitment(), Fr::from(0u64)],
            public_units: units,
            recipient: Fr::from(funder),
            expiry: env.expiry(),
        };
        PendingDeposit {
            plan,
            note,
            owner_key: self.keys.pk,
            nk: self.keys.nk,
            funder,
            payload,
        }
    }

    /// A deposit, prepared, signed by `signer` and finished at once.
    pub fn deposit(
        &self,
        signer: &dyn PlanSigner,
        view: &ChainView,
        env: &PoolEnv,
        units: u64,
        funder: Address,
    ) -> Result<(DepositWitness, Vec<u8>), ActorError> {
        let pending = self.prepare_deposit(env, units, funder);
        let signature = signer.sign_plan(&pending.plan, &[pending.note])?;
        pending.finish(signature, view, env)
    }

    /// An owner-path transfer of exactly these inputs into these outputs,
    /// signed by `signer`.
    pub fn transfer(
        &self,
        signer: &dyn PlanSigner,
        view: &ChainView,
        env: &PoolEnv,
        inputs: Vec<OwnedNote>,
        outputs: [Output; 2],
    ) -> Result<BuiltTransfer, ActorError> {
        build_transfer(
            TransferSpec {
                claim: false,
                owner_key: self.keys.pk,
                nk: self.keys.nk,
                claim_key: self.keys.pk,
                inputs,
                outputs,
            },
            signer,
            view,
            env,
        )
    }

    /// Step one of an owner-path transfer of exactly these inputs into these
    /// outputs: the plan, for the custody signer.
    pub fn prepare_transfer(
        &self,
        env: &PoolEnv,
        inputs: Vec<OwnedNote>,
        outputs: [Output; 2],
    ) -> Result<PendingTransfer, ActorError> {
        prepare_transfer(
            TransferSpec {
                claim: false,
                owner_key: self.keys.pk,
                nk: self.keys.nk,
                claim_key: self.keys.pk,
                inputs,
                outputs,
            },
            env,
        )
    }

    /// Pays `units` to `to`, with the change back to this wallet. Uses the
    /// smallest single note that covers it, else the two largest.
    pub fn pay(
        &self,
        signer: &dyn PlanSigner,
        view: &ChainView,
        env: &PoolEnv,
        to: Fr,
        to_vpk: ViewingPubkey,
        units: u64,
    ) -> Result<BuiltTransfer, ActorError> {
        let mut notes = self.spendable(env.epoch);
        notes.sort_by_key(|n| n.note.units);
        let inputs = match notes.iter().find(|n| n.note.units >= units) {
            Some(n) => vec![*n],
            None => {
                let top: Vec<OwnedNote> = notes.iter().rev().take(2).copied().collect();
                let have: u64 = top.iter().map(|n| n.note.units).sum();
                if have < units {
                    return Err(ActorError::InsufficientUnits { have, need: units });
                }
                top
            }
        };
        let total: u64 = inputs.iter().map(|n| n.note.units).sum();
        self.transfer(
            signer,
            view,
            env,
            inputs,
            [
                Output {
                    owner: to,
                    units,
                    opening: LockOpening::NONE,
                    vpk: to_vpk,
                },
                Output {
                    owner: self.owner(),
                    units: total - units,
                    opening: LockOpening::NONE,
                    vpk: self.vpk(),
                },
            ],
        )
    }

    /// Step one of withdrawing one whole note to a public address: the plan,
    /// for the custody signer.
    pub fn prepare_withdraw(
        &self,
        env: &PoolEnv,
        owned: &OwnedNote,
        recipient: Address,
    ) -> PendingWithdraw {
        let plan = Plan {
            chain_id: env.chain_id,
            pool: env.pool,
            op: OP_WITHDRAW,
            path: PATH_OWNER,
            nullifiers: [
                note::nullifier(owned.commitment, &self.keys.nk),
                Fr::from(0u64),
            ],
            outputs: [Fr::from(0u64); 2],
            public_units: owned.note.units,
            recipient: Fr::from(recipient),
            expiry: env.expiry(),
        };
        PendingWithdraw {
            plan,
            owned: *owned,
            owner_key: self.keys.pk,
            nk: self.keys.nk,
            recipient,
        }
    }

    /// Withdraws one whole note to a public address: prepared, signed by
    /// `signer` and finished at once.
    pub fn withdraw(
        &self,
        signer: &dyn PlanSigner,
        view: &ChainView,
        env: &PoolEnv,
        owned: &OwnedNote,
        recipient: Address,
    ) -> Result<WithdrawWitness, ActorError> {
        let pending = self.prepare_withdraw(env, owned, recipient);
        let signature = signer.sign_plan(&pending.plan, &[])?;
        pending.finish(signature, view, env)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::keys::OwnerKeys;

    fn env_at(epoch: u64) -> PoolEnv {
        PoolEnv {
            chain_id: 31337,
            pool: Address::from([1; 20]),
            token: Address::from([2; 20]),
            register_key: FeedSecret::random().public_point(),
            claim_key_hash: Fr::from(0u64),
            min_accepted_generation: 0,
            epoch,
            timestamp: epoch * crate::EPOCH_SECONDS,
        }
    }

    /// A plan signed in epoch 100 expires at the midnight that ends epoch 101.
    /// Finished in epoch 101 it gets as far as reading the chain (here, an
    /// attestation the empty view lacks); in epoch 102 it is refused first.
    #[test]
    fn a_plan_is_usable_until_its_midnight() {
        let (signer, keys) = OwnerKeys::random().split();
        let wallet = Wallet::new(keys);
        let signed_at = env_at(100);
        assert_eq!(signed_at.expiry(), 102 * crate::EPOCH_SECONDS);
        let finish_at = |epoch| {
            let pending = wallet.prepare_deposit(&signed_at, 5, Address::from([3; 20]));
            let signature = signer.sign_plan(&pending.plan, &[pending.note]).unwrap();
            pending.finish(signature, &ChainView::default(), &env_at(epoch))
        };
        assert!(matches!(finish_at(101), Err(ActorError::NotAttested(_))));
        assert!(matches!(
            finish_at(102),
            Err(ActorError::PlanExpired { epoch: 102, .. })
        ));
    }

    #[test]
    fn payload_round_trips_for_its_recipient_only() {
        let alice = ViewingKey::random();
        let bob = ViewingKey::random();
        let note = Note {
            token: Fr::from(1u64),
            units: 5,
            owner: Fr::from(2u64),
            salt: Fr::from(3u64),
            lock: LockOpening::hold(9).value(),
        };
        let payload = encrypt_payload(&[
            (note, LockOpening::hold(9), &alice.public_key()),
            (note, LockOpening::NONE, &bob.public_key()),
        ]);
        assert_eq!(
            decrypt_payload(&alice, &payload, 0),
            Some((note, LockOpening::hold(9)))
        );
        assert_eq!(
            decrypt_payload(&bob, &payload, 1),
            Some((note, LockOpening::NONE))
        );
        assert_eq!(decrypt_payload(&bob, &payload, 0), None);
    }

    /// A holder hands its viewing key, and only that, to an auditor (SPEC, Key
    /// Model). Scanning the pool's payloads, the auditor finds every note sent
    /// to the holder, the change from its own payment included, and none sent
    /// to anyone else. Without `nk` it cannot tell which are spent; the
    /// holder's wallet can.
    #[test]
    fn an_auditor_with_the_holders_vk_reads_its_received_notes_only() {
        let (_, alice) = OwnerKeys::random().split();
        let (_, bob) = OwnerKeys::random().split();
        let (alice_vpk, bob_vpk) = (alice.view.public_key(), bob.view.public_key());
        let note = |owner: Fr, units| Note {
            token: Fr::from(1u64),
            units,
            owner,
            salt: random_fr(),
            lock: Fr::from(0u64),
        };
        // Bob pays Alice 100; Alice then pays Bob 40, with 60 back as change.
        let received = note(alice.owner(), 100);
        let operations = [
            [(received, &alice_vpk), (note(bob.owner(), 0), &bob_vpk)],
            [
                (note(bob.owner(), 40), &bob_vpk),
                (note(alice.owner(), 60), &alice_vpk),
            ],
        ];
        let mut view = ChainView::default();
        for outputs in &operations {
            let payload =
                encrypt_payload(&outputs.map(|(n, vpk)| (n, LockOpening::NONE, vpk)));
            for (j, (n, _)) in outputs.iter().enumerate() {
                view.notes.push(crate::chain::NoteRecord {
                    commitment: n.commitment(),
                    leaf_index: view.notes.len(),
                    output: j,
                    feed_r: FeedSecret::random().public_point(),
                    feed_ct: [Fr::from(0u64); FEED_FIELDS],
                    payload: payload.clone(),
                    key_version: 0,
                });
            }
        }
        view.nullifiers
            .insert(note::nullifier(received.commitment(), &alice.nk));

        let auditor = alice.view.clone();
        let seen: Vec<u64> = view
            .notes
            .iter()
            .filter_map(|r| decrypt_payload(&auditor, &r.payload, r.output))
            .map(|(n, _)| n.units)
            .collect();
        assert_eq!(seen, [100, 60], "Alice's notes, change included; not Bob's");

        let mut wallet = Wallet::new(alice);
        wallet.scan(&view);
        let spent: Vec<bool> = wallet.notes.iter().map(|n| n.spent).collect();
        assert_eq!(
            spent,
            [true, false],
            "only the holder's `nk` shows the spend"
        );
    }
}

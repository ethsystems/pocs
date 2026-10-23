//! The transfer agent (SPEC, Participants and Roles): the single attester, the
//! keeper of the register, and the holder of the claim key. It reads every new
//! note and its lock terms through the register feed, under whichever register
//! key was in force, recognizes spends by nullifier, claims, enforces the
//! investor cap at attestation, and at reconciliation reports the rounding
//! remainder and any outflow from the pool that was not a withdrawal.

use std::collections::{
    BTreeMap,
    BTreeSet,
    HashMap,
    VecDeque,
};

use alloy::primitives::{
    B256,
    U256,
    keccak256,
};
use ark_bn254::Fr;

use crate::{
    EPOCH_SECONDS,
    chain::{
        ATTESTATION_PART,
        AttestationBatch,
        ChainView,
        Outflow,
        PoolEnv,
        PoolTotals,
        SpendRecord,
    },
    domain::{
        feed::{
            self,
            FeedSecret,
        },
        grumpkin::Point,
        keys::{
            NullifierKey,
            OwnerKeys,
            PlanSigner,
            PublicSpendKey,
            Registration,
            SpendKey,
            ViewingPubkey,
            owner_value,
        },
        note::{
            self,
            LockOpening,
            Note,
        },
        random_fr,
        witness::DepositWitness,
    },
    error::ActorError,
    poseidon::fr_to_be_bytes,
    types::{
        Address,
        Bytes32,
    },
    wallet::{
        BuiltTransfer,
        Output,
        OwnedNote,
        TransferSpec,
        Wallet,
        build_transfer,
    },
};

/// The attestation period, in epochs: every batch in a period carries the
/// same expiry (SPEC, Onboarding, step 4). The deployment's
/// `MAX_ATTESTATION_EPOCHS`.
pub const ATTESTATION_PERIOD: u64 = 30;

/// The epochs before a period ends in which batches already carry the next
/// period's expiry, so renewals land before the current attestations lapse.
/// The deployment's `OVERLAP_EPOCHS`.
pub const ATTESTATION_OVERLAP: u64 = 3;

/// What `TransferAgent::attestation_batch` built: the batch to send, and the
/// owner values it left out because attesting them would pass a cap. Those
/// stay due, so a later batch admits them once the cap allows, unless the
/// agent stops renewing them.
#[derive(Debug, Clone)]
pub struct AttestationRound {
    pub batch: AttestationBatch,
    pub over_cap: Vec<Fr>,
}

/// A subscription order to hand out (SPEC, Subscription, step 3): `units` for
/// an investor's owner value, held until the epoch `hold_until` under a
/// holding period.
#[derive(Debug, Clone)]
pub struct HandOutOrder {
    pub owner: Fr,
    pub vpk: ViewingPubkey,
    pub units: u64,
    pub hold_until: Option<u64>,
}

/// Where a hand-out transfer's source comes from: the day's aggregate note,
/// or an output of an earlier transfer of the same tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandOutSource {
    Aggregate,
    Output { transfer: usize, index: usize },
}

/// One transfer of a hand-out tree, for `TransferAgent::hand_out_transfer`.
#[derive(Debug, Clone)]
pub struct PlannedHandOut {
    pub source: HandOutSource,
    pub outputs: [Output; 2],
}

/// What the agent keeps per owner value: whom it belongs to, both keys the
/// owner value commits to, and the viewing key to deliver notes to.
#[derive(Debug, Clone)]
pub struct InvestorRecord {
    pub holder: Holder,
    pub pk: PublicSpendKey,
    pub nk: NullifierKey,
    pub vpk: ViewingPubkey,
}

/// The name positions and the register hash give the agent's own holdings.
pub const AGENT_ID: &str = "transfer-agent";

/// The name of the padding owner values' holdings: the agent's own, but kept
/// apart from its inventory, so that units an investor sends to one show up
/// in the register as such.
pub const PADDING_ID: &str = "transfer-agent-padding";

/// A verified investor's pseudonymous ID (SPEC, Onboarding, step 1). An empty
/// ID and the agent's two reserved names are refused: an investor recorded
/// under one would count as the agent's, outside every cap.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InvestorId(String);

impl InvestorId {
    pub fn new(id: &str) -> Result<Self, ActorError> {
        if id.is_empty() || id == AGENT_ID || id == PADDING_ID {
            return Err(ActorError::InvalidInvestorId(id.to_string()));
        }
        Ok(Self(id.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for InvestorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl PartialEq<&str> for InvestorId {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

/// Whom an owner value, and the notes it holds, belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Holder {
    Agent,
    Padding,
    Investor(InvestorId),
}

impl Holder {
    /// The name positions and the register hash use.
    pub fn as_str(&self) -> &str {
        match self {
            Holder::Agent => AGENT_ID,
            Holder::Padding => PADDING_ID,
            Holder::Investor(id) => id.as_str(),
        }
    }

    /// The investor, for a holder that counts toward the caps.
    pub fn investor(&self) -> Option<&InvestorId> {
        match self {
            Holder::Investor(id) => Some(id),
            Holder::Agent | Holder::Padding => None,
        }
    }
}

/// One note in the register, read from the feed.
#[derive(Debug, Clone)]
pub struct RegisterEntry {
    pub note: Note,
    /// The lock terms, also read from the feed; all zero for an unlocked note.
    pub opening: LockOpening,
    pub commitment: Fr,
    pub leaf_index: usize,
    /// Whom it belongs to, or `None` for an owner value the agent does not know.
    pub holder: Option<Holder>,
    pub spent: bool,
}

#[derive(Debug, Clone)]
pub enum ClaimAction {
    Freeze,
    /// A holding period: the owner path can spend the note from epoch `until` on.
    Hold {
        until: u64,
    },
    Release,
    Seize {
        to: Fr,
        to_vpk: ViewingPubkey,
    },
}

/// A redemption the agent recognized: an investor's spend that paid units to
/// the agent's owner value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redemption {
    pub investor_id: InvestorId,
    pub units: u64,
    pub commitment: Fr,
}

/// A claim the agent made (SPEC, Claims, step 6): the note it spent and the
/// two it created. The outputs identify it on-chain, since their salts are its
/// own; the holder's spend of the same note, which shares its nullifier, has
/// other outputs. The chain shows a claim as an ordinary transfer, so these
/// records are what tells a seizure to the agent from a redemption. They are
/// not on-chain and cannot be rebuilt from it: the operator must persist them
/// (the PoC keeps them in memory), or a restarted agent reads its own seizures
/// as redemptions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimRecord {
    pub target: Fr,
    pub outputs: [Fr; 2],
}

/// The public half of a register-key rotation: what `setRegisterKey` takes,
/// and what `commit_register_key` files once the pool has it. The `tk` stays
/// in the agent (`prepared_register_keys`), so after a restart the operator
/// rebuilds this from the pool's key and version. Until the commit, the agent
/// proves under its current key; `read_feed` already reads notes under the
/// prepared one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterKeyRotation {
    pub version: u64,
    pub public_key: Point,
}

/// A note `read_feed` could not read: no register key of its version opens its
/// feed to its commitment. It stays out of the register, and `read_feed` tries
/// it again on each call, so restoring the key brings it in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnreadableNote {
    pub commitment: Fr,
    pub key_version: u64,
}

/// What a reconciliation found (SPEC, Reconciliation).
#[derive(Debug, Clone)]
pub struct Reconciliation {
    /// The rounding remainder: shares no note can withdraw, reported with the
    /// checkpoint.
    pub remainder: U256,
    /// Outflows that were not withdrawals. The SPEC has the agent checkpoint at
    /// once on finding one and alert governance and the guardian; the PoC only
    /// reports them and leaves that to the caller.
    pub outflows: Vec<Outflow>,
}

pub struct TransferAgent {
    /// The agent's own owner value, which holds issuance and redemption notes.
    pub wallet: Wallet,
    /// The spend key of that owner value, apart from the wallet as for any
    /// holder; in production it sits in the agent's HSM, like the claim key.
    pub signer: SpendKey,
    pub claim_key: SpendKey,
    /// The register keys by version: 0 is the key set at deployment, and each
    /// rotation adds the next. Old keys stay, to read the notes created under them.
    pub register_keys: BTreeMap<u64, FeedSecret>,
    /// Keys `new_register_key` prepared and no commit has filed yet, by
    /// version. The operator persists them with the rest of the agent's state
    /// before sending `setRegisterKey`: if the agent stops between the pool
    /// taking a key and the commit, the prepared key is the only one that
    /// reads the notes created under it.
    pub prepared_register_keys: Vec<(u64, FeedSecret)>,
    /// The notes the last `read_feed` could not read. Reconciliation fails
    /// while there are any.
    pub unreadable_notes: Vec<UnreadableNote>,
    pub investors: BTreeMap<Bytes32, InvestorRecord>,
    pub register: Vec<RegisterEntry>,
    /// The cap on investors (SPEC, Onboarding, step 3); `None` for no cap.
    pub max_investors: Option<usize>,
    /// Caps by jurisdiction, on top of `max_investors`; a jurisdiction without
    /// one is uncapped.
    pub jurisdiction_caps: BTreeMap<String, usize>,
    /// Each verified investor's jurisdiction, by investor ID.
    pub jurisdictions: BTreeMap<InvestorId, String>,
    /// Public holders' addresses, mapped to investor IDs, so an investor that
    /// holds shares publicly counts toward the cap like one that holds notes.
    pub public_holders: HashMap<Address, InvestorId>,
    /// The keys of the padding owner values in attestation batches, which the
    /// agent holds so that units sent to one can still be claimed.
    pub padding: Vec<OwnerKeys>,
    /// The epoch the attestation periods count from: the first batch's, the
    /// seed's.
    pub period_start: Option<u64>,
    /// Owner values the agent no longer attests: investors it revoked, and
    /// padding it retired. Revocation is the absence of renewal.
    pub not_renewed: BTreeSet<Bytes32>,
    /// Claims built but not yet seen on-chain. `read_feed` moves each to
    /// `claims` once its outputs appear, and drops it if another transaction
    /// spent its target first, as a holder redeeming the note would.
    pub pending_claims: Vec<ClaimRecord>,
    /// The claims mined: the agent's record of them. The chain cannot tell a
    /// claim from a transfer, so the operator must persist these and
    /// `pending_claims`; the PoC keeps both in memory (README, Limitations).
    pub claims: Vec<ClaimRecord>,
    /// The commitment of the seed's deposit (SPEC, Deployment Parameters),
    /// once `seed_deposit` built it. With the claim records it identifies the
    /// seed (`is_seed`), so the operator persists it with them.
    pub seed_deposit: Option<Fr>,
    /// The secret each checkpoint's salt derives from, kept like `tk`, so the
    /// agent can open any day's register hash to an auditor.
    pub register_salt_key: B256,
}

impl Default for TransferAgent {
    fn default() -> Self {
        Self::new()
    }
}

impl TransferAgent {
    pub fn new() -> Self {
        let (signer, keys) = OwnerKeys::random().split();
        Self {
            wallet: Wallet::new(keys),
            signer,
            claim_key: SpendKey::random(),
            register_keys: BTreeMap::from([(0, FeedSecret::random())]),
            prepared_register_keys: Vec::new(),
            unreadable_notes: Vec::new(),
            investors: BTreeMap::new(),
            register: Vec::new(),
            max_investors: None,
            jurisdiction_caps: BTreeMap::new(),
            jurisdictions: BTreeMap::new(),
            public_holders: HashMap::new(),
            padding: Vec::new(),
            period_start: None,
            not_renewed: BTreeSet::new(),
            pending_claims: Vec::new(),
            claims: Vec::new(),
            seed_deposit: None,
            register_salt_key: B256::from(fr_to_be_bytes(&random_fr())),
        }
    }

    pub fn owner(&self) -> Fr {
        self.wallet.owner()
    }

    /// What governance stores in the pool as `claimKeyHash`.
    pub fn claim_key_hash(&self) -> Fr {
        self.claim_key.public_key().key_hash()
    }

    /// The current register key `tpk`, stored in the pool.
    pub fn register_public_key(&self) -> Point {
        self.register_keys
            .last_key_value()
            .expect("version 0 is set at construction and never removed")
            .1
            .public_point()
    }

    fn next_register_key_version(&self) -> u64 {
        self.register_keys
            .last_key_value()
            .expect("version 0 is set at construction and never removed")
            .0
            + 1
    }

    /// A rotation (SPEC, Governance and Key Rotation): a fresh `tk` and the
    /// next version, for `setRegisterKey`. The key is also kept in
    /// `prepared_register_keys`, which the operator persists before sending
    /// the call. The current key stays until `commit_register_key`, so a
    /// rotation the pool refuses leaves the agent proving as it was.
    pub fn new_register_key(&mut self) -> RegisterKeyRotation {
        let secret = FeedSecret::random();
        let version = self.next_register_key_version();
        self.prepared_register_keys.push((version, secret));
        RegisterKeyRotation {
            version,
            public_key: secret.public_point(),
        }
    }

    /// Keeps a rotation's key, alongside the old ones, once the pool has it,
    /// and drops the other keys prepared for its version.
    pub fn commit_register_key(
        &mut self,
        rotation: RegisterKeyRotation,
    ) -> Result<(), ActorError> {
        if rotation.version != self.next_register_key_version() {
            return Err(ActorError::StaleRotation(rotation.version));
        }
        let (_, secret) = *self
            .prepared_register_keys
            .iter()
            .find(|(version, tk)| {
                *version == rotation.version && tk.public_point() == rotation.public_key
            })
            .ok_or(ActorError::UnpreparedRotation(rotation.version))?;
        self.register_keys.insert(rotation.version, secret);
        self.prepared_register_keys
            .retain(|(version, _)| *version > rotation.version);
        Ok(())
    }

    /// The next attestation batch (SPEC, Onboarding, steps 3 to 5). It takes
    /// every owner value the agent attests whose attestation ends before the
    /// batch's expiry: new values, lapsed ones, and in a period's overlap the
    /// period's renewals, the agent's own value and the standing padding among
    /// them. New investors are admitted while the caps allow, and the rest are
    /// reported in `over_cap`; renewals of investors already counted always
    /// pass, so a refused newcomer never holds up the others.
    ///
    /// The batch is padded to a multiple of `ATTESTATION_PART` with fresh
    /// owner values whose keys the agent holds, shuffled, and split into parts
    /// of exactly `ATTESTATION_PART`. Padding hides how many of a batch's new
    /// values are real. It must be fresh, since a value attested before cannot
    /// stand in for a new one, and it is renewed with the investors from then
    /// on, or it would stand out when the period's renewals came round. Every
    /// part carries the period's uniform expiry. `generation` is the
    /// registry's, which governance moves.
    pub fn attestation_batch(
        &mut self,
        view: &ChainView,
        env: &PoolEnv,
        holding_publicly: &[Address],
        generation: u64,
    ) -> Result<AttestationRound, ActorError> {
        self.read_feed(view)?;
        let start = *self.period_start.get_or_insert(env.epoch);
        let expires_at = period_expiry(start, env.epoch);
        let ends = |owner: Fr| {
            view.attestation_records
                .iter()
                .filter(|r| {
                    r.owner == owner && r.generation >= env.min_accepted_generation
                })
                .map(|r| r.expires_at)
                .max()
        };
        let due: Vec<Fr> = std::iter::once(self.owner())
            .chain(
                self.investors
                    .keys()
                    .map(|o| Fr::try_from(*o).expect("owner values are canonical")),
            )
            .filter(|o| !self.not_renewed.contains(&Bytes32::from(*o)))
            .filter(|o| ends(*o).is_none_or(|end| end < expires_at))
            .collect();

        let before = self.counted_investors(view, env, holding_publicly)?;
        let mut counted = before.clone();
        let mut owners = Vec::with_capacity(due.len());
        let mut over_cap = Vec::new();
        for owner in due {
            let holder = self
                .holder_of(owner)
                .ok_or(ActorError::UnknownOwner(Bytes32::from(owner)))?;
            let Some(id) = holder.investor().filter(|id| !counted.contains(*id)) else {
                owners.push(owner);
                continue;
            };
            let mut with = counted.clone();
            with.insert(id.clone());
            if self.cap_refusal(&before, &with).is_some() {
                over_cap.push(owner);
            } else {
                counted = with;
                owners.push(owner);
            }
        }

        if !owners.is_empty() {
            let padding = owners.len().next_multiple_of(ATTESTATION_PART) - owners.len();
            owners.extend(self.fresh_padding(padding));
        }
        rand::seq::SliceRandom::shuffle(owners.as_mut_slice(), &mut rand::rng());
        let parts = owners
            .chunks(ATTESTATION_PART)
            .map(<[Fr]>::to_vec)
            .collect();
        Ok(AttestationRound {
            batch: AttestationBatch::new(parts, expires_at, generation),
            over_cap,
        })
    }

    /// `n` new padding values, recorded under `PADDING_ID`. The agent holds
    /// their keys, so units sent to one can still be frozen, seized or
    /// redeemed.
    fn fresh_padding(&mut self, n: usize) -> Vec<Fr> {
        (0..n)
            .map(|_| {
                let keys = OwnerKeys::random();
                let owner = self.record_owner(
                    Holder::Padding,
                    keys.spend.public_key(),
                    keys.nk,
                    keys.view.public_key(),
                );
                self.padding.push(keys);
                owner
            })
            .collect()
    }

    /// Stops attesting `owner` (SPEC, Onboarding, step 5): an investor the
    /// agent revoked, or padding it retires. Its current attestation runs to
    /// its expiry. A padding value that stops being renewed looks like an
    /// investor leaving, so retiring padding at a rate plausible for the fund
    /// keeps the standing padding from growing without bound. The agent's own
    /// value stays attested: hand-outs and seizures pay it.
    pub fn stop_renewing(&mut self, owner: Fr) -> Result<(), ActorError> {
        if owner == self.owner() {
            return Err(ActorError::AgentsOwnValue);
        }
        if self.holder_of(owner).is_none() {
            return Err(ActorError::UnknownOwner(Bytes32::from(owner)));
        }
        self.not_renewed.insert(Bytes32::from(owner));
        Ok(())
    }

    /// Verification (SPEC, Onboarding, step 1): the agent, or its KYC
    /// provider, verifies the investor off-chain, assigns its pseudonymous ID,
    /// and records its jurisdiction, by which the jurisdiction caps count it.
    pub fn verify_investor(
        &mut self,
        investor_id: &str,
        jurisdiction: &str,
    ) -> Result<(), ActorError> {
        self.jurisdictions
            .insert(InvestorId::new(investor_id)?, jurisdiction.to_string());
        Ok(())
    }

    /// Onboarding (SPEC, Onboarding, step 2): checks the registration, signed
    /// by the investor's spend key for this pool and this investor ID, and that
    /// `nk`, which the investor sends alongside, is not zero and hashes to the
    /// `nk_hash` it signs; then computes the owner value itself and records
    /// owner value to investor ID. The investor must be verified first, and an
    /// owner value already recorded under another investor ID is refused
    /// rather than moved.
    pub fn onboard(
        &mut self,
        investor_id: &str,
        env: &PoolEnv,
        registration: &Registration,
        signature: &[u8; 64],
        nk: &NullifierKey,
    ) -> Result<Fr, ActorError> {
        let id = InvestorId::new(investor_id)?;
        if !self.jurisdictions.contains_key(&id) {
            return Err(ActorError::UnverifiedInvestor(investor_id.to_string()));
        }
        if registration.chain_id != env.chain_id
            || registration.pool != env.pool
            || registration.investor_id != investor_id
        {
            return Err(ActorError::BadRegistration);
        }
        if nk.0 == Fr::from(0u64) || nk.hash() != registration.nk_hash {
            return Err(ActorError::BadRegistration);
        }
        registration
            .verify(signature)
            .map_err(|_| ActorError::BadRegistration)?;
        let owner = Bytes32::from(owner_value(&registration.pk, nk));
        let holder = Holder::Investor(id);
        if let Some(record) = self.investors.get(&owner)
            && record.holder != holder
        {
            return Err(ActorError::OwnerOfAnotherInvestor(owner));
        }
        Ok(self.record_owner(holder, registration.pk, *nk, registration.vpk.clone()))
    }

    /// Records an owner value: an investor's, once its registration checks
    /// out, or one of the agent's own.
    fn record_owner(
        &mut self,
        holder: Holder,
        pk: PublicSpendKey,
        nk: NullifierKey,
        vpk: ViewingPubkey,
    ) -> Fr {
        let owner = owner_value(&pk, &nk);
        self.investors.insert(
            Bytes32::from(owner),
            InvestorRecord {
                holder,
                pk,
                nk,
                vpk,
            },
        );
        owner
    }

    fn holder_of(&self, owner: Fr) -> Option<Holder> {
        if owner == self.owner() {
            return Some(Holder::Agent);
        }
        self.investors
            .get(&Bytes32::from(owner))
            .map(|r| r.holder.clone())
    }

    fn nk_of(&self, owner: Fr) -> Option<NullifierKey> {
        if owner == self.owner() {
            return Some(self.wallet.keys.nk);
        }
        self.investors.get(&Bytes32::from(owner)).map(|r| r.nk)
    }

    /// Reads every new note through the register feed, with the register key
    /// that was in force when it was created, and marks spent the entries whose
    /// nullifiers the pool recorded. Also keeps the agent's own wallet in step:
    /// its own notes from the feed, and the rest through recipient payloads.
    /// A note no key reads is skipped and listed in `unreadable_notes`, so one
    /// bad record does not stop the cap check, and with it attestation, for
    /// every holder.
    pub fn read_feed(&mut self, view: &ChainView) -> Result<(), ActorError> {
        self.unreadable_notes.clear();
        for record in &view.notes {
            if self
                .register
                .iter()
                .any(|e| e.commitment == record.commitment)
            {
                continue;
            }
            // A version with no committed key may be one the pool took before
            // the agent committed it: a prepared key reads it.
            let keys: Vec<&FeedSecret> = match self.register_keys.get(&record.key_version)
            {
                Some(tk) => vec![tk],
                None => self
                    .prepared_register_keys
                    .iter()
                    .filter(|(version, _)| *version == record.key_version)
                    .map(|(_, tk)| tk)
                    .collect(),
            };
            // The circuit binds the feed to the commitment, so only the wrong
            // key fails to open it.
            let opened = keys.into_iter().find_map(|tk| {
                let fields =
                    feed::decrypt(tk, &record.feed_r, &record.feed_ct, record.output);
                feed::open(&fields)
                    .filter(|(note, _)| note.commitment() == record.commitment)
            });
            let Some((note, opening)) = opened else {
                self.unreadable_notes.push(UnreadableNote {
                    commitment: record.commitment,
                    key_version: record.key_version,
                });
                continue;
            };
            self.register.push(RegisterEntry {
                note,
                opening,
                commitment: record.commitment,
                leaf_index: record.leaf_index,
                holder: self.holder_of(note.owner),
                spent: false,
            });
            // The payload is not bound, so the agent's own notes come from the
            // feed too: a payer's garbage payload must not hide one from it.
            if note.owner == self.owner()
                && !self
                    .wallet
                    .notes
                    .iter()
                    .any(|n| n.commitment == record.commitment)
            {
                self.wallet.notes.push(OwnedNote {
                    note,
                    opening,
                    commitment: record.commitment,
                    leaf_index: record.leaf_index,
                    spent: false,
                });
            }
        }
        let spent: Vec<bool> = self
            .register
            .iter()
            .map(|e| {
                self.nk_of(e.note.owner).is_some_and(|nk| {
                    view.nullifiers
                        .contains(&note::nullifier(e.commitment, &nk))
                })
            })
            .collect();
        for (e, s) in self.register.iter_mut().zip(spent) {
            e.spent = s;
        }
        // A pending claim is mined once its outputs appear; one whose target
        // another transaction spent never will be.
        let targets_spent: Vec<bool> = self
            .pending_claims
            .iter()
            .map(|c| {
                self.register
                    .iter()
                    .any(|e| e.commitment == c.target && e.spent)
            })
            .collect();
        let mut still_pending = Vec::new();
        for (claim, target_spent) in std::mem::take(&mut self.pending_claims)
            .into_iter()
            .zip(targets_spent)
        {
            if view.spends.iter().any(|s| s.outputs == claim.outputs) {
                self.claims.push(claim);
            } else if !target_spent {
                still_pending.push(claim);
            }
        }
        self.pending_claims = still_pending;
        self.wallet.scan(view);
        Ok(())
    }

    /// Units held per holder, from the register alone.
    pub fn positions(&self) -> BTreeMap<String, u64> {
        let mut out = BTreeMap::new();
        for e in self
            .register
            .iter()
            .filter(|e| !e.spent && e.note.units > 0)
        {
            let holder = e.holder.as_ref().map_or("unknown", Holder::as_str);
            *out.entry(holder.to_string()).or_insert(0) += e.note.units;
        }
        out
    }

    pub fn total_units(&self) -> u128 {
        self.register
            .iter()
            .filter(|e| !e.spent)
            .map(|e| u128::from(e.note.units))
            .sum()
    }

    /// The rounding remainder (SPEC, Multiplier Rules): the part of the pool's
    /// balance `B` that no note can withdraw at multiplier `m`,
    /// `B - sum(floor(u_i * m / S))` over the unspent notes. Only the agent can
    /// compute it, from the units in its register; it reports it at
    /// reconciliation. `None` if the notes could withdraw more than `B`, which
    /// the multiplier rules exclude.
    pub fn remainder(&self, balance: U256, m: U256) -> Option<U256> {
        let s = U256::from(crate::S);
        let withdrawable: U256 = self
            .register
            .iter()
            .filter(|e| !e.spent)
            .map(|e| U256::from(e.note.units) * m / s)
            .sum();
        balance.checked_sub(withdrawable)
    }

    /// Records the address a verified investor holds public shares at.
    pub fn register_public_holder(
        &mut self,
        address: Address,
        investor_id: &str,
    ) -> Result<(), ActorError> {
        let id = InvestorId::new(investor_id)?;
        if !self.jurisdictions.contains_key(&id) {
            return Err(ActorError::UnverifiedInvestor(investor_id.to_string()));
        }
        self.public_holders.insert(address, id);
        Ok(())
    }

    /// The investor IDs that count toward the cap (SPEC, Onboarding, step 3):
    /// attested now, holding a confidential position, or holding shares
    /// publicly at one of `holding_publicly`, the addresses with a non-zero
    /// balance on the public token. Each counts once, however many owner values
    /// and addresses it uses. The agent itself does not count.
    pub fn counted_investors(
        &self,
        view: &ChainView,
        env: &PoolEnv,
        holding_publicly: &[Address],
    ) -> Result<BTreeSet<InvestorId>, ActorError> {
        let mut ids = BTreeSet::new();
        for (owner, record) in &self.investors {
            let Some(id) = record.holder.investor() else {
                continue;
            };
            let owner = Fr::try_from(*owner).expect("owner values are canonical");
            if view
                .attestation_of(owner, env.epoch, env.min_accepted_generation)
                .is_some()
            {
                ids.insert(id.clone());
            }
        }
        for e in self
            .register
            .iter()
            .filter(|e| !e.spent && e.note.units > 0)
        {
            if let Some(id) = e.holder.as_ref().and_then(Holder::investor) {
                ids.insert(id.clone());
            }
        }
        // A public holding the agent cannot attribute cannot be counted, so the
        // count fails rather than miss it.
        for address in holding_publicly {
            let id = self
                .public_holders
                .get(address)
                .ok_or(ActorError::UnknownPublicHolder(*address))?;
            ids.insert(id.clone());
        }
        Ok(ids)
    }

    /// Checks a batch of owner values the agent is about to attest against the
    /// cap. The batch is refused if its new investors take the count past the
    /// cap; renewals, and further owner values of an investor already counted,
    /// add nothing. The whole batch is counted together, since its attestations
    /// land at once. Holders are counted from the register, so the feed is
    /// read first: a holder whose note the agent has not read yet, and whose
    /// attestation lapsed, would otherwise not count.
    pub fn check_cap(
        &mut self,
        view: &ChainView,
        env: &PoolEnv,
        owners: &[Fr],
        holding_publicly: &[Address],
    ) -> Result<(), ActorError> {
        self.read_feed(view)?;
        let before = self.counted_investors(view, env, holding_publicly)?;
        let mut counted = before.clone();
        for owner in owners {
            let holder = self
                .holder_of(*owner)
                .ok_or(ActorError::UnknownOwner(Bytes32::from(*owner)))?;
            if let Some(id) = holder.investor() {
                counted.insert(id.clone());
            }
        }
        self.cap_refusal(&before, &counted).map_or(Ok(()), Err)
    }

    /// Why the investors `counted` would pass a cap that `before` does not,
    /// if they would. A count already over a cap may stay there: renewals do
    /// not push anyone out.
    fn cap_refusal(
        &self,
        before: &BTreeSet<InvestorId>,
        counted: &BTreeSet<InvestorId>,
    ) -> Option<ActorError> {
        if let Some(cap) = self.max_investors
            && counted.len() > before.len().max(cap)
        {
            return Some(ActorError::CapReached { cap });
        }
        for (jurisdiction, &cap) in &self.jurisdiction_caps {
            let count = |ids: &BTreeSet<InvestorId>| {
                ids.iter()
                    .filter(|id| self.jurisdictions.get(*id) == Some(jurisdiction))
                    .count()
            };
            if count(counted) > count(before).max(cap) {
                return Some(ActorError::JurisdictionCapReached {
                    jurisdiction: jurisdiction.clone(),
                    cap,
                });
            }
        }
        None
    }

    /// The salt of the checkpoints in `epoch`: keccak256(salt key, epoch). The
    /// agent discloses it with the register to whoever audits that day's hash;
    /// it reveals nothing about other days.
    pub fn checkpoint_salt(&self, epoch: u64) -> B256 {
        let mut bytes = self.register_salt_key.to_vec();
        bytes.extend(epoch.to_be_bytes());
        keccak256(bytes)
    }

    /// The hash the checkpoint publishes: keccak256 over the epoch's salt and
    /// the sorted positions. Without the salt, anyone who guessed a small
    /// register, its investor IDs and units, could confirm the guess against
    /// the public hash. Opens only off-chain, with the register and the salt.
    pub fn register_hash(&self, epoch: u64) -> B256 {
        let mut bytes = self.checkpoint_salt(epoch).to_vec();
        for (holder, units) in self.positions() {
            bytes.extend(keccak256(holder.as_bytes()));
            bytes.extend(units.to_be_bytes());
        }
        keccak256(bytes)
    }

    /// Redemptions (SPEC, Redemption, step 1): investors' spends that paid
    /// units to the agent, still pending. A redemption is processed when the
    /// agent spends its note, withdrawing it or merging it into the day's
    /// withdrawal (step 2), so the chain alone tells which are pending, and an
    /// agent restarted from it does not pay one twice. The agent identifies
    /// the redeemer by matching the spent nullifiers against the investors' `nk`.
    /// Its own claims are not redemptions, even a seizure to itself: they are
    /// told apart by their outputs, from its claim records.
    pub fn redemptions(&self, view: &ChainView) -> Vec<Redemption> {
        let is_claim = |s: &SpendRecord| {
            self.claims
                .iter()
                .chain(&self.pending_claims)
                .any(|c| s.outputs == c.outputs)
        };
        let mut out = Vec::new();
        for spend in view.spends.iter().filter(|s| !is_claim(s)) {
            let redeemer = self.register.iter().find_map(|e| {
                let id = e.holder.as_ref().and_then(Holder::investor)?;
                let nk = self.nk_of(e.note.owner)?;
                spend
                    .nullifiers
                    .contains(&note::nullifier(e.commitment, &nk))
                    .then(|| id.clone())
            });
            let Some(investor_id) = redeemer else {
                continue;
            };
            for c in &spend.outputs {
                let processed = view
                    .nullifiers
                    .contains(&note::nullifier(*c, &self.wallet.keys.nk));
                if processed {
                    continue;
                }
                if let Some(e) = self.register.iter().find(|e| {
                    e.commitment == *c && e.note.owner == self.owner() && e.note.units > 0
                }) {
                    out.push(Redemption {
                        investor_id: investor_id.clone(),
                        units: e.note.units,
                        commitment: *c,
                    });
                }
            }
        }
        out
    }

    /// Outflows from the pool that were not withdrawals: forced transfers,
    /// burns or recoveries (SPEC, Reconciliation). The pool halts only on a net
    /// fall of `m`, so a smaller one shows up only here. The SPEC has the agent
    /// checkpoint at once on finding one and alert governance and the
    /// guardian; this only lists them.
    pub fn unexplained_outflows(&self, view: &ChainView) -> Vec<Outflow> {
        view.outflows
            .iter()
            .filter(|o| !o.by_withdrawal)
            .cloned()
            .collect()
    }

    /// A claim-path transfer on one note in the register (SPEC, Claims).
    pub fn claim(
        &mut self,
        view: &ChainView,
        env: &PoolEnv,
        target: Fr,
        action: ClaimAction,
    ) -> Result<BuiltTransfer, ActorError> {
        // The seed stays frozen for good (SPEC, Deployment Parameters): no
        // claim may release, hold, move or re-freeze it, and its one freeze is
        // `freeze_seed`'s. This is a rule of the agent, not of the pool.
        if self.is_seed(target) {
            return Err(ActorError::SeedNote(Bytes32::from(target)));
        }
        self.build_claim(view, env, target, action)
    }

    /// The seed's deposit (SPEC, Deployment Parameters): `units`, one share,
    /// into the agent's own owner value, funded from `funder`, before any
    /// investor's owner value is attested. It keeps `U` above 0 for good, so
    /// no holder can be alone in the pool and inflate `m`. Records the note as
    /// the seed; `freeze_seed` then locks it.
    pub fn seed_deposit(
        &mut self,
        view: &ChainView,
        env: &PoolEnv,
        units: u64,
        funder: Address,
    ) -> Result<(DepositWitness, Vec<u8>), ActorError> {
        if self.seed_deposit.is_some() {
            return Err(ActorError::SeedExists);
        }
        if let Some(investor) = view.attestation_records.iter().find(|r| {
            self.holder_of(r.owner)
                .is_some_and(|h| h.investor().is_some())
        }) {
            return Err(ActorError::InvestorBeforeSeed(Bytes32::from(
                investor.owner,
            )));
        }
        let (witness, payload) =
            self.wallet
                .deposit(&self.signer, view, env, units, funder)?;
        self.seed_deposit = Some(witness.commitment);
        Ok((witness, payload))
    }

    /// The seed's freeze, through the claim path: the one claim the seed
    /// takes. Its output, the frozen seed, is recognised from the claim's
    /// record.
    pub fn freeze_seed(
        &mut self,
        view: &ChainView,
        env: &PoolEnv,
    ) -> Result<BuiltTransfer, ActorError> {
        let deposit = self.seed_deposit.ok_or(ActorError::NoSeed)?;
        self.build_claim(view, env, deposit, ClaimAction::Freeze)
    }

    /// Whether `commitment` is the seed: its deposit's note, or the note its
    /// freeze creates, from the claim's record, pending or mined.
    pub fn is_seed(&self, commitment: Fr) -> bool {
        let Some(deposit) = self.seed_deposit else {
            return false;
        };
        commitment == deposit
            || self
                .pending_claims
                .iter()
                .chain(&self.claims)
                .any(|c| c.target == deposit && c.outputs[0] == commitment)
    }

    fn build_claim(
        &mut self,
        view: &ChainView,
        env: &PoolEnv,
        target: Fr,
        action: ClaimAction,
    ) -> Result<BuiltTransfer, ActorError> {
        let entry = self
            .register
            .iter()
            .find(|e| e.commitment == target && !e.spent)
            .cloned()
            .ok_or(ActorError::UnknownNote(Bytes32::from(target)))?;
        // The agent's own notes (the seed, issuance and redemption notes) are
        // claimed with its own keys; an investor's with the keys on file.
        let record = if entry.note.owner == self.owner() {
            InvestorRecord {
                holder: Holder::Agent,
                pk: self.wallet.keys.pk,
                nk: self.wallet.keys.nk,
                vpk: self.wallet.vpk(),
            }
        } else {
            self.investors
                .get(&Bytes32::from(entry.note.owner))
                .cloned()
                .ok_or(ActorError::UnknownOwner(Bytes32::from(entry.note.owner)))?
        };
        let input = OwnedNote {
            note: entry.note,
            opening: entry.opening,
            commitment: entry.commitment,
            leaf_index: entry.leaf_index,
            spent: false,
        };
        let same_owner = |units, opening| Output {
            owner: entry.note.owner,
            units,
            opening,
            vpk: record.vpk.clone(),
        };
        let outputs = match action {
            ClaimAction::Freeze => [
                same_owner(entry.note.units, LockOpening::freeze()),
                same_owner(0, LockOpening::NONE),
            ],
            ClaimAction::Hold { until } => [
                same_owner(entry.note.units, LockOpening::hold(until)),
                same_owner(0, LockOpening::NONE),
            ],
            ClaimAction::Release => [
                same_owner(entry.note.units, LockOpening::NONE),
                same_owner(0, LockOpening::NONE),
            ],
            ClaimAction::Seize { to, to_vpk } => [
                Output {
                    owner: to,
                    units: entry.note.units,
                    opening: LockOpening::NONE,
                    vpk: to_vpk,
                },
                same_owner(0, LockOpening::NONE),
            ],
        };
        let built = build_transfer(
            TransferSpec {
                claim: true,
                owner_key: record.pk,
                nk: record.nk,
                claim_key: self.claim_key.public_key(),
                inputs: vec![input],
                outputs,
            },
            &self.claim_key,
            view,
            env,
        )?;
        self.pending_claims.push(ClaimRecord {
            target,
            outputs: built.witness.commitments_out,
        });
        Ok(built)
    }

    /// The hand-out tree for the day's `orders` (SPEC, Subscription, step 3),
    /// planned without the chain. Each transfer spends one of the agent's notes
    /// and creates two outputs, each an order's note or an agent note for
    /// several orders, which a later transfer splits again: `N` orders take
    /// `N - 1` transfers, and a single order one. Transfers come parents
    /// first, so each source exists before it is spent. The day's aggregate
    /// note carries the orders' total.
    pub fn plan_hand_out(&self, orders: &[HandOutOrder]) -> Vec<PlannedHandOut> {
        let order = |o: &HandOutOrder| Output {
            owner: o.owner,
            units: o.units,
            opening: o.hold_until.map_or(LockOpening::NONE, LockOpening::hold),
            vpk: o.vpk.clone(),
        };
        let agents = |units| Output {
            owner: self.owner(),
            units,
            opening: LockOpening::NONE,
            vpk: self.wallet.vpk(),
        };
        let mut plan = Vec::new();
        let mut queue = VecDeque::new();
        if !orders.is_empty() {
            queue.push_back((HandOutSource::Aggregate, orders.to_vec()));
        }
        while let Some((source, group)) = queue.pop_front() {
            let transfer = plan.len();
            let outputs = if let [single] = group.as_slice() {
                [order(single), agents(0)]
            } else {
                let (left, right) = group.split_at(group.len() / 2);
                [left, right]
                    .iter()
                    .enumerate()
                    .map(|(index, part)| {
                        if let [single] = part {
                            return order(single);
                        }
                        queue.push_back((
                            HandOutSource::Output { transfer, index },
                            part.to_vec(),
                        ));
                        agents(part.iter().map(|o| o.units).sum())
                    })
                    .collect::<Vec<_>>()
                    .try_into()
                    .expect("two halves")
            };
            plan.push(PlannedHandOut { source, outputs });
        }
        plan
    }

    /// One transfer of a hand-out (SPEC, Subscription, step 3): the agent's
    /// note `source` into `outputs`. A held order's note must be created
    /// locked, which only the claim path can do, so a transfer with a locked
    /// output goes through it, signed with the claim key; any other goes
    /// through the owner path, signed with the agent's own key.
    pub fn hand_out_transfer(
        &self,
        view: &ChainView,
        env: &PoolEnv,
        source: OwnedNote,
        outputs: [Output; 2],
    ) -> Result<BuiltTransfer, ActorError> {
        if source.note.owner != self.owner() {
            return Err(ActorError::UnknownNote(Bytes32::from(source.commitment)));
        }
        // The seed, before or after its freeze, never pays a hand-out. Nor
        // does any other locked note: the claim path a held order takes skips
        // the input's lock check, so it would move it.
        if self.is_seed(source.commitment) {
            return Err(ActorError::SeedNote(Bytes32::from(source.commitment)));
        }
        if source.note.lock != Fr::from(0u64) {
            return Err(ActorError::LockedNote(Bytes32::from(source.commitment)));
        }
        // Spending a note an investor redeemed marks the redemption processed,
        // so a hand-out from it would drop the redemption unpaid.
        if self
            .redemptions(view)
            .iter()
            .any(|r| r.commitment == source.commitment)
        {
            return Err(ActorError::PendingRedemption(Bytes32::from(
                source.commitment,
            )));
        }
        let claim = outputs.iter().any(|o| o.opening != LockOpening::NONE);
        let signer: &dyn PlanSigner = if claim { &self.claim_key } else { &self.signer };
        build_transfer(
            TransferSpec {
                claim,
                owner_key: self.wallet.keys.pk,
                nk: self.wallet.keys.nk,
                claim_key: self.claim_key.public_key(),
                inputs: vec![source],
                outputs,
            },
            signer,
            view,
            env,
        )
    }

    /// The daily reconciliation (SPEC, Reconciliation, Disclosure and
    /// Corrections): rebuilds the register from the feed, checks its units
    /// total against `U`, computes the rounding remainder, and lists the
    /// outflows that were not withdrawals. The checkpoint then publishes the
    /// register hash with `U`.
    pub fn reconcile(
        &mut self,
        view: &ChainView,
        pool: PoolTotals,
    ) -> Result<Reconciliation, ActorError> {
        self.read_feed(view)?;
        if !self.unreadable_notes.is_empty() {
            return Err(ActorError::UnreadableNotes(self.unreadable_notes.len()));
        }
        let register = self.total_units();
        if register != pool.units {
            return Err(ActorError::RegisterMismatch {
                register,
                pool: pool.units,
            });
        }
        let remainder = self
            .remainder(pool.balance, pool.multiplier)
            .ok_or(ActorError::SharesShort)?;
        Ok(Reconciliation {
            remainder,
            outflows: self.unexplained_outflows(view),
        })
    }
}

/// The uniform expiry of a batch issued in `epoch` (SPEC, Onboarding, step
/// 4): the end of the period that `epoch + ATTESTATION_OVERLAP` falls in,
/// periods counted from `start`. In a period's last overlap epochs a batch
/// already carries the next period's expiry. Within the registry's bounds:
/// after `epoch`, and under `epoch + 1 + ATTESTATION_PERIOD +
/// ATTESTATION_OVERLAP` epochs.
fn period_expiry(start: u64, epoch: u64) -> u64 {
    let period = (epoch + ATTESTATION_OVERLAP - start) / ATTESTATION_PERIOD;
    (start + (period + 1) * ATTESTATION_PERIOD) * EPOCH_SECONDS
}

/// The register hash as a hex string, for logs.
pub fn short(f: Fr) -> String {
    hex::encode(&fr_to_be_bytes(&f)[..4])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        EPOCH_SECONDS,
        chain::{
            AttestationRecord,
            NoteRecord,
        },
        domain::{
            feed::FEED_FIELDS,
            random_fr,
        },
    };

    fn env() -> PoolEnv {
        PoolEnv {
            chain_id: 31337,
            pool: Address::from([1; 20]),
            token: Address::from([2; 20]),
            register_key: FeedSecret::random().public_point(),
            claim_key_hash: Fr::from(0u64),
            min_accepted_generation: 0,
            epoch: 100,
            timestamp: 100 * EPOCH_SECONDS,
        }
    }

    /// Verifies an investor and records a fresh owner value for it directly,
    /// without the signed registration that `TransferAgent::onboard` checks.
    fn record_investor(agent: &mut TransferAgent, id: &str) -> Fr {
        record_investor_in(agent, id, "J1")
    }

    fn record_investor_in(agent: &mut TransferAgent, id: &str, jurisdiction: &str) -> Fr {
        agent.verify_investor(id, jurisdiction).unwrap();
        let keys = OwnerKeys::random();
        agent.record_owner(
            Holder::Investor(InvestorId::new(id).unwrap()),
            keys.spend.public_key(),
            keys.nk,
            keys.view.public_key(),
        )
    }

    fn attest(view: &mut ChainView, env: &PoolEnv, owner: Fr) {
        view.attestation_records.push(AttestationRecord {
            owner,
            attester: Address::from([0; 20]),
            generation: 0,
            issued_at: env.timestamp,
            expires_at: (env.epoch + 30) * EPOCH_SECONDS,
            leaf_index: view.attestation_records.len(),
        });
    }

    fn hold(agent: &mut TransferAgent, owner: Fr, units: u64) {
        let entry = RegisterEntry {
            note: Note {
                token: Fr::from(2u64),
                units,
                owner,
                salt: random_fr(),
                lock: Fr::from(0u64),
            },
            opening: LockOpening::NONE,
            commitment: random_fr(),
            leaf_index: agent.register.len(),
            holder: agent.holder_of(owner),
            spent: false,
        };
        agent.register.push(entry);
    }

    /// A cap of three. Alice is attested and Bob holds notes; Carol holds
    /// shares publicly. Each investor counts once, so Alice's second owner
    /// value and every renewal pass, while a new investor past the cap does not.
    #[test]
    fn cap_counts_each_investor_once() {
        let mut agent = TransferAgent::new();
        agent.max_investors = Some(3);
        let env = env();
        let mut view = ChainView::default();
        let alice = record_investor(&mut agent, "INV-ALICE");
        let alice_again = record_investor(&mut agent, "INV-ALICE");
        let bob = record_investor(&mut agent, "INV-BOB");
        let carol = record_investor(&mut agent, "INV-CAROL");
        let dave = record_investor(&mut agent, "INV-DAVE");
        let erin = record_investor(&mut agent, "INV-ERIN");
        attest(&mut view, &env, alice);
        hold(&mut agent, bob, 100);
        let carol_address = Address::from([0xca; 20]);
        agent
            .register_public_holder(carol_address, "INV-CAROL")
            .unwrap();

        // Without Carol's public shares, two count: room for one, not two.
        assert_eq!(agent.counted_investors(&view, &env, &[]).unwrap().len(), 2);
        assert!(agent.check_cap(&view, &env, &[dave], &[]).is_ok());
        assert!(matches!(
            agent.check_cap(&view, &env, &[dave, erin], &[]),
            Err(ActorError::CapReached { cap: 3 })
        ));

        // With them, three count: no room for Dave, but nothing already counted is refused.
        let public = [carol_address];
        assert_eq!(
            agent.counted_investors(&view, &env, &public).unwrap().len(),
            3
        );
        assert!(matches!(
            agent.check_cap(&view, &env, &[dave], &public),
            Err(ActorError::CapReached { cap: 3 })
        ));
        let counted = [alice, alice_again, bob, carol, agent.owner()];
        assert!(agent.check_cap(&view, &env, &counted, &public).is_ok());

        // An owner value the agent never onboarded cannot be attested at all.
        assert!(matches!(
            agent.check_cap(&view, &env, &[random_fr()], &public),
            Err(ActorError::UnknownOwner(_))
        ));
    }

    /// Each jurisdiction's cap counts the investors verified in it, once each,
    /// on top of the overall cap.
    #[test]
    fn jurisdiction_caps_count_investors_in_their_jurisdiction() {
        let mut agent = TransferAgent::new();
        agent.jurisdiction_caps.insert("J1".to_string(), 1);
        let env = env();
        let mut view = ChainView::default();
        let alice = record_investor(&mut agent, "INV-ALICE");
        let alice_again = record_investor(&mut agent, "INV-ALICE");
        let bob = record_investor(&mut agent, "INV-BOB");
        let carol = record_investor_in(&mut agent, "INV-CAROL", "J2");
        attest(&mut view, &env, alice);

        // J1 is full with Alice: her second owner value passes, and so does
        // Carol, in J2; Bob, in J1, does not.
        assert!(
            agent
                .check_cap(&view, &env, &[alice_again, carol], &[])
                .is_ok()
        );
        assert!(matches!(
            agent.check_cap(&view, &env, &[bob], &[]),
            Err(ActorError::JurisdictionCapReached { cap: 1, .. })
        ));
    }

    /// Council 1, C17: the same register hashes differently each epoch and
    /// for each agent, so a guessed register cannot be confirmed from the
    /// public hash without that day's salt.
    #[test]
    fn the_register_hash_is_salted_per_epoch() {
        let mut agent = TransferAgent::new();
        let mut other = TransferAgent::new();
        for a in [&mut agent, &mut other] {
            let owner = a.owner();
            hold(a, owner, 100);
        }
        assert_eq!(agent.positions(), other.positions());
        assert_eq!(agent.register_hash(7), agent.register_hash(7));
        assert_ne!(agent.register_hash(7), agent.register_hash(8));
        assert_ne!(agent.register_hash(7), other.register_hash(7));
    }

    /// Onboarding takes an investor that has been verified, and a registration
    /// signed by its spend key for this pool.
    #[test]
    fn onboarding_checks_the_registration() {
        let mut agent = TransferAgent::new();
        let env = env();
        let (signer, keys) = OwnerKeys::random().split();
        let wallet = Wallet::new(keys);
        let registration = wallet.registration(&env, "INV-ALICE");
        let signature = signer.sign_registration(&registration).unwrap();
        let nk = wallet.keys.nk;
        assert!(matches!(
            agent.onboard("INV-ALICE", &env, &registration, &signature, &nk),
            Err(ActorError::UnverifiedInvestor(_))
        ));

        agent.verify_investor("INV-ALICE", "J1").unwrap();
        let other = SpendKey::random();
        let not_hers = other
            .sign_registration(&Registration {
                pk: other.public_key(),
                ..registration.clone()
            })
            .unwrap();
        assert!(matches!(
            agent.onboard("INV-ALICE", &env, &registration, &not_hers, &nk),
            Err(ActorError::BadRegistration)
        ));
        // The signer signed `nk`'s hash: another `nk` sent alongside is refused.
        assert!(matches!(
            agent.onboard(
                "INV-ALICE",
                &env,
                &registration,
                &signature,
                &NullifierKey::random()
            ),
            Err(ActorError::BadRegistration)
        ));
        let elsewhere = PoolEnv {
            pool: Address::from([9; 20]),
            ..env
        };
        assert!(matches!(
            agent.onboard("INV-ALICE", &elsewhere, &registration, &signature, &nk),
            Err(ActorError::BadRegistration)
        ));
        // Signed for INV-ALICE: presented under another verified ID, it is
        // refused.
        agent.verify_investor("INV-MALLORY", "J1").unwrap();
        assert!(matches!(
            agent.onboard("INV-MALLORY", &env, &registration, &signature, &nk),
            Err(ActorError::BadRegistration)
        ));
        let owner = agent
            .onboard("INV-ALICE", &env, &registration, &signature, &nk)
            .unwrap();
        assert_eq!(owner, wallet.owner());
        // The same investor may register again.
        assert_eq!(
            agent
                .onboard("INV-ALICE", &env, &registration, &signature, &nk)
                .unwrap(),
            owner
        );
        // The same keys, signed for another ID, do not move the owner value.
        let as_mallory = wallet.registration(&env, "INV-MALLORY");
        let signed_as_mallory = signer.sign_registration(&as_mallory).unwrap();
        assert!(matches!(
            agent.onboard("INV-MALLORY", &env, &as_mallory, &signed_as_mallory, &nk),
            Err(ActorError::OwnerOfAnotherInvestor(_))
        ));
        assert_eq!(
            agent.holder_of(owner).as_ref().map(Holder::as_str),
            Some("INV-ALICE"),
            "the owner value stays with Alice"
        );
        // A zero `nk` would make the holder's nullifiers computable by anyone.
        let zero = NullifierKey(Fr::from(0u64));
        let zero_nk = Registration {
            nk_hash: zero.hash(),
            ..registration.clone()
        };
        let signed_zero = signer.sign_registration(&zero_nk).unwrap();
        assert!(matches!(
            agent.onboard("INV-ALICE", &env, &zero_nk, &signed_zero, &zero),
            Err(ActorError::BadRegistration)
        ));
    }

    /// Padding owner values are the agent's: attested, they count for nobody,
    /// and their notes would be the agent's to claim, kept apart from its own.
    #[test]
    fn padding_does_not_count_toward_the_cap() {
        let mut agent = TransferAgent::new();
        agent.max_investors = Some(1);
        let env = env();
        let mut view = ChainView::default();
        let alice = record_investor(&mut agent, "INV-ALICE");
        let padding = agent.fresh_padding(1)[0];
        attest(&mut view, &env, padding);
        assert!(
            agent
                .counted_investors(&view, &env, &[])
                .unwrap()
                .is_empty()
        );
        assert!(agent.check_cap(&view, &env, &[alice, padding], &[]).is_ok());
        assert_eq!(
            agent.holder_of(padding).as_ref().map(Holder::as_str),
            Some(PADDING_ID)
        );
    }

    /// Council 2, C26: a claim is recorded by its outputs, as pending until
    /// they appear on-chain. If the holder spends the target first, the claim
    /// is dropped and the holder's spend is not mistaken for it.
    #[test]
    fn a_claim_is_recorded_once_mined_and_dropped_if_the_holder_spends_first() {
        let mut agent = TransferAgent::new();
        let alice = record_investor(&mut agent, "INV-ALICE");
        hold(&mut agent, alice, 100);
        hold(&mut agent, alice, 50);
        let (first, second) =
            (agent.register[0].commitment, agent.register[1].commitment);
        let mined = ClaimRecord {
            target: first,
            outputs: [random_fr(), random_fr()],
        };
        let lost = ClaimRecord {
            target: second,
            outputs: [random_fr(), random_fr()],
        };
        agent.pending_claims = vec![mined.clone(), lost.clone()];

        let mut view = ChainView::default();
        agent.read_feed(&view).unwrap();
        assert_eq!(agent.pending_claims, [mined.clone(), lost.clone()]);

        let nk = agent.investors[&Bytes32::from(alice)].nk;
        let spend = |target: Fr, outputs: [Fr; 2]| SpendRecord {
            nullifiers: vec![note::nullifier(target, &nk), random_fr()],
            outputs: outputs.to_vec(),
            withdrawn_units: None,
        };
        view.spends.push(spend(first, mined.outputs));
        view.spends.push(spend(second, [random_fr(), random_fr()]));
        view.nullifiers
            .extend(view.spends.iter().flat_map(|s| s.nullifiers.clone()));
        agent.read_feed(&view).unwrap();
        assert_eq!(agent.claims, [mined]);
        assert!(
            agent.pending_claims.is_empty(),
            "the holder spent the second note first"
        );
    }

    /// Council 2, C44: a rotation changes nothing until it is committed, so
    /// one the pool refuses leaves the agent on its current key.
    #[test]
    fn a_register_key_rotation_takes_effect_when_committed() {
        let mut agent = TransferAgent::new();
        let before = agent.register_public_key();
        let refused = agent.new_register_key();
        assert_eq!(refused.version, 1);
        assert_eq!(agent.register_public_key(), before);

        let accepted = agent.new_register_key();
        assert_eq!(accepted.version, 1, "the refused one took no version");
        let tpk = accepted.public_key;
        agent.commit_register_key(accepted).unwrap();
        assert_eq!(agent.register_public_key(), tpk);
        assert!(matches!(
            agent.commit_register_key(refused),
            Err(ActorError::StaleRotation(1))
        ));
    }

    #[test]
    fn reconciliation_checks_the_register_against_the_pool() {
        let mut agent = TransferAgent::new();
        let owner = agent.owner();
        hold(&mut agent, owner, 100);
        let view = ChainView::default();
        let pool = |units: u128, balance: u64| PoolTotals {
            units,
            balance: U256::from(balance),
            multiplier: U256::from(crate::S),
        };
        let found = agent.reconcile(&view, pool(100, 101)).unwrap();
        assert_eq!(found.remainder, U256::from(1u8));
        assert!(matches!(
            agent.reconcile(&view, pool(99, 101)),
            Err(ActorError::RegisterMismatch {
                register: 100,
                pool: 99
            })
        ));
        assert!(matches!(
            agent.reconcile(&view, pool(100, 99)),
            Err(ActorError::SharesShort)
        ));
    }

    /// A note of `units` for `owner`, with its feed encrypted to `tpk`.
    fn feed_record(tpk: &Point, key_version: u64, owner: Fr, units: u64) -> NoteRecord {
        let note = Note {
            token: Fr::from(2u64),
            units,
            owner,
            salt: random_fr(),
            lock: Fr::from(0u64),
        };
        let (feed_r, k) = feed::derive(&FeedSecret::random(), tpk);
        NoteRecord {
            commitment: note.commitment(),
            leaf_index: 0,
            output: 0,
            feed_r,
            feed_ct: feed::encrypt(k, &feed::fields(&note, &LockOpening::NONE), 0),
            payload: vec![],
            key_version,
        }
    }

    /// A note no register key reads is skipped and reported instead of
    /// stopping the read: the notes after it still reach the register, so the
    /// cap check still runs. Reconciliation fails until the note is read.
    #[test]
    fn an_unreadable_note_is_skipped_and_reported() {
        let mut agent = TransferAgent::new();
        let unreadable = NoteRecord {
            commitment: random_fr(),
            leaf_index: 0,
            output: 0,
            feed_r: FeedSecret::random().public_point(),
            feed_ct: [Fr::from(0u64); FEED_FIELDS],
            payload: vec![],
            key_version: 1,
        };
        let mut view = ChainView::default();
        view.notes.push(unreadable.clone());
        let owner = agent.owner();
        view.notes
            .push(feed_record(&agent.register_public_key(), 0, owner, 100));
        agent.read_feed(&view).unwrap();
        assert_eq!(agent.register.len(), 1, "the note after it is read");
        assert_eq!(
            agent.unreadable_notes,
            [UnreadableNote {
                commitment: unreadable.commitment,
                key_version: 1,
            }]
        );
        let pool = PoolTotals {
            units: 100,
            balance: U256::from(100u64),
            multiplier: U256::from(crate::S),
        };
        assert!(matches!(
            agent.reconcile(&view, pool),
            Err(ActorError::UnreadableNotes(1))
        ));

        // A key of its version that does not open it leaves it unreadable.
        let rotation = agent.new_register_key();
        agent.commit_register_key(rotation).unwrap();
        agent.read_feed(&view).unwrap();
        assert_eq!(agent.unreadable_notes.len(), 1);
    }

    /// The pool takes a rotation's key and the agent stops before committing
    /// it. Restarted from its persisted state, the agent reads the notes made
    /// under the new key with the prepared one, the pool's key and version
    /// rebuild the rotation, and the commit files the key the pool holds.
    #[test]
    fn a_stop_between_a_rotation_and_its_commit_loses_no_note() {
        let mut agent = TransferAgent::new();
        let refused = agent.new_register_key();
        let taken = agent.new_register_key();
        let owner = agent.owner();
        let mut view = ChainView::default();
        view.notes
            .push(feed_record(&taken.public_key, 1, owner, 100));

        agent.read_feed(&view).unwrap();
        assert!(agent.unreadable_notes.is_empty());
        assert_eq!(agent.register.len(), 1);

        let from_the_pool = RegisterKeyRotation {
            version: 1,
            public_key: taken.public_key,
        };
        agent.commit_register_key(from_the_pool).unwrap();
        assert_eq!(agent.register_public_key(), taken.public_key);
        assert!(agent.prepared_register_keys.is_empty());
        assert!(matches!(
            agent.commit_register_key(refused),
            Err(ActorError::StaleRotation(1))
        ));
    }

    /// A rotation the agent never prepared is refused: committing it would
    /// file no key that reads the pool's notes.
    #[test]
    fn a_rotation_the_agent_did_not_prepare_is_refused() {
        let mut agent = TransferAgent::new();
        let foreign = RegisterKeyRotation {
            version: 1,
            public_key: FeedSecret::random().public_point(),
        };
        assert!(matches!(
            agent.commit_register_key(foreign),
            Err(ActorError::UnpreparedRotation(1))
        ));
    }

    /// The agent's own notes reach its wallet from the bound feed, so a
    /// payer's garbage payload cannot hide a redemption note from it.
    #[test]
    fn the_agents_own_notes_come_from_the_feed() {
        let mut agent = TransferAgent::new();
        let note = Note {
            token: Fr::from(2u64),
            units: 100,
            owner: agent.owner(),
            salt: random_fr(),
            lock: Fr::from(0u64),
        };
        let (feed_r, k) =
            feed::derive(&FeedSecret::random(), &agent.register_public_key());
        let mut view = ChainView::default();
        view.notes.push(NoteRecord {
            commitment: note.commitment(),
            leaf_index: 0,
            output: 0,
            feed_r,
            feed_ct: feed::encrypt(k, &feed::fields(&note, &LockOpening::NONE), 0),
            payload: b"not a payload".to_vec(),
            key_version: 0,
        });
        agent.read_feed(&view).unwrap();
        assert!(
            agent
                .wallet
                .notes
                .iter()
                .any(|n| n.commitment == note.commitment())
        );
    }

    /// A hand-out refuses the seed, any other locked note, and a note an
    /// investor redeemed: spending that would mark the redemption processed
    /// with nothing paid.
    #[test]
    fn a_hand_out_refuses_the_seed_and_a_pending_redemption() {
        let mut agent = TransferAgent::new();
        let env = env();
        let alice = record_investor(&mut agent, "INV-ALICE");
        let owner = agent.owner();
        hold(&mut agent, alice, 100);
        hold(&mut agent, owner, 100);
        hold(&mut agent, owner, 1);
        hold(&mut agent, owner, 5);
        agent.seed_deposit = Some(agent.register[2].commitment);
        agent.register[3].note.lock = LockOpening::freeze().value();
        agent.register[3].opening = LockOpening::freeze();
        let source = |e: &RegisterEntry| OwnedNote {
            note: e.note,
            opening: e.opening,
            commitment: e.commitment,
            leaf_index: e.leaf_index,
            spent: false,
        };
        let outputs = || {
            [0, 0].map(|units| Output {
                owner,
                units,
                opening: LockOpening::NONE,
                vpk: agent.wallet.vpk(),
            })
        };

        // Alice spends her note into the agent's: her redemption.
        let nk = agent.investors[&Bytes32::from(alice)].nk;
        let mut view = ChainView::default();
        view.spends.push(SpendRecord {
            nullifiers: vec![
                note::nullifier(agent.register[0].commitment, &nk),
                random_fr(),
            ],
            outputs: vec![agent.register[1].commitment, random_fr()],
            withdrawn_units: None,
        });
        view.nullifiers
            .extend(view.spends.iter().flat_map(|s| s.nullifiers.clone()));
        assert_eq!(agent.redemptions(&view).len(), 1);

        assert!(matches!(
            agent.hand_out_transfer(&view, &env, source(&agent.register[1]), outputs()),
            Err(ActorError::PendingRedemption(_))
        ));
        assert!(matches!(
            agent.hand_out_transfer(&view, &env, source(&agent.register[2]), outputs()),
            Err(ActorError::SeedNote(_))
        ));
        assert!(matches!(
            agent.hand_out_transfer(&view, &env, source(&agent.register[3]), outputs()),
            Err(ActorError::LockedNote(_))
        ));
    }

    /// The seed, its deposit's note and the frozen note its freeze creates,
    /// refuses every claim. Another frozen note of the agent's is not the seed:
    /// it can be released.
    #[test]
    fn the_seed_refuses_every_claim() {
        let mut agent = TransferAgent::new();
        let owner = agent.owner();
        hold(&mut agent, owner, 1);
        hold(&mut agent, owner, 1);
        hold(&mut agent, owner, 5);
        let deposit = agent.register[0].commitment;
        let frozen = agent.register[1].commitment;
        agent.register[1].opening = LockOpening::freeze();
        agent.register[2].opening = LockOpening::freeze();
        agent.seed_deposit = Some(deposit);
        agent.claims.push(ClaimRecord {
            target: deposit,
            outputs: [frozen, random_fr()],
        });
        let view = ChainView::default();
        let env = env();
        for seed in [deposit, frozen] {
            assert!(agent.is_seed(seed));
            for action in [
                ClaimAction::Freeze,
                ClaimAction::Hold {
                    until: env.epoch + 1,
                },
                ClaimAction::Release,
                ClaimAction::Seize {
                    to: owner,
                    to_vpk: agent.wallet.vpk(),
                },
            ] {
                assert!(matches!(
                    agent.claim(&view, &env, seed, action),
                    Err(ActorError::SeedNote(_))
                ));
            }
        }
        assert!(agent.pending_claims.is_empty());

        let other = agent.register[2].commitment;
        assert!(!agent.is_seed(other));
        assert!(!matches!(
            agent.claim(&view, &env, other, ClaimAction::Release),
            Err(ActorError::SeedNote(_))
        ));
    }

    /// The seed comes before any investor, and once.
    #[test]
    fn the_seed_is_deposited_once_and_before_any_investor() {
        let mut agent = TransferAgent::new();
        let mut view = ChainView::default();
        let env = env();
        let alice = record_investor(&mut agent, "INV-ALICE");
        attest(&mut view, &env, alice);
        assert!(matches!(
            agent.seed_deposit(&view, &env, 1, Address::from([3; 20])),
            Err(ActorError::InvestorBeforeSeed(_))
        ));
        assert!(matches!(
            agent.freeze_seed(&view, &env),
            Err(ActorError::NoSeed)
        ));
        agent.seed_deposit = Some(random_fr());
        assert!(matches!(
            agent.seed_deposit(&ChainView::default(), &env, 1, Address::from([3; 20])),
            Err(ActorError::SeedExists)
        ));
    }

    /// The hand-out tree: one transfer for a single order, `N - 1` for `N`,
    /// parents first; each order paid once, with its hold; and every transfer
    /// moves exactly what its source holds.
    #[test]
    fn a_hand_out_plan_pays_each_order_once() {
        let agent = TransferAgent::new();
        let order = |units, hold_until| HandOutOrder {
            owner: random_fr(),
            vpk: OwnerKeys::random().view.public_key(),
            units,
            hold_until,
        };
        assert!(agent.plan_hand_out(&[]).is_empty());
        let single = agent.plan_hand_out(&[order(7, None)]);
        assert_eq!(single.len(), 1);
        assert_eq!(single[0].source, HandOutSource::Aggregate);
        assert_eq!(
            [single[0].outputs[0].units, single[0].outputs[1].units],
            [7, 0]
        );

        let orders: Vec<HandOutOrder> = (1..=5)
            .map(|i| order(10 * i, (i == 3).then_some(200)))
            .collect();
        let plan = agent.plan_hand_out(&orders);
        assert_eq!(plan.len(), orders.len() - 1);
        let mut source_units = vec![orders.iter().map(|o| o.units).sum::<u64>()];
        let mut paid = Vec::new();
        for (i, step) in plan.iter().enumerate() {
            let held = match step.source {
                HandOutSource::Aggregate => source_units[0],
                HandOutSource::Output { transfer, index } => {
                    assert!(transfer < i, "parents first");
                    plan[transfer].outputs[index].units
                }
            };
            assert_eq!(step.outputs[0].units + step.outputs[1].units, held);
            for out in &step.outputs {
                if out.owner != agent.owner() {
                    paid.push((out.owner, out.units, out.opening));
                }
            }
            source_units.push(held);
        }
        assert_eq!(paid.len(), orders.len());
        for o in &orders {
            let opening = o.hold_until.map_or(LockOpening::NONE, LockOpening::hold);
            assert!(paid.contains(&(o.owner, o.units, opening)));
        }
    }

    /// Three one-unit notes, B = 5, so m = floor(5S/3), about 1.67 shares per
    /// unit. Each note withdraws 1, so the remainder is 2, above the
    /// pool-level bound B - floor(U*m/S) = 1.
    #[test]
    fn remainder_rounds_each_note_down() {
        let mut agent = TransferAgent::new();
        let owner = agent.owner();
        for _ in 0..3 {
            hold(&mut agent, owner, 1);
        }
        let s = U256::from(crate::S);
        let balance = U256::from(5u8);
        let m = balance * s / U256::from(3u8);
        assert_eq!(agent.remainder(balance, m), Some(U256::from(2u8)));
        assert_eq!(balance - U256::from(3u8) * m / s, U256::from(1u8));

        agent.register[0].spent = true;
        assert_eq!(agent.remainder(balance, m), Some(U256::from(3u8)));
        assert_eq!(agent.remainder(U256::from(1u8), m), None);
    }

    /// The pool's environment at `epoch`.
    fn env_at(epoch: u64) -> PoolEnv {
        PoolEnv {
            epoch,
            timestamp: epoch * EPOCH_SECONDS,
            ..env()
        }
    }

    /// The registry's records for a batch sent in `epoch`.
    fn send(view: &mut ChainView, batch: &AttestationBatch, epoch: u64) {
        for owner in batch.owners() {
            view.attestation_records.push(AttestationRecord {
                owner: *owner,
                attester: Address::from([0; 20]),
                generation: batch.generation(),
                issued_at: epoch * EPOCH_SECONDS,
                expires_at: batch.expires_at(),
                leaf_index: view.attestation_records.len(),
            });
        }
    }

    /// Batches in a period share its expiry; in its last overlap epochs they
    /// carry the next period's. Every expiry lies within the registry's
    /// bounds for the epoch it is issued in.
    #[test]
    fn a_batch_carries_its_periods_uniform_expiry() {
        let end = |start, epoch| period_expiry(start, epoch) / EPOCH_SECONDS;
        assert_eq!(end(100, 100), 130);
        assert_eq!(end(100, 126), 130);
        assert_eq!(end(100, 127), 160, "the overlap carries the next period's");
        assert_eq!(end(100, 129), 160);
        assert_eq!(end(100, 130), 160);
        assert_eq!(end(100, 157), 190);
        for epoch in 100..400 {
            let e = end(100, epoch);
            assert!(
                epoch < e && e < epoch + 1 + ATTESTATION_PERIOD + ATTESTATION_OVERLAP
            );
        }
    }

    /// Onboarding pads a batch with fresh values, which then stand with the
    /// investors: nothing is due again until the overlap, when the period's
    /// renewals take every value, padding included, and need no new padding
    /// when they fill whole parts.
    #[test]
    fn padding_is_fresh_at_onboarding_and_renewed_with_the_investors() {
        let mut agent = TransferAgent::new();
        let mut view = ChainView::default();
        let alice = record_investor(&mut agent, "INV-ALICE");

        let round = agent
            .attestation_batch(&view, &env_at(100), &[], 0)
            .unwrap();
        assert!(round.over_cap.is_empty());
        let batch = round.batch;
        assert_eq!(batch.parts().len(), 1);
        assert_eq!(batch.parts()[0].len(), ATTESTATION_PART);
        assert_eq!(batch.expires_at(), 130 * EPOCH_SECONDS);
        let owners: BTreeSet<Bytes32> =
            batch.owners().map(|o| Bytes32::from(*o)).collect();
        assert_eq!(owners.len(), ATTESTATION_PART, "each value once");
        assert!(owners.contains(&Bytes32::from(agent.owner())));
        assert!(owners.contains(&Bytes32::from(alice)));
        assert_eq!(agent.padding.len(), ATTESTATION_PART - 2);
        send(&mut view, &batch, 100);

        let nothing = agent
            .attestation_batch(&view, &env_at(105), &[], 0)
            .unwrap();
        assert!(nothing.batch.is_empty(), "nothing is due mid-period");

        let bob = record_investor(&mut agent, "INV-BOB");
        let batch = agent
            .attestation_batch(&view, &env_at(110), &[], 0)
            .unwrap()
            .batch;
        assert_eq!(batch.owners().count(), ATTESTATION_PART);
        assert!(batch.owners().any(|o| *o == bob));
        assert_eq!(agent.padding.len(), 2 * ATTESTATION_PART - 3);
        send(&mut view, &batch, 110);

        let renewals = agent
            .attestation_batch(&view, &env_at(127), &[], 0)
            .unwrap()
            .batch;
        assert_eq!(renewals.expires_at(), 160 * EPOCH_SECONDS);
        assert_eq!(renewals.parts().len(), 2);
        assert_eq!(
            agent.padding.len(),
            2 * ATTESTATION_PART - 3,
            "own, Alice, Bob and the padding fill two parts"
        );
        let renewed: BTreeSet<Bytes32> =
            renewals.owners().map(|o| Bytes32::from(*o)).collect();
        assert!(
            agent
                .padding
                .iter()
                .all(|k| renewed.contains(&Bytes32::from(k.owner())))
        );
    }

    /// A value the agent stops renewing is left out of the period's renewals;
    /// its own value cannot be stopped.
    #[test]
    fn a_stopped_value_is_not_renewed() {
        let mut agent = TransferAgent::new();
        let mut view = ChainView::default();
        let alice = record_investor(&mut agent, "INV-ALICE");
        let batch = agent
            .attestation_batch(&view, &env_at(100), &[], 0)
            .unwrap()
            .batch;
        send(&mut view, &batch, 100);

        agent.stop_renewing(alice).unwrap();
        let retired = agent.padding[0].owner();
        agent.stop_renewing(retired).unwrap();
        let renewals = agent
            .attestation_batch(&view, &env_at(127), &[], 0)
            .unwrap()
            .batch;
        assert!(!renewals.owners().any(|o| *o == alice || *o == retired));
        assert!(renewals.owners().any(|o| *o == agent.owner()));

        assert!(matches!(
            agent.stop_renewing(agent.owner()),
            Err(ActorError::AgentsOwnValue)
        ));
        assert!(matches!(
            agent.stop_renewing(random_fr()),
            Err(ActorError::UnknownOwner(_))
        ));
    }

    /// A new investor past the cap is left out and reported, and the period's
    /// renewals go ahead without it; it stays due for a later batch.
    #[test]
    fn a_newcomer_over_the_cap_does_not_hold_up_renewals() {
        let mut agent = TransferAgent::new();
        agent.max_investors = Some(1);
        let mut view = ChainView::default();
        let alice = record_investor(&mut agent, "INV-ALICE");
        let batch = agent
            .attestation_batch(&view, &env_at(100), &[], 0)
            .unwrap()
            .batch;
        send(&mut view, &batch, 100);

        let carol = record_investor(&mut agent, "INV-CAROL");
        let round = agent
            .attestation_batch(&view, &env_at(127), &[], 0)
            .unwrap();
        assert_eq!(round.over_cap, [carol]);
        assert!(round.batch.owners().any(|o| *o == alice));
        assert!(!round.batch.owners().any(|o| *o == carol));

        agent.max_investors = Some(2);
        send(&mut view, &round.batch, 127);
        let later = agent
            .attestation_batch(&view, &env_at(130), &[], 0)
            .unwrap();
        assert!(later.over_cap.is_empty());
        assert!(later.batch.owners().any(|o| *o == carol));
    }

    /// The agent's reserved names, and an empty ID, are no investor's: an
    /// investor under one would count as the agent's, outside every cap. A
    /// public holder must be a verified investor.
    #[test]
    fn reserved_ids_and_unverified_public_holders_are_refused() {
        let mut agent = TransferAgent::new();
        let env = env();
        for id in [AGENT_ID, PADDING_ID, ""] {
            assert!(matches!(
                agent.verify_investor(id, "J1"),
                Err(ActorError::InvalidInvestorId(_))
            ));
            assert!(matches!(
                agent.register_public_holder(Address::from([4; 20]), id),
                Err(ActorError::InvalidInvestorId(_))
            ));
        }
        let (signer, keys) = OwnerKeys::random().split();
        let wallet = Wallet::new(keys);
        let registration = wallet.registration(&env, AGENT_ID);
        let signature = signer.sign_registration(&registration).unwrap();
        assert!(matches!(
            agent.onboard(AGENT_ID, &env, &registration, &signature, &wallet.keys.nk),
            Err(ActorError::InvalidInvestorId(_))
        ));
        assert!(agent.investors.is_empty());

        assert!(matches!(
            agent.register_public_holder(Address::from([4; 20]), "INV-CAROL"),
            Err(ActorError::UnverifiedInvestor(_))
        ));
        agent.verify_investor("INV-CAROL", "J1").unwrap();
        agent
            .register_public_holder(Address::from([4; 20]), "INV-CAROL")
            .unwrap();
    }

    /// An address holding shares that no investor is registered at cannot be
    /// counted, so the cap check fails rather than miss it, and so does the
    /// attestation batch that runs it.
    #[test]
    fn an_unknown_public_holder_fails_the_count() {
        let mut agent = TransferAgent::new();
        let env = env();
        let view = ChainView::default();
        let stranger = Address::from([5; 20]);
        assert!(matches!(
            agent.counted_investors(&view, &env, &[stranger]),
            Err(ActorError::UnknownPublicHolder(a)) if a == stranger
        ));
        assert!(matches!(
            agent.check_cap(&view, &env, &[], &[stranger]),
            Err(ActorError::UnknownPublicHolder(_))
        ));
        assert!(matches!(
            agent.attestation_batch(&view, &env, &[stranger], 0),
            Err(ActorError::UnknownPublicHolder(_))
        ));
    }
}

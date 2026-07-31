//! Request/response value types for `Wallet`, plus `CompliancePlaintext`: the wire
//! format encrypted into the `0x02`/`0x03` payload elements. No such encoding exists in
//! `domain::payload` (that module only frames opaque ciphertext bytes), so this crate
//! needs exactly one producer and one consumer of it; `wallet` owns it because it is the
//! side that encrypts, and `auditor` imports it to decrypt (`crate::wallet::types`).

use ark_bn254::Fr;

use crate::{
    domain::{
        compliance_note::{
            ComplianceNote,
            Facts,
            StateCommitment,
            compliance_commitment,
        },
        keys::{
            ComplianceViewingKey,
            OwnerPubkey,
            SpendingKey,
            ViewingKey,
            ViewingPubkey,
        },
        note::Note,
        witness::PolicyState,
    },
    error::CryptoError,
    policy::reference::ReferencePolicy,
    ports::{
        merkle::LeafIndex,
        prover::ProofRequest,
    },
    types::{
        Address,
        Bytes32,
        Epoch,
        Flags,
        Seq,
    },
};

use crate::domain::payload::Payload;

/// The wallet's own key material. `viewing_key` decrypts the `0x01` value-note
/// elements addressed to this subject, whether self-minted or received from another
/// party's transfer; its public half travels out of band to whoever builds an output
/// naming this subject as owner.
pub struct WalletKeys {
    pub spending_key: SpendingKey,
    pub compliance_viewing_key: ComplianceViewingKey,
    pub viewing_key: ViewingKey,
}

impl WalletKeys {
    pub fn owner_pubkey(&self) -> OwnerPubkey {
        self.spending_key.derive_owner_pubkey()
    }
}

/// A note the wallet controls, together with its position in the commitment tree so a
/// spend can request a fresh inclusion proof.
#[derive(Debug, Clone, Copy)]
pub struct OwnedNote {
    pub note: Note,
    pub leaf_index: LeafIndex,
}

pub struct DepositRequest {
    pub token: Address,
    pub amount: u64,
}

/// One transfer output. Per SPEC "TxFacts construction", a change output back to the
/// sender still sets `owner` to the sender's own pubkey rather than a sentinel; the
/// caller decides padding and change, the wallet does not infer it.
///
/// `viewing_pubkey` is how the recipient's `0x01` value-note element gets addressed:
/// it travels out of band, the same way `owner`'s attestation already does. For a
/// self-owned output (a change output, or a deposit's minted note) the wallet ignores
/// this field and encrypts to its own `viewing_key` instead, so a caller cannot lock
/// itself out of its own change by supplying the wrong key.
pub struct TransferOutput {
    pub owner: OwnerPubkey,
    pub amount: u64,
    pub viewing_pubkey: ViewingPubkey,
}

pub struct TransferRequest {
    pub token: Address,
    pub inputs: [OwnedNote; 2],
    pub outputs: [TransferOutput; 2],
}

pub struct WithdrawRequest {
    pub input: OwnedNote,
    pub token: Address,
    pub amount: u64,
    pub recipient: Address,
}

/// A built deposit: the proof request, the encrypted compliance-note payload
/// (`ChainWriter::submit_deposit`'s `encrypted_payload`), and the new value note's leaf
/// index so a caller can spend it later.
#[derive(Debug)]
pub struct BuiltDeposit {
    pub request: ProofRequest,
    pub payload: Payload,
    pub note: Note,
    pub output_index: LeafIndex,
}

/// `outputs`/`output_indices` are the wallet's only record of a newly minted note's
/// salt: nothing else observes it, so a caller who needs to spend an output later
/// (e.g. a chained transfer's change output) reads it from here, not by recomputing it.
#[derive(Debug)]
pub struct BuiltTransfer {
    pub request: ProofRequest,
    pub payload: Payload,
    pub outputs: [Note; 2],
    pub output_indices: [LeafIndex; 2],
}

#[derive(Debug)]
pub struct BuiltWithdraw {
    pub request: ProofRequest,
    pub payload: Payload,
}

/// The ungated path carries no compliance note, so there is nothing to encrypt
/// (`ChainWriter::submit_withdraw_blocked` takes no `encrypted_payload` argument).
#[derive(Debug)]
pub struct BuiltWithdrawBlocked {
    pub request: ProofRequest,
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(bytes[offset..offset + 8].try_into().expect("8-byte slice"))
}

fn bytes32_at(bytes: &[u8], offset: usize) -> Bytes32 {
    let array: [u8; 32] = bytes[offset..offset + 32]
        .try_into()
        .expect("32-byte slice");
    Bytes32::from(array)
}

/// The inverse of `Bytes32::from(Fr::from(address))`: rejects a value whose top 12
/// bytes are nonzero, since a genuine `Address` never sets them.
fn address_from_bytes32(bytes: Bytes32) -> Result<Address, CryptoError> {
    let raw = bytes.as_ref();
    if raw[..12].iter().any(|&b| b != 0) {
        return Err(CryptoError::MalformedCiphertext);
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&raw[12..]);
    Ok(Address::from(out))
}

/// `Flags` has no public constructor from a raw `u64` (only the two named consts and
/// `union`), so a decoded bitfield is rebuilt bit by bit against the two flags this
/// crate defines rather than transmuted. A bit outside those two is rejected instead of
/// masked away: this decodes a ciphertext, and silently dropping a set bit would let a
/// sender and an auditor disagree about what the note says.
fn flags_from_u64(raw: u64) -> Result<Flags, CryptoError> {
    let known = Flags::FLAG_SINGLE_TX.as_u64() | Flags::FLAG_AGGREGATE.as_u64();
    if raw & !known != 0 {
        return Err(CryptoError::MalformedCiphertext);
    }
    let mut flags = Flags::NONE;
    if raw & Flags::FLAG_SINGLE_TX.as_u64() != 0 {
        flags = flags.union(Flags::FLAG_SINGLE_TX);
    }
    if raw & Flags::FLAG_AGGREGATE.as_u64() != 0 {
        flags = flags.union(Flags::FLAG_AGGREGATE);
    }
    Ok(flags)
}

/// The plaintext encrypted into a `0x02`/`0x03` payload element: a full opening of one
/// `ComplianceNote<ReferencePolicy>`. Fixed-width, mirroring `domain::payload`'s
/// hand-rolled style: `owner_pubkey(32) epoch(8) seq(8) salt(32) flags(8) state(8)
/// counterparty_0(32) counterparty_1(32) amount_out_0(8) amount_out_1(8) exit(32)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompliancePlaintext {
    pub owner_pubkey: OwnerPubkey,
    pub epoch: Epoch,
    pub seq: Seq,
    pub salt: Bytes32,
    pub flags: Flags,
    pub state: PolicyState,
    pub facts: Facts,
}

const ENCODED_LEN: usize = 32 + 8 + 8 + 32 + 8 + 8 + 32 + 32 + 8 + 8 + 32;

impl CompliancePlaintext {
    pub fn from_note(note: &ComplianceNote<ReferencePolicy>) -> Self {
        Self {
            owner_pubkey: note.owner_pubkey,
            epoch: note.epoch,
            seq: note.seq,
            salt: note.salt,
            flags: note.flags,
            state: note.state,
            facts: note.facts,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ENCODED_LEN);
        out.extend_from_slice(self.owner_pubkey.as_bytes32().as_ref());
        out.extend_from_slice(&self.epoch.0.to_be_bytes());
        out.extend_from_slice(&self.seq.0.to_be_bytes());
        out.extend_from_slice(self.salt.as_ref());
        out.extend_from_slice(&self.flags.as_u64().to_be_bytes());
        out.extend_from_slice(&self.state[0].to_be_bytes());
        out.extend_from_slice(self.facts.counterparty[0].as_ref());
        out.extend_from_slice(self.facts.counterparty[1].as_ref());
        out.extend_from_slice(&self.facts.amount_out[0].to_be_bytes());
        out.extend_from_slice(&self.facts.amount_out[1].to_be_bytes());
        out.extend_from_slice(self.facts.exit.as_ref());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != ENCODED_LEN {
            return Err(CryptoError::MalformedCiphertext);
        }
        let owner_pubkey = OwnerPubkey::from_bytes32(bytes32_at(bytes, 0));
        let epoch = Epoch(u64_at(bytes, 32));
        let seq = Seq(u64_at(bytes, 40));
        let salt = bytes32_at(bytes, 48);
        let flags = flags_from_u64(u64_at(bytes, 80))?;
        let state = [u64_at(bytes, 88)];
        let counterparty = [bytes32_at(bytes, 96), bytes32_at(bytes, 128)];
        let amount_out = [u64_at(bytes, 160), u64_at(bytes, 168)];
        let exit = bytes32_at(bytes, 176);
        Ok(Self {
            owner_pubkey,
            epoch,
            seq,
            salt,
            flags,
            state,
            facts: Facts {
                counterparty,
                amount_out,
                exit,
            },
        })
    }

    /// Recomputes `CN` from this opening. The auditor's way of "locating the leaf": the
    /// result is the exact value the wallet inserted into the commitment tree, so a
    /// caller with chain access can confirm the decrypted note is the one actually
    /// committed rather than a mismatched or tampered ciphertext.
    pub fn recompute_commitment(
        &self,
        state_tag: Bytes32,
    ) -> Result<Bytes32, CryptoError> {
        let state_commitment = StateCommitment {
            epoch: self.epoch,
            seq: self.seq,
            flags: self.flags,
            facts: self.facts,
        }
        .hash::<ReferencePolicy>(state_tag, &self.state)?;
        compliance_commitment(self.owner_pubkey, state_commitment, self.salt)
    }
}

/// The plaintext encrypted into a `0x01` value-note payload element: a full opening of
/// one `Note`. Fixed-width, mirroring `CompliancePlaintext`'s style: `token(32)
/// amount(8) owner_pubkey(32) salt(32)`, `token` encoded the same way every other
/// field-typed public input is (`Bytes32::from(Fr::from(token))`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValueNotePlaintext {
    pub token: Address,
    pub amount: u64,
    pub owner_pubkey: OwnerPubkey,
    pub salt: Bytes32,
}

const VALUE_NOTE_ENCODED_LEN: usize = 32 + 8 + 32 + 32;

impl ValueNotePlaintext {
    pub fn from_note(note: &Note) -> Self {
        Self {
            token: note.token,
            amount: note.amount,
            owner_pubkey: note.owner_pubkey,
            salt: note.salt,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(VALUE_NOTE_ENCODED_LEN);
        out.extend_from_slice(Bytes32::from(Fr::from(self.token)).as_ref());
        out.extend_from_slice(&self.amount.to_be_bytes());
        out.extend_from_slice(self.owner_pubkey.as_bytes32().as_ref());
        out.extend_from_slice(self.salt.as_ref());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != VALUE_NOTE_ENCODED_LEN {
            return Err(CryptoError::MalformedCiphertext);
        }
        let token = address_from_bytes32(bytes32_at(bytes, 0))?;
        let amount = u64_at(bytes, 32);
        let owner_pubkey = OwnerPubkey::from_bytes32(bytes32_at(bytes, 40));
        let salt = bytes32_at(bytes, 72);
        Ok(Self {
            token,
            amount,
            owner_pubkey,
            salt,
        })
    }

    pub fn into_note(self) -> Note {
        Note::with_salt(self.token, self.amount, self.owner_pubkey, self.salt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::keys::SpendingKey;

    fn sample_note() -> ComplianceNote<ReferencePolicy> {
        let owner = SpendingKey::random().derive_owner_pubkey();
        ComplianceNote::<ReferencePolicy> {
            owner_pubkey: owner,
            epoch: Epoch(42),
            seq: Seq(3),
            salt: Bytes32::from([5u8; 32]),
            flags: Flags::NONE.union(Flags::FLAG_SINGLE_TX),
            state: [1234],
            facts: Facts {
                counterparty: [Bytes32::from([1u8; 32]), Bytes32::from([2u8; 32])],
                amount_out: [900, 0],
                exit: Bytes32::from([3u8; 32]),
            },
        }
    }

    #[test]
    fn compliance_plaintext_round_trips_through_encode_decode() {
        let note = sample_note();
        let plaintext = CompliancePlaintext::from_note(&note);
        let decoded = CompliancePlaintext::decode(&plaintext.encode()).expect("decodes");
        assert_eq!(decoded, plaintext);
    }

    #[test]
    fn decode_rejects_the_wrong_length() {
        assert!(CompliancePlaintext::decode(&[0u8; 10]).is_err());
    }

    /// A flags bitfield carrying a bit this crate does not define is rejected, not
    /// masked down to the two known ones.
    #[test]
    fn decode_rejects_an_unknown_flag_bit() {
        let mut bytes = CompliancePlaintext::from_note(&sample_note()).encode();
        bytes[80..88].copy_from_slice(&4u64.to_be_bytes());
        assert!(CompliancePlaintext::decode(&bytes).is_err());

        bytes[80..88].copy_from_slice(&3u64.to_be_bytes());
        let decoded = CompliancePlaintext::decode(&bytes).expect("both known bits set");
        assert_eq!(decoded.flags.as_u64(), 3);
    }

    #[test]
    fn recompute_commitment_matches_the_note_it_was_built_from() {
        let note = sample_note();
        let tag = Bytes32::from([9u8; 32]);
        let plaintext = CompliancePlaintext::from_note(&note);
        assert_eq!(
            plaintext.recompute_commitment(tag).unwrap(),
            note.commitment(tag).unwrap()
        );
    }

    #[test]
    fn value_note_plaintext_round_trips_through_encode_decode() {
        let owner = SpendingKey::random().derive_owner_pubkey();
        let note = Note::with_salt(
            Address::from([7u8; 20]),
            42_000,
            owner,
            Bytes32::from([6u8; 32]),
        );
        let plaintext = ValueNotePlaintext::from_note(&note);
        let decoded = ValueNotePlaintext::decode(&plaintext.encode()).expect("decodes");
        assert_eq!(decoded, plaintext);
        assert_eq!(decoded.into_note(), note);
    }

    #[test]
    fn value_note_plaintext_decode_rejects_the_wrong_length() {
        assert!(ValueNotePlaintext::decode(&[0u8; 10]).is_err());
    }
}

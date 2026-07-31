//! SPEC "On-Chain State", "Encrypted payload framing": a length-prefixed list whose
//! elements each carry a one-byte discriminator (`0x01` value note, `0x02` compliance
//! note to the owner, `0x03` compliance note to the epoch group key). The `0x03`
//! element MUST carry the `committeeVersion` it was encrypted under.
//!
//! Hand-rolled rather than `serde`: the ciphertext is not consensus input and nothing
//! hashes it, but the wire shape (discriminator, optional version, length-prefixed
//! bytes) is exactly what crosses the `encryptedNotes` calldata boundary, so a small
//! explicit codec is clearer than a generic derive here.

use alloy::primitives::keccak256;
use num_bigint::BigUint;

use crate::{
    error::CryptoError,
    types::Bytes32,
};

const TAG_VALUE_NOTE: u8 = 0x01;
const TAG_COMPLIANCE_NOTE_OWNER: u8 = 0x02;
const TAG_COMPLIANCE_NOTE_COMMITTEE: u8 = 0x03;

/// Which of the payload's three element kinds this is, and the `committeeVersion` the
/// `0x03` kind MUST carry (SPEC "Audit Channel").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadKind {
    ValueNote,
    ComplianceNoteToOwner,
    ComplianceNoteToCommittee { committee_version: u64 },
}

impl PayloadKind {
    const fn tag(self) -> u8 {
        match self {
            Self::ValueNote => TAG_VALUE_NOTE,
            Self::ComplianceNoteToOwner => TAG_COMPLIANCE_NOTE_OWNER,
            Self::ComplianceNoteToCommittee { .. } => TAG_COMPLIANCE_NOTE_COMMITTEE,
        }
    }

    /// Additional authenticated data for the ECIES encryption of this element: the
    /// discriminator alone for `0x01`/`0x02`, and the discriminator followed by the
    /// big-endian `committee_version` for `0x03`. Binds the cleartext framing into the
    /// AEAD tag, so flipping either byte on the wire fails decryption instead of
    /// silently opening under the wrong kind or a different committee version.
    pub fn aad(self) -> Vec<u8> {
        let mut out = vec![self.tag()];
        if let Self::ComplianceNoteToCommittee { committee_version } = self {
            out.extend_from_slice(&committee_version.to_be_bytes());
        }
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadElement {
    pub kind: PayloadKind,
    pub ciphertext: Vec<u8>,
}

/// A gated operation's full `encryptedNotes` payload: one value-note element per
/// output plus the two compliance-note elements.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Payload(Vec<PayloadElement>);

impl Payload {
    pub fn new(elements: Vec<PayloadElement>) -> Self {
        Self(elements)
    }

    pub fn elements(&self) -> &[PayloadElement] {
        &self.0
    }

    /// `[u32 element count]` then, per element, `[tag u8][committee_version u64 if
    /// tag == 0x03][ciphertext len u32][ciphertext bytes]`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.0.len() as u32).to_be_bytes());
        for element in &self.0 {
            out.push(element.kind.tag());
            if let PayloadKind::ComplianceNoteToCommittee { committee_version } =
                element.kind
            {
                out.extend_from_slice(&committee_version.to_be_bytes());
            }
            out.extend_from_slice(&(element.ciphertext.len() as u32).to_be_bytes());
            out.extend_from_slice(&element.ciphertext);
        }
        out
    }

    /// The value the contract recomputes and checks against the `payload_commitment`
    /// public input before accepting a `deposit`/`transfer`/`withdraw` proof: binding
    /// this into the public inputs is what stops a relayer from substituting arbitrary
    /// bytes for `encryptedNotes` while the proof still verifies.
    pub fn commitment(&self) -> Bytes32 {
        let digest = keccak256(self.encode());
        let reduced = BigUint::from_bytes_be(digest.as_slice()) % &*crate::BN254_MODULUS;
        let mut bytes = [0u8; 32];
        let reduced_be = reduced.to_bytes_be();
        bytes[32 - reduced_be.len()..].copy_from_slice(&reduced_be);
        Bytes32::from(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        let mut cursor = Cursor::new(bytes);
        let count = cursor.read_u32()?;
        // Every element needs at least a 1-byte tag and a 4-byte ciphertext length, so an
        // untrusted `count` can never plausibly exceed remaining_bytes / 5. Without this
        // cap, `count = u32::MAX` drives a ~4B-element, tens-of-GB allocation before any
        // byte of the claimed elements is validated.
        let plausible_max = cursor.remaining() / 5;
        let mut elements = Vec::with_capacity((count as usize).min(plausible_max));
        for _ in 0..count {
            let tag = cursor.read_u8()?;
            let kind = match tag {
                TAG_VALUE_NOTE => PayloadKind::ValueNote,
                TAG_COMPLIANCE_NOTE_OWNER => PayloadKind::ComplianceNoteToOwner,
                TAG_COMPLIANCE_NOTE_COMMITTEE => {
                    let committee_version = cursor.read_u64()?;
                    PayloadKind::ComplianceNoteToCommittee { committee_version }
                }
                _ => return Err(CryptoError::MalformedCiphertext),
            };
            let len = cursor.read_u32()? as usize;
            let ciphertext = cursor.read_bytes(len)?.to_vec();
            elements.push(PayloadElement { kind, ciphertext });
        }
        Ok(Self(elements))
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], CryptoError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(CryptoError::MalformedCiphertext)?;
        let slice = self
            .bytes
            .get(self.pos..end)
            .ok_or(CryptoError::MalformedCiphertext)?;
        self.pos = end;
        Ok(slice)
    }

    fn read_u8(&mut self) -> Result<u8, CryptoError> {
        Ok(self.read_bytes(1)?[0])
    }

    fn read_u32(&mut self) -> Result<u32, CryptoError> {
        let bytes: [u8; 4] = self
            .read_bytes(4)?
            .try_into()
            .expect("read_bytes(4) returns 4 bytes");
        Ok(u32::from_be_bytes(bytes))
    }

    fn read_u64(&mut self) -> Result<u64, CryptoError> {
        let bytes: [u8; 8] = self
            .read_bytes(8)?
            .try_into()
            .expect("read_bytes(8) returns 8 bytes");
        Ok(u64::from_be_bytes(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_three_element_list_with_committee_version_on_the_0x03_element() {
        let payload = Payload::new(vec![
            PayloadElement {
                kind: PayloadKind::ValueNote,
                ciphertext: vec![0xaa; 12],
            },
            PayloadElement {
                kind: PayloadKind::ComplianceNoteToOwner,
                ciphertext: vec![0xbb; 20],
            },
            PayloadElement {
                kind: PayloadKind::ComplianceNoteToCommittee {
                    committee_version: 7,
                },
                ciphertext: vec![0xcc; 30],
            },
        ]);

        let bytes = payload.encode();
        let decoded = Payload::decode(&bytes).expect("well-formed payload decodes");

        assert_eq!(decoded, payload);
        assert_eq!(decoded.elements()[0].kind, PayloadKind::ValueNote);
        assert_eq!(
            decoded.elements()[1].kind,
            PayloadKind::ComplianceNoteToOwner
        );
        assert_eq!(
            decoded.elements()[2].kind,
            PayloadKind::ComplianceNoteToCommittee {
                committee_version: 7
            }
        );
    }

    #[test]
    fn empty_payload_round_trips() {
        let payload = Payload::default();
        let bytes = payload.encode();
        assert_eq!(Payload::decode(&bytes).unwrap(), payload);
    }

    #[test]
    fn decode_rejects_truncated_bytes() {
        let payload = Payload::new(vec![PayloadElement {
            kind: PayloadKind::ValueNote,
            ciphertext: vec![0xaa; 12],
        }]);
        let mut bytes = payload.encode();
        bytes.truncate(bytes.len() - 1);
        assert!(Payload::decode(&bytes).is_err());
    }

    #[test]
    fn decode_rejects_an_unknown_discriminator() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.push(0x04);
        assert!(Payload::decode(&bytes).is_err());
    }

    #[test]
    fn decode_rejects_an_implausible_element_count_without_over_allocating() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            Payload::decode(&bytes),
            Err(CryptoError::MalformedCiphertext)
        ));
    }

    #[test]
    fn aad_differs_across_element_kinds() {
        let value_note = PayloadKind::ValueNote.aad();
        let to_owner = PayloadKind::ComplianceNoteToOwner.aad();
        let to_committee = PayloadKind::ComplianceNoteToCommittee {
            committee_version: 1,
        }
        .aad();
        assert_ne!(value_note, to_owner);
        assert_ne!(to_owner, to_committee);
        assert_ne!(value_note, to_committee);
    }

    #[test]
    fn aad_differs_across_committee_versions() {
        let v1 = PayloadKind::ComplianceNoteToCommittee {
            committee_version: 1,
        }
        .aad();
        let v2 = PayloadKind::ComplianceNoteToCommittee {
            committee_version: 2,
        }
        .aad();
        assert_ne!(v1, v2);
    }
}

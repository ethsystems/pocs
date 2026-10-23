//! The three circuits' inputs: public inputs in each `main`'s order, and the
//! private witnesses. `adapters::bb_prover` renders these as `Prover.toml`.

use ark_bn254::Fr;

use crate::{
    domain::{
        feed::{
            FEED_FIELDS,
            FeedSecret,
        },
        grumpkin::Point,
        keys::PublicSpendKey,
        note::{
            LockOpening,
            Note,
        },
        tree::MerkleProof,
    },
    types::{
        Address,
        Bytes32,
    },
};

/// The private witnesses of one attestation leaf.
#[derive(Debug, Clone)]
pub struct AttestationWitness {
    pub attester: Address,
    pub generation: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub path: MerkleProof,
}

/// A spent note's private witnesses. Token and owner come from the circuit.
#[derive(Debug, Clone)]
pub struct InputWitness {
    pub units: u64,
    pub salt: Fr,
    pub lock: Fr,
    pub lock_opening: LockOpening,
    pub path: MerkleProof,
}

impl InputWitness {
    /// The zero-unit note that pads a one-input transfer. Never in the tree.
    pub fn padding(salt: Fr) -> Self {
        Self {
            units: 0,
            salt,
            lock: Fr::from(0u64),
            lock_opening: LockOpening::NONE,
            path: MerkleProof::default(),
        }
    }
}

fn fr(v: u64) -> Bytes32 {
    Bytes32::from(Fr::from(v))
}

fn point(p: &Point) -> [Bytes32; 2] {
    [Bytes32::from(p.x), Bytes32::from(p.y)]
}

#[derive(Debug, Clone)]
pub struct DepositWitness {
    // Public, in `DepositPublicInputs` order.
    pub commitment: Fr,
    pub token: Address,
    pub units: u64,
    pub funding_address: Address,
    pub attestation_root: Fr,
    pub min_accepted_generation: u64,
    pub epoch: u64,
    pub chain_id: u64,
    pub pool: Address,
    pub register_key: Point,
    pub feed_r: Point,
    pub feed_ct: [Fr; FEED_FIELDS],
    pub payload_commitment: Fr,
    // Private.
    pub owner_key: PublicSpendKey,
    pub nk: Fr,
    pub signature: [u8; 64],
    /// Private: the circuit checks it against `epoch`.
    pub expiry: u64,
    pub salt: Fr,
    pub attestation: AttestationWitness,
    pub feed_secret: FeedSecret,
}

impl DepositWitness {
    pub fn public_inputs(&self) -> Vec<Bytes32> {
        let mut v = vec![
            Bytes32::from(self.commitment),
            Bytes32::from(Fr::from(self.token)),
            fr(self.units),
            Bytes32::from(Fr::from(self.funding_address)),
            Bytes32::from(self.attestation_root),
            fr(self.min_accepted_generation),
            fr(self.epoch),
            fr(self.chain_id),
            Bytes32::from(Fr::from(self.pool)),
        ];
        v.extend(point(&self.register_key));
        v.extend(point(&self.feed_r));
        v.extend(self.feed_ct.iter().map(|c| Bytes32::from(*c)));
        v.push(Bytes32::from(self.payload_commitment));
        v
    }
}

#[derive(Debug, Clone)]
pub struct TransferWitness {
    // Public, in `TransferPublicInputs` order.
    pub nullifiers: [Fr; 2],
    pub commitments_out: [Fr; 2],
    pub commitment_root: Fr,
    pub attestation_root: Fr,
    pub min_accepted_generation: u64,
    pub epoch: u64,
    pub chain_id: u64,
    pub pool: Address,
    pub claim_key_hash: Fr,
    pub register_key: Point,
    pub feed_r: Point,
    pub feed_ct: [Fr; 2 * FEED_FIELDS],
    pub payload_commitment: Fr,
    // Private.
    pub claim: bool,
    pub token: Address,
    pub owner_key: PublicSpendKey,
    pub nk: Fr,
    pub claim_key: PublicSpendKey,
    pub signature: [u8; 64],
    /// Private: the circuit checks it against `epoch`.
    pub expiry: u64,
    pub inputs: [InputWitness; 2],
    pub outputs: [Note; 2],
    /// Each output's lock terms, which the feed carries.
    pub output_locks: [LockOpening; 2],
    pub input_attestation: AttestationWitness,
    pub output_attestations: [AttestationWitness; 2],
    pub feed_secret: FeedSecret,
}

impl TransferWitness {
    pub fn public_inputs(&self) -> Vec<Bytes32> {
        let mut v = vec![
            Bytes32::from(self.nullifiers[0]),
            Bytes32::from(self.nullifiers[1]),
            Bytes32::from(self.commitments_out[0]),
            Bytes32::from(self.commitments_out[1]),
            Bytes32::from(self.commitment_root),
            Bytes32::from(self.attestation_root),
            fr(self.min_accepted_generation),
            fr(self.epoch),
            fr(self.chain_id),
            Bytes32::from(Fr::from(self.pool)),
            Bytes32::from(self.claim_key_hash),
        ];
        v.extend(point(&self.register_key));
        v.extend(point(&self.feed_r));
        v.extend(self.feed_ct.iter().map(|c| Bytes32::from(*c)));
        v.push(Bytes32::from(self.payload_commitment));
        v
    }
}

#[derive(Debug, Clone)]
pub struct WithdrawWitness {
    // Public, in `WithdrawPublicInputs` order.
    pub nullifier: Fr,
    pub token: Address,
    pub units: u64,
    pub recipient: Address,
    pub commitment_root: Fr,
    pub attestation_root: Fr,
    pub min_accepted_generation: u64,
    pub epoch: u64,
    pub chain_id: u64,
    pub pool: Address,
    // Private.
    pub owner_key: PublicSpendKey,
    pub nk: Fr,
    pub signature: [u8; 64],
    /// Private: the circuit checks it against `epoch`.
    pub expiry: u64,
    pub input: InputWitness,
    pub attestation: AttestationWitness,
}

impl WithdrawWitness {
    pub fn public_inputs(&self) -> Vec<Bytes32> {
        vec![
            Bytes32::from(self.nullifier),
            Bytes32::from(Fr::from(self.token)),
            fr(self.units),
            Bytes32::from(Fr::from(self.recipient)),
            Bytes32::from(self.commitment_root),
            Bytes32::from(self.attestation_root),
            fr(self.min_accepted_generation),
            fr(self.epoch),
            fr(self.chain_id),
            Bytes32::from(Fr::from(self.pool)),
        ]
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::domain::keys::{
        PlanSigner,
        SpendKey,
    };

    /// One library's layout constants in `contracts/src/PublicInputs.sol`, by
    /// name.
    fn solidity_layout(library: &str) -> BTreeMap<String, usize> {
        let source = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/contracts/src/PublicInputs.sol"
        ))
        .unwrap();
        let body = source
            .split(&format!("library {library} {{"))
            .nth(1)
            .and_then(|rest| rest.split('}').next())
            .unwrap();
        body.lines()
            .filter_map(|line| {
                let line = line.trim().strip_prefix("uint256 internal constant ")?;
                let (name, index) = line.split_once(" = ")?;
                Some((name.to_string(), index.trim_end_matches(';').parse().ok()?))
            })
            .collect()
    }

    /// Checks `inputs` against the pool's layout: the length, each named slot,
    /// and the feed's ciphertext from `FEED_CT` on. Every constant must be
    /// checked, so a slot added on either side fails here.
    fn assert_layout(
        library: &str,
        inputs: &[Bytes32],
        named: &[(&str, Bytes32)],
        feed_ct: &[Fr],
    ) {
        let layout = solidity_layout(library);
        assert_eq!(inputs.len(), layout["LENGTH"], "{library}.LENGTH");
        for (name, value) in named {
            assert_eq!(inputs[layout[*name]], *value, "{library}.{name}");
        }
        if let Some(&start) = layout.get("FEED_CT") {
            for (j, c) in feed_ct.iter().enumerate() {
                assert_eq!(
                    inputs[start + j],
                    Bytes32::from(*c),
                    "{library}.FEED_CT[{j}]"
                );
            }
        }
        for name in layout.keys().filter(|n| *n != "LENGTH" && *n != "FEED_CT") {
            assert!(
                named.iter().any(|(n, _)| n == name),
                "{library}.{name} is not checked"
            );
        }
    }

    fn marker(i: u64) -> Fr {
        Fr::from(1000 + i)
    }

    fn b(f: Fr) -> Bytes32 {
        Bytes32::from(f)
    }

    fn attestation() -> AttestationWitness {
        AttestationWitness {
            attester: Address::from([0; 20]),
            generation: 0,
            issued_at: 0,
            expires_at: 0,
            path: MerkleProof::default(),
        }
    }

    /// Rust lays out each circuit's public inputs as the pool does
    /// (`PublicInputs.sol`): every slot holds the field it is named after.
    #[test]
    fn public_inputs_follow_the_pools_layout() {
        let deposit = DepositWitness {
            commitment: marker(0),
            token: Address::from([1; 20]),
            units: 2,
            funding_address: Address::from([3; 20]),
            attestation_root: marker(4),
            min_accepted_generation: 5,
            epoch: 6,
            chain_id: 7,
            pool: Address::from([8; 20]),
            register_key: Point::new(marker(9), marker(10)),
            feed_r: Point::new(marker(11), marker(12)),
            feed_ct: std::array::from_fn(|j| marker(13 + j as u64)),
            payload_commitment: marker(21),
            owner_key: SpendKey::random().public_key(),
            nk: Fr::from(0u64),
            signature: [0; 64],
            expiry: 0,
            salt: Fr::from(0u64),
            attestation: attestation(),
            feed_secret: FeedSecret::random(),
        };
        assert_layout(
            "DepositPublicInputs",
            &deposit.public_inputs(),
            &[
                ("COMMITMENT", b(marker(0))),
                ("TOKEN", b(Fr::from(deposit.token))),
                ("UNITS", fr(2)),
                ("FUNDING_ADDRESS", b(Fr::from(deposit.funding_address))),
                ("ATTESTATION_ROOT", b(marker(4))),
                ("MIN_ACCEPTED_GENERATION", fr(5)),
                ("EPOCH", fr(6)),
                ("CHAIN_ID", fr(7)),
                ("POOL", b(Fr::from(deposit.pool))),
                ("REGISTER_KEY_X", b(marker(9))),
                ("REGISTER_KEY_Y", b(marker(10))),
                ("FEED_R_X", b(marker(11))),
                ("FEED_R_Y", b(marker(12))),
                ("PAYLOAD_COMMITMENT", b(marker(21))),
            ],
            &deposit.feed_ct,
        );

        let note = Note {
            token: Fr::from(0u64),
            units: 0,
            owner: Fr::from(0u64),
            salt: Fr::from(0u64),
            lock: Fr::from(0u64),
        };
        let transfer = TransferWitness {
            nullifiers: [marker(0), marker(1)],
            commitments_out: [marker(2), marker(3)],
            commitment_root: marker(4),
            attestation_root: marker(5),
            min_accepted_generation: 6,
            epoch: 7,
            chain_id: 8,
            pool: Address::from([9; 20]),
            claim_key_hash: marker(10),
            register_key: Point::new(marker(11), marker(12)),
            feed_r: Point::new(marker(13), marker(14)),
            feed_ct: std::array::from_fn(|j| marker(15 + j as u64)),
            payload_commitment: marker(31),
            claim: false,
            token: Address::from([0; 20]),
            owner_key: SpendKey::random().public_key(),
            nk: Fr::from(0u64),
            claim_key: SpendKey::random().public_key(),
            signature: [0; 64],
            expiry: 0,
            inputs: [
                InputWitness::padding(Fr::from(1u64)),
                InputWitness::padding(Fr::from(2u64)),
            ],
            outputs: [note, note],
            output_locks: [LockOpening::NONE; 2],
            input_attestation: attestation(),
            output_attestations: [attestation(), attestation()],
            feed_secret: FeedSecret::random(),
        };
        assert_layout(
            "TransferPublicInputs",
            &transfer.public_inputs(),
            &[
                ("NULLIFIER_0", b(marker(0))),
                ("NULLIFIER_1", b(marker(1))),
                ("COMMITMENT_OUT_0", b(marker(2))),
                ("COMMITMENT_OUT_1", b(marker(3))),
                ("COMMITMENT_ROOT", b(marker(4))),
                ("ATTESTATION_ROOT", b(marker(5))),
                ("MIN_ACCEPTED_GENERATION", fr(6)),
                ("EPOCH", fr(7)),
                ("CHAIN_ID", fr(8)),
                ("POOL", b(Fr::from(transfer.pool))),
                ("CLAIM_KEY_HASH", b(marker(10))),
                ("REGISTER_KEY_X", b(marker(11))),
                ("REGISTER_KEY_Y", b(marker(12))),
                ("FEED_R_X", b(marker(13))),
                ("FEED_R_Y", b(marker(14))),
                ("PAYLOAD_COMMITMENT", b(marker(31))),
            ],
            &transfer.feed_ct,
        );

        let withdraw = WithdrawWitness {
            nullifier: marker(0),
            token: Address::from([1; 20]),
            units: 2,
            recipient: Address::from([3; 20]),
            commitment_root: marker(4),
            attestation_root: marker(5),
            min_accepted_generation: 6,
            epoch: 7,
            chain_id: 8,
            pool: Address::from([9; 20]),
            owner_key: SpendKey::random().public_key(),
            nk: Fr::from(0u64),
            signature: [0; 64],
            expiry: 0,
            input: InputWitness::padding(Fr::from(1u64)),
            attestation: attestation(),
        };
        assert_layout(
            "WithdrawPublicInputs",
            &withdraw.public_inputs(),
            &[
                ("NULLIFIER", b(marker(0))),
                ("TOKEN", b(Fr::from(withdraw.token))),
                ("UNITS", fr(2)),
                ("RECIPIENT", b(Fr::from(withdraw.recipient))),
                ("COMMITMENT_ROOT", b(marker(4))),
                ("ATTESTATION_ROOT", b(marker(5))),
                ("MIN_ACCEPTED_GENERATION", fr(6)),
                ("EPOCH", fr(7)),
                ("CHAIN_ID", fr(8)),
                ("POOL", b(Fr::from(withdraw.pool))),
            ],
            &[],
        );
    }
}

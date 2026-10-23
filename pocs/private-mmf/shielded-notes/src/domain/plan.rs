//! The transaction plan a custody signer approves (SPEC, Transaction Plan).

use ark_bn254::Fr;

use crate::{
    domain::note::Note,
    error::CryptoError,
    poseidon::{
        fr_to_be_bytes,
        sponge,
    },
    types::Address,
};

pub const OP_DEPOSIT: u64 = 1;
pub const OP_TRANSFER: u64 = 2;
pub const OP_WITHDRAW: u64 = 3;
pub const PATH_OWNER: u64 = 0;
pub const PATH_CLAIM: u64 = 1;

/// Unused slots are zero, so every operation absorbs the same 12 elements. The
/// register feed is not in the plan: the circuit derives it from the output
/// openings the signer approves, so a register-key rotation voids proofs but
/// not signatures.
#[derive(Debug, Clone, Copy)]
pub struct Plan {
    pub chain_id: u64,
    pub pool: Address,
    pub op: u64,
    pub path: u64,
    pub nullifiers: [Fr; 2],
    pub outputs: [Fr; 2],
    pub public_units: u64,
    pub recipient: Fr,
    pub expiry: u64,
}

impl Plan {
    pub fn digest(&self) -> Fr {
        sponge(&[
            *crate::PLAN_TAG,
            Fr::from(self.chain_id),
            Fr::from(self.pool),
            Fr::from(self.op),
            Fr::from(self.path),
            self.nullifiers[0],
            self.nullifiers[1],
            self.outputs[0],
            self.outputs[1],
            Fr::from(self.public_units),
            self.recipient,
            Fr::from(self.expiry),
        ])
    }

    /// What a custody signer computes before it signs: each output commitment
    /// from its opening, then the digest's 32 big-endian bytes. Fails if the
    /// openings do not match the plan's commitments, unused slots included, so
    /// the signer never signs a digest it is handed.
    pub fn rebuild(&self, outputs: &[Note]) -> Result<[u8; 32], CryptoError> {
        if outputs.len() > 2 {
            return Err(CryptoError::PlanMismatch);
        }
        for (j, committed) in self.outputs.iter().enumerate() {
            let rebuilt = outputs.get(j).map_or(Fr::from(0u64), Note::commitment);
            if rebuilt != *committed {
                return Err(CryptoError::PlanMismatch);
            }
        }
        Ok(fr_to_be_bytes(&self.digest()))
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;

    use super::*;
    use crate::{
        domain::keys::{
            NullifierKey,
            PlanSigner,
            SpendKey,
            owner_value,
        },
        poseidon::fr_to_be_bytes,
    };

    fn address(hex_str: &str) -> Address {
        let bytes: [u8; 20] = hex::decode(hex_str).unwrap().try_into().unwrap();
        Address::from(bytes)
    }

    /// Rebuilds the deposit circuit's test fixture (`circuits/deposit`, `valid_fixture`)
    /// and checks its plan digest and signature: owner value, commitment and
    /// sponge all have to agree with the circuit for this to match.
    #[test]
    fn deposit_fixture_digest_matches_the_circuit() {
        let mut secret = [0u8; 32];
        secret[31] = 0x0b;
        let key = SpendKey::from_secret(&secret).unwrap();
        let owner = owner_value(&key.public_key(), &NullifierKey(Fr::from(0x6e6bu64)));
        let token = address("1234567890abcdef1234567890abcdef12345678");
        let note = Note {
            token: Fr::from(token),
            units: 1_000_000,
            owner,
            salt: Fr::from(0xabcdu64),
            lock: Fr::from(0u64),
        };
        let plan = Plan {
            chain_id: 31337,
            pool: address("5fbdb2315678afecb367f032d93f642f64180aa3"),
            op: OP_DEPOSIT,
            path: PATH_OWNER,
            nullifiers: [Fr::from(0u64); 2],
            outputs: [note.commitment(), Fr::from(0u64)],
            public_units: 1_000_000,
            recipient: Fr::from(
                BigUint::parse_bytes(b"70997970c51812dc3a010c7d01b50e0d17dc79c8", 16)
                    .unwrap(),
            ),
            expiry: 2_000_073_600,
        };
        assert_eq!(
            format!("0x{}", hex::encode(fr_to_be_bytes(&plan.digest()))),
            "0x173341b1f88150e34f1740b9431d6b57d8ba6afcf9809d9fa52260b8b7c3ce03"
        );
        assert_eq!(
            key.sign_plan(&plan, &[note]).unwrap()[..4],
            [121, 63, 243, 18]
        );
    }

    /// The circuits' test spend key and `nk`, and their owner value.
    fn fixture_owner() -> (SpendKey, NullifierKey, Fr) {
        let mut secret = [0u8; 32];
        secret[31] = 0x0b;
        let key = SpendKey::from_secret(&secret).unwrap();
        let nk = NullifierKey(Fr::from(0x6e6bu64));
        let owner = owner_value(&key.public_key(), &nk);
        (key, nk, owner)
    }

    fn fixture_note(units: u64, owner: Fr, salt: u64) -> Note {
        Note {
            token: Fr::from(address("1234567890abcdef1234567890abcdef12345678")),
            units,
            owner,
            salt: Fr::from(salt),
            lock: Fr::from(0u64),
        }
    }

    /// Rebuilds the transfer circuit's padded fixture (`circuits/transfer`,
    /// `padded`): one input of 1000 and a zero-unit padding note, paying 1000.
    /// The nullifiers, the output commitments and the slots a transfer fills
    /// all have to agree with the circuit for the digest to match.
    #[test]
    fn transfer_fixture_digest_matches_the_circuit() {
        let (key, nk, owner) = fixture_owner();
        let inputs = [
            fixture_note(1000, owner, 0x11),
            fixture_note(0, owner, 0x55),
        ];
        let outputs = [
            fixture_note(1000, Fr::from(0x4ec1u64), 0x33),
            fixture_note(0, owner, 0x44),
        ];
        let plan = Plan {
            chain_id: 31337,
            pool: address("5fbdb2315678afecb367f032d93f642f64180aa3"),
            op: OP_TRANSFER,
            path: PATH_OWNER,
            nullifiers: inputs
                .map(|n| crate::domain::note::nullifier(n.commitment(), &nk)),
            outputs: outputs.map(|n| n.commitment()),
            public_units: 0,
            recipient: Fr::from(0u64),
            expiry: 2_000_073_600,
        };
        assert_eq!(
            format!("0x{}", hex::encode(fr_to_be_bytes(&plan.digest()))),
            "0x108655dbee56ee379030729dd7750fd339c221fa3fddaa173a0f6f128b96360c"
        );
        assert_eq!(
            key.sign_plan(&plan, &outputs).unwrap()[..4],
            [147, 18, 2, 197]
        );
    }

    /// Rebuilds the withdraw circuit's fixture (`circuits/withdraw`,
    /// `valid_fixture`): a note of 1000 withdrawn whole to a public address.
    #[test]
    fn withdraw_fixture_digest_matches_the_circuit() {
        let (key, nk, owner) = fixture_owner();
        let input = fixture_note(1000, owner, 0x11);
        let plan = Plan {
            chain_id: 31337,
            pool: address("5fbdb2315678afecb367f032d93f642f64180aa3"),
            op: OP_WITHDRAW,
            path: PATH_OWNER,
            nullifiers: [
                crate::domain::note::nullifier(input.commitment(), &nk),
                Fr::from(0u64),
            ],
            outputs: [Fr::from(0u64); 2],
            public_units: 1000,
            recipient: Fr::from(address("3c44cdddb6a900fa2b585dd299e03d12fa4293bc")),
            expiry: 2_000_073_600,
        };
        assert_eq!(
            format!("0x{}", hex::encode(fr_to_be_bytes(&plan.digest()))),
            "0x096e90955a8251afe5cb9aca732433d4e65413f7cd39ee765dc92b1f8f59aa61"
        );
        assert_eq!(key.sign_plan(&plan, &[]).unwrap()[..4], [216, 138, 34, 25]);
    }

    /// A signer shown outputs other than the plan's refuses to sign: a
    /// compromised wallet cannot get a plan signed by showing the signer
    /// openings for a different plan. Whether the openings pay whom the holder
    /// meant is the custody platform's policy (SPEC, Transaction Plan), which
    /// this signer does not check.
    #[test]
    fn signer_refuses_openings_that_do_not_match_the_plan() {
        let key = SpendKey::random();
        let paid = Note {
            token: Fr::from(1u64),
            units: 100,
            owner: Fr::from(2u64),
            salt: Fr::from(3u64),
            lock: Fr::from(0u64),
        };
        let shown = Note {
            owner: Fr::from(4u64),
            ..paid
        };
        let plan = Plan {
            chain_id: 31337,
            pool: Address::from([5; 20]),
            op: OP_TRANSFER,
            path: PATH_OWNER,
            nullifiers: [Fr::from(6u64), Fr::from(7u64)],
            outputs: [paid.commitment(), Fr::from(0u64)],
            public_units: 0,
            recipient: Fr::from(0u64),
            expiry: 11,
        };
        assert!(key.sign_plan(&plan, &[paid]).is_ok());
        for outputs in [&[shown][..], &[], &[paid, paid]] {
            assert!(matches!(
                key.sign_plan(&plan, outputs),
                Err(CryptoError::PlanMismatch)
            ));
        }
    }
}

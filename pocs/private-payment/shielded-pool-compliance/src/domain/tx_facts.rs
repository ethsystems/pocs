//! Mirrors `circuits/lib/src/tx_facts.nr` field for field. Owns the `TxFacts` shape
//! `Policy` methods operate on (re-exported at `policy::TxFacts`) and the per-operation
//! constructors that build one from note and chain data.

use ark_bn254::Fr;

use crate::{
    NO_COUNTERPARTY,
    NO_EXIT,
    error::CryptoError,
    types::{
        Address,
        Epoch,
        Seq,
    },
};

use super::keys::OwnerPubkey;

/// What the pool proves about one gated transaction. SPEC "TxFacts construction":
/// every field MUST be bound to a constrained value, never a free witness.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TxFacts {
    pub epoch: u64,
    pub seq: u64,
    pub token: Fr,
    pub subject: Fr,
    pub counterparty: [Fr; 2],
    pub value_in: u64,
    pub value_out: u64,
    pub exit: Fr,
}

/// Saturating, not trapping: mirrors `circuits/lib/src/tx_facts.nr::sat_add`, so a
/// large transfer cannot make the compliance gadget unsatisfiable. `Policy::advance`
/// (`policy::reference::ReferencePolicy`) still traps via `checked_add` on its own
/// accumulator; the two differ on purpose and must not be "corrected" to match.
pub const fn sat_add(a: u64, b: u64) -> u64 {
    let wide = a as u128 + b as u128;
    if wide > u64::MAX as u128 {
        u64::MAX
    } else {
        wide as u64
    }
}

/// SPEC "TxFacts construction", deposit row: `value_in` is the operation's `amount`,
/// `value_out` is 0, both counterparty slots are `NO_COUNTERPARTY`, `exit` is `NO_EXIT`.
pub fn deposit(
    epoch: Epoch,
    seq: Seq,
    token: Address,
    subject: OwnerPubkey,
    amount: u64,
) -> Result<TxFacts, CryptoError> {
    Ok(TxFacts {
        epoch: epoch.0,
        seq: seq.0,
        token: Fr::from(token),
        subject: subject.field()?,
        counterparty: [*NO_COUNTERPARTY, *NO_COUNTERPARTY],
        value_in: amount,
        value_out: 0,
        exit: *NO_EXIT,
    })
}

/// SPEC "TxFacts construction", transfer row: `counterparty[i]` is always `owner_out_i`
/// (even a change output equal to `subject`), and `value_out` sums only the outputs
/// whose owner differs from `subject`, saturating per `sat_add`.
pub fn transfer(
    epoch: Epoch,
    seq: Seq,
    token: Address,
    subject: OwnerPubkey,
    owner_out: [OwnerPubkey; 2],
    amount_out: [u64; 2],
) -> Result<TxFacts, CryptoError> {
    let subject_fr = subject.field()?;
    let counterparty = [owner_out[0].field()?, owner_out[1].field()?];

    let mut value_out = 0u64;
    if counterparty[0] != subject_fr {
        value_out = sat_add(value_out, amount_out[0]);
    }
    if counterparty[1] != subject_fr {
        value_out = sat_add(value_out, amount_out[1]);
    }

    Ok(TxFacts {
        epoch: epoch.0,
        seq: seq.0,
        token: Fr::from(token),
        subject: subject_fr,
        counterparty,
        value_in: 0,
        value_out,
        exit: *NO_EXIT,
    })
}

/// SPEC "TxFacts construction", gated withdraw row: `value_out` is the operation's
/// `amount`, `exit` is the `recipient` public input, both counterparty slots are
/// `NO_COUNTERPARTY`.
pub fn gated_withdraw(
    epoch: Epoch,
    seq: Seq,
    token: Address,
    subject: OwnerPubkey,
    amount: u64,
    recipient: Address,
) -> Result<TxFacts, CryptoError> {
    Ok(TxFacts {
        epoch: epoch.0,
        seq: seq.0,
        token: Fr::from(token),
        subject: subject.field()?,
        counterparty: [*NO_COUNTERPARTY, *NO_COUNTERPARTY],
        value_in: 0,
        value_out: amount,
        exit: Fr::from(recipient),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::keys::SpendingKey;

    fn pubkey(seed: u64) -> OwnerPubkey {
        // Deterministic pubkeys for assertions below: derive from a fixed spending key.
        let sk = SpendingKey::from_canonical_bytes({
            let mut bytes = [0u8; 32];
            bytes[24..].copy_from_slice(&seed.to_be_bytes());
            bytes
        })
        .expect("small seed values are canonical");
        sk.derive_owner_pubkey()
    }

    #[test]
    fn sat_add_normal() {
        assert_eq!(sat_add(1, 2), 3);
    }

    #[test]
    fn sat_add_overflow_saturates() {
        assert_eq!(sat_add(u64::MAX, 1), u64::MAX);
    }

    #[test]
    fn deposit_sets_value_in_and_no_counterparty() {
        let subject = pubkey(1);
        let tx = deposit(Epoch(10), Seq(0), Address::from([0x11; 20]), subject, 500)
            .expect("canonical inputs");
        assert_eq!(tx.value_in, 500);
        assert_eq!(tx.value_out, 0);
        assert_eq!(tx.counterparty, [*NO_COUNTERPARTY, *NO_COUNTERPARTY]);
        assert_eq!(tx.exit, *NO_EXIT);
    }

    #[test]
    fn transfer_value_out_excludes_subject_owned_change_output() {
        let subject = pubkey(2);
        let recipient = pubkey(3);
        let tx = transfer(
            Epoch(10),
            Seq(1),
            Address::from([0x11; 20]),
            subject,
            [recipient, subject],
            [700, 300],
        )
        .expect("canonical inputs");
        // Only the non-subject output (700) counts; the 300 change output does not.
        assert_eq!(tx.value_out, 700);
    }

    #[test]
    fn transfer_value_out_saturates_on_overflow() {
        let subject = pubkey(4);
        let recipient = pubkey(5);
        let tx = transfer(
            Epoch(10),
            Seq(1),
            Address::from([0x11; 20]),
            subject,
            [recipient, recipient],
            [u64::MAX, u64::MAX],
        )
        .expect("canonical inputs");
        assert_eq!(tx.value_out, u64::MAX);
    }

    #[test]
    fn gated_withdraw_binds_exit_to_recipient() {
        let subject = pubkey(6);
        let recipient = Address::from([0x22; 20]);
        let tx = gated_withdraw(
            Epoch(10),
            Seq(2),
            Address::from([0x11; 20]),
            subject,
            900,
            recipient,
        )
        .expect("canonical inputs");
        assert_eq!(tx.value_out, 900);
        assert_eq!(tx.value_in, 0);
        assert_eq!(tx.exit, Fr::from(recipient));
    }
}

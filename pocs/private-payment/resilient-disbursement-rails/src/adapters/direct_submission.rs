//! In-process direct submission adapter.
//!
//! Implements the companion-side `Submission` trait by enqueueing into a
//! per-relay inbox. The relay pulls envelopes via the inherent `pull_voucher`
//! method. The adapter has no mesh, no fan-out, no source-fingerprinting
//! resistance: it exists to make the seam visible at the call site.

use std::{
    collections::{
        HashMap,
        HashSet,
        VecDeque,
    },
    sync::{
        Arc,
        Mutex,
    },
};

use sha2::{
    Digest,
    Sha256,
};

use crate::{
    clock::{
        Clock,
        SystemClock,
    },
    ports::submission::{
        DeliveryReceipt,
        Submission,
        SubmissionError,
    },
    types::{
        Bytes32,
        EncryptedVoucher,
    },
};

pub struct DirectSubmission {
    inboxes: Mutex<HashMap<Bytes32, VecDeque<EncryptedVoucher>>>,
    known_relays: HashSet<Bytes32>,
    clock: Arc<dyn Clock>,
}

impl DirectSubmission {
    pub fn new(known_relays: impl IntoIterator<Item = Bytes32>) -> Self {
        Self::with_clock(known_relays, Arc::new(SystemClock))
    }

    pub fn with_clock(
        known_relays: impl IntoIterator<Item = Bytes32>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let known: HashSet<Bytes32> = known_relays.into_iter().collect();
        let inboxes = known.iter().map(|id| (*id, VecDeque::new())).collect();
        Self {
            inboxes: Mutex::new(inboxes),
            known_relays: known,
            clock,
        }
    }

    /// Relay-side: pull the next envelope addressed to `relay_id`. Returns
    /// `None` if the inbox is empty. Unknown relay ids return `None` rather
    /// than erroring; the relay should already know its own id.
    pub fn pull_voucher(&self, relay_id: &Bytes32) -> Option<EncryptedVoucher> {
        self.inboxes
            .lock()
            .expect("DirectSubmission inbox poisoned")
            .get_mut(relay_id)?
            .pop_front()
    }

    /// Number of envelopes queued for `relay_id`.
    pub fn pending(&self, relay_id: &Bytes32) -> usize {
        self.inboxes
            .lock()
            .expect("DirectSubmission inbox poisoned")
            .get(relay_id)
            .map(|q| q.len())
            .unwrap_or(0)
    }

    fn message_id(env: &EncryptedVoucher) -> Bytes32 {
        let mut hasher = Sha256::new();
        hasher.update(&env.envelope);
        hasher.update(env.relay_id);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }
}

impl Submission for DirectSubmission {
    fn submit_voucher(
        &self,
        envelope: EncryptedVoucher,
        relay_id: &Bytes32,
    ) -> Result<DeliveryReceipt, SubmissionError> {
        if !self.known_relays.contains(relay_id) {
            return Err(SubmissionError::UnknownRelay);
        }
        if envelope.relay_id != *relay_id {
            return Err(SubmissionError::Rejected(
                "envelope relay_id does not match submitted relay_id".into(),
            ));
        }
        let message_id = Self::message_id(&envelope);
        let accepted_at_unix = self.clock.now_unix();
        self.inboxes
            .lock()
            .expect("DirectSubmission inbox poisoned")
            .get_mut(relay_id)
            .ok_or(SubmissionError::UnknownRelay)?
            .push_back(envelope);
        Ok(DeliveryReceipt {
            message_id,
            accepted_at_unix,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::MockClock;

    fn make_envelope(relay_id: Bytes32, byte: u8) -> EncryptedVoucher {
        EncryptedVoucher {
            envelope: vec![byte; 16],
            relay_id,
        }
    }

    #[test]
    fn submit_then_pull_round_trips() {
        let relay_id = [0x11u8; 32];
        let clock = Arc::new(MockClock::new(1_700_000_000));
        let sub = DirectSubmission::with_clock([relay_id], clock);

        let env = make_envelope(relay_id, 0xAA);
        let receipt = sub.submit_voucher(env.clone(), &relay_id).unwrap();
        assert_eq!(receipt.accepted_at_unix, 1_700_000_000);
        assert_eq!(sub.pending(&relay_id), 1);

        let pulled = sub.pull_voucher(&relay_id).unwrap();
        assert_eq!(pulled.envelope, env.envelope);
        assert_eq!(sub.pending(&relay_id), 0);
        assert!(sub.pull_voucher(&relay_id).is_none());
    }

    #[test]
    fn unknown_relay_rejected() {
        let relay_id = [0x11u8; 32];
        let other = [0x22u8; 32];
        let sub = DirectSubmission::new([relay_id]);
        let env = make_envelope(other, 0xBB);
        let err = sub.submit_voucher(env, &other).unwrap_err();
        assert!(matches!(err, SubmissionError::UnknownRelay));
    }

    #[test]
    fn envelope_relay_id_mismatch_rejected() {
        let relay_a = [0x11u8; 32];
        let relay_b = [0x22u8; 32];
        let sub = DirectSubmission::new([relay_a, relay_b]);
        let env = make_envelope(relay_a, 0xCC);
        let err = sub.submit_voucher(env, &relay_b).unwrap_err();
        assert!(matches!(err, SubmissionError::Rejected(_)));
    }

    #[test]
    fn fifo_order_preserved() {
        let relay_id = [0x33u8; 32];
        let sub = DirectSubmission::new([relay_id]);
        sub.submit_voucher(make_envelope(relay_id, 1), &relay_id)
            .unwrap();
        sub.submit_voucher(make_envelope(relay_id, 2), &relay_id)
            .unwrap();
        sub.submit_voucher(make_envelope(relay_id, 3), &relay_id)
            .unwrap();
        assert_eq!(sub.pull_voucher(&relay_id).unwrap().envelope[0], 1);
        assert_eq!(sub.pull_voucher(&relay_id).unwrap().envelope[0], 2);
        assert_eq!(sub.pull_voucher(&relay_id).unwrap().envelope[0], 3);
    }

    #[test]
    fn message_id_is_deterministic() {
        let relay_id = [0x44u8; 32];
        let sub = DirectSubmission::new([relay_id]);
        let env = make_envelope(relay_id, 0xDD);
        let r1 = sub.submit_voucher(env.clone(), &relay_id).unwrap();
        let r2 = sub.submit_voucher(env, &relay_id).unwrap();
        assert_eq!(r1.message_id, r2.message_id);
    }
}

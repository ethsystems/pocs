//! Relay key archive: current + previous static X25519 keys with rotation.

use std::time::{
    Duration,
    Instant,
};

use x25519_dalek::{
    PublicKey,
    StaticSecret,
};
use zeroize::Zeroizing;

pub struct KeyArchive {
    pub current_sk: StaticSecret,
    pub current_pk: PublicKey,
    // No Zeroizing wrapper: x25519-dalek 3's StaticSecret already zeroizes on drop.
    pub previous_sk: Option<StaticSecret>,
    pub previous_pk: Option<PublicKey>,
    pub rotated_at: Instant,
    pub rotation_interval: Duration,
}

impl KeyArchive {
    pub fn rotate(&mut self) {
        let mut seed = Zeroizing::new([0u8; 32]);
        use rand::Rng;
        rand::rng().fill_bytes(seed.as_mut());
        let new_sk = StaticSecret::from(*seed);
        let new_pk = PublicKey::from(&new_sk);
        let prev_sk = std::mem::replace(&mut self.current_sk, new_sk);
        let prev_pk = std::mem::replace(&mut self.current_pk, new_pk);
        self.previous_sk = Some(prev_sk);
        self.previous_pk = Some(prev_pk);
        self.rotated_at = Instant::now();
    }

    pub fn is_due(&self) -> bool {
        self.rotated_at.elapsed() >= self.rotation_interval
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_archive(interval: Duration) -> KeyArchive {
        let sk = StaticSecret::from([7u8; 32]);
        let pk = PublicKey::from(&sk);
        KeyArchive {
            current_sk: sk,
            current_pk: pk,
            previous_sk: None,
            previous_pk: None,
            rotated_at: Instant::now(),
            rotation_interval: interval,
        }
    }

    #[test]
    fn rotate_promotes_current_to_previous_and_replaces_keys() {
        let mut archive = make_archive(Duration::from_secs(60));
        let initial_sk_bytes = archive.current_sk.to_bytes();
        let initial_pk_bytes = archive.current_pk.to_bytes();

        archive.rotate();

        let prev = archive
            .previous_sk
            .as_ref()
            .expect("previous_sk populated after rotate");
        assert_eq!(prev.to_bytes(), initial_sk_bytes);
        assert_eq!(
            archive
                .previous_pk
                .expect("previous_pk populated after rotate")
                .to_bytes(),
            initial_pk_bytes
        );
        assert_ne!(archive.current_sk.to_bytes(), initial_sk_bytes);
        assert_ne!(archive.current_pk.to_bytes(), initial_pk_bytes);
    }

    #[test]
    fn is_due_only_after_interval_elapsed() {
        let archive = make_archive(Duration::from_millis(20));
        assert!(!archive.is_due());
        std::thread::sleep(Duration::from_millis(60));
        assert!(archive.is_due());
    }

    #[test]
    fn rotate_resets_due_clock() {
        let mut archive = make_archive(Duration::from_millis(20));
        std::thread::sleep(Duration::from_millis(60));
        assert!(archive.is_due());
        archive.rotate();
        assert!(!archive.is_due());
    }
}

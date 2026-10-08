use std::{
    collections::HashMap,
    sync::Arc,
};

use tokio::sync::{
    Mutex,
    RwLock,
    mpsc,
};

use crate::{
    domain::{
        commitment::Commitment,
        encrypted::{
            EncryptedNote,
            P2pMessage,
        },
        keys::ViewingPubkey,
    },
    ports::p2p::{
        P2p,
        P2pError,
    },
};

/// Buffer size for the internal message channel.
const CHANNEL_BUFFER_SIZE: usize = 100;

/// A registry that maps viewing public keys to message channels.
/// Shared across all participants for message routing: clones share one map,
/// so a Channel returned by `register` routes to every other registrant.
#[derive(Debug, Default, Clone)]
pub struct ChannelRegistry {
    /// Map from serialized viewing pubkey to sender channel.
    channels: Arc<RwLock<HashMap<Vec<u8>, mpsc::Sender<P2pMessage>>>>,
}

impl ChannelRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            channels: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a new participant and return their channel.
    pub async fn register(&self, viewing_pubkey: &ViewingPubkey) -> Channel {
        let (tx, rx) = mpsc::channel(CHANNEL_BUFFER_SIZE);
        let key = viewing_pubkey.to_sec1_bytes();

        {
            let mut channels = self.channels.write().await;
            channels.insert(key.clone(), tx);
        }

        Channel {
            viewing_pubkey: viewing_pubkey.clone(),
            receiver: Arc::new(Mutex::new(rx)),
            registry: Arc::new(self.clone()),
        }
    }

    /// Unregister a participant.
    pub async fn unregister(&self, viewing_pubkey: &ViewingPubkey) {
        let key = viewing_pubkey.to_sec1_bytes();
        let mut channels = self.channels.write().await;
        channels.remove(&key);
    }

    /// Send a message to a recipient.
    async fn send_to(
        &self,
        recipient_viewing_pubkey: &ViewingPubkey,
        message: P2pMessage,
    ) -> Result<(), P2pError> {
        let key = recipient_viewing_pubkey.to_sec1_bytes();

        let channels = self.channels.read().await;
        let sender = channels.get(&key).ok_or_else(|| {
            P2pError::RecipientNotFound(format!(
                "No channel registered for viewing pubkey: {}",
                hex::encode(&key)
            ))
        })?;

        sender
            .send(message)
            .await
            .map_err(|_| P2pError::ChannelClosed)
    }
}

/// A P2P channel for a single participant.
/// Uses in-memory tokio mpsc channels for message passing.
pub struct Channel {
    /// This participant's viewing public key.
    viewing_pubkey: ViewingPubkey,
    /// Receiver for incoming messages.
    receiver: Arc<Mutex<mpsc::Receiver<P2pMessage>>>,
    /// Reference to the shared registry for sending.
    registry: Arc<ChannelRegistry>,
}

impl Channel {
    /// Create a new channel with a shared registry.
    /// Prefer using `ChannelRegistry::register` instead.
    pub fn new(viewing_pubkey: ViewingPubkey, registry: Arc<ChannelRegistry>) -> Self {
        // This is a simplified constructor; the receiver will be set up separately
        let (_, rx) = mpsc::channel(1);
        Self {
            viewing_pubkey,
            receiver: Arc::new(Mutex::new(rx)),
            registry,
        }
    }

    /// Get this channel's viewing public key.
    pub fn viewing_pubkey(&self) -> &ViewingPubkey {
        &self.viewing_pubkey
    }
}

impl P2p for Channel {
    async fn send_note(
        &self,
        recipient_viewing_pubkey: &ViewingPubkey,
        encrypted_note: EncryptedNote,
        commitment: Commitment,
    ) -> Result<(), P2pError> {
        let message =
            P2pMessage::new(encrypted_note, commitment, recipient_viewing_pubkey.clone());

        self.registry
            .send_to(recipient_viewing_pubkey, message)
            .await
    }

    async fn receive_note(&self) -> Result<Option<P2pMessage>, P2pError> {
        let mut receiver = self.receiver.lock().await;
        match receiver.try_recv() {
            Ok(message) => Ok(Some(message)),
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => Err(P2pError::ChannelClosed),
        }
    }

    async fn receive_note_blocking(&self) -> Result<P2pMessage, P2pError> {
        let mut receiver = self.receiver.lock().await;
        receiver.recv().await.ok_or(P2pError::ChannelClosed)
    }
}

/// A simplified channel system for testing where participants share a registry.
pub struct ChannelSystem {
    registry: Arc<RwLock<HashMap<Vec<u8>, mpsc::Sender<P2pMessage>>>>,
}

impl ChannelSystem {
    /// Create a new channel system.
    pub fn new() -> Self {
        Self {
            registry: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new participant channel.
    pub async fn create_channel(&self, viewing_pubkey: ViewingPubkey) -> SystemChannel {
        let (tx, rx) = mpsc::channel(CHANNEL_BUFFER_SIZE);
        let key = viewing_pubkey.to_sec1_bytes();

        {
            let mut registry = self.registry.write().await;
            registry.insert(key, tx);
        }

        SystemChannel {
            viewing_pubkey,
            receiver: Arc::new(Mutex::new(rx)),
            registry: self.registry.clone(),
        }
    }
}

impl Default for ChannelSystem {
    fn default() -> Self {
        Self::new()
    }
}

/// A channel that's part of a ChannelSystem.
pub struct SystemChannel {
    viewing_pubkey: ViewingPubkey,
    receiver: Arc<Mutex<mpsc::Receiver<P2pMessage>>>,
    registry: Arc<RwLock<HashMap<Vec<u8>, mpsc::Sender<P2pMessage>>>>,
}

impl SystemChannel {
    /// Get this channel's viewing public key.
    pub fn viewing_pubkey(&self) -> &ViewingPubkey {
        &self.viewing_pubkey
    }
}

impl P2p for SystemChannel {
    async fn send_note(
        &self,
        recipient_viewing_pubkey: &ViewingPubkey,
        encrypted_note: EncryptedNote,
        commitment: Commitment,
    ) -> Result<(), P2pError> {
        let key = recipient_viewing_pubkey.to_sec1_bytes();
        let message =
            P2pMessage::new(encrypted_note, commitment, recipient_viewing_pubkey.clone());

        let registry = self.registry.read().await;
        let sender = registry.get(&key).ok_or_else(|| {
            P2pError::RecipientNotFound(format!(
                "No channel registered for viewing pubkey: {}",
                hex::encode(&key)
            ))
        })?;

        sender
            .send(message)
            .await
            .map_err(|_| P2pError::ChannelClosed)
    }

    async fn receive_note(&self) -> Result<Option<P2pMessage>, P2pError> {
        let mut receiver = self.receiver.lock().await;
        match receiver.try_recv() {
            Ok(message) => Ok(Some(message)),
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => Err(P2pError::ChannelClosed),
        }
    }

    async fn receive_note_blocking(&self) -> Result<P2pMessage, P2pError> {
        let mut receiver = self.receiver.lock().await;
        receiver.recv().await.ok_or(P2pError::ChannelClosed)
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::{
        Address,
        U256,
    };

    use super::*;
    use crate::{
        crypto::encryption::encrypt_note,
        domain::{
            keys::{
                SpendingKey,
                ViewingKey,
            },
            note::Note,
        },
    };

    #[tokio::test]
    async fn test_channel_system_send_receive() {
        let system = ChannelSystem::new();

        // Create two participants
        let alice_vk = ViewingKey::random();
        let alice_vpk = alice_vk.derive_viewing_pubkey();
        let alice_channel = system.create_channel(alice_vpk.clone()).await;

        let bob_vk = ViewingKey::random();
        let bob_vpk = bob_vk.derive_viewing_pubkey();
        let bob_channel = system.create_channel(bob_vpk.clone()).await;

        // Create a test note
        let sk = SpendingKey::random();
        let pk = sk.derive_owner_pubkey();
        let note = Note::new(Address::ZERO, U256::from(1000u64), pk);
        let commitment = note.commitment();
        let encrypted = encrypt_note(&note, &bob_vpk);

        // Alice sends to Bob
        alice_channel
            .send_note(&bob_vpk, encrypted.clone(), commitment)
            .await
            .unwrap();

        // Bob receives
        let received = bob_channel.receive_note().await.unwrap().unwrap();
        assert_eq!(received.commitment, commitment);
    }

    #[tokio::test]
    async fn test_registry_register_send_receive() {
        let registry = ChannelRegistry::new();

        // Alice registers first; her channel is handed out before Bob exists
        let alice_vk = ViewingKey::random();
        let alice_vpk = alice_vk.derive_viewing_pubkey();
        let alice_channel = registry.register(&alice_vpk).await;

        let bob_vk = ViewingKey::random();
        let bob_vpk = bob_vk.derive_viewing_pubkey();
        let bob_channel = registry.register(&bob_vpk).await;

        let sk = SpendingKey::random();
        let pk = sk.derive_owner_pubkey();
        let note = Note::new(Address::ZERO, U256::from(1000u64), pk);
        let commitment = note.commitment();
        let encrypted = encrypt_note(&note, &bob_vpk);

        // Alice sends to Bob through the channel register returned
        alice_channel
            .send_note(&bob_vpk, encrypted, commitment)
            .await
            .expect("send between two participants registered on one registry");

        // Bob's registered channel receives the message
        let received = bob_channel.receive_note().await.unwrap().unwrap();
        assert_eq!(received.commitment, commitment);
    }

    #[tokio::test]
    async fn test_channel_receive_empty() {
        let system = ChannelSystem::new();

        let vk = ViewingKey::random();
        let vpk = vk.derive_viewing_pubkey();
        let channel = system.create_channel(vpk).await;

        // Should return None when no messages
        let result = channel.receive_note().await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_channel_unknown_recipient() {
        let system = ChannelSystem::new();

        let alice_vk = ViewingKey::random();
        let alice_vpk = alice_vk.derive_viewing_pubkey();
        let alice_channel = system.create_channel(alice_vpk).await;

        // Bob is not registered
        let bob_vk = ViewingKey::random();
        let bob_vpk = bob_vk.derive_viewing_pubkey();

        let sk = SpendingKey::random();
        let pk = sk.derive_owner_pubkey();
        let note = Note::new(Address::ZERO, U256::from(1000u64), pk);
        let commitment = note.commitment();
        let encrypted = encrypt_note(&note, &bob_vpk);

        // Should fail because Bob is not registered
        let result = alice_channel
            .send_note(&bob_vpk, encrypted, commitment)
            .await;
        assert!(matches!(result, Err(P2pError::RecipientNotFound(_))));
    }
}

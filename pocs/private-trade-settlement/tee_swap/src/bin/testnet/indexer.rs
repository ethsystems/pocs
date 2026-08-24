use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::future::IntoFuture;
use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::{Address, B256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::{Filter, Log};
use alloy::sol_types::SolEvent;
use alloy::transports::{RpcError, TransportErrorKind};
use chainfold::{
    BlockRef, Driver, DriverConfig, EngineConfig, Fold, FoldError, Position,
    ReplayHorizon, Source, Tick,
};
use tokio::runtime::Handle;
use tokio::sync::watch;

use tee_swap::adapters::abi::{IPrivateUTXO, ITeeLock};
use tee_swap::adapters::merkle_tree::LocalMerkleTree;
use tee_swap::domain::commitment::Commitment;
use tee_swap::domain::merkle::CommitmentMerkleProof;

/// Observed blocks the engine retains; the deepest reorg it can bisect.
const RING_CAPACITY: usize = 1024;
/// Rollback checkpoints retained behind the cursor.
const CHECKPOINT_SLOTS: usize = 4;
/// Blocks of cursor progress between checkpoints.
const CHECKPOINT_INTERVAL: u64 = 64;
/// Poll cadence once the source is at the chain tip.
const POLL_INTERVAL: Duration = Duration::from_secs(4);

#[derive(Debug, Clone, Copy)]
enum ChainEvent {
    NoteCreated(B256),
    NoteSpent(B256),
    SwapRevealed(B256),
}

/// Local mirror of the on-chain commitment tree, the spent nullifier set, and the
/// swaps revealed so far.
#[derive(Clone, Default)]
struct IndexFold {
    tree: LocalMerkleTree,
    commitment_indices: HashMap<B256, u64>,
    revealed_swaps: HashSet<B256>,
    spent_nullifiers: HashSet<B256>,
}

impl Fold for IndexFold {
    type Event = ChainEvent;
    type Error = Infallible;

    fn apply(
        &mut self,
        _pos: Position,
        event: &ChainEvent,
    ) -> Result<(), FoldError<Infallible>> {
        match *event {
            ChainEvent::NoteCreated(commitment) => {
                let index = self.tree.len() as u64;
                self.tree.insert_commitment(&Commitment(commitment));
                self.commitment_indices.entry(commitment).or_insert(index);
            }
            ChainEvent::NoteSpent(nullifier) => {
                self.spent_nullifiers.insert(nullifier);
            }
            ChainEvent::SwapRevealed(swap_id) => {
                self.revealed_swaps.insert(swap_id);
            }
        }
        Ok(())
    }
}

/// Failure reading the chain. The driver reports it as `Tick::SourceError` without
/// the cause, so each is logged where it is raised.
#[derive(Debug)]
struct SourceError;

#[cold]
fn rpc_error(error: RpcError<TransportErrorKind>) -> SourceError {
    tracing::warn!("indexer: rpc call failed: {error}");
    SourceError
}

#[cold]
fn log_index_too_large(block: u64, index: u64) -> SourceError {
    tracing::warn!("indexer: log index {index} in block {block} exceeds u32");
    SourceError
}

/// Supplies the engine with one chain's `NoteCreated`, `NoteSpent`, and
/// `SwapRevealed` logs, blocking on the runtime the indexer was spawned from.
struct RpcSource {
    provider: DynProvider,
    runtime: Handle,
    private_utxo: Address,
    tee_lock: Option<Address>,
    deployment_block: u64,
}

/// One query covering every address and topic the fold consumes.
fn log_filter(
    private_utxo: Address,
    tee_lock: Option<Address>,
    from: u64,
    to: u64,
) -> Filter {
    let mut addresses = vec![private_utxo];
    let mut topics = vec![
        IPrivateUTXO::NoteCreated::SIGNATURE_HASH,
        IPrivateUTXO::NoteSpent::SIGNATURE_HASH,
    ];
    if let Some(tee_lock) = tee_lock {
        addresses.push(tee_lock);
        topics.push(ITeeLock::SwapRevealed::SIGNATURE_HASH);
    }
    Filter::new()
        .address(addresses)
        .event_signature(topics)
        .from_block(from)
        .to_block(to)
}

/// Dispatches on the emitting address and topic, so a log the cross-product filter
/// admits from the wrong contract decodes to nothing.
fn decode(
    private_utxo: Address,
    tee_lock: Option<Address>,
    log: &Log,
) -> Option<ChainEvent> {
    let address = log.address();
    let topic = *log.topic0()?;
    if address == private_utxo {
        if topic == IPrivateUTXO::NoteCreated::SIGNATURE_HASH {
            let event = log.log_decode::<IPrivateUTXO::NoteCreated>().ok()?;
            return Some(ChainEvent::NoteCreated(event.inner.commitment));
        }
        if topic == IPrivateUTXO::NoteSpent::SIGNATURE_HASH {
            let event = log.log_decode::<IPrivateUTXO::NoteSpent>().ok()?;
            return Some(ChainEvent::NoteSpent(event.inner.nullifier));
        }
    }
    if Some(address) == tee_lock && topic == ITeeLock::SwapRevealed::SIGNATURE_HASH {
        let event = log.log_decode::<ITeeLock::SwapRevealed>().ok()?;
        return Some(ChainEvent::SwapRevealed(event.inner.swapId));
    }
    None
}

impl Source for RpcSource {
    type Event = ChainEvent;
    type Error = SourceError;

    fn head(&mut self) -> Result<u64, SourceError> {
        self.runtime
            .block_on(self.provider.get_block_number())
            .map_err(rpc_error)
    }

    fn header_at(&mut self, number: u64) -> Result<Option<BlockRef>, SourceError> {
        let block = self
            .runtime
            .block_on(
                self.provider
                    .get_block_by_number(number.into())
                    .into_future(),
            )
            .map_err(rpc_error)?;
        Ok(block.map(|block| BlockRef {
            number,
            hash: block.header.hash.0,
        }))
    }

    fn events_in(
        &mut self,
        from: u64,
        to: u64,
        out: &mut Vec<(BlockRef, u32, ChainEvent)>,
    ) -> Result<(), SourceError> {
        let filter = log_filter(self.private_utxo, self.tee_lock, from, to);
        let logs = self
            .runtime
            .block_on(self.provider.get_logs(&filter))
            .map_err(rpc_error)?;
        for log in &logs {
            let (Some(number), Some(hash), Some(index)) =
                (log.block_number, log.block_hash, log.log_index)
            else {
                continue;
            };
            let Some(event) = decode(self.private_utxo, self.tee_lock, log) else {
                continue;
            };
            let index =
                u32::try_from(index).map_err(|_| log_index_too_large(number, index))?;
            out.push((
                BlockRef {
                    number,
                    hash: hash.0,
                },
                index,
                event,
            ));
        }
        Ok(())
    }

    fn horizon(&self) -> ReplayHorizon {
        ReplayHorizon::FromBlock(self.deployment_block)
    }
}

/// Fold state as of one tick, plus whether that tick reached the chain head.
#[derive(Clone)]
struct Snapshot {
    fold: Arc<IndexFold>,
    caught_up: bool,
}

/// Runs the driver to completion, publishing a snapshot after every tick that
/// moved the fold or flipped the catch-up state.
fn run(mut driver: Driver<IndexFold, RpcSource>, tx: watch::Sender<Snapshot>) {
    let mut caught_up = false;
    loop {
        let tick = driver.tick();
        if matches!(tick, Tick::SourceError) {
            tracing::warn!(
                "indexer: poll failed, retrying in {:?}",
                driver.next_delay()
            );
        }
        let status = driver.status();
        let moved = match tick {
            Tick::Progressed(summary) => summary.applied > 0,
            Tick::RolledBack { .. } | Tick::Resynced => true,
            _ => false,
        };
        if moved || status.caught_up != caught_up {
            caught_up = status.caught_up;
            let snapshot = Snapshot {
                fold: Arc::new(driver.engine().fold().clone()),
                caught_up,
            };
            if tx.send(snapshot).is_err() {
                return;
            }
        }
        if status.is_terminal() {
            tracing::error!("indexer: engine stopped: {}", status.engine);
            return;
        }
        std::thread::sleep(driver.next_delay());
    }
}

/// Indexes one chain's `NoteCreated`, `NoteSpent`, and `SwapRevealed` events.
pub struct ChainIndexer(watch::Receiver<Snapshot>);

impl ChainIndexer {
    /// Starts indexing. `tee_lock` is `Some` only on the announcement chain (Sepolia).
    pub fn spawn(
        rpc_url: &str,
        private_utxo: Address,
        tee_lock: Option<Address>,
        deployment_block: u64,
    ) -> Result<Self, String> {
        let provider = DynProvider::new(
            ProviderBuilder::new().connect_http(
                rpc_url
                    .parse()
                    .map_err(|e| format!("Invalid RPC URL: {e}"))?,
            ),
        );

        let source = RpcSource {
            provider,
            runtime: Handle::current(),
            private_utxo,
            tee_lock,
            deployment_block,
        };

        let driver = Driver::new(
            IndexFold::default(),
            source,
            EngineConfig {
                ring_capacity: RING_CAPACITY,
                checkpoint_slots: CHECKPOINT_SLOTS,
            },
            DriverConfig {
                start_block: deployment_block,
                poll_interval: POLL_INTERVAL,
                checkpoint_interval: Some(CHECKPOINT_INTERVAL),
                ..DriverConfig::default()
            },
        )
        .map_err(|e| format!("indexer configuration invalid: {e}"))?;

        let (tx, rx) = watch::channel(Snapshot {
            fold: Arc::new(IndexFold::default()),
            caught_up: false,
        });
        std::thread::spawn(move || run(driver, tx));
        Ok(Self(rx))
    }

    /// Block until the indexer has caught up with the chain head at least once.
    pub async fn wait_until_caught_up(&self) {
        self.0
            .clone()
            .wait_for(|s| s.caught_up)
            .await
            .expect("indexer stopped");
    }

    /// Wait for a commitment to appear in the indexed tree. Returns the leaf index.
    pub async fn wait_for_commitment(&self, commitment: B256) -> u64 {
        self.0
            .clone()
            .wait_for(|s| s.fold.commitment_indices.contains_key(&commitment))
            .await
            .expect("indexer stopped")
            .fold
            .commitment_indices[&commitment]
    }

    /// Wait for a swap to be revealed on-chain (SwapRevealed event).
    pub async fn wait_for_swap_revealed(&self, swap_id: B256) {
        self.0
            .clone()
            .wait_for(|s| s.fold.revealed_swaps.contains(&swap_id))
            .await
            .expect("indexer stopped");
    }

    /// Generate a Merkle proof for a given leaf index (snapshot of current tree).
    pub async fn generate_proof(&self, leaf_index: u64) -> Option<CommitmentMerkleProof> {
        self.0.borrow().fold.tree.generate_proof(leaf_index)
    }

    /// Get the current root of the indexed Merkle tree.
    pub async fn current_root(&self) -> Option<B256> {
        self.0.borrow().fold.tree.current_root()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_commitment_keeps_first_index() {
        // given a fold that has already indexed a commitment
        let mut fold = IndexFold::default();
        let commitment = B256::repeat_byte(0x01);
        fold.apply(Position::new(1, 0), &ChainEvent::NoteCreated(commitment))
            .unwrap();
        let first = fold.commitment_indices[&commitment];

        // when the same commitment is created again at a later position
        fold.apply(Position::new(2, 0), &ChainEvent::NoteCreated(commitment))
            .unwrap();

        // then the recorded leaf index stays the first one and the tree still grows
        assert_eq!(fold.commitment_indices[&commitment], first);
        assert_eq!(fold.tree.len(), 2);
    }

    #[test]
    fn spent_and_revealed_events_record() {
        // given a fresh fold, a nullifier, and a swap id
        let mut fold = IndexFold::default();
        let nullifier = B256::repeat_byte(0x02);
        let swap_id = B256::repeat_byte(0x03);

        // when a spend and a reveal are folded
        fold.apply(Position::new(1, 0), &ChainEvent::NoteSpent(nullifier))
            .unwrap();
        fold.apply(Position::new(1, 1), &ChainEvent::SwapRevealed(swap_id))
            .unwrap();

        // then both sets carry the value
        assert!(fold.spent_nullifiers.contains(&nullifier));
        assert!(fold.revealed_swaps.contains(&swap_id));
    }

    #[test]
    fn decode_rejects_a_known_topic_from_the_wrong_contract() {
        // given distinct pool and lock addresses, and a SwapRevealed log emitted by the pool
        let private_utxo = Address::repeat_byte(0x11);
        let tee_lock = Address::repeat_byte(0x22);
        let log = Log {
            inner: alloy::primitives::Log::new(
                private_utxo,
                vec![ITeeLock::SwapRevealed::SIGNATURE_HASH, B256::ZERO],
                Default::default(),
            )
            .unwrap(),
            ..Default::default()
        };

        // when it is decoded
        let event = decode(private_utxo, Some(tee_lock), &log);

        // then it maps to no event
        assert!(event.is_none());
    }
}

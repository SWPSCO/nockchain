use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use libp2p::core::ConnectedPoint;
use libp2p::swarm::ConnectionId;
use libp2p::{Multiaddr, PeerId, Swarm};
use nockapp::noun::slab::NounSlab;
use nockapp::NockAppError;
use nockvm::noun::{Noun, NounSpace};
use rand::prelude::SliceRandom;
use tracing::{debug, info, trace};

use crate::ip_block::PeerExclusions;
use crate::messages::NockchainDataRequest;
use crate::metrics::NockchainP2PMetrics;
use crate::p2p_util::MultiaddrExt;
use crate::tip5_util::tip5_hash_to_base58;

#[derive(Default)]
struct IpInfo {
    request_count: u64,
    ping_failure_count: u64,
    connections: BTreeSet<ConnectionId>,
}

#[derive(Default)]
struct PeerRequestHealth {
    successes: u64,
    failures: u64,
    last_success: Option<Instant>,
    last_failure: Option<Instant>,
}

pub struct P2PState {
    metrics: Arc<NockchainP2PMetrics>,
    block_id_to_peers: BTreeMap<String, BTreeSet<PeerId>>,
    peer_to_block_ids: BTreeMap<PeerId, BTreeSet<String>>,
    // It's stupid that we must track this state locally. libp2p does not expose
    // the lookup shape this driver needs.
    connections: BTreeMap<ConnectionId, PeerId>,
    // subset of connections: all inbound connections
    inbound_connections: BTreeMap<ConnectionId, PeerId>,
    pub(crate) peer_connections: BTreeMap<PeerId, BTreeMap<ConnectionId, Multiaddr>>,
    ip_info: BTreeMap<IpAddr, IpInfo>,
    pub seen_blocks: BTreeSet<String>,
    pub seen_txs: BTreeSet<String>,
    pub block_cache: BTreeMap<u64, NounSlab>,
    pub tx_cache: BTreeMap<String, NounSlab>,
    pub elders_cache: BTreeMap<String, NounSlab>,
    pub elders_negative_cache: BTreeSet<String>,
    pub seen_elders: BTreeSet<String>,
    peer_request_health: BTreeMap<PeerId, PeerRequestHealth>,
    // Highest block height seen
    pub first_negative: u64,
    pub seen_tx_clear_interval: u64,
    pub last_tx_cache_clear_height: u64,
}

impl P2PState {
    pub fn new(metrics: Arc<NockchainP2PMetrics>, seen_tx_clear_interval: u64) -> Self {
        Self {
            metrics,
            block_id_to_peers: BTreeMap::new(),
            peer_to_block_ids: BTreeMap::new(),
            connections: BTreeMap::new(),
            inbound_connections: BTreeMap::new(),
            peer_connections: BTreeMap::new(),
            ip_info: BTreeMap::new(),
            seen_blocks: BTreeSet::new(),
            seen_txs: BTreeSet::new(),
            block_cache: BTreeMap::new(),
            tx_cache: BTreeMap::new(),
            elders_cache: BTreeMap::new(),
            elders_negative_cache: BTreeSet::new(),
            seen_elders: BTreeSet::new(),
            peer_request_health: BTreeMap::new(),
            first_negative: 0,
            seen_tx_clear_interval,
            last_tx_cache_clear_height: 0,
        }
    }

    pub(crate) fn track_connection(
        &mut self,
        connection_id: ConnectionId,
        peer_id: PeerId,
        addr: &Multiaddr,
        endpoint: ConnectedPoint,
    ) {
        self.connections.insert(connection_id, peer_id);
        if let ConnectedPoint::Listener { .. } = endpoint {
            self.inbound_connections.insert(connection_id, peer_id);
        }
        if let Some(c) = self.peer_connections.get_mut(&peer_id) {
            c.insert(connection_id, addr.clone());
        } else {
            let mut new_map = BTreeMap::new();
            new_map.insert(connection_id, addr.clone());
            self.peer_connections.insert(peer_id, new_map);
        }
        if let Some(ip) = addr.ip_addr() {
            if let Some(info) = self.ip_info.get_mut(&ip) {
                info.connections.insert(connection_id);
            } else {
                let mut connections = BTreeSet::new();
                connections.insert(connection_id);
                self.ip_info.insert(
                    ip,
                    IpInfo {
                        connections,
                        request_count: 0,
                        ping_failure_count: 0,
                    },
                );
            }
        }
        let peer_count = self.peer_connections.len() as f64;
        let _ = self.metrics.peer_count.swap(peer_count);
    }

    pub(crate) fn lost_connection(&mut self, connection_id: ConnectionId) -> usize {
        if let Some(peer_id) = self.connections.remove(&connection_id) {
            self.inbound_connections.remove(&connection_id);
            if let Some(c) = self.peer_connections.get_mut(&peer_id) {
                let addr = c.remove(&connection_id);
                if c.is_empty() {
                    self.peer_connections.remove(&peer_id);
                    self.remove_peer(&peer_id);
                }
                if let Some(addr) = addr {
                    if let Some(ip) = addr.ip_addr() {
                        if let Some(info) = self.ip_info.get_mut(&ip) {
                            info.connections.remove(&connection_id);
                            if info.connections.is_empty() {
                                self.ip_info.remove(&ip);
                            }
                        }
                    }
                }
            }
        }
        let peer_count = self.peer_connections.len();
        let _ = self.metrics.peer_count.swap(peer_count as f64);
        peer_count
    }

    pub(crate) fn prune_inbound_connections(
        &mut self,
        metrics: Arc<NockchainP2PMetrics>,
        swarm: &mut Swarm<crate::behaviour::NockchainBehaviour>,
        prune_n: usize,
    ) {
        let mut inbound_connections_vec = self
            .inbound_connections
            .keys()
            .cloned()
            .collect::<Vec<ConnectionId>>();
        inbound_connections_vec.shuffle(&mut rand::rng());
        let prune_actual = std::cmp::min(prune_n, inbound_connections_vec.len());
        for connection_id in &inbound_connections_vec[0..prune_actual] {
            metrics.incoming_connections_pruned.increment();
            swarm.close_connection(*connection_id);
        }
    }

    pub(crate) fn requested(&mut self, ip: IpAddr, threshhold: u64) -> Option<u64> {
        if let Some(info) = self.ip_info.get_mut(&ip) {
            info.request_count += 1;
            if info.request_count >= threshhold {
                Some(info.request_count)
            } else {
                None
            }
        } else {
            trace!("Not tracking {ip} but it is connected. Please inform the developers.");
            None
        }
    }

    pub(crate) fn reset_requests(&mut self) {
        for (_ip, info) in self.ip_info.iter_mut() {
            info.request_count = 0;
        }
    }

    pub(crate) fn record_request_success(&mut self, peer_id: PeerId) {
        let now = Instant::now();
        let health = self.peer_request_health.entry(peer_id).or_default();
        health.successes = health.successes.saturating_add(1);
        health.last_success = Some(now);
    }

    pub(crate) fn record_request_failure(&mut self, peer_id: PeerId) {
        let now = Instant::now();
        let health = self.peer_request_health.entry(peer_id).or_default();
        health.failures = health.failures.saturating_add(1);
        health.last_failure = Some(now);
    }

    pub(crate) fn select_request_peers(
        &self,
        target_peers: Vec<PeerId>,
        limit: usize,
        exclusions: &PeerExclusions,
    ) -> Vec<PeerId> {
        let mut healthy = Vec::new();
        let mut fallback = Vec::new();

        for peer_id in target_peers {
            if self.peer_has_only_excluded_ips(&peer_id, exclusions) {
                self.metrics.fast_sync_peers_skipped_for_health.increment();
                continue;
            }

            fallback.push(peer_id);
            if exclusions.is_peer_request_cooled_down(&peer_id) {
                self.metrics.fast_sync_peers_skipped_for_health.increment();
                continue;
            }
            healthy.push(peer_id);
        }

        let mut selected_from = if healthy.is_empty() {
            fallback
        } else {
            healthy
        };
        selected_from.shuffle(&mut rand::rng());
        selected_from.sort_by_key(|peer_id| Reverse(self.request_score(peer_id)));
        selected_from.truncate(limit);
        selected_from
    }

    fn request_score(&self, peer_id: &PeerId) -> i64 {
        self.peer_request_health
            .get(peer_id)
            .map(|health| health.successes as i64 * 2 - health.failures as i64)
            .unwrap_or_default()
    }

    fn peer_has_only_excluded_ips(&self, peer_id: &PeerId, exclusions: &PeerExclusions) -> bool {
        let Some(connections) = self.peer_connections.get(peer_id) else {
            return false;
        };
        let mut saw_ip = false;
        for addr in connections.values() {
            let Some(ip) = addr.ip_addr() else {
                continue;
            };
            saw_ip = true;
            if !exclusions.is_ip_excluded(&ip) {
                return false;
            }
        }
        saw_ip
    }

    pub(crate) fn ping_succeeded(&mut self, connection: ConnectionId) {
        let addr = self.connection_address(connection);
        let Some(addr) = addr else {
            trace!("No address for connection {connection}. Please inform the developers.");
            return;
        };
        let Some(ip) = addr.ip_addr() else {
            debug!("No IP address for connection {connection}.");
            return;
        };
        if let Some(info) = self.ip_info.get_mut(&ip) {
            info.ping_failure_count = 0;
        }
    }

    pub(crate) fn ping_failed(&mut self, connection: ConnectionId) -> u64 {
        let addr = self.connection_address(connection);
        let Some(addr) = addr else {
            trace!("No address for connection {connection}. Please inform the developers.");
            return 0;
        };
        let Some(ip) = addr.ip_addr() else {
            debug!("No IP address for connection {connection}.");
            return 0;
        };
        if let Some(info) = self.ip_info.get_mut(&ip) {
            info.ping_failure_count += 1;
            info.ping_failure_count
        } else {
            0
        }
    }

    pub(crate) fn connection_address(&self, connection_id: ConnectionId) -> Option<Multiaddr> {
        self.connections.get(&connection_id).and_then(|peer_id| {
            self.peer_connections
                .get(peer_id)
                .and_then(|map| map.get(&connection_id))
                .cloned()
        })
    }

    fn track_block_id_str_and_peer(&mut self, block_id_str: String, peer_id: PeerId) {
        self.block_id_to_peers
            .entry(block_id_str.clone())
            .or_default()
            .insert(peer_id);

        self.peer_to_block_ids
            .entry(peer_id)
            .or_default()
            .insert(block_id_str);
    }

    fn remove_block_id_str(&mut self, block_id: &str) {
        let Some(peers) = self.block_id_to_peers.remove(block_id) else {
            return;
        };

        for peer_id in peers {
            let Some(block_ids) = self.peer_to_block_ids.get_mut(&peer_id) else {
                continue;
            };

            block_ids.remove(block_id);
            if block_ids.is_empty() {
                self.peer_to_block_ids.remove(&peer_id);
            }
        }
    }

    /// Removes a peer from the tracker.
    /// done if a peer disconnects or is banned.
    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        info!("Removing peer: {}", peer_id);
        let Some(block_ids) = self.peer_to_block_ids.remove(peer_id) else {
            return;
        };

        for block_id in block_ids {
            let Some(peers) = self.block_id_to_peers.get_mut(&block_id) else {
                continue;
            };

            peers.remove(peer_id);
            if peers.is_empty() {
                self.block_id_to_peers.remove(&block_id);
            }
        }
    }

    /// Adds a block ID and peer to the tracker.
    /// implements [%track %add block-id peer-id] effect
    pub fn track_block_id_and_peer(
        &mut self,
        block_id: Noun,
        peer_id: PeerId,
        space: &NounSpace,
    ) -> Result<(), NockAppError> {
        let block_id_str = tip5_hash_to_base58(block_id, space)?;
        self.track_block_id_str_and_peer(block_id_str, peer_id);
        Ok(())
    }

    /// Adds a peer to an existing block ID. Returns true if the block ID exists and the peer was added,
    /// false if the block ID doesn't exist in the tracker.
    #[allow(dead_code)]
    pub fn add_peer_if_tracking_block_id(
        &mut self,
        block_id: Noun,
        peer_id: PeerId,
        space: &NounSpace,
    ) -> Result<bool, NockAppError> {
        let block_id_str = tip5_hash_to_base58(block_id, space)?;

        if self.block_id_to_peers.contains_key(&block_id_str) {
            self.track_block_id_str_and_peer(block_id_str, peer_id);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Removes a block ID from the tracker.
    /// implements [%track %remove block-id] effect
    pub fn remove_block_id(
        &mut self,
        block_id: Noun,
        space: &NounSpace,
    ) -> Result<(), NockAppError> {
        let block_id_str = tip5_hash_to_base58(block_id, space)?;
        self.remove_block_id_str(&block_id_str);
        Ok(())
    }

    /// Returns a list of peers that have sent us a given block ID.
    #[allow(dead_code)]
    pub fn get_peers_for_block_id(&self, block_id: Noun, space: &NounSpace) -> Vec<PeerId> {
        let Ok(block_id_str) = tip5_hash_to_base58(block_id, space) else {
            panic!("Invalid block ID");
        };
        self.block_id_to_peers
            .get(&block_id_str)
            .map(|peers| peers.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default()
    }

    /// Returns a list of block IDs that a given peer has sent us.
    #[allow(dead_code)]
    pub fn get_block_ids_for_peer(&self, peer_id: PeerId) -> Vec<String> {
        self.peer_to_block_ids
            .get(&peer_id)
            .map(|block_ids| block_ids.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default()
    }

    /// Returns true if we are tracking a given block ID.
    #[allow(dead_code)]
    pub fn is_tracking_block_id(&self, block_id: Noun, space: &NounSpace) -> bool {
        let Ok(block_id_str) = tip5_hash_to_base58(block_id, space) else {
            return false;
        };
        self.block_id_to_peers.contains_key(&block_id_str)
    }

    #[allow(dead_code)]
    pub fn is_tracking_peer(&self, peer_id: PeerId) -> bool {
        self.peer_to_block_ids.contains_key(&peer_id)
    }

    //  Removes the block id from the MessageTracker maps and returns all the
    //  peers who had sent us that block.
    pub fn process_bad_block_id(
        &mut self,
        block_id: Noun,
        space: &NounSpace,
    ) -> Result<Vec<PeerId>, NockAppError> {
        let block_id_str = tip5_hash_to_base58(block_id, space)?;
        let peers_to_ban = self
            .block_id_to_peers
            .get(&block_id_str)
            .map(|peers| peers.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default();

        // Remove each peer that sent us this bad block
        for peer in &peers_to_ban {
            self.remove_peer(peer);
        }

        self.remove_block_id(block_id, space)?;

        Ok(peers_to_ban)
    }

    pub async fn check_cache(
        &mut self,
        request: NockchainDataRequest,
        metrics: &NockchainP2PMetrics,
    ) -> Result<CacheResponse, NockAppError> {
        match request {
            NockchainDataRequest::BlockByHeight(height) => {
                if height >= self.first_negative {
                    metrics.block_request_cache_negative.increment();
                    trace!("Request for block height not yet seen by cache, height = {:?}", height);
                    Ok(CacheResponse::NegativeCached)
                } else if let Some(cached_block) = self.block_cache.get(&height) {
                    trace!("found cached block request by height={:?}", height);
                    metrics.block_request_cache_hits.increment();
                    Ok(CacheResponse::Cached(cached_block.clone()))
                } else {
                    trace!("didn't find cached block request by height={:?}", height);
                    metrics.block_request_cache_misses.increment();
                    Ok(CacheResponse::NotCached)
                }
            }
            NockchainDataRequest::RawTransactionById(id, _) => {
                if let Some(cached_transaction) = self.tx_cache.get(&id) {
                    trace!("found cached transaction request by id={:?}", id);
                    Ok(CacheResponse::Cached(cached_transaction.clone()))
                } else {
                    trace!("didn't find cached transaction request by id={:?}", id);
                    Ok(CacheResponse::NotCached)
                }
            }
            NockchainDataRequest::EldersById(id, ..) => {
                if let Some(cached_elders) = self.elders_cache.get(&id) {
                    trace!("found cached elders request by id={:?}", id);
                    Ok(CacheResponse::Cached(cached_elders.clone()))
                } else if let Some(_cached_negative) = self.elders_negative_cache.get(&id) {
                    trace!("elders id={:?} is cached-not-known", id);
                    Ok(CacheResponse::NegativeCached)
                } else {
                    trace!("didn't find cached elders request by id={:?}", id);
                    Ok(CacheResponse::NotCached)
                }
            }
        }
    }
}

pub enum CacheResponse {
    Cached(NounSlab),
    NotCached,
    NegativeCached,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::LazyLock;

    use nockapp::noun::slab::NounSlab;
    use nockapp::AtomExt;
    use nockvm::mem::{NockStack, NOCK_STACK_SIZE_TINY};
    use nockvm::noun::{NounAllocator, D, T};

    use crate::config::{LibP2PConfig, PeerExclusionConfig};
    use crate::p2p_state::*;
    use crate::p2p_util::PeerIdExt;

    pub static LIBP2P_CONFIG: LazyLock<LibP2PConfig> = LazyLock::new(LibP2PConfig::default);

    fn install_test_arena() -> NockStack {
        NockStack::new(NOCK_STACK_SIZE_TINY, 0)
    }

    #[test]
    #[cfg_attr(miri, ignore)] // ibig has a memory leak so miri fails this test
    fn test_message_tracker_basic() {
        let metrics = Arc::new(
            NockchainP2PMetrics::register(gnort::global_metrics_registry())
                .expect("Could not register metrics"),
        );
        let mut tracker = P2PState::new(metrics, LIBP2P_CONFIG.seen_tx_clear_interval);
        let peer_id = PeerId::random();

        // Create a block ID as [1 2 3 4 5]
        let mut slab: NounSlab = NounSlab::new();
        let block_id_tuple = T(&mut slab, &[D(1), D(2), D(3), D(4), D(5)]);
        let space = slab.noun_space();

        // Add the block ID
        tracker
            .track_block_id_and_peer(block_id_tuple, peer_id, &space)
            .unwrap_or_else(|_| {
                panic!(
                    "Called `expect()` at {}:{} (git sha: {})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA").unwrap_or("unknown")
                )
            });

        // Get the block ID string
        let block_id_str = tip5_hash_to_base58(block_id_tuple, &space).unwrap_or_else(|_| {
            panic!(
                "Called `expect()` at {}:{} (git sha: {})",
                file!(),
                line!(),
                option_env!("GIT_SHA").unwrap_or("unknown")
            )
        });

        // Verify it was added correctly
        assert!(tracker.block_id_to_peers.contains_key(&block_id_str));
        assert!(tracker.peer_to_block_ids.contains_key(&peer_id));

        // Remove the block ID
        tracker
            .remove_block_id(block_id_tuple, &space)
            .unwrap_or_else(|_| {
                panic!(
                    "Called `expect()` at {}:{} (git sha: {})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA").unwrap_or("unknown")
                )
            });

        // Verify it was removed
        assert!(!tracker.block_id_to_peers.contains_key(&block_id_str));
        assert!(!tracker.peer_to_block_ids.contains_key(&peer_id));
    }

    #[test]
    #[cfg_attr(miri, ignore)] // ibig has a memory leak so miri fails this test
    fn test_bad_block_id() {
        let _arena = install_test_arena();
        let metrics = Arc::new(
            NockchainP2PMetrics::register(gnort::global_metrics_registry())
                .expect("Could not register metrics"),
        );
        let mut tracker = P2PState::new(metrics, LIBP2P_CONFIG.seen_tx_clear_interval);
        let peer_id = PeerId::random();

        // Create a block ID
        let mut slab: NounSlab = NounSlab::new();
        let block_id_tuple = T(&mut slab, &[D(1), D(2), D(3), D(4), D(5)]);
        let space = slab.noun_space();

        // Track the block ID
        tracker
            .track_block_id_and_peer(block_id_tuple, peer_id, &space)
            .unwrap_or_else(|_| {
                panic!(
                    "Called `expect()` at {}:{} (git sha: {})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA").unwrap_or("unknown")
                )
            });

        // Mark it as bad
        let peers_to_ban = tracker
            .process_bad_block_id(block_id_tuple, &space)
            .unwrap_or_else(|_| {
                panic!(
                    "Called `expect()` at {}:{} (git sha: {})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA").unwrap_or("unknown")
                )
            });

        // Verify the peer is returned for banning
        assert_eq!(peers_to_ban.len(), 1);
        assert_eq!(peers_to_ban[0], peer_id);
    }

    #[test]
    fn test_peer_id_base58_roundtrip() {
        let _arena = install_test_arena();
        use nockvm::noun::Atom;
        // Generate a random PeerId
        let original_peer_id = PeerId::random();
        let base58_str = original_peer_id.to_base58();
        println!("Original base58: {}", base58_str);

        // Create a NounSlab and store the base58 string as an Atom
        let mut slab: NounSlab = NounSlab::new();
        let peer_id_atom = Atom::from_value(&mut slab, base58_str.as_bytes())
            .expect("Failed to create peer ID atom");

        // Use the from_noun method to convert back to PeerId
        let space = slab.noun_space();
        let recovered_peer_id =
            PeerId::from_noun(peer_id_atom.as_noun(), &space).unwrap_or_else(|_| {
                panic!(
                    "Called `expect()` at {}:{} (git sha: {})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA").unwrap_or("unknown")
                )
            });

        // Verify round trip
        assert_eq!(original_peer_id, recovered_peer_id);
    }

    #[test]
    #[cfg_attr(miri, ignore)] // ibig has a memory leak so miri fails this test
    fn test_add_peer_if_tracking_block_id() {
        let _arena = install_test_arena();
        let metrics = Arc::new(
            NockchainP2PMetrics::register(gnort::global_metrics_registry())
                .expect("Could not register metrics"),
        );
        let mut tracker = P2PState::new(metrics, LIBP2P_CONFIG.seen_tx_clear_interval);
        let peer_id1 = PeerId::random();
        let peer_id2 = PeerId::random();

        // Create a block ID
        let mut slab: NounSlab = NounSlab::new();
        let block_id_tuple = T(&mut slab, &[D(1), D(2), D(3), D(4), D(5)]);
        let space = slab.noun_space();

        // First, try to add a peer to a non-existent block ID
        let result = tracker
            .add_peer_if_tracking_block_id(block_id_tuple, peer_id1, &space)
            .unwrap_or_else(|_| {
                panic!(
                    "Called `expect()` at {}:{} (git sha: {})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA").unwrap_or("unknown")
                )
            });
        assert!(!result); // Should return false since block ID doesn't exist

        // Now track the block ID with peer1
        tracker
            .track_block_id_and_peer(block_id_tuple, peer_id1, &space)
            .unwrap_or_else(|_| {
                panic!(
                    "Called `expect()` at {}:{} (git sha: {})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA").unwrap_or("unknown")
                )
            });

        // Add peer2 to the existing block ID
        let result = tracker
            .add_peer_if_tracking_block_id(block_id_tuple, peer_id2, &space)
            .unwrap_or_else(|_| {
                panic!(
                    "Called `expect()` at {}:{} (git sha: {})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA").unwrap_or("unknown")
                )
            });
        assert!(result); // Should return true since block ID exists

        // Verify both peers are associated with the block ID
        let peers = tracker.get_peers_for_block_id(block_id_tuple, &space);
        assert_eq!(peers.len(), 2);
        assert!(peers.contains(&peer_id1));
        assert!(peers.contains(&peer_id2));
    }

    #[test]
    #[cfg_attr(miri, ignore)] // ibig has a memory leak so miri fails this test
    fn test_add_peer_if_tracking_block_id_then_remove() {
        let _arena = install_test_arena();
        let metrics = Arc::new(
            NockchainP2PMetrics::register(gnort::global_metrics_registry())
                .expect("Could not register metrics"),
        );
        let mut tracker = P2PState::new(metrics, LIBP2P_CONFIG.seen_tx_clear_interval);
        let peer_id1 = PeerId::random();
        let peer_id2 = PeerId::random();

        // Create a block ID
        let mut slab: NounSlab = NounSlab::new();
        let block_id_tuple = T(&mut slab, &[D(1), D(2), D(3), D(4), D(5)]);
        let space = slab.noun_space();
        let block_id_str = tip5_hash_to_base58(block_id_tuple, &space).unwrap_or_else(|_| {
            panic!(
                "Called `expect()` at {}:{} (git sha: {})",
                file!(),
                line!(),
                option_env!("GIT_SHA").unwrap_or("unknown")
            )
        });

        // Track the block ID with peer1
        tracker
            .track_block_id_and_peer(block_id_tuple, peer_id1, &space)
            .unwrap_or_else(|_| {
                panic!(
                    "Called `expect()` at {}:{} (git sha: {})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA").unwrap_or("unknown")
                )
            });

        // Add peer2 to the existing block ID
        let result = tracker
            .add_peer_if_tracking_block_id(block_id_tuple, peer_id2, &space)
            .unwrap_or_else(|_| {
                panic!(
                    "Called `expect()` at {}:{} (git sha: {})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA").unwrap_or("unknown")
                )
            });
        assert!(result); // Should return true since block ID exists

        // Verify both peers are associated with the block ID
        let peers = tracker.get_peers_for_block_id(block_id_tuple, &space);
        assert_eq!(peers.len(), 2);
        assert!(peers.contains(&peer_id1));
        assert!(peers.contains(&peer_id2));

        // Now remove the block ID
        tracker
            .remove_block_id(block_id_tuple, &space)
            .unwrap_or_else(|_| {
                panic!(
                    "Called `expect()` at {}:{} (git sha: {})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA").unwrap_or("unknown")
                )
            });

        // Verify the block ID is no longer tracked
        let peers_after_removal = tracker.get_peers_for_block_id(block_id_tuple, &space);
        assert_eq!(peers_after_removal.len(), 0);

        // Verify the block ID is removed from block_id_to_peers
        assert!(!tracker.block_id_to_peers.contains_key(&block_id_str));

        // Verify the peers either don't exist in the map anymore or don't have this block ID
        // For peer_id1
        if let Some(block_ids) = tracker.peer_to_block_ids.get(&peer_id1) {
            assert!(!block_ids.contains(&block_id_str));
        }
        // For peer_id2
        if let Some(block_ids) = tracker.peer_to_block_ids.get(&peer_id2) {
            assert!(!block_ids.contains(&block_id_str));
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)] // ibig has a memory leak so miri fails this test
    fn test_process_bad_block_id_removes_peers() {
        let _arena = install_test_arena();
        let metrics = Arc::new(
            NockchainP2PMetrics::register(gnort::global_metrics_registry())
                .expect("Could not register metrics"),
        );
        let mut tracker = P2PState::new(metrics, LIBP2P_CONFIG.seen_tx_clear_interval);
        let peer_id1 = PeerId::random();
        let peer_id2 = PeerId::random();

        // Create a block ID
        let mut slab: NounSlab = NounSlab::new();
        let block_id_tuple = T(&mut slab, &[D(1), D(2), D(3), D(4), D(5)]);
        let space = slab.noun_space();

        // Create another block ID that both peers will share
        let other_block_id = T(&mut slab, &[D(6), D(7), D(8), D(9), D(10)]);

        // Track both block IDs with both peers
        tracker
            .track_block_id_and_peer(block_id_tuple, peer_id1, &space)
            .unwrap_or_else(|_| {
                panic!(
                    "Called `expect()` at {}:{} (git sha: {})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA").unwrap_or("unknown")
                )
            });
        tracker
            .add_peer_if_tracking_block_id(block_id_tuple, peer_id2, &space)
            .unwrap_or_else(|_| {
                panic!(
                    "Called `expect()` at {}:{} (git sha: {})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA").unwrap_or("unknown")
                )
            });
        tracker
            .track_block_id_and_peer(other_block_id, peer_id1, &space)
            .unwrap_or_else(|_| {
                panic!(
                    "Called `expect()` at {}:{} (git sha: {})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA").unwrap_or("unknown")
                )
            });
        tracker
            .add_peer_if_tracking_block_id(other_block_id, peer_id2, &space)
            .unwrap_or_else(|_| {
                panic!(
                    "Called `expect()` at {}:{} (git sha: {})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA").unwrap_or("unknown")
                )
            });

        // Verify both peers are tracked
        assert!(tracker.is_tracking_peer(peer_id1));
        assert!(tracker.is_tracking_peer(peer_id2));

        // Process the bad block ID
        let banned_peers = tracker
            .process_bad_block_id(block_id_tuple, &space)
            .unwrap_or_else(|_| {
                panic!(
                    "Called `expect()` at {}:{} (git sha: {})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA").unwrap_or("unknown")
                )
            });

        // Verify both peers were returned for banning
        assert_eq!(banned_peers.len(), 2);
        assert!(banned_peers.contains(&peer_id1));
        assert!(banned_peers.contains(&peer_id2));

        // Verify both peers are no longer tracked
        assert!(!tracker.is_tracking_peer(peer_id1));
        assert!(!tracker.is_tracking_peer(peer_id2));

        // Verify the other block ID is also no longer tracked
        // (since we removed the peers entirely)
        assert!(!tracker.is_tracking_block_id(other_block_id, &space));
    }

    #[test]
    fn select_request_peers_skips_cooled_peer_when_healthy_peer_exists() {
        let metrics = Arc::new(
            NockchainP2PMetrics::register(gnort::global_metrics_registry())
                .expect("Could not register metrics"),
        );
        let tracker = P2PState::new(metrics, LIBP2P_CONFIG.seen_tx_clear_interval);
        let exclusions = PeerExclusions::new(PeerExclusionConfig {
            request_peer_cooldown_secs: 60,
            ..PeerExclusionConfig::default()
        });
        let cooled_peer = PeerId::random();
        let healthy_peer = PeerId::random();

        assert!(exclusions.record_peer_request_failure(cooled_peer));

        let selected =
            tracker.select_request_peers(vec![cooled_peer, healthy_peer], 10, &exclusions);

        assert_eq!(selected, vec![healthy_peer]);
    }

    #[test]
    fn select_request_peers_falls_back_when_every_peer_is_cooled() {
        let metrics = Arc::new(
            NockchainP2PMetrics::register(gnort::global_metrics_registry())
                .expect("Could not register metrics"),
        );
        let tracker = P2PState::new(metrics, LIBP2P_CONFIG.seen_tx_clear_interval);
        let exclusions = PeerExclusions::new(PeerExclusionConfig {
            request_peer_cooldown_secs: 60,
            ..PeerExclusionConfig::default()
        });
        let left = PeerId::random();
        let right = PeerId::random();

        assert!(exclusions.record_peer_request_failure(left));
        assert!(exclusions.record_peer_request_failure(right));

        let selected = tracker.select_request_peers(vec![left, right], 10, &exclusions);

        assert_eq!(selected.len(), 2);
        assert!(selected.contains(&left));
        assert!(selected.contains(&right));
    }

    #[test]
    fn select_request_peers_drops_peer_with_only_excluded_ips() {
        let metrics = Arc::new(
            NockchainP2PMetrics::register(gnort::global_metrics_registry())
                .expect("Could not register metrics"),
        );
        let mut tracker = P2PState::new(metrics, LIBP2P_CONFIG.seen_tx_clear_interval);
        let exclusions = PeerExclusions::new(PeerExclusionConfig {
            wrong_peer_id_ip_threshold: 1,
            ..PeerExclusionConfig::default()
        });
        let excluded_peer = PeerId::random();
        let healthy_peer = PeerId::random();
        let excluded_addr = "/ip4/15.235.216.78/udp/3602/quic-v1"
            .parse::<Multiaddr>()
            .expect("valid multiaddr");
        let healthy_addr = "/ip4/203.0.113.9/udp/3006/quic-v1"
            .parse::<Multiaddr>()
            .expect("valid multiaddr");

        tracker
            .peer_connections
            .entry(excluded_peer)
            .or_default()
            .insert(ConnectionId::new_unchecked(1), excluded_addr.clone());
        tracker
            .peer_connections
            .entry(healthy_peer)
            .or_default()
            .insert(ConnectionId::new_unchecked(2), healthy_addr);

        let outcome =
            exclusions.record_wrong_peer_id(&excluded_addr, Some(excluded_peer), PeerId::random());
        assert!(outcome.ip_exclusion.is_some());

        let selected =
            tracker.select_request_peers(vec![excluded_peer, healthy_peer], 10, &exclusions);

        assert_eq!(selected, vec![healthy_peer]);
    }

    #[test]
    fn select_request_peers_keeps_peer_with_a_clean_connection() {
        let metrics = Arc::new(
            NockchainP2PMetrics::register(gnort::global_metrics_registry())
                .expect("Could not register metrics"),
        );
        let mut tracker = P2PState::new(metrics, LIBP2P_CONFIG.seen_tx_clear_interval);
        let exclusions = PeerExclusions::new(PeerExclusionConfig {
            wrong_peer_id_ip_threshold: 1,
            ..PeerExclusionConfig::default()
        });
        let peer = PeerId::random();
        let excluded_addr = "/ip4/15.235.216.78/udp/3602/quic-v1"
            .parse::<Multiaddr>()
            .expect("valid multiaddr");
        let clean_addr = "/ip4/203.0.113.9/udp/3006/quic-v1"
            .parse::<Multiaddr>()
            .expect("valid multiaddr");

        tracker
            .peer_connections
            .entry(peer)
            .or_default()
            .insert(ConnectionId::new_unchecked(1), excluded_addr.clone());
        tracker
            .peer_connections
            .entry(peer)
            .or_default()
            .insert(ConnectionId::new_unchecked(2), clean_addr);

        let outcome = exclusions.record_wrong_peer_id(&excluded_addr, Some(peer), PeerId::random());
        assert!(outcome.ip_exclusion.is_some());

        let selected = tracker.select_request_peers(vec![peer], 10, &exclusions);

        assert_eq!(selected, vec![peer]);
    }

    #[test]
    fn request_success_clears_request_cooldown() {
        let exclusions = PeerExclusions::new(PeerExclusionConfig {
            request_peer_cooldown_secs: 60,
            ..PeerExclusionConfig::default()
        });
        let peer = PeerId::random();

        assert!(exclusions.record_peer_request_failure(peer));
        assert!(exclusions.is_peer_request_cooled_down(&peer));

        exclusions.record_peer_request_success(&peer);

        assert!(!exclusions.is_peer_request_cooled_down(&peer));
    }

    #[test]
    fn test_fail2ban_logging() {
        let peer_id: PeerId = libp2p::PeerId::from_bytes(&[0; 2]).unwrap();
        assert_eq!("11", peer_id.to_base58());
        let ipv4_addr = Ipv4Addr::new(192, 168, 1, 1);
        let ipv6_addr = Ipv6Addr::new(0x2001, 0x0db8, 0x0db8, 0x0db8, 0x0db8, 0x0db8, 0x0db8, 0x1);
        // Check the display representation of the IP addresses
        let ipv4_display = format!("{}", ipv4_addr);
        let ipv6_display = format!("{}", ipv6_addr);
        assert_eq!(ipv4_display, "192.168.1.1");
        assert_eq!(ipv6_display, "2001:db8:db8:db8:db8:db8:db8:1");
    }
}

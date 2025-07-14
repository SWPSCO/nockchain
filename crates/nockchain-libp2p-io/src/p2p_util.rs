use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;

use libp2p::core::ConnectedPoint;
use libp2p::swarm::ConnectionId;
use libp2p::{Multiaddr, PeerId, Swarm};
use nockapp::noun::slab::NounSlab;
use nockapp::{AtomExt, NockAppError, NounExt};
use nockvm::noun::{Noun, D};
use nockvm_macros::tas;
use rand::prelude::SliceRandom;
use tracing::{info, trace, warn};

use crate::metrics::NockchainP2PMetrics;
use crate::tip5_util::tip5_hash_to_base58;

// The warn logs are specifically constructed for fail2ban
// Changing these breaks the integration with the fail2ban regex
pub fn log_fail2ban_ipv4(peer_id: &PeerId, ip: &Ipv4Addr) {
    warn!("fail2ban: Blocked peer {peer_id} with IPv4 address: {ip}");
}
pub fn log_fail2ban_ipv6(peer_id: &PeerId, ip: &Ipv6Addr) {
    warn!("fail2ban: Blocked peer {peer_id} with IPv6 address: {ip}");
}

pub trait PeerIdExt {
    fn from_noun(noun: Noun) -> Result<PeerId, NockAppError>;
}

impl PeerIdExt for PeerId {
    fn from_noun(noun: Noun) -> Result<PeerId, NockAppError> {
        let peer_id_bytes = noun.as_atom()?.to_bytes_until_nul()?;
        let peer_id_str = String::from_utf8(peer_id_bytes)?;
        PeerId::from_str(&peer_id_str).map_err(|_| NockAppError::OtherError)
    }
}

pub enum CacheResponse {
    Cached(NounSlab),
    NotCached,
    NegativeCached,
}

/// This struct is used to track which peers sent us which block IDs.
/// `block_id_to_peers` is the one we really care about, since it's what we use
/// to figure out which peers to ban when we get a %liar-block-id effect.
/// But when we are removing peers, we don't want to have to iterate over
/// every block ID and check if the peer is in the set. So we also maintain
/// a `peer_to_block_ids` map.
pub struct MessageTracker {
    metrics: Arc<NockchainP2PMetrics>,
    block_id_to_peers: BTreeMap<String, BTreeSet<PeerId>>,
    peer_to_block_ids: BTreeMap<PeerId, BTreeSet<String>>,
    // It's stupid that we must track this state instead of just getting it from libp2p.
    connections: BTreeMap<ConnectionId, PeerId>,
    // subset of connections: all inbound connections
    inbound_connections: BTreeMap<ConnectionId, PeerId>,
    peer_connections: BTreeMap<PeerId, BTreeMap<ConnectionId, Multiaddr>>,
    request_counts_by_ip: BTreeMap<Ipv4Addr, u64>,
    pub seen_blocks: BTreeSet<String>,
    pub seen_txs: BTreeSet<String>,
    pub block_cache: BTreeMap<u64, NounSlab>,
    pub tx_cache: BTreeMap<String, NounSlab>,
    pub elders_cache: BTreeMap<String, NounSlab>,
    pub elders_negative_cache: BTreeSet<String>,
    pub seen_elders: BTreeSet<String>,
    // Highest block height seen
    pub first_negative: u64,
    pub seen_tx_clear_interval: u64,
    pub last_tx_cache_clear_height: u64,
}

impl MessageTracker {
    pub fn new(metrics: Arc<NockchainP2PMetrics>, seen_tx_clear_interval: u64) -> Self {
        Self {
            metrics,
            block_id_to_peers: BTreeMap::new(),
            peer_to_block_ids: BTreeMap::new(),
            connections: BTreeMap::new(),
            inbound_connections: BTreeMap::new(),
            peer_connections: BTreeMap::new(),
            request_counts_by_ip: BTreeMap::new(),
            seen_blocks: BTreeSet::new(),
            seen_txs: BTreeSet::new(),
            block_cache: BTreeMap::new(),
            tx_cache: BTreeMap::new(),
            elders_cache: BTreeMap::new(),
            elders_negative_cache: BTreeSet::new(),
            seen_elders: BTreeSet::new(),
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
        let peer_count = self.peer_connections.len() as f64;
        let _ = self.metrics.peer_count.swap(peer_count);
    }

    pub(crate) fn lost_connection(&mut self, connection_id: ConnectionId) {
        if let Some(peer_id) = self.connections.remove(&connection_id) {
            self.inbound_connections.remove(&connection_id);
            if let Some(c) = self.peer_connections.get_mut(&peer_id) {
                c.remove(&connection_id);
                if c.is_empty() {
                    self.peer_connections.remove(&peer_id);
                    self.remove_peer(&peer_id);
                }
            }
        }
        let peer_count = self.peer_connections.len() as f64;
        let _ = self.metrics.peer_count.swap(peer_count);
    }

    pub(crate) fn prune_inbound_connections(
        &mut self,
        metrics: Arc<NockchainP2PMetrics>,
        swarm: &mut Swarm<crate::p2p::NockchainBehaviour>,
        prune_n: usize,
    ) {
        let mut inbound_connections_vec = self
            .inbound_connections
            .keys()
            .cloned()
            .collect::<Vec<ConnectionId>>();
        inbound_connections_vec.shuffle(&mut rand::thread_rng());
        let prune_actual = std::cmp::min(prune_n, inbound_connections_vec.len());
        for connection_id in &inbound_connections_vec[0..prune_actual] {
            metrics.incoming_connections_pruned.increment();
            swarm.close_connection(*connection_id);
        }
    }

    pub(crate) fn requested(&mut self, ip4: Ipv4Addr, threshhold: u64) -> Option<u64> {
        if let Some(count) = self.request_counts_by_ip.get_mut(&ip4) {
            *count += 1;
            if *count >= threshhold {
                Some(*count)
            } else {
                None
            }
        } else {
            self.request_counts_by_ip.insert(ip4, 1);
            if threshhold <= 1 {
                Some(1)
            } else {
                None
            }
        }
    }

    pub(crate) fn reset_requests(&mut self) {
        self.request_counts_by_ip.clear();
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
    ) -> Result<(), NockAppError> {
        let block_id_str = tip5_hash_to_base58(block_id)?;
        self.track_block_id_str_and_peer(block_id_str, peer_id);
        Ok(())
    }

    /// Adds a peer to an existing block ID. Returns true if the block ID exists and the peer was added,
    /// false if the block ID doesn't exist in the tracker.
    pub fn add_peer_if_tracking_block_id(
        &mut self,
        block_id: Noun,
        peer_id: PeerId,
    ) -> Result<bool, NockAppError> {
        let block_id_str = tip5_hash_to_base58(block_id)?;

        if self.block_id_to_peers.contains_key(&block_id_str) {
            self.track_block_id_str_and_peer(block_id_str, peer_id);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Removes a block ID from the tracker.
    /// implements [%track %remove block-id] effect
    pub fn remove_block_id(&mut self, block_id: Noun) -> Result<(), NockAppError> {
        let block_id_str = tip5_hash_to_base58(block_id)?;
        self.remove_block_id_str(&block_id_str);
        Ok(())
    }

    /// Returns a list of peers that have sent us a given block ID.
    pub fn get_peers_for_block_id(&self, block_id: Noun) -> Vec<PeerId> {
        let Ok(block_id_str) = tip5_hash_to_base58(block_id) else {
            panic!("Invalid block ID");
        };
        self.block_id_to_peers
            .get(&block_id_str)
            .map(|peers| peers.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default()
    }

    /// Returns a list of block IDs that a given peer has sent us.
    pub fn get_block_ids_for_peer(&self, peer_id: PeerId) -> Vec<String> {
        self.peer_to_block_ids
            .get(&peer_id)
            .map(|block_ids| block_ids.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default()
    }

    /// Returns true if we are tracking a given block ID.
    pub fn is_tracking_block_id(&self, block_id: Noun) -> bool {
        let Ok(block_id_str) = tip5_hash_to_base58(block_id) else {
            return false;
        };
        self.block_id_to_peers.contains_key(&block_id_str)
    }

    pub fn is_tracking_peer(&self, peer_id: PeerId) -> bool {
        self.peer_to_block_ids.contains_key(&peer_id)
    }

    //  Removes the block id from the MessageTracker maps and returns all the
    //  peers who had sent us that block.
    pub fn process_bad_block_id(&mut self, block_id: Noun) -> Result<Vec<PeerId>, NockAppError> {
        let block_id_str = tip5_hash_to_base58(block_id)?;
        let peers_to_ban = self
            .block_id_to_peers
            .get(&block_id_str)
            .map(|peers| peers.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default();

        // Remove each peer that sent us this bad block
        for peer in &peers_to_ban {
            self.remove_peer(peer);
        }

        self.remove_block_id(block_id)?;

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

const POKE_VERSION: u64 = 0;

#[derive(Debug, Clone)]
pub enum NockchainFact {
    // [%heard-block p=page:dt] with poke slab
    HeardBlock(String, NounSlab),
    // [%heard-elders p=[oldest=page-number:dt ids=(list block-id:dt)]] with poke slab
    HeardElders(u64, Vec<String>, NounSlab),
    // [%heard-tx p=raw-tx:dt] with poke slab
    HeardTx(String, NounSlab),
}

impl NockchainFact {
    pub fn from_noun_slab(slab: &NounSlab) -> Result<Self, NockAppError> {
        let mut poke_slab = NounSlab::new();

        poke_slab.copy_from_slab(slab);
        poke_slab.modify(|response_noun| vec![D(tas!(b"fact")), D(POKE_VERSION), response_noun]);

        let noun = unsafe { slab.root() };
        let head = noun.as_cell()?.head();

        if head.eq_bytes(b"heard-block") {
            let page = noun.as_cell()?.tail();
            let block_id = page.as_cell()?.head();
            let block_id_str = tip5_hash_to_base58(block_id)?;
            Ok(NockchainFact::HeardBlock(block_id_str, poke_slab))
        } else if head.eq_bytes(b"heard-tx") {
            let raw_tx = noun.as_cell()?.tail();
            let tx_id = raw_tx.as_cell()?.head();
            let tx_id_str = tip5_hash_to_base58(tx_id)?;
            Ok(NockchainFact::HeardTx(tx_id_str, poke_slab))
        } else if head.eq_bytes(b"heard-elders") {
            let elders_dat = noun.as_cell()?.tail();
            let oldest = elders_dat.as_cell()?.head().as_atom()?.as_u64()?;
            let elder_ids = elders_dat.as_cell()?.tail();
            let elder_id_strings: Result<Vec<String>, nockapp::NockAppError> = elder_ids
                .list_iter()
                .map(|id_noun| tip5_hash_to_base58(id_noun))
                .collect();
            Ok(NockchainFact::HeardElders(
                oldest, elder_id_strings?, poke_slab,
            ))
        } else {
            Err(NockAppError::OtherError)
        }
    }
    pub fn fact_poke(&self) -> &NounSlab {
        match self {
            Self::HeardBlock(_, slab) => &slab,
            Self::HeardTx(_, slab) => &slab,
            Self::HeardElders(_, _, slab) => &slab,
        }
    }
}

#[derive(Debug, Clone)]
pub enum NockchainDataRequest {
    BlockByHeight(u64),                   // Height requested
    EldersById(String, PeerId, NounSlab), // Block ID as string, peer id, block id as noun,
    RawTransactionById(String, NounSlab), // transaction id as string, transaction id as noun,
}

impl NockchainDataRequest {
    /// Takes noun of type [%request p=request]
    pub fn from_noun(noun: Noun) -> Result<Self, NockAppError> {
        let res = (|| {
            let request_cell = noun.as_cell()?;
            if !request_cell.head().eq_bytes(b"request") {
                return Err(NockAppError::OtherError);
            }
            // kind cell type $%([%block request-block] [%raw-tx request-tx])
            let kind_cell = request_cell.tail().as_cell()?;
            if kind_cell.head().eq_bytes(b"block") {
                // block_cell type
                // $%  [%by-height p=page-number:dt]
                //     [%elders p=block-id:dt q=peer-id]
                // ==
                let block_cell = kind_cell.tail().as_cell()?;
                if block_cell.head().eq_bytes(b"by-height") {
                    let height = block_cell.tail().as_atom()?.as_u64()?;
                    Ok(Self::BlockByHeight(height))
                } else if block_cell.head().eq_bytes(b"elders") {
                    let elders_cell = block_cell.tail().as_cell()?;
                    let block_id = tip5_hash_to_base58(elders_cell.head())?;
                    let peer_id = PeerId::from_noun(elders_cell.tail())?;
                    let slab = {
                        let mut slab = NounSlab::new();
                        slab.copy_into(elders_cell.head());
                        slab
                    };
                    Ok(Self::EldersById(block_id, peer_id, slab))
                } else {
                    Err(NockAppError::OtherError)
                }
            } else if kind_cell.head().eq_bytes(b"raw-tx") {
                // has type [%by-id p=tx-id:dt]
                let raw_tx_cell = kind_cell.tail().as_cell()?;
                let raw_tx_id = tip5_hash_to_base58(raw_tx_cell.tail())?;
                let slab = {
                    let mut slab = NounSlab::new();
                    slab.copy_into(raw_tx_cell.tail());
                    slab
                };
                Ok(Self::RawTransactionById(raw_tx_id, slab))
            } else {
                Err(NockAppError::OtherError)
            }
        })();
        res.map_err(|_| {
            NockAppError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                "bad request",
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use nockapp::noun::slab::NounSlab;
    use nockvm::noun::{D, T};

    use super::*;
    use crate::config::LibP2PConfig;

    pub static LIBP2P_CONFIG: LazyLock<LibP2PConfig> = LazyLock::new(|| LibP2PConfig::default());

    #[test]
    #[cfg_attr(miri, ignore)] // ibig has a memory leak so miri fails this test
    fn test_message_tracker_basic() {
        let metrics = Arc::new(
            NockchainP2PMetrics::register(gnort::global_metrics_registry())
                .expect("Could not register metrics"),
        );
        let mut tracker = MessageTracker::new(metrics, LIBP2P_CONFIG.seen_tx_clear_interval);
        let peer_id = PeerId::random();

        // Create a block ID as [1 2 3 4 5]
        let mut slab: NounSlab = NounSlab::new();
        let block_id_tuple = T(&mut slab, &[D(1), D(2), D(3), D(4), D(5)]);

        // Add the block ID
        tracker
            .track_block_id_and_peer(block_id_tuple, peer_id)
            .unwrap_or_else(|_| {
                panic!(
                    "Called `expect()` at {}:{} (git sha: {})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA").unwrap_or("unknown")
                )
            });

        // Get the block ID string
        let block_id_str = tip5_hash_to_base58(block_id_tuple).unwrap_or_else(|_| {
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
        tracker.remove_block_id(block_id_tuple).unwrap_or_else(|_| {
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
        let metrics = Arc::new(
            NockchainP2PMetrics::register(gnort::global_metrics_registry())
                .expect("Could not register metrics"),
        );
        let mut tracker = MessageTracker::new(metrics, LIBP2P_CONFIG.seen_tx_clear_interval);
        let peer_id = PeerId::random();

        // Create a block ID
        let mut slab: NounSlab = NounSlab::new();
        let block_id_tuple = T(&mut slab, &[D(1), D(2), D(3), D(4), D(5)]);

        // Track the block ID
        tracker
            .track_block_id_and_peer(block_id_tuple, peer_id)
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
            .process_bad_block_id(block_id_tuple)
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
        let recovered_peer_id = PeerId::from_noun(peer_id_atom.as_noun()).unwrap_or_else(|_| {
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
        let metrics = Arc::new(
            NockchainP2PMetrics::register(gnort::global_metrics_registry())
                .expect("Could not register metrics"),
        );
        let mut tracker = MessageTracker::new(metrics, LIBP2P_CONFIG.seen_tx_clear_interval);
        let peer_id1 = PeerId::random();
        let peer_id2 = PeerId::random();

        // Create a block ID
        let mut slab: NounSlab = NounSlab::new();
        let block_id_tuple = T(&mut slab, &[D(1), D(2), D(3), D(4), D(5)]);

        // First, try to add a peer to a non-existent block ID
        let result = tracker
            .add_peer_if_tracking_block_id(block_id_tuple, peer_id1)
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
            .track_block_id_and_peer(block_id_tuple, peer_id1)
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
            .add_peer_if_tracking_block_id(block_id_tuple, peer_id2)
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
        let peers = tracker.get_peers_for_block_id(block_id_tuple);
        assert_eq!(peers.len(), 2);
        assert!(peers.contains(&peer_id1));
        assert!(peers.contains(&peer_id2));
    }

    #[test]
    #[cfg_attr(miri, ignore)] // ibig has a memory leak so miri fails this test
    fn test_add_peer_if_tracking_block_id_then_remove() {
        let metrics = Arc::new(
            NockchainP2PMetrics::register(gnort::global_metrics_registry())
                .expect("Could not register metrics"),
        );
        let mut tracker = MessageTracker::new(metrics, LIBP2P_CONFIG.seen_tx_clear_interval);
        let peer_id1 = PeerId::random();
        let peer_id2 = PeerId::random();

        // Create a block ID
        let mut slab: NounSlab = NounSlab::new();
        let block_id_tuple = T(&mut slab, &[D(1), D(2), D(3), D(4), D(5)]);
        let block_id_str = tip5_hash_to_base58(block_id_tuple).unwrap_or_else(|_| {
            panic!(
                "Called `expect()` at {}:{} (git sha: {})",
                file!(),
                line!(),
                option_env!("GIT_SHA").unwrap_or("unknown")
            )
        });

        // Track the block ID with peer1
        tracker
            .track_block_id_and_peer(block_id_tuple, peer_id1)
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
            .add_peer_if_tracking_block_id(block_id_tuple, peer_id2)
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
        let peers = tracker.get_peers_for_block_id(block_id_tuple);
        assert_eq!(peers.len(), 2);
        assert!(peers.contains(&peer_id1));
        assert!(peers.contains(&peer_id2));

        // Now remove the block ID
        tracker.remove_block_id(block_id_tuple).unwrap_or_else(|_| {
            panic!(
                "Called `expect()` at {}:{} (git sha: {})",
                file!(),
                line!(),
                option_env!("GIT_SHA").unwrap_or("unknown")
            )
        });

        // Verify the block ID is no longer tracked
        let peers_after_removal = tracker.get_peers_for_block_id(block_id_tuple);
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
        let metrics = Arc::new(
            NockchainP2PMetrics::register(gnort::global_metrics_registry())
                .expect("Could not register metrics"),
        );
        let mut tracker = MessageTracker::new(metrics, LIBP2P_CONFIG.seen_tx_clear_interval);
        let peer_id1 = PeerId::random();
        let peer_id2 = PeerId::random();

        // Create a block ID
        let mut slab: NounSlab = NounSlab::new();
        let block_id_tuple = T(&mut slab, &[D(1), D(2), D(3), D(4), D(5)]);

        // Create another block ID that both peers will share
        let other_block_id = T(&mut slab, &[D(6), D(7), D(8), D(9), D(10)]);

        // Track both block IDs with both peers
        tracker
            .track_block_id_and_peer(block_id_tuple, peer_id1)
            .unwrap_or_else(|_| {
                panic!(
                    "Called `expect()` at {}:{} (git sha: {})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA").unwrap_or("unknown")
                )
            });
        tracker
            .add_peer_if_tracking_block_id(block_id_tuple, peer_id2)
            .unwrap_or_else(|_| {
                panic!(
                    "Called `expect()` at {}:{} (git sha: {})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA").unwrap_or("unknown")
                )
            });
        tracker
            .track_block_id_and_peer(other_block_id, peer_id1)
            .unwrap_or_else(|_| {
                panic!(
                    "Called `expect()` at {}:{} (git sha: {})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA").unwrap_or("unknown")
                )
            });
        tracker
            .add_peer_if_tracking_block_id(other_block_id, peer_id2)
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
            .process_bad_block_id(block_id_tuple)
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
        assert!(!tracker.is_tracking_block_id(other_block_id));
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

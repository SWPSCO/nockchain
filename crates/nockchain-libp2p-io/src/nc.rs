use std::collections::HashMap;
use std::mem::size_of;
use std::str::FromStr;
use std::sync::Arc;

use bytes::Bytes;
use crown::nockapp::driver::{IODriverFn, NockAppHandle, PokeResult};
use crown::nockapp::wire::{Wire, WireRepr};
use crown::nockapp::NockAppError;
use crown::noun::slab::NounSlab;
use crown::utils::make_tas;
use crown::utils::scry::*;
use crown::{AtomExt, NounExt};
use either::{Either, Left, Right};
use futures::{Future, StreamExt};
use libp2p::allow_block_list;
use libp2p::connection_limits;
use libp2p::identify::Event::Received;
use libp2p::identity::Keypair;
use libp2p::kad::NoKnownPeers;
use libp2p::memory_connection_limits;
use libp2p::request_response::Event::*;
use libp2p::request_response::Message::*;
use libp2p::request_response::{self};
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId, Swarm};
use serde_bytes::ByteBuf;
use sword::noun::{Atom, Noun, D, T};
use sword_macros::tas;
use tokio::sync::{mpsc, Mutex};
use tokio::task::{AbortHandle, JoinError, JoinSet};
use tracing::{debug, error, info, instrument, trace, warn};

use crate::metrics::NockchainP2PMetrics;
use crate::p2p::*;
use crate::p2p_util::{MessageTracker, PeerIdExt};
use crate::tip5_util::tip5_hash_to_base58;

//TODO This wire is a placeholder for now. The libp2p driver is entangled with the other types of nockchain pokes
//for historical reasons, and should be disentangled in the future.
pub enum NockchainWire {
    Local,
}

impl Wire for NockchainWire {
    const VERSION: u64 = 1;
    const SOURCE: &'static str = "nc";
}

pub enum Libp2pWire {
    Gossip(PeerId),
    Response(PeerId),
}

impl Libp2pWire {
    fn verb(&self) -> &'static str {
        match self {
            Libp2pWire::Gossip(_) => "gossip",
            Libp2pWire::Response(_) => "response",
        }
    }

    fn peer_id(&self) -> &PeerId {
        match self {
            Libp2pWire::Gossip(peer_id) => peer_id,
            Libp2pWire::Response(peer_id) => peer_id,
        }
    }
}

impl Wire for Libp2pWire {
    const VERSION: u64 = 1;
    const SOURCE: &'static str = "libp2p";

    fn to_wire(&self) -> WireRepr {
        let tags = vec![self.verb().into(), "peer-id".into(), self.peer_id().to_base58().into()];
        WireRepr::new(Libp2pWire::SOURCE, Libp2pWire::VERSION, tags)
    }
}

enum EffectType {
    Gossip,
    Request,
    LiarPeer,
    LiarBlockId,
    Track,
    Seen,
    Unknown,
}

impl EffectType {
    fn from_noun_slab(noun_slab: &NounSlab) -> Self {
        let Ok(effect_cell) = (unsafe { noun_slab.root().as_cell() }) else {
            return EffectType::Unknown;
        };

        let head = effect_cell.head();
        let Ok(atom) = head.as_atom() else {
            return EffectType::Unknown;
        };
        let bytes = atom
            .to_bytes_until_nul()
            .expect("failed to strip null bytes");

        match bytes.as_slice() {
            b"gossip" => EffectType::Gossip,
            b"request" => EffectType::Request,
            b"liar-peer" => EffectType::LiarPeer,
            b"liar-block-id" => EffectType::LiarBlockId,
            b"track" => EffectType::Track,
            b"seen" => EffectType::Seen,
            _ => EffectType::Unknown,
        }
    }
}

struct TrackedJoinSet<T> {
    inner: JoinSet<T>,
    tasks: HashMap<String, AbortHandle>,
}

impl<T: 'static> TrackedJoinSet<T> {
    fn new() -> Self {
        Self {
            inner: JoinSet::new(),
            tasks: HashMap::new(),
        }
    }

    fn spawn(&mut self, name: String, task: impl Future<Output = T> + Send + 'static)
    where
        T: Send + 'static,
    {
        let handle = self.inner.spawn(task);
        self.tasks.insert(name, handle);
    }

    async fn join_next(&mut self) -> Option<Result<T, JoinError>> {
        let result = self.inner.join_next().await;
        if result.is_some() {
            // Remove the completed task from our tracking
            self.tasks.retain(|_, v| !v.is_finished());
        }
        result
    }

    // Keep this around for debugging
    #[allow(dead_code)]
    fn get_running_tasks(&self) -> Vec<String> {
        self.tasks.keys().cloned().collect()
    }
}

#[derive(Debug, Clone)]
pub struct MiningKeyConfig {
    pub share: u64,
    pub m: u64,
    pub keys: Vec<String>,
}

impl FromStr for MiningKeyConfig {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Expected format: "share,m:key1,key2,key3"
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return Err("Invalid format. Expected 'share,m:key1,key2,key3'".to_string());
        }

        let share_m: Vec<&str> = parts[0].split(',').collect();
        if share_m.len() != 2 {
            return Err("Invalid share,m format".to_string());
        }

        let share = share_m[0].parse::<u64>().map_err(|e| e.to_string())?;
        let m = share_m[1].parse::<u64>().map_err(|e| e.to_string())?;
        let keys: Vec<String> = parts[1].split(',').map(String::from).collect();

        Ok(MiningKeyConfig { share, m, keys })
    }
}

#[instrument(skip(keypair, bind, allowed, limits, memory_limits, equix_builder))]
pub fn make_libp2p_driver(
    keypair: Keypair,
    bind: Vec<Multiaddr>,
    allowed: Option<allow_block_list::Behaviour<allow_block_list::AllowedPeers>>,
    limits: connection_limits::ConnectionLimits,
    memory_limits: Option<memory_connection_limits::Behaviour>,
    initial_peers: &[Multiaddr],
    equix_builder: equix::EquiXBuilder,
    mining_config: Option<Vec<MiningKeyConfig>>,
    init_complete_tx: Option<tokio::sync::oneshot::Sender<()>>,
) -> IODriverFn {
    let initial_peers = Vec::from(initial_peers);
    Box::new(|mut handle| {
        let metrics = NockchainP2PMetrics::register(gnort::global_metrics_registry())
            .expect("Failed to register metrics!");

        Box::pin(async move {
            let mut swarm = crate::p2p::start_swarm(keypair, bind, allowed, limits, memory_limits)
                .map_err(|e| {
                    warn!("Could not create swarm: {}", e);
                    NockAppError::OtherError
                })?;
            let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmAction>(1000); // number needs to be high enough to send gossips to peers
            let mut join_set = TrackedJoinSet::<Result<(), NockAppError>>::new();
            let message_tracker = Arc::new(Mutex::new(MessageTracker::new()));
            let mut kad_bootstrap = tokio::time::interval(KADEMLIA_BOOTSTRAP_INTERVAL);

            let mut initial_peer_retries_remaining = INITIAL_PEER_RETRIES;
            dial_initial_peers(&mut swarm, &initial_peers)?;

            if let Some(configs) = mining_config {
                if configs.len() == 1
                    && configs[0].share == 1
                    && configs[0].m == 1
                    && configs[0].keys.len() == 1
                {
                    // Simple case - use set_mining_key
                    set_mining_key(&handle, configs[0].keys[0].clone()).await?;
                } else {
                    // Advanced case - use set_mining_key_advanced
                    set_mining_key_advanced(&handle, configs).await?;
                }
                enable_mining(&handle, true).await?;
            } else {
                enable_mining(&handle, false).await?;
            }

            if let Some(tx) = init_complete_tx {
                let _ = tx.send(());
                debug!("libp2p driver initialization complete signal sent");
            }

            loop {
                tokio::select! {
                    Ok(noun_slab) = handle.next_effect() => {
                        let _span = tracing::trace_span!("broadcast").entered();
                        let swarm_tx_clone = swarm_tx.clone();
                        let equix_builder_clone = equix_builder.clone();
                        let local_peer_id = *swarm.local_peer_id();
                        let connected_peers: Vec<PeerId> = swarm.connected_peers().cloned().collect();
                        let message_tracker_clone = Arc::clone(&message_tracker); // Clone the Arc, not the MessageTracker
                        join_set.spawn("handle_effect".to_string(), async move {
                            handle_effect(noun_slab, swarm_tx_clone, equix_builder_clone, local_peer_id, connected_peers, message_tracker_clone).await
                        });
                    },
                    Some(event) = swarm.next() => {
                        match event {
                            SwarmEvent::NewListenAddr { address, .. } => {
                                info!("SEvent: Listening on {address:?}");
                            },
                            SwarmEvent::Behaviour(NockchainEvent::Identify(Received { connection_id: _, peer_id, info })) => {
                                trace!("SEvent: identify_received");
                                identify_received(&mut swarm, peer_id, info)?;
                            },
                            SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                                info!("SEvent: {peer_id} is new friend via: {endpoint:?}");
                            },
                            SwarmEvent::ConnectionClosed { peer_id, endpoint, cause, .. } => {
                                info!("SEvent: friendship ended with {peer_id} via: {endpoint:?}. cause: {cause:?}");
                                // Clean up the message tracker when a peer disconnects
                                let mut tracker = message_tracker.lock().await;
                                tracker.remove_peer(&peer_id);
                            },
                            SwarmEvent::IncomingConnectionError { local_addr, send_back_addr, error, .. } => {
                               error!("SEvent: Failed incoming connection from {} to {}: {}",
                               send_back_addr, local_addr, error);
                            },
                            SwarmEvent::Behaviour(NockchainEvent::RequestResponse(Message { connection_id: _, peer, message })) => {
                                trace!("SEvent: received RequestResponse");
                                let _span = tracing::debug_span!("SwarmEvent::Behavior(NockchainEvent::RequestResponse(…))").entered();
                                let swarm_tx_clone = swarm_tx.clone();
                                let mut equix_builder_clone = equix_builder.clone();
                                let local_peer_id = *swarm.local_peer_id();
                                // We have to dup and move a handle back into `handle` to propitiate the borrow checker
                                let (orig_handle, request_response_handle) = handle.dup();
                                handle = orig_handle;
                                let metrics = metrics.clone();
                                let message_tracker_clone = Arc::clone(&message_tracker); // Clone the Arc, not the MessageTracker
                                join_set.spawn("handle_request_response".to_string(), async move {
                                    handle_request_response(peer, message, swarm_tx_clone, &mut equix_builder_clone, local_peer_id, request_response_handle, metrics, message_tracker_clone).await
                                });
                            },
                            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                                error!("Failed outgoing connection to {:?}: {}", peer_id, error);
                            },
                            SwarmEvent::IncomingConnection {
                                local_addr,
                                send_back_addr,
                                connection_id,
                                ..
                            } => {
                                debug!("SEvent: Incoming connection from {local_addr:?} to {send_back_addr:?} with {connection_id:?}");
                            },
                            SwarmEvent::Dialing { peer_id, connection_id } => {
                                debug!("SEvent: Dialing {peer_id:?} {connection_id}");
                            },
                            _ => {
                                // Handle other swarm events
                                trace!("SEvent: other swarm event {:?}", event);
                            }
                        }
                    },
                    Some(swarm_action) = swarm_rx.recv() => {
                        // We do this because Swarm doesn't implement Send, and so we can't pass it into the tasks
                        // being spawned in the match cases above.
                        match swarm_action {
                            SwarmAction::SendRequest { peer_id, request } => {
                                trace!("SAction: SendRequest: {peer_id}");
                                let _ = swarm.behaviour_mut().request_response.send_request(&peer_id, request);
                            },
                            SwarmAction::SendResponse { channel, response } => {
                                trace!("SAction: SendResponse");
                                let _ = swarm.behaviour_mut().request_response.send_response(channel, response);
                            },
                            SwarmAction::BlockPeer { peer_id } => {
                                warn!("SAction: Blocking peer {peer_id}");
                                swarm.behaviour_mut().allow_block_list.block_peer(peer_id);
                                // Disconnect the peer if they're currently connected
                                let _ = swarm.disconnect_peer_id(peer_id);
                            },
                        }
                    },
                    _ = kad_bootstrap.tick() => {
                        // If we don't have any peers, we should retry dialing our initial peers
                        if let Err(NoKnownPeers())= swarm.behaviour_mut().kad.bootstrap() {
                            if initial_peer_retries_remaining > 0 {
                                info!("Failed to bootstrap: {}", NoKnownPeers());
                                initial_peer_retries_remaining -= 1;
                                dial_initial_peers(&mut swarm, &initial_peers)?;
                            } else {
                                warn!("Failed to bootstrap after {} retries, will not attempt to redial initial peers.", INITIAL_PEER_RETRIES);
                            }
                        }
                    },
                    Some(result) = join_set.join_next() => {
                        if let Err(e) = result {
                            error!("Task error: {:?}", e);
                        }
                    },
                }
            }
        })
    })
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
/// Network struct (in serde/CBOR) for requests
pub enum NockchainRequest {
    /// Request a block or TX from another node, carry PoW
    Request {
        pow: equix::SolutionByteArray,
        nonce: u64,
        message: ByteBuf,
    },
    /// Gossip a block or TX to another node
    Gossip { message: ByteBuf },
}

impl NockchainRequest {
    /// Make a new "request" which gossips a block or a TX
    fn new_gossip(message: &NounSlab) -> NockchainRequest {
        let message_bytes = ByteBuf::from(message.jam().as_ref());
        NockchainRequest::Gossip {
            message: message_bytes,
        }
    }

    /// Make a new request for a block or a TX
    fn new_request(
        builder: &mut equix::EquiXBuilder,
        local_peer_id: &libp2p::PeerId,
        remote_peer_id: &libp2p::PeerId,
        message: &NounSlab,
    ) -> NockchainRequest {
        let message_bytes = ByteBuf::from(message.jam().as_ref());
        let local_peer_bytes = (*local_peer_id).to_bytes();
        let remote_peer_bytes = (*remote_peer_id).to_bytes();
        let mut pow_buf = Vec::with_capacity(
            size_of::<u64>()
                + local_peer_bytes.len()
                + remote_peer_bytes.len()
                + message_bytes.len(),
        );
        pow_buf.extend_from_slice(&[0; size_of::<u64>()][..]);
        pow_buf.extend_from_slice(&local_peer_bytes[..]);
        pow_buf.extend_from_slice(&remote_peer_bytes[..]);
        pow_buf.extend_from_slice(&message_bytes[..]);

        let mut nonce = 0u64;
        let sol_bytes = loop {
            {
                let nonce_buf = &mut pow_buf[0..size_of::<u64>()];
                nonce_buf.copy_from_slice(&nonce.to_le_bytes()[..]);
            }
            if let Ok(sols) = builder.solve(&pow_buf[..]) {
                if !sols.is_empty() {
                    break sols[0].to_bytes();
                }
            }
            nonce += 1;
        };

        NockchainRequest::Request {
            pow: sol_bytes,
            nonce,
            message: message_bytes,
        }
    }

    /// Verify the EquiX PoW attached to a request
    fn verify_pow(
        &self,
        builder: &mut equix::EquiXBuilder,
        local_peer_id: &libp2p::PeerId,
        remote_peer_id: &libp2p::PeerId,
    ) -> Result<(), equix::Error> {
        match self {
            NockchainRequest::Request {
                pow,
                nonce,
                message,
            } => {
                //  This looks backwards, but it's because which node is local and which is remote
                //  is swapped between generation at the sender and verification at the receiver.
                let local_peer_bytes = (*remote_peer_id).to_bytes();
                let remote_peer_bytes = (*local_peer_id).to_bytes();
                let nonce_bytes = nonce.to_le_bytes();
                let mut pow_buf = Vec::with_capacity(
                    size_of::<u64>()
                        + local_peer_bytes.len()
                        + remote_peer_bytes.len()
                        + message.len(),
                );
                pow_buf.extend_from_slice(&nonce_bytes[..]);
                pow_buf.extend_from_slice(&local_peer_bytes[..]);
                pow_buf.extend_from_slice(&remote_peer_bytes[..]);
                pow_buf.extend_from_slice(&message[..]);
                builder.verify_bytes(&pow_buf[..], pow)
            }
            NockchainRequest::Gossip { message: _ } => Ok(()),
        }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
/// Responses to Nockchain requests
pub enum NockchainResponse {
    /// The requested block or raw-tx
    Result { message: ByteBuf },
    /// If the request was a gossip, no actual response is needed
    Ack,
}

impl NockchainResponse {
    fn new_response_result(message: impl AsRef<[u8]>) -> NockchainResponse {
        let message_bytes: &[u8] = message.as_ref();
        let message_bytebuf = ByteBuf::from(message_bytes.to_vec());
        NockchainResponse::Result {
            message: message_bytebuf,
        }
    }
}

#[instrument(skip(handle, pubkey))]
async fn set_mining_key(
    handle: &NockAppHandle,
    pubkey: String,
) -> Result<PokeResult, NockAppError> {
    let mut set_mining_key_slab = NounSlab::new();
    let set_mining_key = Atom::from_value(&mut set_mining_key_slab, "set-mining-key")
        .expect("Failed to create set-mining-key atom");
    let pubkey_cord =
        Atom::from_value(&mut set_mining_key_slab, pubkey).expect("Failed to create pubkey atom");
    let set_mining_key_poke = T(
        &mut set_mining_key_slab,
        &[D(tas!(b"command")), set_mining_key.as_noun(), pubkey_cord.as_noun()],
    );
    set_mining_key_slab.set_root(set_mining_key_poke);

    let wire = NockchainWire::Local;
    handle.poke(wire.to_wire(), set_mining_key_slab).await
}

async fn set_mining_key_advanced(
    handle: &NockAppHandle,
    configs: Vec<MiningKeyConfig>,
) -> Result<PokeResult, NockAppError> {
    let mut set_mining_key_slab = NounSlab::new();
    let set_mining_key_adv = Atom::from_value(&mut set_mining_key_slab, "set-mining-key-advanced")
        .expect("Failed to create set-mining-key-advanced atom");

    // Create the list of configs
    let mut config_list = Vec::new();
    for config in configs {
        // Create the list of keys
        let mut key_list = Vec::new();
        for key in config.keys {
            let key_atom =
                Atom::from_value(&mut set_mining_key_slab, key).expect("Failed to create key atom");
            key_list.push(key_atom.as_noun());
        }
        let keys_cell = T(&mut set_mining_key_slab, &key_list);

        // Create the config tuple [share m keys]
        let config_tuple = T(
            &mut set_mining_key_slab,
            &[D(config.share), D(config.m), keys_cell],
        );
        config_list.push(config_tuple);
    }
    let configs_cell = T(&mut set_mining_key_slab, &config_list);

    let set_mining_key_poke = T(
        &mut set_mining_key_slab,
        &[D(tas!(b"command")), set_mining_key_adv.as_noun(), configs_cell],
    );
    set_mining_key_slab.set_root(set_mining_key_poke);

    let wire = NockchainWire::Local;
    handle.poke(wire.to_wire(), set_mining_key_slab).await
}

//TODO add %set-mining-key-multisig poke
#[instrument(skip(handle))]
async fn enable_mining(handle: &NockAppHandle, enable: bool) -> Result<PokeResult, NockAppError> {
    let mut enable_mining_slab = NounSlab::new();
    let enable_mining = Atom::from_value(&mut enable_mining_slab, "enable-mining")
        .expect("Failed to create enable-mining atom");
    let enable_mining_poke = T(
        &mut enable_mining_slab,
        &[D(tas!(b"command")), enable_mining.as_noun(), D(if enable { 0 } else { 1 })],
    );
    enable_mining_slab.set_root(enable_mining_poke);
    let wire = NockchainWire::Local;
    handle.poke(wire.to_wire(), enable_mining_slab).await
}

async fn handle_effect(
    noun_slab: NounSlab,
    swarm_tx: mpsc::Sender<SwarmAction>,
    equix_builder: equix::EquiXBuilder,
    local_peer_id: PeerId,
    connected_peers: Vec<PeerId>,
    message_tracker: Arc<Mutex<MessageTracker>>,
) -> Result<(), NockAppError> {
    match EffectType::from_noun_slab(&noun_slab) {
        EffectType::Gossip => {
            // remove the %gossip head
            let mut tail_slab = NounSlab::new();
            tail_slab.copy_into(unsafe { noun_slab.root().as_cell()?.tail() });

            // Check if this is a heard-block gossip
            let gossip_noun = unsafe { tail_slab.root() };
            if let Ok(cell) = gossip_noun.as_cell() {
                if cell.head().eq_bytes(b"heard-block") {
                    trace!("Gossip effect for heard-block, clearing block cache");
                    let mut tracker = message_tracker.lock().await;
                    tracker.block_cache.clear();
                }
            }

            let gossip_request = NockchainRequest::new_gossip(&tail_slab);
            for peer_id in connected_peers.clone() {
                let gossip_request_clone = gossip_request.clone();
                swarm_tx
                    .send(SwarmAction::SendRequest {
                        peer_id,
                        request: gossip_request_clone,
                    })
                    .await
                    .map_err(|_e| NockAppError::OtherError)?;
            }
        }
        EffectType::Request => {
            // Extract request details to check if it's a peer-specific request
            let request_cell = unsafe { noun_slab.root().as_cell()? };
            let request_body = request_cell.tail().as_cell()?;
            let request_type = request_body.head().as_direct()?;

            let target_peers = if request_type.data() == tas!(b"block") {
                let block_cell = request_body.tail().as_cell()?;
                if block_cell.head().eq_bytes(b"elders") {
                    // Extract peer ID from elders request
                    let elders_cell = block_cell.tail().as_cell()?;
                    let peer_id_atom = elders_cell.tail().as_atom()?;
                    if let Ok(bytes) = peer_id_atom.to_bytes_until_nul() {
                        if let Ok(peer_id) = PeerId::from_bytes(&bytes) {
                            vec![peer_id]
                        } else {
                            connected_peers.clone()
                        }
                    } else {
                        connected_peers.clone()
                    }
                } else {
                    connected_peers.clone()
                }
            } else {
                connected_peers.clone()
            };

            for peer_id in target_peers {
                let local_peer_id_clone = local_peer_id;
                let mut equix_builder_clone = equix_builder.clone();
                let request = NockchainRequest::new_request(
                    &mut equix_builder_clone, &local_peer_id_clone, &peer_id, &noun_slab,
                );
                swarm_tx
                    .send(SwarmAction::SendRequest { peer_id, request })
                    .await
                    .map_err(|_e| NockAppError::OtherError)?;
            }
        }
        EffectType::LiarPeer => {
            let effect_cell = unsafe { noun_slab.root().as_cell()? };
            let peer_id_atom = effect_cell.tail().as_atom().map_err(|_| {
                NockAppError::IoError(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Expected peer ID atom in liar-peer effect",
                ))
            })?;

            let bytes = peer_id_atom
                .to_bytes_until_nul()
                .expect("failed to strip null bytes");
            let peer_id_str = String::from_utf8(bytes).map_err(|_| {
                NockAppError::IoError(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Invalid UTF-8 in peer ID",
                ))
            })?;

            let peer_id = PeerId::from_str(&peer_id_str).map_err(|_| {
                NockAppError::IoError(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Invalid peer ID format",
                ))
            })?;

            swarm_tx
                .send(SwarmAction::BlockPeer { peer_id })
                .await
                .map_err(|_| NockAppError::OtherError)?;
        }
        EffectType::LiarBlockId => {
            let effect_cell = unsafe { noun_slab.root().as_cell()? };
            let block_id = effect_cell.tail();

            //add the bad block ID
            let mut tracker = message_tracker.lock().await;
            let peers_to_ban = tracker.process_bad_block_id(block_id)?;

            // Ban each peer that sent this block
            for peer_id in peers_to_ban {
                swarm_tx
                    .send(SwarmAction::BlockPeer { peer_id })
                    .await
                    .map_err(|_| NockAppError::OtherError)?;
            }
        }
        EffectType::Track => {
            let effect_cell = unsafe { noun_slab.root().as_cell()? };
            let track_cell = effect_cell.tail().as_cell()?;
            let action = track_cell.head();

            if action.eq_bytes(b"add") {
                // Handle [%track %add block-id peer-id]
                let data_cell = track_cell.tail().as_cell()?;
                let block_id = data_cell.head();
                let peer_id_atom = data_cell.tail().as_atom()?;

                // Convert peer_id from base58 string to PeerId
                let Ok(peer_id) = PeerId::from_noun(peer_id_atom.as_noun()) else {
                    return Err(NockAppError::OtherError);
                };

                // Add to message tracker
                let mut tracker = message_tracker.lock().await;
                tracker.track_block_id_and_peer(block_id, peer_id)?;
            } else if action.eq_bytes(b"remove") {
                // Handle [%track %remove block-id]
                let block_id = track_cell.tail();

                // Remove from message tracker
                let mut tracker = message_tracker.lock().await;
                tracker.remove_block_id(block_id)?;
            } else {
                return Err(NockAppError::IoError(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Invalid track action",
                )));
            }
        }
        EffectType::Seen => {
            let effect_cell = unsafe { noun_slab.root().as_cell()? };
            let seen_cell = effect_cell.tail().as_cell()?;
            let seen_type = seen_cell.head();

            if seen_type.eq_bytes(b"block") {
                let block_id = seen_cell.tail().as_cell()?;
                let mut tracker = message_tracker.lock().await;
                let block_id_str = tip5_hash_to_base58(block_id.as_noun())
                    .expect("failed to convert block ID to base58");
                debug!("seen block id: {:?}", &block_id_str);
                tracker.seen_blocks.insert(block_id_str);
            } else if seen_type.eq_bytes(b"tx") {
                let tx_id = seen_cell.tail().as_cell()?;
                let mut tracker = message_tracker.lock().await;
                let tx_id_str = tip5_hash_to_base58(tx_id.as_noun())
                    .expect("failed to convert tx ID to base58");
                tracker.seen_txs.insert(tx_id_str);
            }
        }
        EffectType::Unknown => {
            //  This isn't unexpected - any effect that this driver doesn't handle
            //  will hit this case.
        }
    }
    Ok(())
}

// TODO: Wrap some of this up.
#[allow(clippy::too_many_arguments)]
async fn handle_request_response(
    peer: PeerId,
    message: request_response::Message<NockchainRequest, NockchainResponse>,
    swarm_tx: mpsc::Sender<SwarmAction>,
    equix_builder: &mut equix::EquiXBuilder,
    local_peer_id: PeerId,
    nockapp: NockAppHandle,
    metrics: NockchainP2PMetrics,
    message_tracker: Arc<Mutex<MessageTracker>>,
) -> Result<(), NockAppError> {
    trace!("handle_request_response peer: {peer}");
    match message {
        Request {
            request, channel, ..
        } => {
            let Ok(()) = request.verify_pow(equix_builder, &local_peer_id, &peer) else {
                warn!("bad libp2p powork from {peer}, blocking!");
                swarm_tx
                    .send(SwarmAction::BlockPeer { peer_id: peer })
                    .await
                    .map_err(|_| NockAppError::OtherError)?;
                return Ok(());
            };
            trace!("handle_request_response: powork verified");
            let mut request_slab = NounSlab::new();
            match request {
                NockchainRequest::Request {
                    pow: _,
                    nonce: _,
                    message,
                } => {
                    trace!("handle_request_response: Request received");
                    let message_bytes = Bytes::from(message.to_vec());
                    let request_noun = request_slab.cue_into(message_bytes)?;
                    let (scry_res_slab, cache_hit) = if let Ok(Some(cache_result)) = {
                        let mut tracker = message_tracker.lock().await;
                        tracker.check_cache(&request_noun, &metrics).await
                    } {
                        debug!("found cached response for request");
                        (cache_result, true)
                    } else {
                        let scry_slab = request_to_scry_slab(&request_noun)?;
                        let Some(scry_res_slab) = (match nockapp.try_peek(scry_slab).await {
                            Ok(Some(res_slab)) => {
                                metrics.requests_peeked_some.increment();
                                Some(res_slab)
                            }
                            Ok(None) => {
                                metrics.requests_peeked_none.increment();
                                trace!(
                                "No data found for incoming request from: {}, request type: {:?}",
                                peer,
                                request_noun.as_cell()?.tail().as_cell().map(|c| c.head())
                            );
                                None
                            }
                            Err(NockAppError::MPSCFullError(act)) => {
                                metrics.requests_dropped.increment();
                                trace!(
                                    "handle_request_response: Request dropped due to backpressure"
                                );
                                Err(NockAppError::MPSCFullError(act))?
                            }
                            Err(err) => {
                                metrics.requests_erred.increment();
                                trace!("handle_request_response: Error getting response");
                                Err(err)?
                            }
                        }) else {
                            return Ok(());
                        };
                        (scry_res_slab, false)
                    };

                    let Ok(request_cell) = request_noun.as_cell() else {
                        error!("request noun not a cell");
                        return Err(NockAppError::OtherError);
                    };
                    let Ok(scry_tag) = request_cell.tail().as_cell()?.head().as_direct() else {
                        error!("request tag axis not an atom");
                        return Err(NockAppError::OtherError);
                    };
                    trace!("handle_request_response: request cell parsed");
                    let mut res_slab = NounSlab::new();
                    let response = match scry_tag.data() {
                        tas!(b"block") => {
                            trace!("handle_request_response: block tag");
                            let scry_res = unsafe { scry_res_slab.root() };

                            // Extract the request type from under %block
                            let request_type = request_cell
                                .tail()
                                .as_cell()
                                .and_then(|c| c.tail().as_cell())
                                .map(|c| c.head().eq_bytes(b"elders"))
                                .map_err(|_| {
                                    NockAppError::IoError(std::io::Error::new(
                                        std::io::ErrorKind::Other,
                                        "invalid block request structure",
                                    ))
                                })?;

                            // Use heard-elders for elders requests, heard-block otherwise
                            let heard_type = if request_type {
                                "heard-elders"
                            } else {
                                "heard-block"
                            };

                            match create_scry_response(scry_res, heard_type, &mut res_slab) {
                                Left(()) => {
                                    trace!(
                                        "No data found for incoming block request, type: {}",
                                        heard_type
                                    );
                                    return Ok(());
                                }
                                Right(result) => {
                                    // cache response
                                    if !cache_hit && heard_type == "heard-block" {
                                        let height = request_cell
                                            .tail()
                                            .as_cell()?
                                            .tail()
                                            .as_cell()?
                                            .tail()
                                            .as_direct()?
                                            .data();
                                        let mut tracker = message_tracker.lock().await;
                                        tracker.block_cache.insert(height, scry_res_slab.clone());
                                        debug!("cacheing block request by height={:?}", height);
                                    }
                                    result?
                                }
                            }
                        }
                        tas!(b"raw-tx") => {
                            trace!("handle_request_response: raw-tx tag");
                            let scry_res = unsafe { scry_res_slab.root() };
                            match create_scry_response(scry_res, "heard-tx", &mut res_slab) {
                                Left(()) => {
                                    trace!("No data found for incoming raw-tx request");
                                    return Ok(());
                                }
                                Right(result) => {
                                    if !cache_hit {
                                        let tx_id = request_cell.tail().as_cell()?.tail();
                                        let tx_id_str = tip5_hash_to_base58(tx_id)?;
                                        let mut tracker = message_tracker.lock().await;
                                        debug!("cacheing tx request by id={:?}", tx_id_str);
                                        tracker.tx_cache.insert(tx_id_str, scry_res_slab.clone());
                                    }
                                    result?
                                }
                            }
                        }
                        tag => {
                            error!("Unknown request tag: {:?}", tag);
                            return Err(NockAppError::OtherError);
                        }
                    };
                    swarm_tx
                        .send(SwarmAction::SendResponse { channel, response })
                        .await
                        .map_err(|_| NockAppError::OtherError)?;
                }
                NockchainRequest::Gossip { message } => {
                    trace!("handle_request_response: Gossip received");
                    let message_bytes = Bytes::from(message.to_vec());
                    let request_noun = request_slab.cue_into(message_bytes)?;
                    trace!("handle_request_response: Gossip noun parsed");

                    let send_response: tokio::task::JoinHandle<Result<(), NockAppError>> =
                        tokio::spawn(async move {
                            let response = NockchainResponse::Ack;
                            swarm_tx
                                .send(SwarmAction::SendResponse { channel, response })
                                .await
                                .map_err(|_| NockAppError::OtherError)?;
                            Ok(())
                        });

                    let poke_kernel = tokio::task::spawn(async move {
                        let head = request_noun.as_cell()?.head();
                        if head.eq_bytes(b"heard-block") {
                            let page = request_noun.as_cell()?.tail();
                            let block_id = page.as_cell()?.head();
                            let block_id_str = tip5_hash_to_base58(block_id)?;
                            let tracker = message_tracker.lock().await;
                            if tracker.seen_blocks.contains(&block_id_str) {
                                debug!("Block already seen, not processing: {:?}", block_id_str);
                                metrics.block_seen_cache_hits.increment();
                                return Ok(());
                            } else {
                                debug!("block not seen, processing: {:?}", block_id_str);
                                metrics.block_seen_cache_misses.increment();
                            }
                        }

                        if head.eq_bytes(b"heard-tx") {
                            let raw_tx = request_noun.as_cell()?.tail();
                            let tx_id = raw_tx.as_cell()?.head();
                            let tracker = message_tracker.lock().await;
                            let tx_id_str = tip5_hash_to_base58(tx_id)?;
                            if tracker.seen_txs.contains(&tx_id_str) {
                                debug!("Tx already seen, not processing: {:?}", tx_id_str);
                                metrics.tx_seen_cache_hits.increment();
                                return Ok(());
                            } else {
                                debug!("tx not seen, processing: {:?}", tx_id_str);
                                metrics.tx_seen_cache_misses.increment();
                            }
                        }

                        let request_fact = prepend_tas(&mut request_slab, "fact", request_noun)?;
                        request_slab.set_root(request_fact);
                        let wire = Libp2pWire::Gossip(peer);

                        match nockapp.try_poke(wire.to_wire(), request_slab).await {
                            Ok(PokeResult::Ack) => {
                                metrics.gossip_acked.increment();
                            }
                            Ok(PokeResult::Nack) => {
                                metrics.gossip_nacked.increment();
                                trace!("handle_request_response: gossip poke nacked");
                                return Ok(());
                            }
                            Err(NockAppError::MPSCFullError(act)) => {
                                metrics.gossip_dropped.increment();
                                trace!(
                                "handle_request_response: gossip poke dropped due to backpressure"
                            );
                                return Err(NockAppError::MPSCFullError(act));
                            }
                            Err(err) => {
                                metrics.gossip_erred.increment();
                                trace!("handle_request_response: Poke errored");
                                return Err(err);
                            }
                        };
                        trace!("handle_request_response: Poke successful");
                        Ok(())
                    });
                    send_response.await??;
                    poke_kernel.await??;
                }
            }
        }
        Response { response, .. } => match response {
            NockchainResponse::Result { message } => {
                trace!("handle_request_response: Response result received");
                let mut response_slab = NounSlab::new();
                let message_bytes = Bytes::from(message.to_vec());
                let response_noun = response_slab.cue_into(message_bytes)?;
                trace!("Received response from peer");

                let response_fact = prepend_tas(&mut response_slab, "fact", response_noun)?;
                response_slab.set_root(response_fact);
                let wire = Libp2pWire::Response(peer);

                match nockapp.try_poke(wire.to_wire(), response_slab).await {
                    Ok(PokeResult::Ack) => {
                        metrics.responses_acked.increment();
                    }
                    Ok(PokeResult::Nack) => {
                        metrics.responses_nacked.increment();
                        trace!("handle_request_response: Poke failed");
                        return Ok(());
                    }
                    Err(NockAppError::MPSCFullError(act)) => {
                        trace!("handle_request_response: Response dropped due to backpressure.");
                        metrics.responses_dropped.increment();
                        return Err(NockAppError::MPSCFullError(act));
                    }
                    Err(_) => {
                        trace!("handle_request_response: Error poking with response");
                        metrics.responses_erred.increment();
                        trace!("Error sending poke")
                    }
                }
                trace!("handle_request_response: Poke successful");
            }
            NockchainResponse::Ack => {
                trace!("Received acknowledgement from peer {}", peer);
            }
        },
    }
    Ok(())
}

/// Converts a request noun into a scry path that can be used to query the Nockchain state.
///
/// The request noun is expected to be in the format:
/// `[%request [type data]]` where:
/// - `type` can be either "block" or "raw-tx"
/// - For "block" type:
///   - `data` can be either `[%by-height height]` or `[%elders block-id peer-id]`
/// - For "raw-tx" type:
///   - `data` must be `[%by-id id]`
///
/// # Arguments
/// * `noun` - The request noun to convert
///
/// # Returns
/// * `Ok(NounSlab)` - A noun slab containing the constructed scry path
/// * `Err(NockAppError)` - If the request format is invalid or unknown
///
/// # Examples
/// For a block by height request:
/// [%request [%block [%by-height 123]]] -> [%heavy-n 123 0]
/// For a block by id request:
/// [%request [%block [%elders [1 2 3 4 5] abcDEF]]] -> [%elders base58-block-id peer-id 0]
/// For a raw transaction request:
/// [%request [%raw-tx [%by-id [1 2 3 4 5]]]] -> [%raw-transaction base58-tx-id 0]
fn request_to_scry_slab(noun: &Noun) -> Result<NounSlab, NockAppError> {
    let Ok(request) = noun.as_cell() else {
        return Err(NockAppError::IoError(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Unknown request - not a cell",
        )));
    };

    let Ok(tag) = request.head().as_direct() else {
        return Err(NockAppError::IoError(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Unknown request - not a direct",
        )));
    };

    if tag.data() != tas!(b"request") {
        return Err(NockAppError::IoError(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Unknown request - not a request",
        )));
    }

    let mut scry_path_slab = NounSlab::new();
    let request_body = request.tail().as_cell()?;

    if request_body.head().eq_bytes(b"block") {
        let Ok(tail_cell) = request_body.tail().as_cell() else {
            return Err(NockAppError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Invalid block request",
            )));
        };

        if tail_cell.head().eq_bytes(b"by-height") && tail_cell.tail().is_atom() {
            let pax = T(
                &mut scry_path_slab,
                &[D(tas!(b"heavy-n")), tail_cell.tail(), D(0)],
            );
            scry_path_slab.set_root(pax);
            info!(
                "block by-height: {:?}",
                sword::noun::DebugPath(&pax.as_cell()?)
            );
            return Ok(scry_path_slab);
        } else if tail_cell.head().eq_bytes(b"elders") {
            let Ok(elders_cell) = tail_cell.tail().as_cell() else {
                return Err(NockAppError::IoError(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Invalid elders request",
                )));
            };

            let block_id_b58 = tip5_hash_to_base58(elders_cell.head())?;
            let block_id_atom =
                Atom::from_value(&mut scry_path_slab, block_id_b58).unwrap_or_else(|_| {
                    panic!(
                        "Called `expect()` at {}:{} (git sha: {})",
                        file!(),
                        line!(),
                        option_env!("GIT_SHA").unwrap_or("unknown")
                    )
                });
            let peer_id = elders_cell.tail();

            let pax = T(
                &mut scry_path_slab,
                &[D(tas!(b"elders")), block_id_atom.as_noun(), peer_id, D(0)],
            );
            info!(
                "block elders: {:?}",
                sword::noun::DebugPath(&pax.as_cell()?)
            );
            scry_path_slab.set_root(pax);
            return Ok(scry_path_slab);
        }
    } else if request_body.head().eq_bytes(b"raw-tx") {
        let Ok(tail_cell) = request_body.tail().as_cell() else {
            return Err(NockAppError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Invalid raw-tx request",
            )));
        };

        if tail_cell.head().eq_bytes(b"by-id") {
            let tx_id_b58 = tip5_hash_to_base58(tail_cell.tail())?;
            let tx_id_atom =
                Atom::from_value(&mut scry_path_slab, tx_id_b58).unwrap_or_else(|_| {
                    panic!(
                        "Called `expect()` at {}:{} (git sha: {})",
                        file!(),
                        line!(),
                        option_env!("GIT_SHA").unwrap_or("unknown")
                    )
                });
            let raw_tx_tag = make_tas(&mut scry_path_slab, "raw-transaction").as_noun();
            let pax = T(
                &mut scry_path_slab,
                &[raw_tx_tag, tx_id_atom.as_noun(), D(0)],
            );
            info!("tx by-id: {:?}", sword::noun::DebugPath(&pax.as_cell()?));
            scry_path_slab.set_root(pax);
            return Ok(scry_path_slab);
        }
    }

    // log the head of the request body
    Err(NockAppError::IoError(std::io::Error::new(
        std::io::ErrorKind::Other,
        format!("Unknown request - {:?}", request_body.head()),
    )))
}

/// Creates a response to a scry request by processing the scry result noun
///
/// # Arguments
/// * `scry_res` - The noun containing the scry result to process
/// * `heard_type` - The type of request that was heard (as a string)
/// * `res_slab` - Mutable reference to the noun slab for storing the response
///
/// # Returns
/// Either:
/// - `Left(())` if the scry path was bad or nothing was found
/// - `Right(Ok(NockchainResponse))` containing the successful response
/// - `Right(Err(NockAppError))` if there was an error processing the result
fn create_scry_response(
    scry_res: &Noun,
    heard_type: &str,
    res_slab: &mut NounSlab,
) -> Either<(), Result<NockchainResponse, NockAppError>> {
    match ScryResult::from(scry_res) {
        ScryResult::BadPath => {
            warn!("Bad scry path");
            Left(())
        }
        ScryResult::Nothing => {
            trace!("Nothing found at scry path");
            Left(())
        }
        ScryResult::Some(x) => {
            if let Ok(response_noun) = prepend_tas(res_slab, heard_type, x) {
                res_slab.set_root(response_noun);
                Right(Ok(NockchainResponse::new_response_result(res_slab.jam())))
            } else {
                error!("Failed to prepend tas to response noun");
                Right(Err(NockAppError::OtherError))
            }
        }
        ScryResult::Invalid => {
            error!("Invalid scry result");
            Right(Err(NockAppError::OtherError))
        }
    }
}

/// Prepends a @tas to a Noun.
///
/// # Arguments
/// * `slab` - The NounSlab containing the noun
/// * `noun` - The Noun to prepend @tas to
///
/// # Returns
/// The noun with @tas prepended
fn prepend_tas(slab: &mut NounSlab, tas_str: &str, noun: Noun) -> Result<Noun, NockAppError> {
    let tas_atom = Atom::from_value(slab, tas_str)?;
    Ok(T(slab, &[tas_atom.as_noun(), noun]))
}

#[cfg(test)]
mod tests {
    use crown::noun::slab::NounSlab;
    use sword::noun::{D, T};
    use sword_macros::tas;

    use super::*;

    #[test]
    #[cfg_attr(miri, ignore)] // ibig has a memory leak so miri fails this test
    fn test_request_to_scry_slab() {
        // Test block by-height request
        {
            let mut slab = NounSlab::new();
            let height = 123u64;
            let by_height_tas = make_tas(&mut slab, "by-height");
            let by_height = T(&mut slab, &[by_height_tas.as_noun(), D(height)]);
            let block_cell = T(&mut slab, &[D(tas!(b"block")), by_height]);
            let request = T(&mut slab, &[D(tas!(b"request")), block_cell]);
            slab.set_root(request);

            let result_slab = request_to_scry_slab(unsafe { slab.root() }).unwrap_or_else(|_| {
                panic!(
                    "Called `expect()` at {}:{} (git sha: {})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA").unwrap_or("unknown")
                )
            });
            let result = unsafe { result_slab.root() };

            assert!(result.is_cell());
            let result_cell = result.as_cell().unwrap_or_else(|_| {
                panic!(
                    "Called `expect()` at {}:{} (git sha: {})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA").unwrap_or("unknown")
                )
            });
            assert!(result_cell.head().eq_bytes(b"heavy-n"));

            // Get the tail cell and check its components
            let tail_cell = result_cell.tail().as_cell().unwrap_or_else(|_| {
                panic!(
                    "Called `expect()` at {}:{} (git sha: {})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA").unwrap_or("unknown")
                )
            });
            let height_atom = tail_cell.head().as_atom().unwrap_or_else(|_| {
                panic!(
                    "Called `expect()` at {}:{} (git sha: {})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA").unwrap_or("unknown")
                )
            });
            assert_eq!(
                height_atom.as_u64().unwrap_or_else(|err| {
                    panic!(
                        "Panicked with {err:?} at {}:{} (git sha: {:?})",
                        file!(),
                        line!(),
                        option_env!("GIT_SHA")
                    )
                }),
                height
            );
            let tail_atom = tail_cell.tail().as_atom().unwrap_or_else(|_| {
                panic!(
                    "Called `expect()` at {}:{} (git sha: {})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA").unwrap_or("unknown")
                )
            });
            assert_eq!(
                tail_atom.as_u64().unwrap_or_else(|err| {
                    panic!(
                        "Panicked with {err:?} at {}:{} (git sha: {:?})",
                        file!(),
                        line!(),
                        option_env!("GIT_SHA")
                    )
                }),
                0
            );
        }

        // Test invalid request (not a cell)
        {
            let mut slab = NounSlab::new();
            slab.set_root(D(123));
            let result = request_to_scry_slab(unsafe { slab.root() });
            assert!(result.is_err());
        }

        // Test elders request
        {
            let mut slab = NounSlab::new();
            // Create a 5-tuple [1 2 3 4 5] for the block ID
            let five_tuple = T(&mut slab, &[D(1), D(2), D(3), D(4), D(5)]);

            // Create a random peer ID and store its bytes
            let peer_id = PeerId::random();
            let peer_id_atom =
                Atom::from_value(&mut slab, peer_id.to_base58()).unwrap_or_else(|_| {
                    panic!(
                        "Called `expect()` at {}:{} (git sha: {})",
                        file!(),
                        line!(),
                        option_env!("GIT_SHA").unwrap_or("unknown")
                    )
                });

            let elders_cell = T(&mut slab, &[five_tuple, peer_id_atom.as_noun()]);
            let elders_tas = D(tas!(b"elders"));
            let inner_cell = T(&mut slab, &[elders_tas, elders_cell]);
            let block_cell = T(&mut slab, &[D(tas!(b"block")), inner_cell]);
            let request = T(&mut slab, &[D(tas!(b"request")), block_cell]);
            slab.set_root(request);

            let result_slab = request_to_scry_slab(unsafe { slab.root() }).unwrap_or_else(|_| {
                panic!(
                    "Called `expect()` at {}:{} (git sha: {})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA").unwrap_or("unknown")
                )
            });
            let result = unsafe { result_slab.root() };

            // Verify the structure: [%elders block_id_b58 peer_id 0]
            assert!(result.is_cell());
            let result_cell = result.as_cell().unwrap_or_else(|_| {
                panic!(
                    "Called `expect()` at {}:{} (git sha: {})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA").unwrap_or("unknown")
                )
            });

            // Check %elders tag
            assert!(result_cell.head().eq_bytes(b"elders"));

            // Get the tail cell
            let tail_cell = result_cell.tail().as_cell().unwrap_or_else(|_| {
                panic!(
                    "Called `expect()` at {}:{} (git sha: {})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA").unwrap_or("unknown")
                )
            });

            // Check block ID (should be base58 encoded)
            let block_id_atom = tail_cell.head().as_atom().unwrap_or_else(|_| {
                panic!(
                    "Called `expect()` at {}:{} (git sha: {})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA").unwrap_or("unknown")
                )
            });
            let block_id_bytes = block_id_atom.to_bytes_until_nul().unwrap_or_else(|_| {
                panic!(
                    "Called `expect()` at {}:{} (git sha: {})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA").unwrap_or("unknown")
                )
            });
            let block_id_str = String::from_utf8(block_id_bytes).unwrap_or_else(|_| {
                panic!(
                    "Called `expect()` at {}:{} (git sha: {})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA").unwrap_or("unknown")
                )
            });

            // Get the expected base58 string
            let expected_b58 = tip5_hash_to_base58(five_tuple).unwrap_or_else(|_| {
                panic!(
                    "Called `expect()` at {}:{} (git sha: {})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA").unwrap_or("unknown")
                )
            });
            assert_eq!(block_id_str, expected_b58);

            // Check peer ID
            let peer_cell = tail_cell.tail().as_cell().unwrap_or_else(|_| {
                panic!(
                    "Called `expect()` at {}:{} (git sha: {})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA").unwrap_or("unknown")
                )
            });
            let peer_id_result = peer_cell.head().as_atom().unwrap_or_else(|_| {
                panic!(
                    "Called `expect()` at {}:{} (git sha: {})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA").unwrap_or("unknown")
                )
            });
            let peer_bytes = peer_id_result.to_bytes_until_nul().unwrap_or_else(|_| {
                panic!(
                    "Called `expect()` at {}:{} (git sha: {})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA").unwrap_or("unknown")
                )
            });
            let peer_str = String::from_utf8(peer_bytes).unwrap_or_else(|_| {
                panic!(
                    "Called `expect()` at {}:{} (git sha: {})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA").unwrap_or("unknown")
                )
            });
            assert_eq!(peer_str, peer_id.to_base58());

            // Check final 0
            assert_eq!(
                peer_cell
                    .tail()
                    .as_direct()
                    .unwrap_or_else(|err| {
                        panic!(
                            "Panicked with {err:?} at {}:{} (git sha: {:?})",
                            file!(),
                            line!(),
                            option_env!("GIT_SHA")
                        )
                    })
                    .data(),
                0
            );
        }

        // Test invalid elders request (not a cell)
        {
            let mut slab = NounSlab::new();
            let invalid_request = T(
                &mut slab,
                &[D(tas!(b"request")), D(tas!(b"block")), D(tas!(b"elders"))],
            );
            slab.set_root(invalid_request);

            let result = request_to_scry_slab(unsafe { slab.root() });
            assert!(result.is_err());
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)] // equix uses a foreign function so miri fails this tes
    fn test_equix_pow_verification() {
        use equix::EquiXBuilder;
        // Create EquiX builder - new() doesn't return Result
        let mut builder = EquiXBuilder::new();

        // Create test peer IDs
        let local_peer_id = PeerId::random();
        let remote_peer_id = PeerId::random();

        // Create test message
        let message = ByteBuf::from(vec![1, 2, 3, 4, 5]);

        // Create valid request with correct PoW
        let valid_request =
            NockchainRequest::new_request(&mut builder, &local_peer_id, &remote_peer_id, &{
                let mut slab = NounSlab::new();
                let message_noun = Atom::from_value(&mut slab, &message[..])
                    .expect("Failed to create message atom")
                    .as_noun();
                slab.set_root(message_noun);
                slab
            });

        // Verify the valid request
        match &valid_request {
            NockchainRequest::Request {
                pow,
                nonce,
                message: _,
            } => {
                // Test successful verification
                let result = valid_request.verify_pow(
                    &mut builder, &remote_peer_id, // Note: peers are swapped for verification
                    &local_peer_id,
                );
                assert!(result.is_ok(), "Valid PoW should verify successfully");

                // Test failed verification with tampered nonce
                let tampered_request = NockchainRequest::Request {
                    pow: *pow,
                    nonce: nonce + 1, // Tamper with the nonce
                    message: message.clone(),
                };
                let result =
                    tampered_request.verify_pow(&mut builder, &remote_peer_id, &local_peer_id);
                assert!(result.is_err(), "Tampered nonce should fail verification");

                // Test failed verification with wrong peer order
                let result = valid_request.verify_pow(
                    &mut builder, &local_peer_id, // Wrong order - not swapped
                    &remote_peer_id,
                );
                assert!(result.is_err(), "Wrong peer order should fail verification");
            }
            _ => panic!("Expected Request variant"),
        }

        // Test that gossip requests always verify successfully
        let gossip_request = NockchainRequest::Gossip {
            message: message.clone(),
        };
        let result = gossip_request.verify_pow(&mut builder, &remote_peer_id, &local_peer_id);
        assert!(
            result.is_ok(),
            "Gossip requests should always verify successfully"
        );
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_liar_peer_effect() {
        use equix::EquiXBuilder;
        use tokio::sync::mpsc;

        // Create a test peer ID and convert to base58
        let peer_id = PeerId::random();
        let peer_id_base58 = peer_id.to_base58();

        // Create the liar-peer effect noun
        let mut effect_slab = NounSlab::new();
        let liar_peer_atom = Atom::from_value(&mut effect_slab, "liar-peer")
            .expect("Failed to create liar-peer atom");
        let peer_id_atom = Atom::from_value(&mut effect_slab, peer_id_base58)
            .expect("Failed to create peer ID atom");
        let effect = T(
            &mut effect_slab,
            &[liar_peer_atom.as_noun(), peer_id_atom.as_noun()],
        );
        effect_slab.set_root(effect);

        // Create channel to receive SwarmAction
        let (swarm_tx, mut swarm_rx) = mpsc::channel(1);

        // Call handle_effect with the liar-peer effect
        let result = handle_effect(
            effect_slab,
            swarm_tx,
            EquiXBuilder::new(),
            PeerId::random(), // local peer ID (not relevant for this test)
            vec![],           // connected peers (not relevant for this test)
            Arc::new(Mutex::new(MessageTracker::new())),
        )
        .await;

        // Verify the function succeeded
        assert!(result.is_ok(), "handle_effect should succeed");

        // Verify that a BlockPeer action was sent with the correct peer ID
        match swarm_rx.recv().await {
            Some(SwarmAction::BlockPeer {
                peer_id: blocked_peer,
            }) => {
                assert_eq!(blocked_peer, peer_id, "Wrong peer ID was blocked");
            }
            other => panic!("Expected BlockPeer action, got {:?}", other),
        }

        // Verify no more actions were sent
        assert!(swarm_rx.try_recv().is_err(), "Should only send one action");
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // ibig has a memory leak so miri fails this test
    async fn test_track_add_effect() {
        use equix::EquiXBuilder;
        use tokio::sync::mpsc;

        // Create test peer ID
        let peer_id = PeerId::random();
        let peer_id_base58 = peer_id.to_base58();

        // Create the track add effect noun
        let mut effect_slab = NounSlab::new();
        let track_atom = make_tas(&mut effect_slab, "track");
        let add_atom = make_tas(&mut effect_slab, "add");

        // Create block ID as [1 2 3 4 5]
        let block_id_tuple = T(&mut effect_slab, &[D(1), D(2), D(3), D(4), D(5)]);
        let peer_id_atom = Atom::from_value(&mut effect_slab, peer_id_base58)
            .expect("Failed to create peer ID atom");

        // Build the noun structure: [%track %add block-id peer-id]
        let data_cell = T(&mut effect_slab, &[block_id_tuple, peer_id_atom.as_noun()]);
        let add_cell = T(&mut effect_slab, &[add_atom.as_noun(), data_cell]);
        let track_cell = T(&mut effect_slab, &[track_atom.as_noun(), add_cell]);
        effect_slab.set_root(track_cell);

        // Create message tracker and other required components
        let message_tracker = Arc::new(Mutex::new(MessageTracker::new()));
        let (swarm_tx, _swarm_rx) = mpsc::channel(1);

        // Call handle_effect with the track add effect
        let result = handle_effect(
            effect_slab.clone(), // test fails if we don't clone
            swarm_tx,
            EquiXBuilder::new(),
            PeerId::random(), // local peer ID (not relevant for this test)
            vec![],           // connected peers (not relevant for this test)
            message_tracker.clone(),
        )
        .await;

        // Verify the function succeeded
        assert!(result.is_ok(), "handle_effect should succeed");

        // Get the expected block ID string (base58 of [1 2 3 4 5])
        let block_id_str = tip5_hash_to_base58(block_id_tuple).unwrap_or_else(|_| {
            panic!(
                "Called `expect()` at {}:{} (git sha: {})",
                file!(),
                line!(),
                option_env!("GIT_SHA").unwrap_or("unknown")
            )
        });

        // Verify the message tracker state
        let tracker = message_tracker.lock().await;

        // Check block_id_to_peers mapping
        let peers = tracker.get_peers_for_block_id(block_id_tuple);
        assert!(
            peers.contains(&peer_id),
            "Peer ID should be associated with block ID"
        );

        // Check peer_to_block_ids mapping
        let block_ids = tracker.get_block_ids_for_peer(peer_id);
        assert!(
            block_ids.contains(&block_id_str),
            "Block ID should be associated with peer ID"
        );
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // ibig has a memory leak so miri fails this test
    async fn test_track_remove_effect() {
        use equix::EquiXBuilder;
        use tokio::sync::mpsc;

        // Create test peer ID
        let peer_id = PeerId::random();

        // Create a message tracker and add an entry that we'll later remove
        let message_tracker = Arc::new(Mutex::new(MessageTracker::new()));

        // Create block ID as [1 2 3 4 5]
        let mut setup_slab = NounSlab::new();
        let block_id_tuple = T(&mut setup_slab, &[D(1), D(2), D(3), D(4), D(5)]);

        {
            let mut tracker = message_tracker.lock().await;
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

            // Verify it was added correctly
            assert!(tracker.is_tracking_block_id(block_id_tuple));
            assert!(tracker.is_tracking_peer(peer_id));
        }

        // Now create the track remove effect noun
        let mut effect_slab = NounSlab::new();
        let track_atom = make_tas(&mut effect_slab, "track");
        let remove_atom = make_tas(&mut effect_slab, "remove");

        // Copy the block ID tuple to the effect slab
        let block_id_tuple_in_effect = T(&mut effect_slab, &[D(1), D(2), D(3), D(4), D(5)]);

        // Build the noun structure: [%track %remove block-id]
        let remove_cell = T(
            &mut effect_slab,
            &[remove_atom.as_noun(), block_id_tuple_in_effect],
        );
        let track_cell = T(&mut effect_slab, &[track_atom.as_noun(), remove_cell]);
        effect_slab.set_root(track_cell);

        // Create channel for SwarmAction (not used in this test)
        let (swarm_tx, _swarm_rx) = mpsc::channel(1);

        // Call handle_effect with the track remove effect
        let result = handle_effect(
            effect_slab,
            swarm_tx,
            EquiXBuilder::new(),
            PeerId::random(), // local peer ID (not relevant for this test)
            vec![],           // connected peers (not relevant for this test)
            message_tracker.clone(),
        )
        .await;

        // Verify the function succeeded
        assert!(result.is_ok(), "handle_effect should succeed");

        // Verify the message tracker state after removal
        let tracker = message_tracker.lock().await;

        // Check that the block ID was removed from block_id_to_peers
        assert!(
            !tracker.is_tracking_block_id(block_id_tuple),
            "Block ID should be removed"
        );

        // Check that the peer's entry in peer_to_block_ids is also removed
        // (since this was the only block ID associated with the peer)
        assert!(
            !tracker.is_tracking_peer(peer_id),
            "Peer ID should be removed since it has no more block IDs"
        );
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // ibig has a memory leak so miri fails this test
    async fn test_liar_block_id_effect() {
        use equix::EquiXBuilder;
        use tokio::sync::mpsc;

        println!("Starting test_liar_block_id_effect");

        // Create test peer IDs
        let bad_peer1 = PeerId::random();
        let bad_peer2 = PeerId::random();
        let good_peer = PeerId::random();
        println!(
            "Created peer_ids: bad1={}, bad2={}, good={}",
            bad_peer1, bad_peer2, good_peer
        );

        // Create a message tracker and add entries
        let message_tracker = Arc::new(Mutex::new(MessageTracker::new()));

        // Create block IDs
        let mut setup_slab = NounSlab::new();
        // Bad block ID as [1 2 3 4 5]
        let bad_block_id = T(&mut setup_slab, &[D(1), D(2), D(3), D(4), D(5)]);
        // Good block ID as [6 7 8 9 10]
        let good_block_id = T(&mut setup_slab, &[D(6), D(7), D(8), D(9), D(10)]);
        println!("Created block_ids");

        {
            let mut tracker = message_tracker.lock().await;
            println!("Tracking block_ids and peers");

            // Associate bad_peer1 with the bad block
            tracker
                .track_block_id_and_peer(bad_block_id, bad_peer1)
                .unwrap_or_else(|_| {
                    panic!(
                        "Called `expect()` at {}:{} (git sha: {})",
                        file!(),
                        line!(),
                        option_env!("GIT_SHA").unwrap_or("unknown")
                    )
                });

            // Associate bad_peer2 with the bad block
            tracker
                .add_peer_if_tracking_block_id(bad_block_id, bad_peer2)
                .unwrap_or_else(|_| {
                    panic!(
                        "Called `expect()` at {}:{} (git sha: {})",
                        file!(),
                        line!(),
                        option_env!("GIT_SHA").unwrap_or("unknown")
                    )
                });

            // Associate good_peer with a different block
            tracker
                .track_block_id_and_peer(good_block_id, good_peer)
                .unwrap_or_else(|_| {
                    panic!(
                        "Called `expect()` at {}:{} (git sha: {})",
                        file!(),
                        line!(),
                        option_env!("GIT_SHA").unwrap_or("unknown")
                    )
                });

            // Verify tracking is working
            assert!(tracker.is_tracking_block_id(bad_block_id));
            assert!(tracker.is_tracking_block_id(good_block_id));
            assert!(tracker.is_tracking_peer(bad_peer1));
            assert!(tracker.is_tracking_peer(bad_peer2));
            assert!(tracker.is_tracking_peer(good_peer));
            println!("Verified tracking is working");
        }

        // Now create the liar-block-id effect noun for the bad block
        let mut effect_slab = NounSlab::new();
        let liar_block_id_atom = Atom::from_value(&mut effect_slab, "liar-block-id")
            .expect("Failed to create liar-block-id atom");

        // Copy the bad block ID tuple to the effect slab
        let bad_block_id_in_effect = T(&mut effect_slab, &[D(1), D(2), D(3), D(4), D(5)]);

        // Build the noun structure: [%liar-block-id bad-block-id]
        let effect = T(
            &mut effect_slab,
            &[liar_block_id_atom.as_noun(), bad_block_id_in_effect],
        );
        effect_slab.set_root(effect);
        println!("Created liar-block-id effect");

        // Create channel for SwarmAction
        let (swarm_tx, mut swarm_rx) = mpsc::channel(10); // Increased capacity for multiple actions
        println!("Created swarm channel");

        // Call handle_effect with the liar-block-id effect
        println!("Calling handle_effect");
        let result = handle_effect(
            effect_slab,
            swarm_tx,
            EquiXBuilder::new(),
            PeerId::random(), // local peer ID (not relevant for this test)
            vec![],           // connected peers (not relevant for this test)
            message_tracker.clone(),
        )
        .await;

        println!("handle_effect result: {:?}", result);

        // Verify the function succeeded
        assert!(result.is_ok(), "handle_effect should succeed");
        println!("Verified handle_effect succeeded");

        // Collect all the block actions
        let mut blocked_peers = Vec::new();
        while let Ok(action) = swarm_rx.try_recv() {
            match action {
                SwarmAction::BlockPeer { peer_id } => {
                    println!("Received BlockPeer action for peer: {}", peer_id);
                    blocked_peers.push(peer_id);
                }
                other => {
                    println!("Unexpected action received: {:?}", other);
                    panic!("Expected BlockPeer action, got {:?}", other);
                }
            }
        }

        // Verify both bad peers were blocked
        assert_eq!(
            blocked_peers.len(),
            2,
            "Should have blocked exactly 2 peers"
        );
        assert!(
            blocked_peers.contains(&bad_peer1),
            "bad_peer1 should be blocked"
        );
        assert!(
            blocked_peers.contains(&bad_peer2),
            "bad_peer2 should be blocked"
        );
        assert!(
            !blocked_peers.contains(&good_peer),
            "good_peer should not be blocked"
        );
        println!("Verified correct peers were blocked");

        // Verify the bad block ID was removed from the tracker
        {
            let tracker = message_tracker.lock().await;

            // Bad block should be removed
            assert!(
                !tracker.is_tracking_block_id(bad_block_id),
                "Bad block ID should be removed"
            );

            // Good block should still be tracked
            assert!(
                tracker.is_tracking_block_id(good_block_id),
                "Good block ID should still be tracked"
            );

            // Bad peers should be removed
            assert!(
                !tracker.is_tracking_peer(bad_peer1),
                "bad_peer1 should be removed from tracker"
            );
            assert!(
                !tracker.is_tracking_peer(bad_peer2),
                "bad_peer2 should be removed from tracker"
            );

            // Good peer should still be tracked
            assert!(
                tracker.is_tracking_peer(good_peer),
                "good_peer should still be tracked"
            );

            println!("Verified tracker state is correct after processing effect");
        }
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // ibig has a memory leak so miri fails this test

    async fn test_seen_block_effect() {
        use equix::EquiXBuilder;
        use tokio::sync::mpsc;

        let mut effect_slab = NounSlab::new();
        let block_id = T(&mut effect_slab, &[D(1), D(2), D(3), D(4), D(5)]);
        let block_id_str = tip5_hash_to_base58(block_id).unwrap_or_else(|_| {
            panic!(
                "Called `expect()` at {}:{} (git sha: {})",
                file!(),
                line!(),
                option_env!("GIT_SHA").unwrap_or("unknown")
            )
        });
        let effect = T(
            &mut effect_slab,
            &[D(tas!(b"seen")), D(tas!(b"block")), block_id],
        );
        effect_slab.set_root(effect);

        let (swarm_tx, _) = mpsc::channel(1);

        let message_tracker = Arc::new(Mutex::new(MessageTracker::new()));
        let message_tracker_clone = Arc::clone(&message_tracker); // Clone the Arc, not the MessageTracker
        let result = handle_effect(
            effect_slab,
            swarm_tx,
            EquiXBuilder::new(),
            PeerId::random(), // local peer ID (not relevant for this test)
            vec![],           // connected peers (not relevant for this test)
            message_tracker_clone,
        )
        .await;

        assert!(result.is_ok(), "handle_effect should succeed");

        // Verify that the block id was added to the seen_blocks set
        let tracker = message_tracker.lock().await;
        let contains = tracker.seen_blocks.contains(&block_id_str);
        assert!(contains, "Block ID should be marked as seen");
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // ibig has a memory leak so miri fails this test
    async fn test_seen_tx_effect() {
        use equix::EquiXBuilder;
        use tokio::sync::mpsc;

        let mut effect_slab = NounSlab::new();
        let tx_id = T(&mut effect_slab, &[D(1), D(2), D(3), D(4), D(5)]);
        let tx_id_str = tip5_hash_to_base58(tx_id).unwrap_or_else(|_| {
            panic!(
                "Called `expect()` at {}:{} (git sha: {})",
                file!(),
                line!(),
                option_env!("GIT_SHA").unwrap_or("unknown")
            )
        });
        let effect = T(&mut effect_slab, &[D(tas!(b"seen")), D(tas!(b"tx")), tx_id]);

        effect_slab.set_root(effect);

        let (swarm_tx, _) = mpsc::channel(1);

        let message_tracker = Arc::new(Mutex::new(MessageTracker::new()));
        let message_tracker_clone = Arc::clone(&message_tracker); // Clone the Arc, not the MessageTracker
        let result = handle_effect(
            effect_slab,
            swarm_tx,
            EquiXBuilder::new(),
            PeerId::random(), // local peer ID (not relevant for this test)
            vec![],           // connected peers (not relevant for this test)
            message_tracker_clone,
        )
        .await;

        assert!(result.is_ok(), "handle_effect should succeed");

        // Verify that the tx id was added to the seen_blocks set
        let tracker = message_tracker.lock().await;
        let contains = tracker.seen_txs.contains(&tx_id_str);
        assert!(contains, "tx ID should be marked as seen");
    }
}

fn dial_initial_peers(
    swarm: &mut Swarm<NockchainBehaviour>,
    peers: &[Multiaddr],
) -> Result<(), NockAppError> {
    for peer in peers {
        let peer = peer.clone();
        swarm.dial(peer.clone()).map_err(|e| {
            error!("Failed to dial initial peer {}: {}", peer, e);
            NockAppError::OtherError
        })?;
    }
    Ok(())
}

use std::convert::Infallible;
use std::error::Error;
use std::time::Duration;

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use libp2p::identity::Keypair;
use libp2p::multiaddr::Multiaddr;
use libp2p::request_response::{self, cbor, ResponseChannel};
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::NetworkBehaviour;
use libp2p::{
    allow_block_list, connection_limits, identify, kad, memory_connection_limits, ping, PeerId,
    Swarm,
};
use nockapp::NockAppError;
use tracing::{debug, trace};

use crate::nc::*;

// Kademlia constants
/** How often we should run a kademlia bootstrap to keep our peer table fresh */
pub const KADEMLIA_BOOTSTRAP_INTERVAL: Duration = Duration::from_secs(300);

/** How long we should keep a peer connection alive with no traffic */
pub const SWARM_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

// Core protocol (QUIC/ping/etc) constants
/** How many times we should retry dialing our initial peers if we can't get Kademlia initialized */
// TODO: Make command-line configurable
pub const INITIAL_PEER_RETRIES: u32 = 5;
/** How often we should send a keep-alive message to a peer */
pub const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);
/** How long should we wait before timing out the connection */
pub const CONNECTION_TIMEOUT: Duration = SWARM_IDLE_TIMEOUT;
/** How long should we wait before timing out the handshake */
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/** How long QUIC should wait before timing out an idle connection */
pub const MAX_IDLE_TIMEOUT_MILLISECS: u32 = CONNECTION_TIMEOUT.as_millis() as u32;
/** How often we should send an identify message to a peer */
pub const IDENTIFY_INTERVAL: Duration = KADEMLIA_BOOTSTRAP_INTERVAL;

/** Maximum number of established *incoming* connections */
pub const MAX_ESTABLISHED_INCOMING_CONNECTIONS: u32 = 32;

/** Maximum number of established *incoming* connections */
pub const MAX_ESTABLISHED_OUTGOING_CONNECTIONS: u32 = 32;

/** Maximum number of established connections */
pub const MAX_ESTABLISHED_CONNECTIONS: u32 = 64;

/** Maximum number of established connections with a single peer ID */
pub const MAX_ESTABLISHED_CONNECTIONS_PER_PEER: u32 = 2;

/** Maximum pending incoming connections */
pub const MAX_PENDING_INCOMING_CONNECTIONS: u32 = 16;

/** Maximum pending outcoing connections */
pub const MAX_PENDING_OUTGOING_CONNECTIONS: u32 = 16;

// Request/response constants
pub const REQUEST_RESPONSE_MAX_CONCURRENT_STREAMS: usize = MAX_ESTABLISHED_CONNECTIONS as usize * 2;
pub const REQUEST_RESPONSE_TIMEOUT: Duration = Duration::from_secs(20);

// ALL PROTOCOLS MUST HAVE UNIQUE VERSIONS
pub const REQ_RES_PROTOCOL_VERSION: &str = "/nockchain-1-req-res";
pub const KAD_PROTOCOL_VERSION: &str = "/nockchain-1-kad";
pub const IDENTIFY_PROTOCOL_VERSION: &str = "/nockchain-1-identify";

const PEER_STORE_RECORD_CAPACITY: usize = 10 * 1024;

#[derive(Debug)]
pub enum SwarmAction {
    SendResponse {
        channel: ResponseChannel<NockchainResponse>,
        response: NockchainResponse,
    },
    SendRequest {
        peer_id: PeerId,
        request: NockchainRequest,
    },
    BlockPeer {
        peer_id: PeerId,
    },
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "NockchainEvent")]
/** Composed [NetworkBehaviour] implementation for Nockchain */
pub struct NockchainBehaviour {
    /// Allows nodes to connect via just IP and port and exchange pubkeys
    identify: identify::Behaviour,
    /// Connectivity testing
    ping: ping::Behaviour,
    /// Peer discovery via a DHT
    pub kad: kad::Behaviour<kad::store::MemoryStore>,
    /// Peer banning
    pub allow_block_list: allow_block_list::Behaviour<allow_block_list::BlockedPeers>,
    /// Peer whitelisting
    pub allow_peers: Toggle<allow_block_list::Behaviour<allow_block_list::AllowedPeers>>,
    /// Connection limiting
    connection_limits: connection_limits::Behaviour,
    /// Memory connection limits
    memory_connection_limits: Toggle<memory_connection_limits::Behaviour>,
    /// Peer store for tracking peer information (including addresses)
    pub peer_store: libp2p::peer_store::Behaviour<libp2p::peer_store::memory_store::MemoryStore>,
    /// Actual comms
    pub request_response: cbor::Behaviour<NockchainRequest, NockchainResponse>,
}

impl NockchainBehaviour {
    fn pre_new(
        allowed: Option<allow_block_list::Behaviour<allow_block_list::AllowedPeers>>,
        limits: connection_limits::ConnectionLimits,
        memory_limits: Option<memory_connection_limits::Behaviour>,
    ) -> impl FnOnce(&libp2p::identity::Keypair) -> Self {
        |keypair: &libp2p::identity::Keypair| {
            let peer_id = libp2p::identity::PeerId::from_public_key(&keypair.public());

            let identify_config =
                identify::Config::new(IDENTIFY_PROTOCOL_VERSION.to_string(), keypair.public())
                    .with_interval(IDENTIFY_INTERVAL)
                    .with_hide_listen_addrs(true); // Only send externally confirmed addresses so we don't send loopback addresses
            let identify_behaviour = identify::Behaviour::new(identify_config);

            let memory_store = kad::store::MemoryStore::new(peer_id);

            let kad_config = kad::Config::new(libp2p::StreamProtocol::new(KAD_PROTOCOL_VERSION));
            let kad_behaviour = kad::Behaviour::with_config(peer_id, memory_store, kad_config);

            let request_response_config = request_response::Config::default()
                .with_max_concurrent_streams(REQUEST_RESPONSE_MAX_CONCURRENT_STREAMS)
                .with_request_timeout(REQUEST_RESPONSE_TIMEOUT);

            let request_response_behaviour = cbor::Behaviour::new(
                [(
                    libp2p::StreamProtocol::new(REQ_RES_PROTOCOL_VERSION),
                    request_response::ProtocolSupport::Full,
                )],
                request_response_config,
            );
            let connection_limits_behaviour = connection_limits::Behaviour::new(limits);
            let memory_connection_limits =
                Toggle::<memory_connection_limits::Behaviour>::from(memory_limits);

            let allow_peers =
                Toggle::<allow_block_list::Behaviour<allow_block_list::AllowedPeers>>::from(
                    allowed,
                );
            let peer_store_config = libp2p::peer_store::memory_store::Config::default();
            let record_capacity = PEER_STORE_RECORD_CAPACITY.try_into().unwrap();
            let peer_store_config = peer_store_config.set_record_capacity(record_capacity);
            let peer_store_memory =
                libp2p::peer_store::memory_store::MemoryStore::new(peer_store_config);

            let peer_store_behaviour = libp2p::peer_store::Behaviour::new(peer_store_memory);
            NockchainBehaviour {
                ping: ping::Behaviour::default(),
                identify: identify_behaviour,
                kad: kad_behaviour,
                allow_block_list: allow_block_list::Behaviour::default(),
                allow_peers,
                request_response: request_response_behaviour,
                connection_limits: connection_limits_behaviour,
                memory_connection_limits,
                peer_store: peer_store_behaviour,
            }
        }
    }
}

/// # Create a swarm and set it to listen
///
/// This function initializes a libp2p swarm with the provided keypair and binding addresses.
/// It configures the swarm to listen on specified multiaddresses and sets up the behavior for network interactions.
///
/// # Arguments
/// * `keypair` - The keypair for the node's identity
/// * `bind` - A vector of multiaddresses specifying the network interfaces to bind to
///
/// # Returns
/// A Result containing the Swarm instance or an error if any operation fails
pub fn start_swarm(
    keypair: Keypair,
    bind: Vec<Multiaddr>,
    allowed: Option<allow_block_list::Behaviour<allow_block_list::AllowedPeers>>,
    limits: connection_limits::ConnectionLimits,
    memory_limits: Option<memory_connection_limits::Behaviour>,
) -> Result<Swarm<NockchainBehaviour>, Box<dyn Error>> {
    let (resolver_config, resolver_opts) =
        if let Ok(sys) = hickory_resolver::system_conf::read_system_conf() {
            debug!("resolver configs and opts: {:?}", sys);
            sys
        } else {
            (ResolverConfig::cloudflare(), ResolverOpts::default())
        };

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_quic_config(|mut cfg| {
            cfg.max_idle_timeout = MAX_IDLE_TIMEOUT_MILLISECS;
            cfg.keep_alive_interval = KEEP_ALIVE_INTERVAL;
            cfg.handshake_timeout = HANDSHAKE_TIMEOUT;
            cfg
        })
        .with_dns_config(resolver_config, resolver_opts)
        .with_behaviour(NockchainBehaviour::pre_new(allowed, limits, memory_limits))?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(SWARM_IDLE_TIMEOUT))
        .with_connection_timeout(CONNECTION_TIMEOUT)
        .build();

    for bind_addr in bind {
        swarm.listen_on(bind_addr)?;
    }
    Ok(swarm)
}

// TODO: We need to box identify::Event but we are on stable so no boxed patterns.
#[derive(Debug)]
#[allow(dead_code)]
#[allow(clippy::large_enum_variant)]
/** Events that can be emitted by the swarm running [NockchainBehaviour] */
pub enum NockchainEvent {
    /// Received or sent identify message
    Identify(identify::Event),
    /// Received or failed ping
    Ping(ping::Event),
    /// DHT state changes
    Kad(kad::Event),
    /// Request or response received from peer
    RequestResponse(request_response::Event<NockchainRequest, NockchainResponse>),
    /// Peer store events
    PeerStore(libp2p::peer_store::memory_store::Event),
}

impl From<identify::Event> for NockchainEvent {
    fn from(event: identify::Event) -> Self {
        Self::Identify(event)
    }
}

impl From<ping::Event> for NockchainEvent {
    fn from(event: ping::Event) -> Self {
        Self::Ping(event)
    }
}

impl From<kad::Event> for NockchainEvent {
    fn from(event: kad::Event) -> Self {
        Self::Kad(event)
    }
}

impl From<Infallible> for NockchainEvent {
    fn from(i: Infallible) -> Self {
        match i {}
    }
}

impl From<request_response::Event<NockchainRequest, NockchainResponse>> for NockchainEvent {
    fn from(event: request_response::Event<NockchainRequest, NockchainResponse>) -> Self {
        Self::RequestResponse(event)
    }
}

impl From<libp2p::peer_store::memory_store::Event> for NockchainEvent {
    fn from(event: libp2p::peer_store::memory_store::Event) -> Self {
        Self::PeerStore(event)
    }
}

///** Handler for "identify" messages */
//#[instrument(skip(swarm))]
pub fn identify_received(
    swarm: &mut Swarm<NockchainBehaviour>,
    peer_id: PeerId,
    info: libp2p::identify::Info,
) -> Result<(), NockAppError> {
    swarm.add_external_address(info.observed_addr.clone());
    let us = *swarm.local_peer_id();
    let kad = &mut swarm.behaviour_mut().kad;
    trace!("identify received for peer {}", peer_id);
    trace!("Adding address {} for us: {}", info.observed_addr, us);
    kad.add_address(&us, info.observed_addr);
    for addr in info.listen_addrs {
        trace!("Adding address {} for peer {}", addr, peer_id);
        kad.add_address(&peer_id, addr);
    }
    Ok(())
}

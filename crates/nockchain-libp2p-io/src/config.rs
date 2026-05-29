use std::collections::HashSet;
use std::net::IpAddr;
use std::num::NonZero;
use std::str::FromStr;
use std::time::Duration;

use config::{Config, ConfigError, Environment};
use serde::Deserialize;

// Kademlia constants
/** How often we should run a kademlia bootstrap to keep our peer table fresh */
const KADEMLIA_BOOTSTRAP_INTERVAL: Duration = Duration::from_secs(300);

// If the --force-peer cli arg is passed, we will force dial it every FORCE_PEER_BOOT_INTERVAL
const FORCE_PEER_DIAL_INTERVAL: Duration = Duration::from_secs(1200);

/** How long we should keep a peer connection alive with no traffic */
const SWARM_IDLE_TIMEOUT: Duration = Duration::from_secs(180);

// Core protocol (QUIC/ping/etc) constants
/** How many times we should retry dialing our initial peers if we can't get Kademlia initialized */
// TODO: Make command-line configurable
const INITIAL_PEER_RETRIES: u32 = 5;
/** How often we should send a keep-alive message to a peer */
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(12);
/** How long should we wait before timing out the handshake */
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
/** How often we should send an identify message to a peer */
const IDENTIFY_INTERVAL: Duration = Duration::from_secs(120);

/** Maximum number of established *incoming* connections */
const MAX_ESTABLISHED_INCOMING_CONNECTIONS: u32 = 256;

/** Maximum number of established *incoming* connections */
const MAX_ESTABLISHED_OUTGOING_CONNECTIONS: u32 = 32;

/** Maximum number of established connections */
const MAX_ESTABLISHED_CONNECTIONS: u32 = 288;

/** Maximum number of established connections with a single peer ID */
const MAX_ESTABLISHED_CONNECTIONS_PER_PEER: u32 = 2;

/** Maximum pending incoming connections */
const MAX_PENDING_INCOMING_CONNECTIONS: u32 = 64;

/** Maximum pending outcoing connections */
const MAX_PENDING_OUTGOING_CONNECTIONS: u32 = 32;

/** Minimum number of peers */
const MIN_PEERS: usize = 8;

// Request/response constants
const REQUEST_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
const REQUEST_HIGH_THRESHOLD: u64 = 60;
const REQUEST_HIGH_RESET: Duration = Duration::from_secs(60);

// Elders debounce
const ELDERS_DEBOUNCE_RESET: Duration = Duration::from_secs(60);

// Cache clear interval of seen_tx cache handled in libp2p driver
const SEEN_TX_CLEAR_INTERVAL: u64 = 30;

// ALL PROTOCOLS MUST HAVE UNIQUE VERSIONS
const REQ_RES_PROTOCOL_VERSION: &str = "/nockchain-1-req-res";
const KAD_PROTOCOL_VERSION: &str = "/nockchain-1-kad";
const IDENTIFY_PROTOCOL_VERSION: &str = "/nockchain-1-identify";

const PEER_STORE_RECORD_CAPACITY: usize = 1024;

// Default timeout for network-originating pokes
const POKE_TIMEOUT_SECS: u64 = 180;

// Default max failed pings before closing connection
const FAILED_PINGS_BEFORE_CLOSE: u64 = 4;

const IP_HYGIENE_ENABLED: bool = true;
const ADDRESS_COOLDOWN: Duration = Duration::from_secs(3600);
const IP_EXCLUSION: Duration = Duration::from_secs(3600);
const IP_EXTENDED_EXCLUSION: Duration = Duration::from_secs(21600);
const EVIDENCE_WINDOW: Duration = Duration::from_secs(600);
const IP_EXCLUSION_HISTORY: Duration = Duration::from_secs(86400);
const PERMISSION_DENIED_COOLDOWN: Duration = Duration::from_secs(300);
const WRONG_PEER_ID_IP_THRESHOLD: usize = 3;
const DIAL_FAILURE_IP_THRESHOLD: usize = 5;
const SAME_IP_KAD_ENTRY_THRESHOLD: usize = 8;
const MAX_AUTO_EXCLUSION: Duration = Duration::from_secs(21600);
const MAX_EXCLUSION_ENTRIES: usize = 4096;
const REQUEST_PEER_COOLDOWN: Duration = Duration::from_secs(300);
const FAIL2BAN_ON_TEMP_EXCLUSION: bool = false;

/// Configuration struct that allows overriding default constants from environment variables
#[derive(Debug, Deserialize, Clone)]
pub struct LibP2PConfig {
    /// How often we should run a kademlia bootstrap to keep our peer table fresh (seconds)
    #[serde(default = "default_kademlia_bootstrap_interval_secs")]
    pub kademlia_bootstrap_interval_secs: u64,

    /// How often we should force dial force peers (seconds)
    #[serde(default = "default_force_peer_dial_interval_secs")]
    pub force_peer_dial_interval_secs: u64,

    /// How long we should keep a peer connection alive with no traffic (seconds)
    #[serde(default = "default_swarm_idle_timeout_secs")]
    pub swarm_idle_timeout_secs: u64,

    /// How many times we should retry dialing our initial peers if we can't get Kademlia initialized
    #[serde(default = "default_initial_peer_retries")]
    pub initial_peer_retries: u32,

    /// How often we should send a keep-alive message to a peer (seconds)
    #[serde(default = "default_keep_alive_interval_secs")]
    pub keep_alive_interval_secs: u64,

    /// How long should we wait before timing out the handshake (seconds)
    #[serde(default = "default_handshake_timeout_secs")]
    pub handshake_timeout_secs: u64,

    /// How often we should send an identify message to a peer (seconds)
    #[serde(default = "default_identify_interval_secs")]
    pub identify_interval_secs: u64,

    /// Maximum number of established incoming connections
    #[serde(default = "default_max_established_incoming_connections")]
    pub max_established_incoming_connections: u32,

    /// Maximum number of established outgoing connections
    #[serde(default = "default_max_established_outgoing_connections")]
    pub max_established_outgoing_connections: u32,

    /// Maximum number of established connections
    #[serde(default = "default_max_established_connections")]
    pub max_established_connections: u32,

    /// Maximum number of established connections with a single peer ID
    #[serde(default = "default_max_established_connections_per_peer")]
    pub max_established_connections_per_peer: u32,

    /// Maximum pending incoming connections
    #[serde(default = "default_max_pending_incoming_connections")]
    pub max_pending_incoming_connections: u32,

    /// Maximum pending outgoing connections
    #[serde(default = "default_max_pending_outgoing_connections")]
    pub max_pending_outgoing_connections: u32,

    /// Minimum number of peers
    #[serde(default = "default_min_peers")]
    pub min_peers: usize,

    /// Request/response timeout (seconds)
    #[serde(default = "default_request_response_timeout_secs")]
    pub request_response_timeout_secs: u64,

    /// Request high threshold
    #[serde(default = "default_request_high_threshold")]
    pub request_high_threshold: u64,

    /// Request high reset timeout (seconds)
    #[serde(default = "default_request_high_reset_secs")]
    pub request_high_reset_secs: u64,

    // These have to be static.
    // /// Request/response protocol version
    // #[serde(default = "default_req_res_protocol_version")]
    // pub req_res_protocol_version: String,

    // /// Kademlia protocol version
    // #[serde(default = "default_kad_protocol_version")]
    // pub kad_protocol_version: String,
    ///// Identify protocol version
    //#[serde(default = "default_identify_protocol_version")]
    //pub identify_protocol_version: String,
    /// Peer store record capacity
    /// This is the maximum number of records that can be stored in the peer store.
    #[serde(default = "default_peer_store_record_capacity")]
    pub peer_store_record_capacity: NonZero<usize>,

    /// Interval for logging peer status
    /// This is the interval at which peer status will be logged.
    #[serde(default = "default_peer_status_interval_secs")]
    pub peer_status_interval_secs: u64,

    /// Interval for debouncing elders
    #[serde(default = "default_elders_debounce_reset_secs")]
    pub elders_debounce_reset_secs: u64,

    /// Block interval for clearing seen transactions.
    /// The cache will clear after seeing this many new blocks
    /// added to the heaviest chain.
    #[serde(default = "default_seen_tx_clear_interval")]
    pub seen_tx_clear_interval: u64,

    /// Timeout for pokes
    #[serde(default = "default_poke_timeout_secs")]
    pub poke_timeout_secs: u64,

    /// Number of failed pings before closing connection
    #[serde(default = "default_failed_pings_before_close")]
    pub failed_pings_before_close: u64,

    /// Whether temporary IP and endpoint hygiene is active
    #[serde(default = "default_ip_hygiene_enabled")]
    pub ip_hygiene_enabled: bool,

    /// Address cooldown duration after endpoint-local evidence
    #[serde(default = "default_address_cooldown_secs")]
    pub address_cooldown_secs: u64,

    /// First IP exclusion duration after same-IP evidence crosses a threshold
    #[serde(default = "default_ip_exclusion_secs")]
    pub ip_exclusion_secs: u64,

    /// Recurrent IP exclusion duration
    #[serde(default = "default_ip_extended_exclusion_secs")]
    pub ip_extended_exclusion_secs: u64,

    /// Evidence window for escalation
    #[serde(default = "default_evidence_window_secs")]
    pub evidence_window_secs: u64,

    /// Time horizon for repeated exclusion escalation
    #[serde(default = "default_ip_exclusion_history_secs")]
    pub ip_exclusion_history_secs: u64,

    /// Cooldown for local PermissionDenied transport failures
    #[serde(default = "default_permission_denied_cooldown_secs")]
    pub permission_denied_cooldown_secs: u64,

    /// Distinct wrong peer IDs or ports needed before IP exclusion
    #[serde(default = "default_wrong_peer_id_ip_threshold")]
    pub wrong_peer_id_ip_threshold: usize,

    /// Failed endpoints on one IP needed before IP exclusion
    #[serde(default = "default_dial_failure_ip_threshold")]
    pub dial_failure_ip_threshold: usize,

    /// Local Kademlia cardinality that marks same-IP pollution
    #[serde(default = "default_same_ip_kad_entry_threshold")]
    pub same_ip_kad_entry_threshold: usize,

    /// Upper bound for automatic exclusion duration
    #[serde(default = "default_max_auto_exclusion_secs")]
    pub max_auto_exclusion_secs: u64,

    /// Max evidence events retained in memory
    #[serde(default = "default_max_exclusion_entries")]
    pub max_exclusion_entries: usize,

    /// Peer request cooldown after request-response failure
    #[serde(default = "default_request_peer_cooldown_secs")]
    pub request_peer_cooldown_secs: u64,

    /// Comma-separated IPs exempt from automatic exclusion
    #[serde(default)]
    pub exclusion_allow_ips: String,

    /// Emit fail2ban-compatible lines for local peer blocks and temporary exclusions
    #[serde(default = "default_fail2ban_on_temp_exclusion")]
    pub fail2ban_on_temp_exclusion: bool,
}

// Default value functions
fn default_kademlia_bootstrap_interval_secs() -> u64 {
    KADEMLIA_BOOTSTRAP_INTERVAL.as_secs()
}
fn default_force_peer_dial_interval_secs() -> u64 {
    FORCE_PEER_DIAL_INTERVAL.as_secs()
}
fn default_swarm_idle_timeout_secs() -> u64 {
    SWARM_IDLE_TIMEOUT.as_secs()
}
fn default_initial_peer_retries() -> u32 {
    INITIAL_PEER_RETRIES
}
fn default_keep_alive_interval_secs() -> u64 {
    KEEP_ALIVE_INTERVAL.as_secs()
}
fn default_handshake_timeout_secs() -> u64 {
    HANDSHAKE_TIMEOUT.as_secs()
}
fn default_identify_interval_secs() -> u64 {
    IDENTIFY_INTERVAL.as_secs()
}
fn default_max_established_incoming_connections() -> u32 {
    MAX_ESTABLISHED_INCOMING_CONNECTIONS
}
fn default_max_established_outgoing_connections() -> u32 {
    MAX_ESTABLISHED_OUTGOING_CONNECTIONS
}
fn default_max_established_connections() -> u32 {
    MAX_ESTABLISHED_CONNECTIONS
}
fn default_max_established_connections_per_peer() -> u32 {
    MAX_ESTABLISHED_CONNECTIONS_PER_PEER
}
fn default_max_pending_incoming_connections() -> u32 {
    MAX_PENDING_INCOMING_CONNECTIONS
}
fn default_max_pending_outgoing_connections() -> u32 {
    MAX_PENDING_OUTGOING_CONNECTIONS
}
fn default_min_peers() -> usize {
    MIN_PEERS
}
fn default_request_response_timeout_secs() -> u64 {
    REQUEST_RESPONSE_TIMEOUT.as_secs()
}
fn default_request_high_threshold() -> u64 {
    REQUEST_HIGH_THRESHOLD
}
fn default_request_high_reset_secs() -> u64 {
    REQUEST_HIGH_RESET.as_secs()
}

fn default_peer_store_record_capacity() -> NonZero<usize> {
    PEER_STORE_RECORD_CAPACITY
        .try_into()
        .expect("Peer store record capacity must be non-zero")
}

fn default_peer_status_interval_secs() -> u64 {
    300 // Log peer status and potentially redial every 5 minutes
}

fn default_elders_debounce_reset_secs() -> u64 {
    ELDERS_DEBOUNCE_RESET.as_secs() // Reset elders debounce every 60 seconds
}

fn default_seen_tx_clear_interval() -> u64 {
    SEEN_TX_CLEAR_INTERVAL // By default, clear seen_tx cache after every new block on heaviest chain
}

fn default_poke_timeout_secs() -> u64 {
    POKE_TIMEOUT_SECS // Timeout for pokes
}

fn default_failed_pings_before_close() -> u64 {
    FAILED_PINGS_BEFORE_CLOSE // Number of failed pings before closing connection
}
fn default_ip_hygiene_enabled() -> bool {
    IP_HYGIENE_ENABLED
}
fn default_address_cooldown_secs() -> u64 {
    ADDRESS_COOLDOWN.as_secs()
}
fn default_ip_exclusion_secs() -> u64 {
    IP_EXCLUSION.as_secs()
}
fn default_ip_extended_exclusion_secs() -> u64 {
    IP_EXTENDED_EXCLUSION.as_secs()
}
fn default_evidence_window_secs() -> u64 {
    EVIDENCE_WINDOW.as_secs()
}
fn default_ip_exclusion_history_secs() -> u64 {
    IP_EXCLUSION_HISTORY.as_secs()
}
fn default_permission_denied_cooldown_secs() -> u64 {
    PERMISSION_DENIED_COOLDOWN.as_secs()
}
fn default_wrong_peer_id_ip_threshold() -> usize {
    WRONG_PEER_ID_IP_THRESHOLD
}
fn default_dial_failure_ip_threshold() -> usize {
    DIAL_FAILURE_IP_THRESHOLD
}
fn default_same_ip_kad_entry_threshold() -> usize {
    SAME_IP_KAD_ENTRY_THRESHOLD
}
fn default_max_auto_exclusion_secs() -> u64 {
    MAX_AUTO_EXCLUSION.as_secs()
}
fn default_max_exclusion_entries() -> usize {
    MAX_EXCLUSION_ENTRIES
}
fn default_request_peer_cooldown_secs() -> u64 {
    REQUEST_PEER_COOLDOWN.as_secs()
}
fn default_fail2ban_on_temp_exclusion() -> bool {
    FAIL2BAN_ON_TEMP_EXCLUSION
}

// Do _not_ use this default implementation in production code. It's just a fallback.
// Use from_env() to load from environment variables with sensible defaults.
impl Default for LibP2PConfig {
    fn default() -> Self {
        Self {
            kademlia_bootstrap_interval_secs: default_kademlia_bootstrap_interval_secs(),
            force_peer_dial_interval_secs: default_force_peer_dial_interval_secs(),
            swarm_idle_timeout_secs: default_swarm_idle_timeout_secs(),
            initial_peer_retries: default_initial_peer_retries(),
            keep_alive_interval_secs: default_keep_alive_interval_secs(),
            handshake_timeout_secs: default_handshake_timeout_secs(),
            identify_interval_secs: default_identify_interval_secs(),
            max_established_incoming_connections: default_max_established_incoming_connections(),
            max_established_outgoing_connections: default_max_established_outgoing_connections(),
            max_established_connections: default_max_established_connections(),
            max_established_connections_per_peer: default_max_established_connections_per_peer(),
            max_pending_incoming_connections: default_max_pending_incoming_connections(),
            max_pending_outgoing_connections: default_max_pending_outgoing_connections(),
            min_peers: default_min_peers(),
            request_response_timeout_secs: default_request_response_timeout_secs(),
            request_high_threshold: default_request_high_threshold(),
            request_high_reset_secs: default_request_high_reset_secs(),
            peer_store_record_capacity: default_peer_store_record_capacity(),
            peer_status_interval_secs: default_peer_status_interval_secs(),
            elders_debounce_reset_secs: default_elders_debounce_reset_secs(),
            seen_tx_clear_interval: default_seen_tx_clear_interval(),
            poke_timeout_secs: default_poke_timeout_secs(),
            failed_pings_before_close: default_failed_pings_before_close(),
            ip_hygiene_enabled: default_ip_hygiene_enabled(),
            address_cooldown_secs: default_address_cooldown_secs(),
            ip_exclusion_secs: default_ip_exclusion_secs(),
            ip_extended_exclusion_secs: default_ip_extended_exclusion_secs(),
            evidence_window_secs: default_evidence_window_secs(),
            ip_exclusion_history_secs: default_ip_exclusion_history_secs(),
            permission_denied_cooldown_secs: default_permission_denied_cooldown_secs(),
            wrong_peer_id_ip_threshold: default_wrong_peer_id_ip_threshold(),
            dial_failure_ip_threshold: default_dial_failure_ip_threshold(),
            same_ip_kad_entry_threshold: default_same_ip_kad_entry_threshold(),
            max_auto_exclusion_secs: default_max_auto_exclusion_secs(),
            max_exclusion_entries: default_max_exclusion_entries(),
            request_peer_cooldown_secs: default_request_peer_cooldown_secs(),
            exclusion_allow_ips: String::new(),
            fail2ban_on_temp_exclusion: default_fail2ban_on_temp_exclusion(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PeerExclusionConfig {
    pub(crate) enabled: bool,
    pub(crate) address_cooldown_secs: u64,
    pub(crate) ip_exclusion_secs: u64,
    pub(crate) ip_extended_exclusion_secs: u64,
    pub(crate) evidence_window_secs: u64,
    pub(crate) ip_exclusion_history_secs: u64,
    pub(crate) permission_denied_cooldown_secs: u64,
    pub(crate) wrong_peer_id_ip_threshold: usize,
    pub(crate) dial_failure_ip_threshold: usize,
    pub(crate) same_ip_kad_entry_threshold: usize,
    pub(crate) max_auto_exclusion_secs: u64,
    pub(crate) max_exclusion_entries: usize,
    pub(crate) request_peer_cooldown_secs: u64,
    pub(crate) allow_ips: HashSet<IpAddr>,
    pub(crate) fail2ban_on_temp_exclusion: bool,
}

impl Default for PeerExclusionConfig {
    fn default() -> Self {
        Self {
            enabled: default_ip_hygiene_enabled(),
            address_cooldown_secs: default_address_cooldown_secs(),
            ip_exclusion_secs: default_ip_exclusion_secs(),
            ip_extended_exclusion_secs: default_ip_extended_exclusion_secs(),
            evidence_window_secs: default_evidence_window_secs(),
            ip_exclusion_history_secs: default_ip_exclusion_history_secs(),
            permission_denied_cooldown_secs: default_permission_denied_cooldown_secs(),
            wrong_peer_id_ip_threshold: default_wrong_peer_id_ip_threshold(),
            dial_failure_ip_threshold: default_dial_failure_ip_threshold(),
            same_ip_kad_entry_threshold: default_same_ip_kad_entry_threshold(),
            max_auto_exclusion_secs: default_max_auto_exclusion_secs(),
            max_exclusion_entries: default_max_exclusion_entries(),
            request_peer_cooldown_secs: default_request_peer_cooldown_secs(),
            allow_ips: HashSet::new(),
            fail2ban_on_temp_exclusion: default_fail2ban_on_temp_exclusion(),
        }
    }
}

impl PeerExclusionConfig {
    pub(crate) fn from_libp2p_config(config: &LibP2PConfig) -> Result<Self, ConfigError> {
        let mut allow_ips = HashSet::new();
        for raw in config.exclusion_allow_ips.split(',') {
            let raw = raw.trim();
            if raw.is_empty() {
                continue;
            }
            let ip = IpAddr::from_str(raw).map_err(|err| {
                ConfigError::Message(format!(
                    "invalid NOCKCHAIN_LIBP2P_EXCLUSION_ALLOW_IPS entry {raw}: {err}"
                ))
            })?;
            allow_ips.insert(ip);
        }

        Ok(Self {
            enabled: config.ip_hygiene_enabled,
            address_cooldown_secs: config.address_cooldown_secs,
            ip_exclusion_secs: config.ip_exclusion_secs,
            ip_extended_exclusion_secs: config.ip_extended_exclusion_secs,
            evidence_window_secs: config.evidence_window_secs,
            ip_exclusion_history_secs: config.ip_exclusion_history_secs,
            permission_denied_cooldown_secs: config.permission_denied_cooldown_secs,
            wrong_peer_id_ip_threshold: config.wrong_peer_id_ip_threshold,
            dial_failure_ip_threshold: config.dial_failure_ip_threshold,
            same_ip_kad_entry_threshold: config.same_ip_kad_entry_threshold,
            max_auto_exclusion_secs: config.max_auto_exclusion_secs,
            max_exclusion_entries: config.max_exclusion_entries,
            request_peer_cooldown_secs: config.request_peer_cooldown_secs,
            allow_ips,
            fail2ban_on_temp_exclusion: config.fail2ban_on_temp_exclusion,
        })
    }

    pub(crate) fn address_cooldown(&self) -> Duration {
        Duration::from_secs(self.address_cooldown_secs)
    }

    pub(crate) fn ip_exclusion(&self) -> Duration {
        Duration::from_secs(self.ip_exclusion_secs)
    }

    pub(crate) fn ip_extended_exclusion(&self) -> Duration {
        Duration::from_secs(self.ip_extended_exclusion_secs)
    }

    pub(crate) fn evidence_window(&self) -> Duration {
        Duration::from_secs(self.evidence_window_secs)
    }

    pub(crate) fn ip_exclusion_history(&self) -> Duration {
        Duration::from_secs(self.ip_exclusion_history_secs)
    }

    pub(crate) fn permission_denied_cooldown(&self) -> Duration {
        Duration::from_secs(self.permission_denied_cooldown_secs)
    }

    pub(crate) fn max_auto_exclusion(&self) -> Duration {
        Duration::from_secs(self.max_auto_exclusion_secs)
    }

    pub(crate) fn event_history(&self) -> Duration {
        self.evidence_window().max(self.ip_exclusion_history())
    }

    pub(crate) fn request_peer_cooldown(&self) -> Duration {
        Duration::from_secs(self.request_peer_cooldown_secs)
    }
}

impl LibP2PConfig {
    /// Load configuration from environment variables with NOCKCHAIN_LIBP2P_ prefix
    pub fn from_env() -> Result<Self, ConfigError> {
        let config = Config::builder()
            .add_source(Environment::with_prefix("NOCKCHAIN_LIBP2P"))
            .build()?;

        config.try_deserialize()
    }

    /// Load configuration from environment variables, falling back to defaults on error
    pub fn from_env_or_default() -> Self {
        Self::from_env().unwrap_or_default()
    }

    pub fn kad_protocol_version() -> &'static str {
        KAD_PROTOCOL_VERSION
    }

    pub fn req_res_protocol_version() -> &'static str {
        REQ_RES_PROTOCOL_VERSION
    }

    pub fn identify_protocol_version() -> &'static str {
        IDENTIFY_PROTOCOL_VERSION
    }

    /// Get kademlia bootstrap interval as Duration
    pub fn kademlia_bootstrap_interval(&self) -> Duration {
        Duration::from_secs(self.kademlia_bootstrap_interval_secs)
    }

    /// Get force peer dial interval as Duration
    pub fn force_peer_dial_interval(&self) -> Duration {
        Duration::from_secs(self.force_peer_dial_interval_secs)
    }

    /// Get swarm idle timeout as Duration
    pub fn swarm_idle_timeout(&self) -> Duration {
        Duration::from_secs(self.swarm_idle_timeout_secs)
    }

    /// Get keep alive interval as Duration
    pub fn keep_alive_interval(&self) -> Duration {
        Duration::from_secs(self.keep_alive_interval_secs)
    }

    /// Get handshake timeout as Duration
    pub fn handshake_timeout(&self) -> Duration {
        Duration::from_secs(self.handshake_timeout_secs)
    }

    /// Get identify interval as Duration
    pub fn identify_interval(&self) -> Duration {
        Duration::from_secs(self.identify_interval_secs)
    }

    /// Get request response timeout as Duration
    pub fn request_response_timeout(&self) -> Duration {
        Duration::from_secs(self.request_response_timeout_secs)
    }

    /// Get request high reset as Duration
    pub fn request_high_reset(&self) -> Duration {
        Duration::from_secs(self.request_high_reset_secs)
    }

    /// Get connection timeout (same as swarm idle timeout)
    pub fn connection_timeout(&self) -> Duration {
        self.swarm_idle_timeout()
    }

    /// Get max idle timeout in milliseconds for QUIC
    pub fn max_idle_timeout_millisecs(&self) -> u32 {
        self.connection_timeout().as_millis() as u32
    }

    /// Get request response max concurrent streams
    pub fn request_response_max_concurrent_streams(&self) -> usize {
        self.max_established_connections as usize * 8
    }

    pub fn peer_status_interval_secs(&self) -> std::time::Duration {
        Duration::from_secs(self.peer_status_interval_secs)
    }

    pub fn elders_debounce_reset(&self) -> std::time::Duration {
        Duration::from_secs(self.elders_debounce_reset_secs)
    }

    pub fn seen_tx_clear_interval(&self) -> u64 {
        self.seen_tx_clear_interval
    }

    pub fn min_peers(&self) -> usize {
        self.min_peers
    }

    pub fn poke_timeout_secs(&self) -> u64 {
        self.poke_timeout_secs
    }

    pub fn poke_timeout(&self) -> Duration {
        Duration::from_secs(self.poke_timeout_secs)
    }

    pub fn failed_pings_before_close(&self) -> u64 {
        self.failed_pings_before_close
    }

    pub(crate) fn peer_exclusion_config(&self) -> Result<PeerExclusionConfig, ConfigError> {
        PeerExclusionConfig::from_libp2p_config(self)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use crate::config::{LibP2PConfig, PeerExclusionConfig};

    #[test]
    fn peer_exclusion_config_parses_allow_ips_and_overrides() {
        let config = LibP2PConfig {
            ip_hygiene_enabled: false,
            address_cooldown_secs: 7,
            ip_exclusion_secs: 11,
            ip_extended_exclusion_secs: 13,
            evidence_window_secs: 17,
            ip_exclusion_history_secs: 19,
            permission_denied_cooldown_secs: 23,
            wrong_peer_id_ip_threshold: 3,
            dial_failure_ip_threshold: 5,
            same_ip_kad_entry_threshold: 8,
            max_auto_exclusion_secs: 29,
            max_exclusion_entries: 31,
            request_peer_cooldown_secs: 37,
            exclusion_allow_ips: String::from("203.0.113.1,2001:db8::1"),
            fail2ban_on_temp_exclusion: true,
            ..LibP2PConfig::default()
        };

        let exclusion =
            PeerExclusionConfig::from_libp2p_config(&config).expect("valid exclusion config");

        assert!(!exclusion.enabled);
        assert_eq!(exclusion.address_cooldown_secs, 7);
        assert_eq!(exclusion.max_exclusion_entries, 31);
        assert!(exclusion.fail2ban_on_temp_exclusion);
        assert!(exclusion
            .allow_ips
            .contains(&IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))));
        assert!(exclusion.allow_ips.contains(&IpAddr::V6(
            "2001:db8::1".parse::<Ipv6Addr>().expect("valid ipv6")
        )));
    }

    #[test]
    fn peer_exclusion_config_rejects_invalid_allow_ip() {
        let config = LibP2PConfig {
            exclusion_allow_ips: String::from("203.0.113.1,nope"),
            ..LibP2PConfig::default()
        };

        assert!(PeerExclusionConfig::from_libp2p_config(&config).is_err());
    }
}

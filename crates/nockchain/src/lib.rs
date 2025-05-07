use std::error::Error;
use std::fs;
use std::path::Path;

use clap::{arg, command, ArgAction, Parser};
use crown::kernel::boot;
use crown::nockapp::NockApp;
use libp2p::identity::Keypair;
use libp2p::multiaddr::Multiaddr;
use libp2p::{allow_block_list, connection_limits, memory_connection_limits, PeerId};
use nockchain_bitcoin_sync::{bitcoin_watcher_driver, BitcoinRPCConnection, GenesisNodeType};
use nockchain_libp2p_io::p2p::{
    MAX_ESTABLISHED_CONNECTIONS, MAX_ESTABLISHED_CONNECTIONS_PER_PEER,
    MAX_ESTABLISHED_INCOMING_CONNECTIONS, MAX_ESTABLISHED_OUTGOING_CONNECTIONS,
    MAX_PENDING_INCOMING_CONNECTIONS, MAX_PENDING_OUTGOING_CONNECTIONS,
};
use termcolor::{ColorChoice, StandardStream};
use tokio::net::UnixListener;
pub mod colors;
use std::path::PathBuf;

use clap::value_parser;
use colors::*;
use crown::noun::slab::NounSlab;
use nockchain_libp2p_io::nc::MiningKeyConfig;
use sword::jets::hot::HotEntry;
use sword::noun::{D, T};
use sword_macros::tas;
use tracing::{debug, info, instrument};

/// Module for handling driver initialization signals
pub mod driver_init {
    use crown::nockapp::driver::{make_driver, IODriverFn, PokeResult};
    use crown::nockapp::wire::{SystemWire, Wire};
    use crown::noun::slab::NounSlab;
    use sword::noun::{D, T};
    use sword_macros::tas;
    use tokio::sync::oneshot;
    use tracing::{debug, error, info};

    /// A collection of initialization signals for drivers
    #[derive(Default)]
    pub struct DriverInitSignals {
        /// Sender for the born signal
        pub born_tx: Option<oneshot::Sender<()>>,
        /// Receiver for the born signal
        pub born_rx: Option<oneshot::Receiver<()>>,
        /// Map of driver names to their initialization signal senders
        pub driver_signals: std::collections::HashMap<String, oneshot::Receiver<()>>,
    }

    impl DriverInitSignals {
        /// Create a new DriverInitSignals instance
        pub fn new() -> Self {
            let (born_tx, born_rx) = oneshot::channel();
            Self {
                born_tx: Some(born_tx),
                born_rx: Some(born_rx),
                driver_signals: std::collections::HashMap::new(),
            }
        }

        /// Register a driver with an initialization signal
        pub fn register_driver(&mut self, name: &str) -> oneshot::Sender<()> {
            let (tx, rx) = oneshot::channel();
            self.driver_signals.insert(name.to_string(), rx);
            tx
        }

        /// Get the initialization signal sender for a driver
        pub fn get_signal_sender(&self, name: &str) -> Option<&oneshot::Receiver<()>> {
            self.driver_signals.get(name)
        }

        /// Create a task that waits for all registered drivers to initialize
        pub fn create_born_task(&mut self) -> tokio::task::JoinHandle<()> {
            let born_tx = self.born_tx.take().expect("Born signal already used");
            let driver_signals = std::mem::take(&mut self.driver_signals);

            tokio::spawn(async move {
                // Wait for all registered drivers to initialize concurrently
                let mut join_set = tokio::task::JoinSet::new();
                for (name, rx) in driver_signals {
                    let name = name.clone();
                    join_set.spawn(async move {
                        let _ = rx.await;
                        info!("driver '{}' initialized", name);
                    });
                }

                // Wait for all tasks to complete
                while let Some(result) = join_set.join_next().await {
                    result.expect("Task panicked");
                }

                // Send the born poke signal
                let _ = born_tx.send(());
                info!("all drivers initialized, born poke sent");
            })
        }

        /// Create the born driver that waits for the born signal
        pub fn create_born_driver(&mut self) -> IODriverFn {
            let born_rx = self.born_rx.take().expect("born signal already used");

            make_driver(move |handle| {
                Box::pin(async move {
                    // Wait for the born signal
                    let _ = born_rx.await;

                    // Send the born poke
                    let mut born_slab = NounSlab::new();
                    let born = T(
                        &mut born_slab,
                        &[D(tas!(b"command")), D(tas!(b"born")), D(0)],
                    );
                    born_slab.set_root(born);
                    let wire = SystemWire.to_wire();
                    let result = handle.poke(wire, born_slab).await?;

                    match result {
                        PokeResult::Ack => debug!("born poke acknowledged"),
                        PokeResult::Nack => error!("Born poke nacked"),
                    }

                    Ok(())
                })
            })
        }
    }
}

// TODO: command-line/configure
/** Path to read current node's identity from */
pub const IDENTITY_PATH: &str = ".nockchain_identity";

/** Path to read current node's peer ID from */
pub const PEER_ID_EXTENSION: &str = ".peer_id";

// TODO: command-line/configure
/** Extension for peer ID files */
const PEER_ID_FILE_EXTENSION: &str = "peerid";

// Libp2p multiaddrs don't support const construction, so we have to put strings literals and parse them at startup
/** Backbone nodes for our testnet */
const TESTNET_BACKBONE_NODES: &[&str] = &[];

// Libp2p multiaddrs don't support const construction, so we have to put strings literals and parse them at startup
// TODO: feature flag testnet/realnet
/** Backbone nodes for our realnet */
#[allow(dead_code)]
const REALNET_BACKBONE_NODES: &[&str] = &[];

/** List of backbone nodes baked into the executable: we'll try to join these unconditionally */
const BACKBONE_NODES: &[&str] = TESTNET_BACKBONE_NODES;

/** How often we should affirmatively ask other nodes for their heaviest chain */
const CHAIN_INTERVAL_SECS: u64 = 20;

/// The height of the bitcoin block that we want to sync our genesis block to
/// Currently, this is the height of an existing block for testing. It will be
/// switched to a future block for launch.
const GENESIS_HEIGHT: u64 = 892723;

/// Command line arguments
#[derive(Parser, Debug, Clone)]
#[command(name = "nockchain")]
pub struct NockchainCli {
    #[command(flatten)]
    pub crown_cli: crown::kernel::boot::Cli,
    #[arg(
        long,
        help = "npc socket path",
        default_value = ".socket/nockchain_npc.sock"
    )]
    pub npc_socket: String,
    #[arg(long, help = "Mine in-kernel", default_value = "false")]
    pub mine: bool,
    #[arg(
        long,
        help = "Pubkey to mine to (mutually exclusive with --mining-key-adv)"
    )]
    pub mining_pubkey: Option<String>,
    #[arg(
        long,
        help = "Advanced mining key configuration (mutually exclusive with --mining-pubkey). Format: share,m:key1,key2,key3",
        value_parser = value_parser!(MiningKeyConfig),
        num_args = 1..,
        value_delimiter = ',',
    )]
    pub mining_key_adv: Option<Vec<MiningKeyConfig>>,
    #[arg(long, help = "Watch for genesis block", default_value = "false")]
    pub genesis_watcher: bool,
    #[arg(long, help = "Mine genesis block", default_value = "false")]
    pub genesis_leader: bool,
    #[arg(long, help = "use fake genesis block", default_value = "false")]
    pub fakenet: bool,
    #[arg(long, help = "Genesis block message", default_value = "Hail Zorp")]
    pub genesis_message: String,
    #[arg(
        long,
        help = "URL for Bitcoin Core RPC",
        default_value = "http://100.98.183.39:8332"
    )]
    pub btc_node_url: String,
    #[arg(long, help = "Username for Bitcoin Core RPC")]
    pub btc_username: Option<String>,
    #[arg(long, help = "Password for Bitcoin Core RPC")]
    pub btc_password: Option<String>,
    #[arg(long, help = "Auth cookie path for Bitcoin Core RPC")]
    pub btc_auth_cookie: Option<String>,
    #[arg(long, short, help = "Initial peer", action = ArgAction::Append)]
    pub peer: Vec<String>,
    #[arg(long, help = "Allowed peer IDs file")]
    pub allowed_peers_path: Option<String>,
    #[arg(long, help = "Don't dial default peers")]
    pub no_default_peers: bool,
    #[arg(long, help = "Bind address", action = ArgAction::Append)]
    pub bind: Vec<String>,
    #[arg(
        long,
        help = "Generate a new peer ID, discarding the existing one",
        default_value = "false"
    )]
    pub new_peer_id: bool,
    #[arg(long, help = "Maximum established incoming connections")]
    pub max_established_incoming: Option<u32>,
    #[arg(long, help = "Maximum established outgoing connections")]
    pub max_established_outgoing: Option<u32>,
    #[arg(long, help = "Maximum pending incoming connections")]
    pub max_pending_incoming: Option<u32>,
    #[arg(long, help = "Maximum pending outgoing connections")]
    pub max_pending_outgoing: Option<u32>,
    #[arg(long, help = "Maximum established connections")]
    pub max_established: Option<u32>,
    #[arg(long, help = "Maximum established connections per peer")]
    pub max_established_per_peer: Option<u32>,
    #[arg(long, help = "Maximum system memory percentage for connection limits")]
    pub max_system_memory_fraction: Option<f64>,
    #[arg(long, help = "Maximum process memory for connection limits (bytes)")]
    pub max_system_memory_bytes: Option<usize>,
}

impl NockchainCli {
    pub fn validate(&self) -> Result<(), String> {
        if self.mining_pubkey.is_some() && self.mining_key_adv.is_some() {
            return Err(
                "Cannot specify both mining_pubkey and mining_key_adv at the same time".to_string(),
            );
        }

        if self.genesis_leader && self.genesis_watcher {
            return Err(
                "Cannot specify both genesis_leader and genesis_watcher at the same time"
                    .to_string(),
            );
        }

        if !self.fakenet && (self.genesis_watcher || self.genesis_leader) {
            if self.btc_node_url.is_empty() {
                return Err(
                    "Must specify --btc-node-url when using genesis_watcher or genesis_leader"
                        .to_string(),
                );
            }
            if self.btc_auth_cookie.is_none() {
                if self.btc_username.is_none() && self.btc_password.is_none() {
                    return Err("Must specify either --btc-username or --btc-password when using genesis_watcher or genesis_leader on livenet".to_string());
                }
            }
        }

        Ok(())
    }

    /// Helper function to create a BitcoinRPCConnection from CLI arguments
    fn create_bitcoin_connection(&self) -> BitcoinRPCConnection {
        let url = self.btc_node_url.clone();
        let height = GENESIS_HEIGHT;
        let auth = if let Some(username) = self.btc_username.clone() {
            let password = self.btc_password.clone().unwrap_or_else(|| {
                panic!(
                    "Panicked at {}:{} (git sha: {:?})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA")
                )
            });
            bitcoincore_rpc::Auth::UserPass(username, password)
        } else {
            let cookie_path_str = self.btc_auth_cookie.clone().unwrap_or_else(|| {
                panic!(
                    "Panicked at {}:{} (git sha: {:?})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA")
                )
            });
            let cookie_path = PathBuf::from(cookie_path_str);
            bitcoincore_rpc::Auth::CookieFile(cookie_path)
        };
        BitcoinRPCConnection::new(url, auth, height)
    }
}

/// # Load a keypair from a file or create a new one if the file doesn't exist
///
/// This function attempts to read a keypair from a specified file. If the file exists, it reads the keypair from the file.
/// If the file does not exist, it generates a new keypair, writes it to the file, and returns it.
///
/// # Arguments
/// * `keypair_path` - A reference to a Path object representing the file path where the keypair should be stored
/// * `force_new` - If true, generate a new keypair even if one already exists
///
/// # Returns
/// A Result containing the Keypair or an error if any operation fails
pub fn gen_keypair(keypair_path: &Path) -> Result<Keypair, Box<dyn Error>> {
    let new_keypair = libp2p::identity::Keypair::generate_ed25519();
    let new_keypair_bytes = new_keypair.to_protobuf_encoding()?;
    std::fs::write(keypair_path, new_keypair_bytes)?;
    let peer_id = new_keypair.public().to_peer_id();
    // write the peer_id encoded as base58 to a file
    std::fs::write(
        keypair_path.with_extension(PEER_ID_FILE_EXTENSION),
        peer_id.to_base58(),
    )?;
    info!("Generated new identity as peer {peer_id}");
    Ok(new_keypair)
}

fn load_keypair(keypair_path: &Path, force_new: bool) -> Result<Keypair, Box<dyn Error>> {
    if keypair_path.try_exists()? && !force_new {
        let keypair_bytes = std::fs::read(keypair_path)?;
        let keypair = libp2p::identity::Keypair::from_protobuf_encoding(&keypair_bytes[..])?;
        let peer_id = keypair.public().to_peer_id();
        info!("Loaded identity as peer {peer_id}");
        Ok(keypair)
    } else {
        if force_new && keypair_path.try_exists()? {
            info!("Discarding existing peer ID and generating a new one");
            std::fs::remove_file(keypair_path)?;
        }
        gen_keypair(keypair_path)
    }
}

#[instrument(skip(kernel_jam, hot_state))]
pub async fn init_with_kernel(
    cli: Option<NockchainCli>,
    kernel_jam: &[u8],
    hot_state: &[HotEntry],
) -> Result<NockApp, Box<dyn Error>> {
    welcome();

    if let Some(cli) = &cli {
        cli.validate()?;
    }

    let mut nockapp = boot::setup(
        kernel_jam,
        cli.as_ref().map(|c| c.crown_cli.clone()),
        hot_state,
        "nockchain",
        None,
    )
    .await?;

    let keypair = {
        let keypair_path = Path::new(IDENTITY_PATH);
        load_keypair(
            keypair_path,
            cli.as_ref().map(|c| c.new_peer_id).unwrap_or(false),
        )?
    };
    eprintln!(
        "allowed_peers_path: {:?}",
        cli.as_ref().unwrap().allowed_peers_path
    );
    let allowed = cli.as_ref().and_then(|c| {
        c.allowed_peers_path.as_ref().map(|path| {
            let contents = fs::read_to_string(path).expect("failed to read allowed peers file: {}");
            let peer_ids: Vec<PeerId> = contents
                .lines()
                .map(|line| {
                    let peer_id_bytes = bs58::decode(line)
                        .into_vec()
                        .expect("failed to decode peer ID bytes from base58");
                    PeerId::from_bytes(&peer_id_bytes).expect("failed to decode peer ID from bytes")
                })
                .collect();
            let mut allow_behavior =
                allow_block_list::Behaviour::<allow_block_list::AllowedPeers>::default();
            for peer_id in peer_ids {
                allow_behavior.allow_peer(peer_id);
            }
            allow_behavior
        })
    });

    let bind_multiaddrs = cli
        .as_ref()
        .map_or(vec!["/ip4/0.0.0.0/udp/0/quic-v1".parse()?], |c| {
            c.bind
                .clone()
                .into_iter()
                .map(|addr_str| addr_str.parse().expect("could not parse bind multiaddr"))
                .collect()
        });

    let limits = connection_limits::ConnectionLimits::default()
        .with_max_established_incoming(
            cli.as_ref()
                .and_then(|c| c.max_established_incoming)
                .and(Some(MAX_ESTABLISHED_INCOMING_CONNECTIONS)),
        )
        .with_max_established_outgoing(
            cli.as_ref()
                .and_then(|c| c.max_established_outgoing)
                .and(Some(MAX_ESTABLISHED_OUTGOING_CONNECTIONS)),
        )
        .with_max_pending_incoming(
            cli.as_ref()
                .and_then(|c| c.max_pending_incoming)
                .and(Some(MAX_PENDING_INCOMING_CONNECTIONS)),
        )
        .with_max_pending_outgoing(
            cli.as_ref()
                .and_then(|c| c.max_pending_outgoing)
                .and(Some(MAX_PENDING_OUTGOING_CONNECTIONS)),
        )
        .with_max_established(
            cli.as_ref()
                .and_then(|c| c.max_established)
                .and(Some(MAX_ESTABLISHED_CONNECTIONS)),
        )
        .with_max_established_per_peer(
            cli.as_ref()
                .and_then(|c| c.max_established_per_peer)
                .and(Some(MAX_ESTABLISHED_CONNECTIONS_PER_PEER)),
        );
    let memory_limits = cli.as_ref().and_then(|c| {
        if c.max_system_memory_bytes.is_some() && c.max_system_memory_fraction.is_some() { panic!( "Must provide neither or one of --max-system-memory_bytes or --max-system-memory_percentage" )};
        if let Some(max_bytes) = c.max_system_memory_bytes {
            Some(memory_connection_limits::Behaviour::with_max_bytes(max_bytes))
        } else { c.max_system_memory_fraction.map(memory_connection_limits::Behaviour::with_max_percentage) }
    });

    let backbone_peers = BACKBONE_NODES
        .iter()
        .map(|multiaddr_str| {
            multiaddr_str
                .parse()
                .expect("could not parse multiaddr from built-in string")
        })
        .collect();

    // Set up initial peer addresses to connect to
    let mut peer_multiaddrs: Vec<Multiaddr> = if cli.as_ref().is_some_and(|c| c.no_default_peers) {
        Vec::new()
    } else {
        backbone_peers
    };

    if let Some(c) = cli.as_ref() {
        let v: Vec<Multiaddr> = c
            .peer
            .clone()
            .into_iter()
            .map(|multiaddr_str| {
                multiaddr_str
                    .parse()
                    .expect("could not parse multiaddr from string")
            })
            .collect();
        peer_multiaddrs.extend(v);
    }

    debug!("peer_multiaddrs: {:?}", peer_multiaddrs);

    let equix_builder = equix::EquiXBuilder::new();

    // Create driver initialization signals. the idea here is that we want to wait for
    // drivers that emit init pokes to complete before we send the born poke.
    let mut driver_signals = driver_init::DriverInitSignals::new();

    // Register drivers that need initialization signals
    let libp2p_init_tx = driver_signals.register_driver("libp2p");
    let watcher_init_tx = driver_signals.register_driver("bitcoin_watcher");

    // Create the born task that waits for all drivers to initialize
    let _born_task = driver_signals.create_born_task();

    if cli.as_ref().map(|c| c.fakenet).unwrap_or(false) {
        let message = cli
            .as_ref()
            .map(|c| c.genesis_message.clone())
            .unwrap_or("".to_string());
        let node_type = if cli.as_ref().map(|c| c.genesis_leader).unwrap_or(false) {
            GenesisNodeType::Leader
        } else {
            GenesisNodeType::Watcher
        };
        let watcher_driver =
            bitcoin_watcher_driver(None, node_type, message, Some(watcher_init_tx));
        nockapp.add_io_driver(watcher_driver).await;
    } else if cli
        .as_ref()
        .map(|c| c.genesis_watcher || c.genesis_leader)
        .unwrap_or(false)
    {
        let message = cli
            .as_ref()
            .map(|c| c.genesis_message.clone())
            .unwrap_or("".to_string());
        let connection = cli.as_ref().unwrap().create_bitcoin_connection();
        let node_type = if cli.as_ref().map(|c| c.genesis_leader).unwrap_or(false) {
            GenesisNodeType::Leader
        } else {
            GenesisNodeType::Watcher
        };
        let watcher_driver =
            bitcoin_watcher_driver(Some(connection), node_type, message, Some(watcher_init_tx));
        nockapp.add_io_driver(watcher_driver).await;
    }

    let libp2p_driver = nockchain_libp2p_io::nc::make_libp2p_driver(
        keypair,
        bind_multiaddrs,
        allowed,
        limits,
        memory_limits,
        &peer_multiaddrs,
        equix_builder,
        cli.as_ref().and_then(|c| {
            if let Some(pubkey) = &c.mining_pubkey {
                Some(vec![nockchain_libp2p_io::nc::MiningKeyConfig {
                    share: 1,
                    m: 1,
                    keys: vec![pubkey.clone()],
                }])
            } else {
                c.mining_key_adv.clone()
            }
        }),
        Some(libp2p_init_tx),
    );
    nockapp.add_io_driver(libp2p_driver).await;

    // Create the born driver that waits for the born signal
    let born_driver = driver_signals.create_born_driver();

    // Add the born driver to the nockapp
    nockapp.add_io_driver(born_driver).await;

    // set up socket
    let socket_path = Path::new(
        &cli.as_ref()
            .unwrap_or_else(|| {
                panic!(
                    "Panicked at {}:{} (git sha: {:?})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA")
                )
            })
            .npc_socket,
    );
    nockapp.npc_socket_path = Some(socket_path.to_path_buf());

    if let Some(parent) = socket_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let listener = UnixListener::bind(socket_path)?;

    nockapp
        .add_io_driver(crown::npc_listener_driver(listener))
        .await;

    // set up timer
    let mut timer_slab = NounSlab::new();
    let timer_noun = T(
        &mut timer_slab,
        &[D(tas!(b"command")), D(tas!(b"timer")), D(0)],
    );
    timer_slab.set_root(timer_noun);
    nockapp
        .add_io_driver(crown::timer_driver(CHAIN_INTERVAL_SECS, timer_slab))
        .await;

    Ok(nockapp)
}

fn welcome() {
    let mut stdout = StandardStream::stdout(ColorChoice::Auto);

    let banner = "
    _   _            _        _           _
   | \\ | | ___   ___| | _____| |__   __ _(_)_ __
   |  \\| |/ _ \\ / __| |/ / __| '_ \\ / _` | | '_ \\
   | |\\  | (_) | (__|   < (__| | | | (_| | | | | |
   |_| \\_|\\___/ \\___|_|\\_\\___|_| |_|\\__,_|_|_| |_|
   ";

    print_banner(&mut stdout, banner);

    let info = [
        ("Build label", env!("BUILD_EMBED_LABEL")),
        ("Build host", env!("BUILD_HOST")),
        ("Build user", env!("BUILD_USER")),
        ("Build timestamp", env!("BUILD_TIMESTAMP")),
        ("Build date", env!("FORMATTED_DATE")),
        // ("Git commit", env!("BAZEL_GIT_COMMIT")),
        // ("Build timestamp", env!("VERGEN_BUILD_TIMESTAMP")),
        // ("Cargo debug", env!("VERGEN_CARGO_DEBUG")),
        // ("Cargo features", env!("VERGEN_CARGO_FEATURES")),
        // ("Cargo opt level", env!("VERGEN_CARGO_OPT_LEVEL")),
        // ("Cargo target", env!("VERGEN_CARGO_TARGET_TRIPLE")),
        // ("Git branch", env!("VERGEN_GIT_BRANCH")),
        // ("Git commit date", env!("VERGEN_GIT_COMMIT_DATE")),
        // ("Git commit author", env!("VERGEN_GIT_COMMIT_AUTHOR_NAME")),
        // ("Git commit message", env!("VERGEN_GIT_COMMIT_MESSAGE")),
        // ("Git commit timestamp", env!("VERGEN_GIT_COMMIT_TIMESTAMP")),
        // ("Git commit SHA", env!("VERGEN_GIT_SHA")),
        // ("Rustc channel", env!("VERGEN_RUSTC_CHANNEL")),
        // ("Rustc host", env!("VERGEN_RUSTC_HOST_TRIPLE")),
        // ("Rustc LLVM version", env!("VERGEN_RUSTC_LLVM_VERSION")),
    ];

    print_version_info(&mut stdout, &info);
}

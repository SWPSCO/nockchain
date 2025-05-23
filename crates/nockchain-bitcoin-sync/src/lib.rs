use std::error::Error;
use std::str::FromStr;
use std::sync::Arc;

use bitcoincore_rpc::bitcoin::BlockHash;
use bitcoincore_rpc::bitcoincore_rpc_json::{BlockRef, GetBlockResult};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use ibig::ops::DivRem;
use ibig::{ubig, UBig};
use nockapp::driver::{make_driver, IODriverFn};
use nockapp::noun::slab::NounSlab;
use nockapp::wire::{SystemWire, Wire};
use nockapp::{AtomExt, Bytes, ToBytes};
use nockvm::noun::{Atom, Noun, NounAllocator, D, T};
use nockvm_macros::tas;
use tokio::sync::oneshot::channel;
use tokio::sync::RwLock;
use tracing::{debug, info, instrument};
use zkvm_jetpack::form::math::base::PRIME;

/** Hash used for test genesis block */
const TEST_GENESIS_BLOCK_HASH: &str =
    "00000000e6c3c75c18bdb06cc39d616d636fca0fc967c29ebf8225ddf7f2fe48";
const TEST_GENESIS_BLOCK_HEIGHT: u64 = 2048;

const GENESIS_SEAL_MSG: &str = "2c8Ltbg44dPkEGcNPupcVAtDgD87753M9pG2fg8yC2mTEqg5qAFvvbT";

/// Helper function to get the test block used for fake genesis blocks
fn get_test_block() -> BlockRef {
    BlockRef {
        hash: BlockHash::from_str(TEST_GENESIS_BLOCK_HASH).unwrap_or_else(|err| {
            panic!(
                "Panicked with {err:?} at {}:{} (git sha: {:?})",
                file!(),
                line!(),
                option_env!("GIT_SHA")
            )
        }),
        height: TEST_GENESIS_BLOCK_HEIGHT,
    }
}

/// Convert a GetBlockResult to a BlockRef
fn get_block_ref_from_result(block: &GetBlockResult) -> BlockRef {
    BlockRef {
        hash: block.hash,
        height: block.height as u64,
    }
}

/// Represents the type of node in the network
#[derive(Debug)]
pub enum GenesisNodeType {
    /// A node that will attempt to mine the genesis block
    Leader,
    /// A node that will wait to see a genesis block but not mine it
    Watcher,
}

/// Connection information for the Bitcoin watcher
#[derive(Debug)]
pub struct BitcoinRPCConnection {
    /// The URL of the Bitcoin RPC node
    pub url: String,
    /// Authentication credentials for the Bitcoin RPC node
    pub auth: Auth,
    /// The desired block height to watch for
    pub wanted_height: u64,
}

impl BitcoinRPCConnection {
    /// Create a new BitcoinRPCConnection
    pub fn new(url: String, auth: Auth, wanted_height: u64) -> Self {
        BitcoinRPCConnection {
            url,
            auth,
            wanted_height,
        }
    }
}

#[instrument]
pub fn bitcoin_watcher_driver(
    connection: Option<BitcoinRPCConnection>,
    node_type: GenesisNodeType,
    message: String,
    init_signal_tx: Option<tokio::sync::oneshot::Sender<()>>,
) -> IODriverFn {
    make_driver(|handle| async move {
        debug!(
            "Starting bitcoin_watcher_driver with node_type: {:?}",
            node_type
        );
        if let Some(conn) = connection {
            debug!("Using Bitcoin RPC connection to: {}", conn.url);
            let watcher = BitcoinWatcher::new(conn).await.unwrap_or_else(|err| {
                panic!(
                    "Panicked with {err:?} at {}:{} (git sha: {:?})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA")
                )
            });
            debug!("BitcoinWatcher initialized successfully");

            match node_type {
                GenesisNodeType::Leader => {
                    debug!("Node type is Miner, watching for target bitcoin block...");
                    let block = watcher.watch().await.unwrap_or_else(|err| {
                        panic!(
                            "Panicked with {err:?} at {}:{} (git sha: {:?})",
                            file!(),
                            line!(),
                            option_env!("GIT_SHA")
                        )
                    });
                    debug!(
                        "Target bitcoin block found: hash={}, height={}",
                        block.hash, block.height
                    );

                    let mut poke_slab = NounSlab::new();
                    let block_height_noun =
                        Atom::new(&mut poke_slab, TEST_GENESIS_BLOCK_HEIGHT).as_noun();
                    let seal_byts = Bytes::from(GENESIS_SEAL_MSG.to_bytes().expect("blah 242"));
                    let seal_noun = Atom::from_bytes(&mut poke_slab, &seal_byts).as_noun();
                    let set_genesis_seal_byts = Bytes::from(b"set-genesis-seal".to_vec());
                    let set_genesis_seal =
                        Atom::from_bytes(&mut poke_slab, &set_genesis_seal_byts).as_noun();
                    let poke_noun = T(
                        &mut poke_slab,
                        &[D(tas!(b"command")), set_genesis_seal, block_height_noun, seal_noun],
                    );
                    poke_slab.set_root(poke_noun);

                    let wire = SystemWire.to_wire();
                    debug!("Setting genesis seal");
                    handle.poke(wire, poke_slab).await?;
                    debug!("Genesis seal set successfully");

                    let mut poke_slab = NounSlab::new();
                    let template = bitcoin_block_to_genesis_template(
                        &mut poke_slab,
                        get_block_ref_from_result(&block),
                        &message,
                    );
                    let poke_noun = T(
                        &mut poke_slab,
                        &[D(tas!(b"command")), D(tas!(b"genesis")), template],
                    );
                    poke_slab.set_root(poke_noun);

                    let wire = SystemWire.to_wire();
                    debug!("Setting genesis template");
                    handle.poke(wire, poke_slab).await?;
                    debug!("Genesis template set successfully");

                    // Signal that initialization is complete
                    if let Some(tx) = init_signal_tx {
                        let _ = tx.send(());
                        info!("Bitcoin watcher driver initialization complete signal sent");
                    }
                }
                GenesisNodeType::Watcher => {
                    debug!("Node type is Node, watching for bitcoin block for genesis...");

                    let mut poke_slab = NounSlab::new();
                    let block_height_noun =
                        Atom::new(&mut poke_slab, TEST_GENESIS_BLOCK_HEIGHT).as_noun();
                    let seal_byts = Bytes::from(GENESIS_SEAL_MSG.to_bytes().expect("blah 242"));
                    let seal_noun = Atom::from_bytes(&mut poke_slab, &seal_byts).as_noun();
                    let set_genesis_seal_byts = Bytes::from(b"set-genesis-seal".to_vec());
                    let set_genesis_seal =
                        Atom::from_bytes(&mut poke_slab, &set_genesis_seal_byts).as_noun();
                    let poke_noun = T(
                        &mut poke_slab,
                        &[D(tas!(b"command")), set_genesis_seal, block_height_noun, seal_noun],
                    );
                    poke_slab.set_root(poke_noun);

                    let wire = SystemWire.to_wire();
                    debug!("Setting genesis seal");
                    handle.poke(wire, poke_slab).await?;
                    debug!("Genesis seal set successfully");

                    let block = watcher
                        .watch()
                        .await
                        .expect("Failed to watch for bitcoin block for genesis");
                    debug!(
                        "Bitcoin block for genesis found: hash={}, height={}",
                        block.hash, block.height
                    );
                    let mut poke_slab = NounSlab::new();

                    // Send a %btc-data command with just the block hash
                    let hash_tuple = block_hash_to_belts(&mut poke_slab, &block.hash);
                    let poke_noun = T(
                        &mut poke_slab,
                        &[D(tas!(b"command")), D(tas!(b"btc-data")), D(0), hash_tuple],
                    );
                    poke_slab.set_root(poke_noun);

                    debug!("Sending btc-data command");
                    let wire = SystemWire.to_wire();
                    handle.poke(wire, poke_slab).await?;
                    debug!("btc-data command sent successfully");
                    // Signal that initialization is complete
                    if let Some(tx) = init_signal_tx {
                        let _ = tx.send(());
                        info!("Bitcoin watcher driver initialization complete signal sent");
                    }
                }
            }
        } else {
            debug!("No Bitcoin RPC connection provided, using test genesis block");
            let wire = SystemWire.to_wire();
            match node_type {
                GenesisNodeType::Leader => {
                    debug!("Creating test genesis block for leader node");
                    let poke_slab = make_test_genesis_block(&message);
                    handle.poke(wire, poke_slab).await?;
                    debug!("test genesis block template sent successfully");
                    // Signal that initialization is complete
                    if let Some(tx) = init_signal_tx {
                        let _ = tx.send(());
                        info!("Bitcoin watcher driver initialization complete signal sent");
                    }
                }
                GenesisNodeType::Watcher => {
                    debug!("Send %btc-data command with test genesis block hash for watcher node");
                    // For nodes, send a %btc-data command with the hash from make_test_genesis_block
                    let mut poke_slab = NounSlab::new();
                    let test_block = get_test_block();
                    debug!(
                        "Using test block: hash={}, height={}",
                        test_block.hash, test_block.height
                    );

                    // Send a %btc-data command with just the block hash
                    let hash_tuple = block_hash_to_belts(&mut poke_slab, &test_block.hash);
                    let poke_noun = T(
                        &mut poke_slab,
                        &[D(tas!(b"command")), D(tas!(b"btc-data")), D(0), hash_tuple],
                    );
                    poke_slab.set_root(poke_noun);

                    handle.poke(wire, poke_slab).await?;
                    debug!("btc-data command for fake genesis block sent successfully");
                    // Signal that initialization is complete
                    if let Some(tx) = init_signal_tx {
                        let _ = tx.send(());
                        info!("Bitcoin watcher driver initialization complete signal sent");
                    }
                }
            }
        }
        debug!("bitcoin_watcher_driver completed successfully");
        Ok(())
    })
}

fn make_test_genesis_block(message: &String) -> NounSlab {
    // we use bitcoin block 2048 for testing
    let test_block = get_test_block();
    let mut poke_slab = NounSlab::new();

    let template = bitcoin_block_to_genesis_template(&mut poke_slab, test_block, message);
    let poke_noun = T(
        &mut poke_slab,
        &[D(tas!(b"command")), D(tas!(b"genesis")), template],
    );
    poke_slab.set_root(poke_noun);

    poke_slab
}

fn bitcoin_block_to_genesis_template<A: NounAllocator>(
    allocator: &mut A,
    block: BlockRef,
    message: &String,
) -> Noun {
    let hash_tuple = block_hash_to_belts(allocator, &block.hash);
    let block_height_noun = Atom::new(allocator, block.height).as_noun();
    let msg_byts = Bytes::from(message.to_bytes().expect("blah 242"));
    let message_noun = Atom::from_bytes(allocator, &msg_byts).as_noun();
    T(allocator, &[hash_tuple, block_height_noun, message_noun])
}

fn block_hash_to_belts<A: NounAllocator>(allocator: &mut A, hash: &BlockHash) -> Noun {
    let hash_ubig = UBig::from_le_bytes(hash.as_ref());

    let (hash_ubig_1, digit_0) = hash_ubig.div_rem(PRIME);
    let (hash_ubig_2, digit_1) = hash_ubig_1.div_rem(PRIME);
    let (hash_ubig_3, digit_2) = hash_ubig_2.div_rem(PRIME);
    let (hash_ubig_4, digit_3) = hash_ubig_3.div_rem(PRIME);
    let (hash_ubig_5, digit_4) = hash_ubig_4.div_rem(PRIME);
    let (hash_ubig_6, digit_5) = hash_ubig_5.div_rem(PRIME);
    let (hash_ubig_7, digit_6) = hash_ubig_6.div_rem(PRIME);
    let (hash_ubig_8, digit_7) = hash_ubig_7.div_rem(PRIME);
    assert!(hash_ubig_8 == ubig!(0));

    let mut tuple_elements = Vec::new();

    for digit in [digit_0, digit_1, digit_2, digit_3, digit_4, digit_5, digit_6, digit_7] {
        tuple_elements.push(Atom::new(allocator, digit).as_noun());
    }

    T(allocator, &tuple_elements[..])
}

#[derive(Debug)]
pub struct BitcoinWatcher {
    wanted_height: u64,
    client: Arc<RwLock<Client>>,
}

impl BitcoinWatcher {
    pub async fn new(connection: BitcoinRPCConnection) -> Result<BitcoinWatcher, Box<dyn Error>> {
        debug!(
            "Creating new BitcoinWatcher with wanted_height: {}",
            connection.wanted_height
        );
        let (tx, rx) = channel();
        tokio::task::spawn_blocking(move || {
            let new_result = Client::new(connection.url.as_ref(), connection.auth).map(|c| {
                let client = Arc::new(RwLock::new(c));
                BitcoinWatcher {
                    wanted_height: connection.wanted_height,
                    client,
                }
            });
            tx.send(new_result).unwrap_or_else(|err| {
                panic!(
                    "Panicked with {err:?} at {}:{} (git sha: {:?})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA")
                )
            });
        })
        .await?;
        Ok(rx.await??)
    }

    #[allow(clippy::comparison_chain)]
    pub async fn watch(&self) -> Result<GetBlockResult, Box<dyn Error>> {
        let wanted_height = self.wanted_height;
        debug!("Starting watch() for block at height: {}", wanted_height);

        loop {
            debug!("Attempting to get block hash at height: {}", wanted_height);
            let client = self.client.clone().read_owned().await;

            // Try to get the block hash at the desired height
            let block_hash_result =
                tokio::task::spawn_blocking(move || (*client).get_block_hash(wanted_height))
                    .await?;

            match block_hash_result {
                Ok(block_hash) => {
                    debug!(
                        "Block hash found at height {}: {}",
                        wanted_height, block_hash
                    );
                    // Block exists, get the full block info
                    let client = self.client.clone().read_owned().await;
                    let block_info =
                        tokio::task::spawn_blocking(move || (*client).get_block_info(&block_hash))
                            .await??;

                    debug!(
                        "Block info retrieved: hash={}, height={}, confirmations={}",
                        block_info.hash, block_info.height, block_info.confirmations
                    );

                    // Check if the block has enough confirmations
                    if block_info.confirmations >= 2 {
                        debug!(
                            "Block has sufficient confirmations ({}), returning",
                            block_info.confirmations
                        );
                        return Ok(block_info);
                    } else {
                        // Not enough confirmations yet, wait and try again
                        debug!(
                            "Block at height {} has {} confirmations, waiting for at least 3...",
                            wanted_height, block_info.confirmations
                        );
                        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    }
                }
                Err(e) => {
                    // Block doesn't exist yet, wait and try again
                    debug!(
                        "Block at height {} not found yet, waiting... Error: {}",
                        wanted_height, e
                    );
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                }
            }
        }
    }
}

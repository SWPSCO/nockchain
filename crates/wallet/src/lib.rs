use std::fs;
use std::path::PathBuf;

use crown::kernel::boot::{self, Cli as BootCli};
use crown::nockapp::driver::*;
use crown::nockapp::{NockApp, NockAppError};
use crown::noun::slab::NounSlab;
use crown::noun::IntoNoun;
use crown::utils::make_tas;
use crown::{exit_driver, file_driver, markdown_driver, CrownError, ToBytesExt};
use getrandom::getrandom;
use sword::jets::cold::Nounable;
use sword::noun::{Atom, Cell, IndirectAtom, Noun, D, SIG, T};
use tokio::net::UnixStream;
use tracing::{error, info};
use zkvm_jetpack::hot::produce_prover_hot_state;

mod error;

pub use crown::utils::bytes::Byts;

// Re-export the WalletWire and Commands enums
pub mod wire;
pub use wire::{WalletWire, Commands, KeyType};

/// Represents a Noun that the wallet kernel can handle
pub type CommandNoun<T> = Result<(T, Operation), NockAppError>;

/// Wallet implementation providing cryptocurrency wallet functionality
pub struct Wallet {
    app: NockApp,
}

impl Wallet {
    /// Creates a new `Wallet` instance with the given kernel.
    ///
    /// This wraps the kernel in a NockApp, which exposes a substrate
    /// for kernel interaction with IO driver semantics.
    ///
    /// # Arguments
    ///
    /// * `kernel` - The kernel to initialize the wallet with.
    ///
    /// # Returns
    ///
    /// A new `Wallet` instance with the kernel initialized
    /// as a NockApp.
    pub fn new(nockapp: NockApp) -> Self {
        Wallet { app: nockapp }
    }

    /// Get the underlying NockApp instance
    pub fn app(&mut self) -> &mut NockApp {
        &mut self.app
    }

    /// Adds an IO driver to the wallet app
    pub async fn add_io_driver(&mut self, driver: crown::nockapp::driver::IODriverFn) {
        self.app.add_io_driver(driver).await;
    }

    /// Runs the wallet app
    pub async fn run(&mut self) -> Result<(), NockAppError> {
        // We need to run the app but can't move it out of self
        // Using a safer approach than std::ptr::read
        let result = self.app.run_no_join().await;
        result
    }
    
    /// Connect to a nockchain node via socket
    pub async fn connect_to_nockchain(&mut self, socket_path: &PathBuf) {
        match UnixStream::connect(socket_path).await {
            Ok(stream) => {
                info!("Connected to nockchain NPC socket at {:?}", socket_path);
                self.app.add_io_driver(crown::npc_client_driver(stream)).await;
            }
            Err(e) => {
                error!(
                    "Failed to connect to nockchain NPC socket at {:?}: {}\n\
                     This could mean:\n\
                     1. Nockchain is not running\n\
                     2. The socket path is incorrect\n\
                     3. The socket file exists but is stale (try removing it)\n\
                     4. Insufficient permissions to access the socket",
                    socket_path, e
                );
            }
        }
    }

    /// Wraps a command with sync-run to ensure it runs after block and balance updates
    ///
    /// # Arguments
    ///
    /// * `command_noun_slab` - The command noun to wrap
    /// * `operation` - The operation type (Poke or Peek)
    ///
    /// # Returns
    ///
    /// A result containing the wrapped command noun and operation, or an error
    pub fn wrap_with_sync_run(
        command_noun_slab: NounSlab,
        operation: Operation,
    ) -> Result<(NounSlab, Operation), NockAppError> {
        let original_root_noun_clone = unsafe { command_noun_slab.root() };
        let mut sync_slab = command_noun_slab.clone();
        let sync_tag = make_tas(&mut sync_slab, "sync-run");
        let tag_noun = sync_tag.as_noun();
        let sync_run_cell = Cell::new(&mut sync_slab, tag_noun, *original_root_noun_clone);
        let sync_run_noun = sync_run_cell.as_noun();
        sync_slab.set_root(sync_run_noun);

        Ok((sync_slab, operation))
    }

    /// Prepares a wallet command for execution.
    ///
    /// # Arguments
    ///
    /// * `command` - The command to execute.
    /// * `args` - The arguments for the command.
    /// * `operation` - The operation type (Poke or Peek).
    /// * `slab` - The NounSlab to use for the command.
    ///
    /// # Returns
    ///
    /// A `CommandNoun` containing the prepared NounSlab and operation.
    pub fn wallet(
        command: &str,
        args: &[Noun],
        operation: Operation,
        slab: &mut NounSlab,
    ) -> CommandNoun<NounSlab> {
        let head = make_tas(slab, command).as_noun();

        let tail = match args.len() {
            0 => D(0),
            1 => args[0],
            _ => T(slab, args),
        };

        let full = T(slab, &[head, tail]);

        slab.set_root(full);
        Ok((slab.clone(), operation))
    }

    /// Retrieves the wallet balance.
    pub fn wallet_balance() -> CommandNoun<NounSlab> {
        Self::wallet("balance", &[], Operation::Peek, &mut NounSlab::new())
    }

    /// Generates a new key pair.
    ///
    /// # Arguments
    ///
    /// * `entropy` - The entropy to use for key generation.
    pub fn keygen(entropy: &[u8; 32], sal: &[u8; 16]) -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        let ent: Byts = Byts::new(entropy.to_vec());
        let ent_noun = ent.into_noun(&mut slab);
        let sal: Byts = Byts::new(sal.to_vec());
        let sal_noun = sal.into_noun(&mut slab);
        Self::wallet("keygen", &[ent_noun, sal_noun], Operation::Poke, &mut slab)
    }

    // Derives a child key from current master key.
    //
    // # Arguments
    //
    // * `key_type` - The type of key to derive (e.g., "pub", "priv")
    // * `index` - The index of the child key to derive
    // TODO: add label if necessary
    pub fn derive_child(key_type: KeyType, index: u64) -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        let key_type_noun = make_tas(&mut slab, key_type.to_string()).as_noun();
        let index_noun = D(index);

        Self::wallet(
            "derive-child",
            &[key_type_noun, index_noun, SIG],
            Operation::Poke,
            &mut slab,
        )
    }

    /// Signs a transaction.
    ///
    /// # Arguments
    ///
    /// * `draft_path` - Path to the draft file
    /// * `index` - Optional index of the key to use for signing
    pub fn sign_tx(draft_path: &str, index: Option<u64>) -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();

        // Validate index is within range (though clap should prevent this)
        if let Some(idx) = index {
            if idx > 255 {
                return Err(CrownError::Unknown("Key index must not exceed 255".into()).into());
            }
        }

        // Read and decode the input bundle
        let draft_data = fs::read(draft_path)
            .map_err(|e| CrownError::Unknown(format!("Failed to read draft: {}", e)))?;

        // Convert the bundle data into a noun using cue
        let draft_noun = slab
            .cue_into(draft_data.as_bytes()?)
            .map_err(|e| CrownError::Unknown(format!("Failed to decode draft: {}", e)))?;

        let index_noun = match index {
            Some(i) => D(i),
            None => D(0),
        };

        // Generate random entropy
        let mut entropy_bytes = [0u8; 32];
        getrandom(&mut entropy_bytes).map_err(|e| CrownError::Unknown(e.to_string()))?;
        let entropy = from_bytes(&mut slab, &entropy_bytes).as_noun();

        Self::wallet(
            "sign-tx",
            &[draft_noun, index_noun, entropy],
            Operation::Poke,
            &mut slab,
        )
    }

    /// Shows the balance of a specific address at a given block.
    ///
    /// # Arguments
    ///
    /// * `block` - The block hash or height to show the balance at.
    pub fn balance_at_block(block: &str) -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        let block_noun = IntoNoun::into_noun(block);
        Self::wallet("show-balance", &[block_noun], Operation::Poke, &mut slab)
    }

    /// Generates a master private key from a seed phrase.
    ///
    /// # Arguments
    ///
    /// * `seedphrase` - The seed phrase to generate the master private key from.
    pub fn gen_master_privkey(seedphrase: &str) -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        let seedphrase_noun = make_tas(&mut slab, seedphrase).as_noun();
        Self::wallet(
            "gen-master-privkey",
            &[seedphrase_noun],
            Operation::Poke,
            &mut slab,
        )
    }

    /// Generates a master public key from a master private key.
    ///
    /// # Arguments
    ///
    /// * `master_privkey` - The master private key to generate the public key from.
    pub fn gen_master_pubkey(master_privkey: &str) -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        let master_privkey_noun = make_tas(&mut slab, master_privkey).as_noun();
        Self::wallet(
            "gen-master-pubkey",
            &[master_privkey_noun],
            Operation::Poke,
            &mut slab,
        )
    }

    /// Imports keys.
    ///
    /// # Arguments
    ///
    /// * `input_path` - Path to jammed keys file
    pub fn import_keys(input_path: &str) -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();

        let key_data = fs::read(input_path)
            .map_err(|e| CrownError::Unknown(format!("Failed to read master pubkeys: {}", e)))?;

        let pubkey_noun = slab
            .cue_into(key_data.as_bytes()?)
            .map_err(|e| CrownError::Unknown(format!("Failed to decode master pubkeys: {}", e)))?;

        Self::wallet("import-keys", &[pubkey_noun], Operation::Poke, &mut slab)
    }

    /// Performs a simple scan of the blockchain.
    ///
    /// # Arguments
    ///
    /// * `master_pubkey` - The master public key to scan for.
    /// * `search_depth` - How many addresses to scan (default 100)
    pub fn scan(
        master_pubkey: &str,
        search_depth: u64,
        include_timelocks: bool,
        include_multisig: bool,
    ) -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        let master_pubkey_noun = make_tas(&mut slab, master_pubkey).as_noun();
        let search_depth_noun = D(search_depth);
        let include_timelocks_noun = D(include_timelocks as u64);
        let include_multisig_noun = D(include_multisig as u64);

        Self::wallet(
            "scan",
            &[
                master_pubkey_noun, search_depth_noun, include_timelocks_noun,
                include_multisig_noun,
            ],
            Operation::Poke,
            &mut slab,
        )
    }

    /// Performs a simple spend operation by creating transaction inputs from notes.
    ///
    /// Takes a list of note names, recipient addresses, and gift amounts to create
    /// transaction inputs. The fee is subtracted from the first note that has sufficient
    /// assets to cover both the fee and its corresponding gift amount.
    ///
    /// # Arguments
    ///
    /// * `names` - Comma-separated list of note name pairs in format "[first last]"
    ///             Example: "[first1 last1],[first2 last2]"
    ///
    /// * `recipients` - Comma-separated list of recipient $locks
    ///                 Example: "[1 pk1],[2 pk2,pk3,pk4]"
    ///                 A simple comma-separated list is also supported: "pk1,pk2,pk3",
    ///                 where it is presumed that all recipients are single-signature,
    ///                 that is to say, it is the same as "[1 pk1],[1 pk2],[1 pk3]"
    ///
    /// * `gifts` - Comma-separated list of amounts to send to each recipient
    ///             Example: "100,200"
    ///
    /// * `fee` - Transaction fee to be subtracted from one of the input notes
    ///
    /// # Returns
    ///
    /// Returns a `CommandNoun` containing:
    /// - A `NounSlab` with the encoded simple-spend command
    /// - The `Operation` type (Poke)
    ///
    /// # Errors
    ///
    /// Returns `NockAppError` if:
    /// - Name pairs are not properly formatted as "[first last]"
    /// - Number of names, recipients, and gifts don't match
    /// - Any input parsing fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// let names = "[first1 last1],[first2 last2]";
    /// let recipients = "[1 pk1],[2 pk2,pk3,pk4]";
    /// let gifts = "100,200";
    /// let fee = 10;
    /// wallet.simple_spend(names.to_string(), recipients.to_string(), gifts.to_string(), fee)?;
    /// ```
    pub fn simple_spend(
        names: String,
        recipients: String,
        gifts: String,
        fee: u64,
    ) -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();

        // Split the comma-separated inputs
        // Each name should be in format "[first last]"
        let names_vec: Vec<(String, String)> = names
            .split(',')
            .filter_map(|pair| {
                let pair = pair.trim();
                if pair.starts_with('[') && pair.ends_with(']') {
                    let inner = &pair[1..pair.len() - 1];
                    let parts: Vec<&str> = inner.split_whitespace().collect();
                    if parts.len() == 2 {
                        Some((parts[0].to_string(), parts[1].to_string()))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        // Convert recipients to list of [number pubkeys] pairs
        let recipients_vec: Vec<(u64, Vec<String>)> = if recipients.contains('[') {
            // Parse complex format: "[1 pk1],[2 pk2,pk3,pk4]"
            recipients
                .split(',')
                .filter_map(|pair| {
                    let pair = pair.trim();
                    if pair.starts_with('[') && pair.ends_with(']') {
                        let inner = &pair[1..pair.len() - 1];
                        let mut parts = inner.splitn(2, ' ');

                        // Parse the number
                        let number = parts.next()?.parse().ok()?;

                        // Parse the pubkeys
                        let pubkeys = parts
                            .next()?
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .collect();

                        Some((number, pubkeys))
                    } else {
                        None
                    }
                })
                .collect()
        } else {
            // Parse simple format: "pk1,pk2,pk3"
            recipients
                .split(',')
                .map(|addr| (1, vec![addr.trim().to_string()]))
                .collect()
        };

        let gifts_vec: Vec<u64> = gifts.split(',').filter_map(|s| s.parse().ok()).collect();

        // Verify equal lengths
        if names_vec.len() != recipients_vec.len() || names_vec.len() != gifts_vec.len() {
            return Err(CrownError::Unknown(
                "Invalid input - names, recipients, and gifts must have the same length"
                    .to_string(),
            )
            .into());
        }

        // Convert names to list of pairs
        let names_noun = names_vec
            .into_iter()
            .rev()
            .fold(D(0), |acc, (first, last)| {
                // Create a tuple [first_name last_name] for each name pair
                let first_noun = make_tas(&mut slab, &first).as_noun();
                let last_noun = make_tas(&mut slab, &last).as_noun();
                let name_pair = T(&mut slab, &[first_noun, last_noun]);
                Cell::new(&mut slab, name_pair, acc).as_noun()
            });

        // Convert recipients to list
        let recipients_noun = recipients_vec
            .into_iter()
            .rev()
            .fold(D(0), |acc, (num, pubkeys)| {
                // Create the inner list of pubkeys
                let pubkeys_noun = pubkeys.into_iter().rev().fold(D(0), |acc, pubkey| {
                    let pubkey_noun = make_tas(&mut slab, &pubkey).as_noun();
                    Cell::new(&mut slab, pubkey_noun, acc).as_noun()
                });

                // Create the pair of [number pubkeys_list]
                let pair = T(&mut slab, &[D(num), pubkeys_noun]);
                Cell::new(&mut slab, pair, acc).as_noun()
            });

        // Convert gifts to list
        let gifts_noun = gifts_vec.into_iter().rev().fold(D(0), |acc, amount| {
            Cell::new(&mut slab, D(amount), acc).as_noun()
        });

        let fee_noun = D(fee);

        Self::wallet(
            "simple-spend",
            &[names_noun, recipients_noun, gifts_noun, fee_noun],
            Operation::Poke,
            &mut slab,
        )
    }

    pub fn update_balance() -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        Self::wallet("update-balance", &[], Operation::Poke, &mut slab)
    }

    /// Lists all notes in the wallet.
    ///
    /// Retrieves and displays all notes from the wallet's balance, sorted by assets.
    pub fn list_notes() -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        Self::wallet("list-notes", &[], Operation::Poke, &mut slab)
    }

    /// Imports a master public key.
    ///
    /// # Arguments
    ///
    /// * `key` - Base58-encoded public key
    /// * `knot` - Base58-encoded chain code
    pub fn import_master_pubkey(key: &str, knot: &str) -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        let key_noun = make_tas(&mut slab, key).as_noun();
        let knot_noun = make_tas(&mut slab, knot).as_noun();

        Self::wallet(
            "import-master-pubkey",
            &[key_noun, knot_noun],
            Operation::Poke,
            &mut slab,
        )
    }

    /// Creates a transaction from a draft file.
    ///
    /// # Arguments
    ///
    /// * `draft_path` - Path to the draft file to create transaction from
    pub fn make_tx(draft_path: &str) -> CommandNoun<NounSlab> {
        // Read and decode the draft file
        let draft_data = fs::read(draft_path)
            .map_err(|e| CrownError::Unknown(format!("Failed to read draft file: {}", e)))?;

        let mut slab = NounSlab::new();
        let draft_noun = slab
            .cue_into(draft_data.as_bytes()?)
            .map_err(|e| CrownError::Unknown(format!("Failed to decode draft data: {}", e)))?;

        Self::wallet("make-tx", &[draft_noun], Operation::Poke, &mut slab)
    }

    /// Lists all public keys in the wallet.
    pub fn list_pubkeys() -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        Self::wallet("list-pubkeys", &[], Operation::Poke, &mut slab)
    }

    /// Lists notes by public key
    pub fn list_notes_by_pubkey(pubkey: &str) -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        let pubkey_noun = make_tas(&mut slab, pubkey).as_noun();
        Self::wallet(
            "list-notes-by-pubkey",
            &[pubkey_noun],
            Operation::Poke,
            &mut slab,
        )
    }
}

/// Helper function to convert from bytes to an Atom
pub fn from_bytes(stack: &mut NounSlab, bytes: &[u8]) -> Atom {
    unsafe {
        let mut tas_atom = IndirectAtom::new_raw_bytes(stack, bytes.len(), bytes.as_ptr());
        tas_atom.normalize_as_atom()
    }
}

/// Initialize a wallet from a kernel
pub async fn init_wallet(
    boot_cli: Option<BootCli>, 
    nockchain_socket: Option<PathBuf>, 
    kernel: &[u8]
) -> Result<Wallet, NockAppError> {
    let prover_hot_state = produce_prover_hot_state();
    
    let boot_cli = boot_cli.unwrap_or_else(|| boot::default_boot_cli(true));
    
    let nockapp = boot::setup(
        kernel,
        Some(boot_cli),
        prover_hot_state.as_slice(),
        "wallet",
        None,
    )
    .await
    .map_err(|e| CrownError::Unknown(format!("Kernel setup failed: {}", e)))?;

    let mut wallet = Wallet::new(nockapp);
    
    if let Some(socket_path) = nockchain_socket {
        wallet.connect_to_nockchain(&socket_path).await;
    }
    
    wallet.add_io_driver(file_driver()).await;
    wallet.add_io_driver(markdown_driver()).await;
    wallet.add_io_driver(exit_driver()).await;
    
    Ok(wallet)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::Once;

    use crown::kernel::boot::{self, Cli as BootCli};
    use crown::nockapp::wire::SystemWire;
    use crown::{exit_driver, Bytes, CrownError};
    use crown::nockapp::NockAppError;
    use getrandom::getrandom;
    use tokio::sync::mpsc;
    use sword::noun::D;
    use zkvm_jetpack::hot::produce_prover_hot_state;

    use super::*;
    use kernels::wallet::KERNEL;

    static INIT: Once = Once::new();

    fn init_tracing() {
        INIT.call_once(|| {
            let cli = boot::default_boot_cli(true);
            boot::init_default_tracing(&cli);
        });
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_keygen() -> Result<(), NockAppError> {
        init_tracing();
        let cli = BootCli::parse_from(&["--new"]);

        let prover_hot_state = produce_prover_hot_state();
        let nockapp = boot::setup(
            KERNEL,
            Some(cli.clone()),
            prover_hot_state.as_slice(),
            "wallet",
            None,
        )
        .await
        .map_err(|e| CrownError::Unknown(e.to_string()))?;
        let mut wallet = Wallet::new(nockapp);
        let mut entropy = [0u8; 32];
        let mut salt = [0u8; 16];
        getrandom(&mut entropy).map_err(|e| CrownError::Unknown(e.to_string()))?;
        getrandom(&mut salt).map_err(|e| CrownError::Unknown(e.to_string()))?;
        let (noun, op) = Wallet::keygen(&entropy, &salt)?;

        let wire = WalletWire::Command(Commands::Keygen).to_wire();

        let keygen_result = wallet.app.poke(wire, noun.clone()).await?;

        println!("keygen result: {:?}", keygen_result);
        assert!(
            keygen_result.len() == 1,
            "Expected keygen result to be a list of 1 noun slab"
        );
        let exit_cause = unsafe { keygen_result[0].root() };
        let code = exit_cause.as_cell()?.tail();
        assert!(unsafe { code.raw_equals(&D(0)) }, "Expected exit code 0");

        Ok(())
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_derive_child() -> Result<(), NockAppError> {
        init_tracing();
        let cli = BootCli::parse_from(&["--new"]);

        let prover_hot_state = produce_prover_hot_state();
        let nockapp = boot::setup(
            KERNEL,
            Some(cli.clone()),
            prover_hot_state.as_slice(),
            "wallet",
            None,
        )
        .await
        .map_err(|e| CrownError::Unknown(e.to_string()))?;
        let mut wallet = Wallet::new(nockapp);
        let key_type = KeyType::Prv;

        // Generate a new key pair
        let mut entropy = [0u8; 32];
        let mut salt = [0u8; 16];
        let (noun, op) = Wallet::keygen(&entropy, &salt)?;
        let wire = WalletWire::Command(Commands::Keygen).to_wire();
        let _ = wallet.app.poke(wire, noun.clone()).await?;

        // Derive a child key
        let index = 0;
        let (noun, op) = Wallet::derive_child(key_type.clone(), index)?;

        let wire = WalletWire::Command(Commands::DeriveChild {
            key_type: key_type.clone().to_string().to_owned(),
            index,
        })
        .to_wire();

        let derive_result = wallet.app.poke(wire, noun.clone()).await?;

        assert!(
            derive_result.len() == 1,
            "Expected derive result to be a list of 1 noun slab"
        );

        let exit_cause = unsafe { derive_result[0].root() };
        let code = exit_cause.as_cell()?.tail();
        assert!(unsafe { code.raw_equals(&D(0)) }, "Expected exit code 0");

        Ok(())
    }

    // TODO make this a real test by creating and signing a real draft
    #[tokio::test]
    #[ignore]
    async fn test_sign_tx() -> Result<(), NockAppError> {
        init_tracing();
        let cli = BootCli::parse_from(&[""]);
        let nockapp = boot::setup(KERNEL, Some(cli.clone()), &[], "wallet", None)
            .await
            .map_err(|e| CrownError::Unknown(e.to_string()))?;
        let mut wallet = Wallet::new(nockapp);

        // Create a temporary input bundle file
        let bundle_path = "test_bundle.jam";
        let test_data = vec![0u8; 32]; // TODO make this a real input bundle
        fs::write(bundle_path, &test_data).map_err(|e| NockAppError::IoError(e))?;

        let wire = WalletWire::Command(Commands::SignTx {
            draft: bundle_path.to_string(),
            index: None,
        })
        .to_wire();

        // Test signing with valid indices
        let (noun, op) = Wallet::sign_tx(bundle_path, None)?;
        let sign_result = wallet.app.poke(wire, noun.clone()).await?;

        println!("sign_result: {:?}", sign_result);

        let wire = WalletWire::Command(Commands::SignTx {
            draft: bundle_path.to_string(),
            index: Some(1),
        })
        .to_wire();

        let (noun, op) = Wallet::sign_tx(bundle_path, Some(1))?;
        let sign_result = wallet.app.poke(wire, noun.clone()).await?;

        println!("sign_result: {:?}", sign_result);

        let wire = WalletWire::Command(Commands::SignTx {
            draft: bundle_path.to_string(),
            index: Some(255),
        })
        .to_wire();

        let (noun, op) = Wallet::sign_tx(bundle_path, Some(255))?;
        let sign_result = wallet.app.poke(wire, noun.clone()).await?;

        println!("sign_result: {:?}", sign_result);

        // Cleanup
        fs::remove_file(bundle_path).map_err(|e| NockAppError::IoError(e))?;
        Ok(())
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_show_balance() -> Result<(), NockAppError> {
        init_tracing();
        let cli = BootCli::parse_from(&[""]);
        let nockapp = boot::setup(KERNEL, Some(cli.clone()), &[], "wallet", None)
            .await
            .map_err(|e| CrownError::Unknown(e.to_string()))?;
        let mut wallet = Wallet::new(nockapp);
        let block = "block123";
        let (noun, op) = Wallet::balance_at_block(block)?;
        let wire = WalletWire::Command(Commands::Balance {}).to_wire();
        let balance_result = wallet.app.poke(wire, noun.clone()).await?;
        println!("balance_result: {:?}", balance_result);
        // Verify balance
        Ok(())
    }

    // Tests for Cold Side Commands
    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_gen_master_privkey() -> Result<(), NockAppError> {
        init_tracing();
        let cli = BootCli::parse_from(&[""]);
        let nockapp = boot::setup(KERNEL, Some(cli.clone()), &[], "wallet", None)
            .await
            .map_err(|e| CrownError::Unknown(e.to_string()))?;
        let mut wallet = Wallet::new(nockapp);
        let seedphrase = "correct horse battery staple";
        let (noun, op) = Wallet::gen_master_privkey(seedphrase)?;
        println!("privkey_slab: {:?}", noun);
        let wire = WalletWire::Command(Commands::GenMasterPrivkey {
            seedphrase: seedphrase.to_string(),
        })
        .to_wire();
        let privkey_result = wallet.app.poke(wire, noun.clone()).await?;
        println!("privkey_result: {:?}", privkey_result);
        Ok(())
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_gen_master_pubkey() -> Result<(), NockAppError> {
        init_tracing();
        let cli = BootCli::parse_from(&[""]);
        let nockapp = boot::setup(KERNEL, Some(cli.clone()), &[], "wallet", None)
            .await
            .map_err(|e| CrownError::Unknown(e.to_string()))?;
        let mut wallet = Wallet::new(nockapp);
        let master_privkey = "privkey123";
        let (noun, op) = Wallet::gen_master_pubkey(master_privkey)?;
        let wire = WalletWire::Command(Commands::GenMasterPubkey {
            master_privkey: master_privkey.to_string(),
        })
        .to_wire();
        let pubkey_result = wallet.app.poke(wire, noun.clone()).await?;
        println!("pubkey_result: {:?}", pubkey_result);
        Ok(())
    }

    // Tests for Hot Side Commands
    // TODO: fix this test by adding a real key file
    #[tokio::test]
    #[ignore]
    async fn test_import_keys() -> Result<(), NockAppError> {
        init_tracing();
        let cli = BootCli::parse_from(&["--new"]);
        let nockapp = boot::setup(KERNEL, Some(cli.clone()), &[], "wallet", None)
            .await
            .map_err(|e| CrownError::Unknown(e.to_string()))?;
        let mut wallet = Wallet::new(nockapp);

        // Create test key file
        let test_path = "test_keys.jam";
        let test_data = vec![0u8; 32]; // TODO: Use real jammed key data
        fs::write(test_path, &test_data).map_err(|e| CrownError::Unknown(format!("Failed to write test file: {}", e)))?;

        let (noun, op) = Wallet::import_keys(test_path)?;
        let wire = SystemWire.to_wire();
        let import_result = wallet.app.poke(wire, noun.clone()).await?;

        fs::remove_file(test_path).map_err(|e| CrownError::Unknown(format!("Failed to remove test file: {}", e)))?;

        println!("import result: {:?}", import_result);
        assert!(
            !import_result.is_empty(),
            "Expected non-empty import result"
        );

        Ok(())
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_simple_scan() -> Result<(), NockAppError> {
        init_tracing();
        let cli = BootCli::parse_from(&[""]);
        let nockapp = boot::setup(KERNEL, Some(cli.clone()), &[], "wallet", None)
            .await
            .map_err(|e| CrownError::Unknown(e.to_string()))?;
        let mut wallet = Wallet::new(nockapp);
        let master_pubkey = "pubkey123";
        let (noun, op) = Wallet::scan(master_pubkey, 100, false, false)?;
        let wire = WalletWire::Command(Commands::Scan {
            master_pubkey: master_pubkey.to_string(),
            search_depth: 100,
            include_timelocks: false,
            include_multisig: false,
        })
        .to_wire();
        let scan_result = wallet.app.poke(wire, noun.clone()).await?;
        println!("scan_result: {:?}", scan_result);
        Ok(())
    }

    // TODO: fix this test
    #[tokio::test]
    #[ignore]
    async fn test_simple_spend_multisig_format() -> Result<(), NockAppError> {
        init_tracing();
        let cli = BootCli::parse_from(&[""]);
        let nockapp = boot::setup(KERNEL, Some(cli.clone()), &[], "wallet", None)
            .await
            .map_err(|e| CrownError::Unknown(e.to_string()))?;
        let mut wallet = Wallet::new(nockapp);

        let names = "[first1 last1],[first2 last2]".to_string();
        let recipients = "[1 pk1],[2 pk2,pk3,pk4]".to_string();
        let gifts = "1,2".to_string();
        let fee = 1;

        let (noun, op) =
            Wallet::simple_spend(names.clone(), recipients.clone(), gifts.clone(), fee)?;
        let wire = WalletWire::Command(Commands::SimpleSpend {
            names: names.clone(),
            recipients: recipients.clone(),
            gifts: gifts.clone(),
            fee,
        })
        .to_wire();
        let spend_result = wallet.app.poke(wire, noun.clone()).await?;
        println!("spend_result: {:?}", spend_result);

        Ok(())
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_simple_spend_single_sig_format() -> Result<(), NockAppError> {
        let cli = BootCli::parse_from(&[""]);
        let nockapp = boot::setup(KERNEL, Some(cli.clone()), &[], "wallet", None)
            .await
            .map_err(|e| CrownError::Unknown(e.to_string()))?;
        init_tracing();
        let mut wallet = Wallet::new(nockapp);

        // these should be valid names of notes in the wallet balance
        let names = "[Amt4GcpYievY4PXHfffiWriJ1sYfTXFkyQsGzbzwMVzewECWDV3Ad8Q BJnaDB3koU7ruYVdWCQqkFYQ9e3GXhFsDYjJ1vSmKFdxzf6Y87DzP4n]".to_string();
        let recipients = "EHmKL2U3vXfS5GYAY5aVnGdukfDWwvkQPCZXnjvZVShsSQi3UAuA4tQ".to_string();
        let gifts = "0".to_string();
        let fee = 0;

        // generate keys
        let (genkey_noun, genkey_op) = Wallet::gen_master_privkey("correct horse battery staple")?;
        let (spend_noun, spend_op) =
            Wallet::simple_spend(names.clone(), recipients.clone(), gifts.clone(), fee)?;

        let wire1 = WalletWire::Command(Commands::GenMasterPrivkey {
            seedphrase: "correct horse battery staple".to_string(),
        })
        .to_wire();
        let genkey_result = wallet.app.poke(wire1, genkey_noun.clone()).await?;
        println!("genkey_result: {:?}", genkey_result);

        let wire2 = WalletWire::Command(Commands::SimpleSpend {
            names: names.clone(),
            recipients: recipients.clone(),
            gifts: gifts.clone(),
            fee,
        })
        .to_wire();
        let spend_result = wallet.app.poke(wire2, spend_noun.clone()).await?;
        println!("spend_result: {:?}", spend_result);

        Ok(())
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_update_balance() -> Result<(), NockAppError> {
        init_tracing();
        let cli = BootCli::parse_from(&["--new"]);
        let nockapp = boot::setup(KERNEL, Some(cli.clone()), &[], "wallet", None)
            .await
            .map_err(|e| CrownError::Unknown(e.to_string()))?;
        let mut wallet = Wallet::new(nockapp);

        let (noun, _) = Wallet::update_balance()?;

        let wire = WalletWire::Command(Commands::UpdateBalance {}).to_wire();
        let update_result = wallet.app.poke(wire, noun.clone()).await?;
        println!("update_result: {:?}", update_result);

        Ok(())
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_list_notes() -> Result<(), NockAppError> {
        init_tracing();
        let cli = BootCli::parse_from(&[""]);
        let nockapp = boot::setup(KERNEL, Some(cli.clone()), &[], "wallet", None)
            .await
            .map_err(|e| CrownError::Unknown(e.to_string()))?;
        let mut wallet = Wallet::new(nockapp);

        // Test listing notes
        let (noun, op) = Wallet::list_notes()?;
        let wire = WalletWire::Command(Commands::ListNotes {}).to_wire();
        let list_result = wallet.app.poke(wire, noun.clone()).await?;
        println!("list_result: {:?}", list_result);

        Ok(())
    }

    // TODO: fix this test by adding a real draft
    #[tokio::test]
    #[ignore]
    async fn test_make_tx_from_draft() -> Result<(), NockAppError> {
        init_tracing();
        let cli = BootCli::parse_from(&[""]);
        let nockapp = boot::setup(KERNEL, Some(cli.clone()), &[], "wallet", None)
            .await
            .map_err(|e| CrownError::Unknown(e.to_string()))?;
        let mut wallet = Wallet::new(nockapp);

        // use the draft in .drafts/
        let draft_path = ".drafts/test_draft.draft";
        let test_data = vec![0u8; 32]; // TODO: Use real draft data
        fs::write(draft_path, &test_data).map_err(|e| CrownError::Unknown(format!("Failed to write test file: {}", e)))?;

        let (noun, op) = Wallet::make_tx(draft_path)?;
        let wire = WalletWire::Command(Commands::MakeTx {
            draft: draft_path.to_string(),
        })
        .to_wire();
        let tx_result = wallet.app.poke(wire, noun.clone()).await?;

        fs::remove_file(draft_path).map_err(|e| CrownError::Unknown(format!("Failed to remove test file: {}", e)))?;

        println!("transaction result: {:?}", tx_result);
        assert!(
            !tx_result.is_empty(),
            "Expected non-empty transaction result"
        );

        Ok(())
    }
} 
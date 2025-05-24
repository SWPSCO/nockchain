#![allow(clippy::doc_overindented_list_items)]

use std::fs;
use std::path::PathBuf;

use clap::Subcommand;
use getrandom::getrandom;
use nockapp::utils::bytes::Byts;
use nockapp::{system_data_dir, CrownError, NockApp, NockAppError, ToBytesExt};
use nockvm::jets::cold::Nounable;
use nockvm::noun::{Atom, Cell, IndirectAtom, Noun, D, SIG, T};
use tokio::fs as tokio_fs;

use nockapp::driver::*;
use nockapp::noun::slab::NounSlab;
use nockapp::utils::make_tas;
use nockapp::wire::{Wire, WireRepr};

#[derive(Debug)]
pub enum WalletWire {
    ListNotes,
    UpdateBalance,
    UpdateBlock,
    Exit,
    Command(Commands),
}

impl Wire for WalletWire {
    const VERSION: u64 = 1;
    const SOURCE: &str = "wallet";

    fn to_wire(&self) -> WireRepr {
        let tags = match self {
            WalletWire::ListNotes => vec!["list-notes".into()],
            WalletWire::UpdateBalance => vec!["update-balance".into()],
            WalletWire::UpdateBlock => vec!["update-block".into()],
            WalletWire::Exit => vec!["exit".into()],
            WalletWire::Command(command) => {
                vec!["command".into(), command.as_wire_tag().into()]
            }
        };
        WireRepr::new(WalletWire::SOURCE, WalletWire::VERSION, tags)
    }
}

/// Represents a Noun that the wallet kernel can handle
pub type CommandNoun<T> = Result<(T, Operation), NockAppError>;

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]

pub enum Commands {
    /// Generate a new key pair
    Keygen,

    /// Derive a child key from the current master key
    DeriveChild {
        /// Type of key to derive (e.g., "pub", "priv")
        #[arg(short, long)]
        key_type: String,

        /// Index of the child key to derive
        #[arg(short, long, value_parser = clap::value_parser!(u64).range(0..=255))]
        index: u64,

        /// Label of the child key to derive
        #[arg(short, long)]
        label: Option<String>,
    },

    /// Import keys from a file
    ImportKeys {
        /// Path to the jammed keys file
        #[arg(short, long, value_name = "FILE")]
        input: String,
    },

    /// Export all wallet keys to a file
    ExportKeys,

    /// Signs a transaction
    SignTx {
        /// Path to input bundle file
        #[arg(short, long)]
        draft: String,

        /// Optional key index to use for signing (0-255)
        #[arg(short, long, value_parser = clap::value_parser!(u64).range(0..=255))]
        index: Option<u64>,
    },

    /// Generate a master private key from a seed phrase
    GenMasterPrivkey {
        /// Seed phrase to generate master private key
        #[arg(short, long)]
        seedphrase: String,
    },

    /// Generate a master public key from a master private key
    GenMasterPubkey {
        /// Master private key to generate master public key
        #[arg(short, long)]
        master_privkey: String,
    },

    /// Perform a simple scan of the blockchain
    Scan {
        /// Master public key to scan for
        #[arg(short, long)]
        master_pubkey: String,
        /// Optional search depth (default 100)
        #[arg(short, long, default_value = "100")]
        search_depth: u64,
        /// Include timelocks in scan
        #[arg(long, default_value = "false")]
        include_timelocks: bool,
        /// Include multisig in scan
        #[arg(long, default_value = "false")]
        include_multisig: bool,
    },

    /// List all notes in the wallet
    ListNotes,

    /// List notes by public key
    ListNotesByPubkey {
        /// Optional public key to filter notes
        #[arg(short, long)]
        pubkey: Option<String>,
    },

    /// Perform a simple spend operation
    SimpleSpend {
        /// Names of notes to spend (comma-separated)
        #[arg(long)]
        names: String,
        /// Recipient addresses (comma-separated)
        #[arg(long)]
        recipients: String,
        /// Amounts to send (comma-separated)
        #[arg(long)]
        gifts: String,
        /// Transaction fee
        #[arg(long)]
        fee: u64,
    },

    /// Create a transaction from a draft file
    MakeTx {
        /// Draft file to create transaction from
        #[arg(short, long)]
        draft: String,
    },

    /// Update the wallet balance
    UpdateBalance,

    /// Export a master public key
    ExportMasterPubkey,

    /// Import a master public key from a file
    ImportMasterPubkey {
        /// Path to keys file generated from export-master-pubkey
        #[arg(short, long)]
        key_path: String,
    },

    /// Lists all public keys in the wallet
    ListPubkeys,

    /// Get the balance of the current wallet
    PeekBalance,

    /// Show the seed phrase for the current master key
    ShowSeedphrase,

    /// Show the master public key
    ShowMasterPubkey,

    /// Show the master private key
    ShowMasterPrivkey,

    /// Get the seed phrase for the current master key
    PeekSeedphrase,

    /// Get the master public key
    PeekMasterPubkey,

    /// Get the state of the current wallet
    PeekState,

    /// Get the receive address
    PeekReceiveAddress,

    /// Get pubkeys
    PeekPubkeys,
}

impl Commands {
    fn as_wire_tag(&self) -> &'static str {
        match self {
            Commands::Keygen => "keygen",
            Commands::DeriveChild { .. } => "derive-child",
            Commands::ImportKeys { .. } => "import-keys",
            Commands::ExportKeys => "export-keys",
            Commands::SignTx { .. } => "sign-tx",
            Commands::GenMasterPrivkey { .. } => "gen-master-privkey",
            Commands::GenMasterPubkey { .. } => "gen-master-pubkey",
            Commands::Scan { .. } => "scan",
            Commands::ListNotes => "list-notes",
            Commands::ListNotesByPubkey { .. } => "list-notes-by-pubkey",
            Commands::SimpleSpend { .. } => "simple-spend",
            Commands::MakeTx { .. } => "make-tx",
            Commands::UpdateBalance => "update-balance",
            Commands::ExportMasterPubkey => "export-master-pubkey",
            Commands::ImportMasterPubkey { .. } => "import-master-pubkey",
            Commands::ListPubkeys => "list-pubkeys",
            Commands::ShowSeedphrase => "show-seedphrase",
            Commands::ShowMasterPubkey => "show-master-pubkey",
            Commands::ShowMasterPrivkey => "show-master-privkey",
            // Peeks
            Commands::PeekBalance => "peek-balance",
            Commands::PeekSeedphrase => "peek-seedphrase",
            Commands::PeekMasterPubkey => "peek-master-pubkey",
            Commands::PeekState => "peek-state",
            Commands::PeekReceiveAddress => "peek-receive-address",
            Commands::PeekPubkeys => "peek-pubkeys",
        }
    }
}

pub struct Wallet {
    pub app: NockApp,
}

#[derive(Debug, Clone)]
pub enum KeyType {
    Pub,
    Prv,
}
impl KeyType {
    pub fn to_string(&self) -> &'static str {
        match self {
            KeyType::Pub => "pub",
            KeyType::Prv => "prv",
        }
    }
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
        let mut sync_slab = command_noun_slab.clone();

        let sync_tag = make_tas(&mut sync_slab, "sync-run");
        let tag_noun = sync_tag.as_noun();

        sync_slab.modify(move |original_root| vec![tag_noun, original_root]);

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
    fn wallet(
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

    // Peeks
    pub fn peek_balance() -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        Self::wallet("balance", &[], Operation::Peek, &mut slab)
    }
    pub fn peek_seedphrase() -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        Self::wallet("seed-phrase", &[], Operation::Peek, &mut slab)
    }
    pub fn peek_master_pubkey() -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        Self::wallet("master-pubkey", &[], Operation::Peek, &mut slab)
    }
    pub fn peek_state() -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        Self::wallet("state", &[], Operation::Peek, &mut slab)
    }
    pub fn peek_receive_address() -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        Self::wallet("receive-address", &[], Operation::Peek, &mut slab)
    }
    pub fn peek_pubkeys() -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        Self::wallet("pubkeys", &[], Operation::Peek, &mut slab)
    }

    // Derives a child key from current master key.
    //
    // # Arguments
    //
    // * `key_type` - The type of key to derive (e.g., "pub", "priv")
    // * `index` - The index of the child key to derive
    // TODO: add label if necessary
    pub fn derive_child(key_type: KeyType, index: u64, label: Option<String>) -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        let key_type_noun = make_tas(&mut slab, key_type.to_string()).as_noun();
        let index_noun = D(index);
        let derive_child_noun_vec: Vec<Noun> = match label {
            Some(label) => {
                let label_str: &str = label.as_str();
                let label_noun = make_tas(&mut slab, label_str).as_noun();
                vec![key_type_noun, index_noun, SIG, label_noun]
            }
            None => vec![key_type_noun, index_noun, SIG],
        };

        Self::wallet(
            "derive-child",
            &derive_child_noun_vec,
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
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use nockchain_wallet_lib::Wallet;
    /// let names = "[first1 last1],[first2 last2]";
    /// let recipients = "[1 pk1],[2 pk2,pk3,pk4]";
    /// let gifts = "100,200";
    /// let fee = 10;
    /// Wallet::simple_spend(names.to_string(), recipients.to_string(), gifts.to_string(), fee)?;
    /// # Ok(())
    /// # }
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

    /// Exports the master public key.
    pub fn export_master_pubkey() -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        Self::wallet("export-master-pubkey", &[], Operation::Poke, &mut slab)
    }

    /// Imports a master public key from a file.
    pub fn import_master_pubkey(key_path: &str) -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        let key_data = fs::read(key_path)
            .map_err(|e| CrownError::Unknown(format!("Failed to read master pubkey file: {}", e)))?;
        let pubkey_noun = slab
            .cue_into(key_data.as_bytes()?)
            .map_err(|e| CrownError::Unknown(format!("Failed to decode master pubkey data: {}", e)))?;
        Self::wallet(
            "import-master-pubkey",
            &[pubkey_noun],
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

    /// Shows the seed phrase for the current master key.
    pub fn show_seedphrase() -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        Self::wallet("show-seedphrase", &[], Operation::Poke, &mut slab)
    }

    /// Shows the master public key.
    pub fn show_master_pubkey() -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        Self::wallet("show-master-pubkey", &[], Operation::Poke, &mut slab)
    }

    /// Shows the master private key.
    pub fn show_master_privkey() -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        Self::wallet("show-master-privkey", &[], Operation::Poke, &mut slab)
    }

    /// Exports all wallet keys.
    pub fn export_keys() -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        Self::wallet("export-keys", &[], Operation::Poke, &mut slab)
    }
}

pub async fn wallet_data_dir() -> Result<PathBuf, NockAppError> {
    let wallet_data_dir = system_data_dir().join("wallet");
    if !wallet_data_dir.exists() {
        tokio_fs::create_dir_all(&wallet_data_dir)
            .await
            .map_err(|e| {
                CrownError::Unknown(format!("Failed to create wallet data directory: {}", e))
            })?;
    }
    Ok(wallet_data_dir)
}

pub fn from_bytes(stack: &mut NounSlab, bytes: &[u8]) -> Atom {
    unsafe {
        let mut tas_atom = IndirectAtom::new_raw_bytes(stack, bytes.len(), bytes.as_ptr());
        tas_atom.normalize_as_atom()
    }
}

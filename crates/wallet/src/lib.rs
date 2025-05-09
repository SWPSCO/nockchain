pub mod error;

use clap::Subcommand;
use crown::nockapp::wire::{Wire, WireRepr};
use crown::nockapp::NockApp;

// Copied from main.rs
#[derive(Debug)]
pub enum WalletWire {
    ListNotes,
    UpdateBalance,
    UpdateBlock,
    Exit,
    Command(Commands),
}

// Copied from main.rs
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

// Copied from main.rs
#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Display the current wallet balance
    Balance,

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
    },

    /// Import keys from a file
    ImportKeys {
        /// Path to the jammed keys file
        #[arg(short, long, value_name = "FILE")]
        input: String,
    },

    /// Signs a transaction
    SignTx {
        /// Path to input bundle file
        #[arg(short, long)]
        draft: String,

        /// Optional key index to use for signing (0-255)
        #[arg(short, long, value_parser = clap::value_parser!(u64).range(0..=255))]
        index: Option<u64>,
    },

    /// Show the balance of a specific address at a given block
    ShowBalance {
        /// Block to show balance at
        #[arg(short, long)]
        block: String,
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

    /// Import a master public key
    ImportMasterPubkey {
        /// Base58-encoded public key
        #[arg(short, long)]
        key: String,
        /// Base58-encoded chain code
        #[arg(short, long)]
        knot: String,
    },

    /// Lists all public keys in the wallet
    ListPubkeys,
}

// Copied from main.rs
impl Commands {
    fn as_wire_tag(&self) -> &'static str {
        match self {
            Commands::Balance => "balance",
            Commands::Keygen => "keygen",
            Commands::DeriveChild { .. } => "derive-child",
            Commands::ImportKeys { .. } => "import-keys",
            Commands::SignTx { .. } => "sign-tx",
            Commands::ShowBalance { .. } => "show-balance",
            Commands::GenMasterPrivkey { .. } => "gen-master-privkey",
            Commands::GenMasterPubkey { .. } => "gen-master-pubkey",
            Commands::Scan { .. } => "scan",
            Commands::ListNotes => "list-notes",
            Commands::ListNotesByPubkey { .. } => "list-notes-by-pubkey",
            Commands::SimpleSpend { .. } => "simple-spend",
            Commands::MakeTx { .. } => "make-tx",
            Commands::UpdateBalance => "update-balance",
            Commands::ImportMasterPubkey { .. } => "import-master-pubkey",
            Commands::ListPubkeys => "list-pubkeys",
        }
    }
}

// Copied from main.rs
#[derive(Debug, Clone)]
pub enum KeyType {
    Pub,
    Prv,
}

// Copied from main.rs
impl KeyType {
    pub fn to_string(&self) -> &'static str {
        match self {
            KeyType::Pub => "pub",
            KeyType::Prv => "prv",
        }
    }
}

// Copied from main.rs
pub struct Wallet {
    app: NockApp,
}

// Copied and modified from main.rs
// All methods made pub, and Wallet::wallet made pub(crate)
use crown::noun::slab::NounSlab;
use sword::noun::{Cell, Noun, D, SIG, T, Atom, IndirectAtom};
use crown::noun::IntoNoun;
use crown::nockapp::driver::Operation;
use crown::nockapp::NockAppError;
use crown::utils::make_tas;
use crown::utils::bytes::Byts;
use getrandom::getrandom;
use sword::jets::cold::Nounable;
use std::fs;
use crown::ToBytesExt; // For as_bytes()
use crown::CrownError;

/// Represents a Noun that the wallet kernel can handle
type CommandNoun<T> = Result<(T, Operation), NockAppError>;

impl Wallet {
    /// Creates a new `Wallet` instance with the given kernel.
    pub fn new(nockapp: NockApp) -> Self {
        Wallet { app: nockapp }
    }

    /// Wraps a command with sync-run to ensure it runs after block and balance updates
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
    pub(crate) fn wallet(
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
    pub fn keygen(entropy: &[u8; 32], sal: &[u8; 16]) -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        let ent: Byts = Byts::new(entropy.to_vec());
        let ent_noun = ent.into_noun(&mut slab);
        let sal: Byts = Byts::new(sal.to_vec());
        let sal_noun = sal.into_noun(&mut slab);
        Self::wallet("keygen", &[ent_noun, sal_noun], Operation::Poke, &mut slab)
    }

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

    pub fn sign_tx(draft_path: &str, index: Option<u64>) -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();

        if let Some(idx) = index {
            if idx > 255 {
                return Err(CrownError::Unknown("Key index must not exceed 255".into()).into());
            }
        }

        let draft_data = fs::read(draft_path)
            .map_err(|e| CrownError::Unknown(format!("Failed to read draft: {}", e)))?;

        let draft_noun = slab.cue_into(draft_data.as_bytes()?)
            .map_err(|e| CrownError::Unknown(format!("Failed to decode draft: {}", e)))?;

        let index_noun = match index {
            Some(i) => D(i),
            None => D(0),
        };

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

    pub fn balance_at_block(block: &str) -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        let block_noun = IntoNoun::into_noun(block);
        Self::wallet("show-balance", &[block_noun], Operation::Poke, &mut slab)
    }

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

    pub fn import_keys(input_path: &str) -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();

        let key_data = fs::read(input_path)
            .map_err(|e| CrownError::Unknown(format!("Failed to read master pubkeys: {}", e)))?;

        let pubkey_noun = slab.cue_into(key_data.as_bytes()?)
            .map_err(|e| CrownError::Unknown(format!("Failed to decode master pubkeys: {}", e)))?;

        Self::wallet("import-keys", &[pubkey_noun], Operation::Poke, &mut slab)
    }

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

    pub fn simple_spend(
        names: String,
        recipients: String,
        gifts: String,
        fee: u64,
    ) -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();

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

        let recipients_vec: Vec<(u64, Vec<String>)> = if recipients.contains('[') {
            recipients
                .split(',')
                .filter_map(|pair| {
                    let pair = pair.trim();
                    if pair.starts_with('[') && pair.ends_with(']') {
                        let inner = &pair[1..pair.len() - 1];
                        let mut parts = inner.splitn(2, ' ');
                        let number = parts.next()?.parse().ok()?;
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
            recipients
                .split(',')
                .map(|addr| (1, vec![addr.trim().to_string()]))
                .collect()
        };

        let gifts_vec: Vec<u64> = gifts.split(',').filter_map(|s| s.parse().ok()).collect();

        if names_vec.len() != recipients_vec.len() || names_vec.len() != gifts_vec.len() {
            return Err(CrownError::Unknown(
                "Invalid input - names, recipients, and gifts must have the same length"
                    .to_string(),
            )
            .into());
        }

        let names_noun = names_vec
            .into_iter()
            .rev()
            .fold(D(0), |acc, (first, last)| {
                let first_noun = make_tas(&mut slab, &first).as_noun();
                let last_noun = make_tas(&mut slab, &last).as_noun();
                let name_pair = T(&mut slab, &[first_noun, last_noun]);
                Cell::new(&mut slab, name_pair, acc).as_noun()
            });

        let recipients_noun = recipients_vec
            .into_iter()
            .rev()
            .fold(D(0), |acc, (num, pubkeys)| {
                let pubkeys_noun = pubkeys.into_iter().rev().fold(D(0), |acc_inner, pubkey| {
                    let pubkey_noun = make_tas(&mut slab, &pubkey).as_noun();
                    Cell::new(&mut slab, pubkey_noun, acc_inner).as_noun()
                });
                let pair = T(&mut slab, &[D(num), pubkeys_noun]);
                Cell::new(&mut slab, pair, acc).as_noun()
            });

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

    pub fn list_notes() -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        Self::wallet("list-notes", &[], Operation::Poke, &mut slab)
    }

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

    pub fn make_tx(draft_path: &str) -> CommandNoun<NounSlab> {
        let draft_data = fs::read(draft_path)
            .map_err(|e| CrownError::Unknown(format!("Failed to read draft file: {}", e)))?;

        let mut slab = NounSlab::new();
        let draft_noun = slab.cue_into(draft_data.as_bytes()?)
            .map_err(|e| CrownError::Unknown(format!("Failed to decode draft data: {}", e)))?;

        Self::wallet("make-tx", &[draft_noun], Operation::Poke, &mut slab)
    }

    pub fn list_pubkeys() -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        Self::wallet("list-pubkeys", &[], Operation::Poke, &mut slab)
    }

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
    
    // This gives access to NockApp's methods if needed, e.g. for IO driver additions in main
    pub fn app_mut(&mut self) -> &mut NockApp {
        &mut self.app
    }

    pub async fn run(self) -> Result<(), NockAppError> { // Consumes Wallet
        self.app.run().await
    }

    // Or provide specific methods to add drivers if that's preferred
    // pub async fn add_io_driver<D: IoDriver + Send + Sync + 'static>(
    //     &mut self,
    //     driver: D,
    // ) {
    //     self.app.add_io_driver(driver).await;
    // }
}

// from_bytes function also needs to be in lib.rs if Wallet methods use it (sign_tx does)
// and it's not already public or moved.
// It appears to be a free function in main.rs, so we can move it here too.
pub fn from_bytes(stack: &mut NounSlab, bytes: &[u8]) -> Atom {
    unsafe {
        let mut tas_atom = IndirectAtom::new_raw_bytes(stack, bytes.len(), bytes.as_ptr());
        tas_atom.normalize_as_atom()
    }
}

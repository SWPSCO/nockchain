use clap::Subcommand;
use crown::nockapp::wire::{Wire, WireRepr};

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

impl Commands {
    pub fn as_wire_tag(&self) -> &'static str {
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
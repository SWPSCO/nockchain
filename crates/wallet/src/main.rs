#![allow(clippy::doc_overindented_list_items)]

use std::path::PathBuf;

use clap::Parser;
use getrandom::getrandom;
use crown::kernel::boot::{self, Cli as BootCli};
use crown::nockapp::NockAppError;
use crown::nockapp::wire::Wire;

// Import from our library
use wallet::{Commands, Wallet, WalletWire, KeyType, init_wallet};
use kernels::wallet::KERNEL;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
struct WalletCli {
    #[command(flatten)]
    boot: BootCli,

    #[command(subcommand)]
    command: Commands,

    #[arg(long, value_name = "PATH")]
    nockchain_socket: Option<PathBuf>,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Socket path to connect to nockchain daemon
    #[arg(long)]
    socket: Option<PathBuf>,

    #[clap(subcommand)]
    command: Commands,
}

#[tokio::main]
async fn main() -> Result<(), NockAppError> {
    let cli = WalletCli::parse();
    boot::init_default_tracing(&cli.boot.clone()); // Init tracing early

    let mut wallet = init_wallet(Some(cli.boot.clone()), cli.nockchain_socket.clone(), KERNEL).await?;

    // Determine if this command requires chain synchronization
    let requires_sync = match &cli.command {
        // Commands that DON'T need sync
        Commands::Keygen
        | Commands::DeriveChild { .. }
        | Commands::ImportKeys { .. }
        | Commands::SignTx { .. }
        | Commands::MakeTx { .. }
        | Commands::GenMasterPrivkey { .. }
        | Commands::GenMasterPubkey { .. }
        | Commands::ImportMasterPubkey { .. }
        | Commands::ListPubkeys
        | Commands::SimpleSpend { .. } => false,

        // All other commands DO need sync
        _ => true,
    };

    // Check if we need sync but don't have a socket
    if requires_sync && cli.nockchain_socket.is_none() {
        return Err(crown::CrownError::Unknown(
            "This command requires connection to a nockchain node. Please provide --nockchain-socket"
            .to_string()
        ).into());
    }

    // Generate the command noun and operation
    let poke = match &cli.command {
        Commands::Balance => Wallet::wallet_balance(),
        Commands::Keygen => {
            let mut entropy = [0u8; 32];
            let mut salt = [0u8; 16];
            getrandom(&mut entropy).map_err(|e| crown::CrownError::Unknown(e.to_string()))?;
            getrandom(&mut salt).map_err(|e| crown::CrownError::Unknown(e.to_string()))?;
            Wallet::keygen(&entropy, &salt)
        }
        Commands::DeriveChild { key_type, index } => {
            // Validate key_type is either "pub" or "priv"
            let key_type = match key_type.as_str() {
                "pub" => KeyType::Pub,
                "priv" => KeyType::Prv,
                _ => {
                    return Err(crown::CrownError::Unknown(
                        "Key type must be either 'pub' or 'priv'".into(),
                    )
                    .into())
                }
            };
            Wallet::derive_child(key_type, *index)
        }
        Commands::SignTx { draft, index } => Wallet::sign_tx(draft, *index),
        Commands::ShowBalance { block } => Wallet::balance_at_block(block),
        Commands::ImportKeys { input } => Wallet::import_keys(input),
        Commands::GenMasterPrivkey { seedphrase } => Wallet::gen_master_privkey(seedphrase),
        Commands::GenMasterPubkey { master_privkey } => Wallet::gen_master_pubkey(master_privkey),
        Commands::Scan {
            master_pubkey,
            search_depth,
            include_timelocks,
            include_multisig,
        } => Wallet::scan(
            master_pubkey, *search_depth, *include_timelocks, *include_multisig,
        ),
        Commands::ListNotes => Wallet::list_notes(),
        Commands::ListNotesByPubkey { pubkey } => {
            if let Some(pk) = pubkey {
                Wallet::list_notes_by_pubkey(pk)
            } else {
                return Err(crown::CrownError::Unknown("Public key is required".into()).into());
            }
        }
        Commands::SimpleSpend {
            names,
            recipients,
            gifts,
            fee,
        } => Wallet::simple_spend(names.clone(), recipients.clone(), gifts.clone(), *fee),
        Commands::MakeTx { draft } => Wallet::make_tx(draft),
        Commands::UpdateBalance => Wallet::update_balance(),
        Commands::ImportMasterPubkey { key, knot } => Wallet::import_master_pubkey(key, knot),
        Commands::ListPubkeys => Wallet::list_pubkeys(),
    }?;

    // If this command requires sync and we have a socket, wrap it with sync-run
    let final_poke = if requires_sync && cli.nockchain_socket.is_some() {
        Wallet::wrap_with_sync_run(poke.0, poke.1)?
    } else {
        poke
    };

    // Create the wire protocol message
    let _wire = WalletWire::Command(cli.command).to_wire();
    
    // Send the command to the wallet
    wallet.app().add_io_driver(crown::one_punch_driver(final_poke.0, final_poke.1)).await;
    
    // Run the wallet app
    wallet.run().await?;
    Ok(())
}

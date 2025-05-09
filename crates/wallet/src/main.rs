#![allow(clippy::doc_overindented_list_items)]

// use std::fs; // Unused
use std::path::PathBuf;

use clap::Parser;
use getrandom::getrandom;
use tokio::net::UnixStream;
use tracing::{error, info};
use zkvm_jetpack::hot::produce_prover_hot_state;

use wallet::{Commands, KeyType, Wallet};

use crown::kernel::boot::{self, Cli as BootCli};
use crown::nockapp::driver::*;
use crown::nockapp::NockAppError;
use crown::{exit_driver, file_driver, markdown_driver, one_punch_driver, CrownError};
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

#[tokio::main]
async fn main() -> Result<(), NockAppError> {
    let cli = WalletCli::parse();
    boot::init_default_tracing(&cli.boot.clone()); // Init tracing early

    let prover_hot_state = produce_prover_hot_state();

    let kernel = boot::setup(
        KERNEL,
        Some(cli.boot.clone()),
        prover_hot_state.as_slice(),
        "wallet",
        None,
    )
    .await
    .map_err(|e| CrownError::Unknown(format!("Kernel setup failed: {}", e)))?;

    let mut wallet = Wallet::new(kernel);

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
        return Err(CrownError::Unknown(
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
            getrandom(&mut entropy).map_err(|e| CrownError::Unknown(e.to_string()))?;
            getrandom(&mut salt).map_err(|e| CrownError::Unknown(e.to_string()))?;
            Wallet::keygen(&entropy, &salt)
        }
        Commands::DeriveChild { key_type, index } => {
            let key_type = match key_type.as_str() {
                "pub" => KeyType::Pub,
                "priv" => KeyType::Prv,
                _ => {
                    return Err(CrownError::Unknown(
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
                return Err(CrownError::Unknown("Public key is required".into()).into());
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

    let final_poke = if requires_sync && cli.nockchain_socket.is_some() {
        Wallet::wrap_with_sync_run(poke.0, poke.1)?
    } else {
        poke
    };

    wallet
        .app_mut()
        .add_io_driver(one_punch_driver(final_poke.0, final_poke.1))
        .await;

    {
        if let Some(socket_path) = cli.nockchain_socket {
            match UnixStream::connect(&socket_path).await {
                Ok(stream) => {
                    info!("Connected to nockchain NPC socket at {:?}", socket_path);
                    wallet
                        .app_mut()
                        .add_io_driver(crown::npc_client_driver(stream))
                        .await;
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

        wallet.app_mut().add_io_driver(file_driver()).await;
        wallet.app_mut().add_io_driver(markdown_driver()).await;
        wallet.app_mut().add_io_driver(exit_driver()).await;

        wallet.run().await?;
        Ok(())
    }
}

// TODO: all these tests need to also validate the results and not
// just ensure that the wallet can be poked with the expected noun.
#[allow(warnings)]
#[cfg(test)]
mod tests {
    use std::sync::Once;
    use clap::Parser;

    use crown::kernel::boot::{self, Cli as BootCli};
    use crown::nockapp::wire::{SystemWire, Wire as TestWireTrait};
    use crown::{exit_driver, Bytes, CrownError};
    use tokio::sync::mpsc;
    use zkvm_jetpack::hot::produce_prover_hot_state;
    use getrandom::getrandom;
    use sword::noun::D;
    use std::fs;

    use wallet::{
        Wallet, Commands, KeyType, WalletWire,
    };
    use crate::KERNEL;
    use crate::NockAppError;

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
        let (noun, _op) = Wallet::keygen(&entropy, &salt)?;

        let wire = WalletWire::Command(Commands::Keygen).to_wire();

        let keygen_result = wallet.app_mut().poke(wire, noun.clone()).await?;

        println!("keygen result: {:?}", keygen_result);
        assert!(
            keygen_result.len() == 1,
            "Expected keygen result to be a list of 1 noun slab"
        );
        let exit_cause = unsafe { keygen_result[0].root() };
        let code = exit_cause.as_cell().unwrap().tail();
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
        let (noun, _op) = Wallet::keygen(&entropy, &salt)?;
        let wire = WalletWire::Command(Commands::Keygen).to_wire();
        let _ = wallet.app_mut().poke(wire, noun.clone()).await?;

        // Derive a child key
        let index = 0;
        let (noun, _op) = Wallet::derive_child(key_type.clone(), index)?;

        let wire = WalletWire::Command(Commands::DeriveChild {
            key_type: key_type.to_string().to_owned(),
            index,
        })
        .to_wire();

        let derive_result = wallet.app_mut().poke(wire, noun.clone()).await?;

        assert!(
            derive_result.len() == 1,
            "Expected derive result to be a list of 1 noun slab"
        );

        let exit_cause = unsafe { derive_result[0].root() };
        let code = exit_cause.as_cell().unwrap().tail();
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
        let (noun, _op) = Wallet::sign_tx(bundle_path, None)?;
        let sign_result = wallet.app_mut().poke(wire, noun.clone()).await?;

        println!("sign_result: {:?}", sign_result);

        let wire = WalletWire::Command(Commands::SignTx {
            draft: bundle_path.to_string(),
            index: Some(1),
        })
        .to_wire();

        let (noun, _op) = Wallet::sign_tx(bundle_path, Some(1))?;
        let sign_result = wallet.app_mut().poke(wire, noun.clone()).await?;

        println!("sign_result: {:?}", sign_result);

        let wire = WalletWire::Command(Commands::SignTx {
            draft: bundle_path.to_string(),
            index: Some(255),
        })
        .to_wire();

        let (noun, _op) = Wallet::sign_tx(bundle_path, Some(255))?;
        let sign_result = wallet.app_mut().poke(wire, noun.clone()).await?;

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
        let (noun, _op) = Wallet::balance_at_block(block)?;
        let wire = WalletWire::Command(Commands::Balance {}).to_wire();
        let balance_result = wallet.app_mut().poke(wire, noun.clone()).await?;
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
        let (noun, _op) = Wallet::gen_master_privkey(seedphrase)?;
        println!("privkey_slab: {:?}", noun);
        let wire = WalletWire::Command(Commands::GenMasterPrivkey {
            seedphrase: seedphrase.to_string(),
        })
        .to_wire();
        let privkey_result = wallet.app_mut().poke(wire, noun.clone()).await?;
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
        let (noun, _op) = Wallet::gen_master_pubkey(master_privkey)?;
        let wire = WalletWire::Command(Commands::GenMasterPubkey {
            master_privkey: master_privkey.to_string(),
        })
        .to_wire();
        let pubkey_result = wallet.app_mut().poke(wire, noun.clone()).await?;
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
        fs::write(test_path, &test_data).expect(&format!(
            "Called `expect()` at {}:{} (git sha: {})",
            file!(),
            line!(),
            option_env!("GIT_SHA").unwrap_or("unknown")
        ));

        let (noun, _op) = Wallet::import_keys(test_path)?;
        let wire = SystemWire.to_wire();
        let import_result = wallet.app_mut().poke(wire, noun.clone()).await?;

        fs::remove_file(test_path).expect(&format!(
            "Called `expect()` at {}:{} (git sha: {})",
            file!(),
            line!(),
            option_env!("GIT_SHA").unwrap_or("unknown")
        ));

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
        let (noun, _op) = Wallet::scan(master_pubkey, 100, false, false)?;
        let wire = WalletWire::Command(Commands::Scan {
            master_pubkey: master_pubkey.to_string(),
            search_depth: 100,
            include_timelocks: false,
            include_multisig: false,
        })
        .to_wire();
        let scan_result = wallet.app_mut().poke(wire, noun.clone()).await?;
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

        let (noun, _op) =
            Wallet::simple_spend(names.clone(), recipients.clone(), gifts.clone(), fee)?;
        let wire = WalletWire::Command(Commands::SimpleSpend {
            names: names.clone(),
            recipients: recipients.clone(),
            gifts: gifts.clone(),
            fee: fee.clone(),
        })
        .to_wire();
        let spend_result = wallet.app_mut().poke(wire, noun.clone()).await?;
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
        let (genkey_noun, _genkey_op) = Wallet::gen_master_privkey("correct horse battery staple")?;
        let (spend_noun, _spend_op) =
            Wallet::simple_spend(names.clone(), recipients.clone(), gifts.clone(), fee)?;

        let wire1 = WalletWire::Command(Commands::GenMasterPrivkey {
            seedphrase: "correct horse battery staple".to_string(),
        })
        .to_wire();
        let genkey_result = wallet.app_mut().poke(wire1, genkey_noun.clone()).await?;
        println!("genkey_result: {:?}", genkey_result);

        let wire2 = WalletWire::Command(Commands::SimpleSpend {
            names: names.clone(),
            recipients: recipients.clone(),
            gifts: gifts.clone(),
            fee: fee.clone(),
        })
        .to_wire();
        let spend_result = wallet.app_mut().poke(wire2, spend_noun.clone()).await?;
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
        let update_result = wallet.app_mut().poke(wire, noun.clone()).await?;
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
        let (noun, _op) = Wallet::list_notes()?;
        let wire = WalletWire::Command(Commands::ListNotes {}).to_wire();
        let list_result = wallet.app_mut().poke(wire, noun.clone()).await?;
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
        fs::write(draft_path, &test_data).expect(&format!(
            "Called `expect()` at {}:{} (git sha: {})",
            file!(),
            line!(),
            option_env!("GIT_SHA").unwrap_or("unknown")
        ));

        let (noun, _op) = Wallet::make_tx(draft_path)?;
        let wire = WalletWire::Command(Commands::MakeTx {
            draft: draft_path.to_string(),
        })
        .to_wire();
        let tx_result = wallet.app_mut().poke(wire, noun.clone()).await?;

        fs::remove_file(draft_path).expect(&format!(
            "Called `expect()` at {}:{} (git sha: {})",
            file!(),
            line!(),
            option_env!("GIT_SHA").unwrap_or("unknown")
        ));

        println!("transaction result: {:?}", tx_result);
        assert!(
            !tx_result.is_empty(),
            "Expected non-empty transaction result"
        );

        Ok(())
    }
}

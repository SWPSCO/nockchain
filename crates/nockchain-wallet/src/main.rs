#![allow(clippy::doc_overindented_list_items)]

mod command;
mod connection;
mod error;

use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use clap::Parser;
#[cfg(test)]
use command::TimelockRangeCli;
#[cfg(test)]
use command::WalletWire;
use command::{ClientType, CommandNoun, Commands, WalletCli};
use kernels::wallet::KERNEL;
use nockapp::driver::*;
use nockapp::kernel::boot;
use nockapp::noun::slab::{NockJammer, NounSlab};
use nockapp::utils::bytes::Byts;
use nockapp::utils::make_tas;
use nockapp::wire::{SystemWire, Wire};
use nockapp::{
    exit_driver, file_driver, markdown_driver, one_punch_driver, system_data_dir, CrownError,
    NockApp, NockAppError, ToBytesExt,
};
use nockapp_grpc::pb::common::v1::Base58Hash as PbBase58Hash;
use nockapp_grpc::pb::public::v1::transaction_accepted_response;
use nockapp_grpc::{private_nockapp, public_nockchain};
use nockchain_types::tx_engine::note::{
    BalanceUpdate, Hash as DomainHash, TimelockIntent, TimelockRangeAbsolute, TimelockRangeRelative,
};
use nockchain_types::SchnorrPubkey;
use nockvm::jets::cold::Nounable;
use nockvm::noun::{Atom, Cell, FullDebugCell, IndirectAtom, Noun, D, NO, SIG, T, YES};
use noun_serde::prelude::*;
use noun_serde::NounDecodeError;
use termimad::MadSkin;
use tokio::fs as tokio_fs;
use tracing::{error, info};
use zkvm_jetpack::hot::produce_prover_hot_state;

#[tokio::main]
async fn main() -> Result<(), NockAppError> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("default provider already set elsewhere");

    let cli = WalletCli::parse();
    boot::init_default_tracing(&cli.boot.clone()); // Init tracing early

    if let Commands::TxAccepted { tx_id } = &cli.command {
        return run_transaction_accepted(&cli.connection, tx_id).await;
    }

    let prover_hot_state = produce_prover_hot_state();
    let data_dir = wallet_data_dir().await?;

    let kernel = boot::setup(
        KERNEL,
        cli.boot.clone(),
        prover_hot_state.as_slice(),
        "wallet",
        Some(data_dir),
    )
    .await
    .map_err(|e| CrownError::Unknown(format!("Kernel setup failed: {}", e)))?;

    let mut wallet = Wallet::new(kernel);

    // Determine if this command requires chain synchronization

    let requires_sync = match &cli.command {
        // Commands that DON'T need syncing either because they don't sync
        // or they don't interact with the chain
        Commands::Keygen
        | Commands::GenerateMiningPkh
        | Commands::DeriveChild { .. }
        | Commands::ImportKeys { .. }
        | Commands::ExportKeys
        | Commands::SignTx { .. }
        | Commands::SignMessage { .. }
        | Commands::VerifyMessage { .. }
        | Commands::SignHash { .. }
        | Commands::VerifyHash { .. }
        | Commands::ExportMasterPubkey
        | Commands::ImportMasterPubkey { .. }
        | Commands::ListActiveAddresses
        | Commands::SetActiveMasterAddress { .. }
        | Commands::ListMasterAddresses
        | Commands::ShowSeedphrase
        | Commands::ShowMasterPubkey
        | Commands::ShowMasterPrivkey
        | Commands::CreateTx { .. }
        | Commands::ShowTx { .. }
        | Commands::TxAccepted { .. } => false,

        // All other commands DO need sync
        _ => true,
    };

    let poke = match &cli.command {
        Commands::Keygen => {
            let mut entropy = [0u8; 32];
            let mut salt = [0u8; 16];
            getrandom::fill(&mut entropy).map_err(|e| CrownError::Unknown(e.to_string()))?;
            getrandom::fill(&mut salt).map_err(|e| CrownError::Unknown(e.to_string()))?;
            Wallet::keygen(&entropy, &salt)
        }
        Commands::GenerateMiningPkh => {
            let mut entropy = [0u8; 32];
            let mut salt = [0u8; 16];
            getrandom::fill(&mut entropy).map_err(|e| CrownError::Unknown(e.to_string()))?;
            getrandom::fill(&mut salt).map_err(|e| CrownError::Unknown(e.to_string()))?;
            Wallet::generate_mining_pkh(&entropy, &salt)
        }
        Commands::DeriveChild {
            index,
            hardened,
            label,
        } => Wallet::derive_child(*index, *hardened, label),
        Commands::SignTx {
            transaction,
            index,
            hardened,
        } => Wallet::sign_tx(transaction, *index, *hardened),
        Commands::SignMessage {
            message,
            message_file,
            message_pos,
            index,
            hardened,
        } => {
            let bytes = if let Some(m) = message.clone().or(message_pos.clone()) {
                m.as_bytes().to_vec()
            } else if let Some(path) = message_file {
                fs::read(path).map_err(|e| {
                    CrownError::Unknown(format!("Failed to read message file: {}", e))
                })?
            } else {
                return Err(CrownError::Unknown(
                    "either --message or --message-file must be provided".into(),
                )
                .into());
            };
            Wallet::sign_message(&bytes, *index, *hardened)
        }
        Commands::SignHash {
            hash_b58,
            index,
            hardened,
        } => Wallet::sign_hash(hash_b58, *index, *hardened),
        Commands::VerifyMessage {
            message,
            message_file,
            message_pos,
            signature_path,
            signature_pos,
            pubkey,
            pubkey_pos,
        } => {
            let msg_bytes = if let Some(m) = message.clone().or(message_pos.clone()) {
                m.as_bytes().to_vec()
            } else if let Some(path) = message_file {
                fs::read(path).map_err(|e| {
                    CrownError::Unknown(format!("Failed to read message file: {}", e))
                })?
            } else {
                return Err(CrownError::Unknown(
                    "either --message or --message-file must be provided".into(),
                )
                .into());
            };
            let sig_path = signature_path
                .clone()
                .or(signature_pos.clone())
                .ok_or_else(|| {
                    NockAppError::from(CrownError::Unknown(
                        "--signature or SIGNATURE_FILE positional is required".into(),
                    ))
                })?;
            let pk_b58 = pubkey.clone().or(pubkey_pos.clone()).ok_or_else(|| {
                NockAppError::from(CrownError::Unknown(
                    "--pubkey or PUBKEY positional is required".into(),
                ))
            })?;

            let sig_bytes = fs::read(sig_path)
                .map_err(|e| CrownError::Unknown(format!("Failed to read signature: {}", e)))?;
            Wallet::verify_message(&msg_bytes, &sig_bytes, &pk_b58)
        }
        Commands::VerifyHash {
            hash_b58,
            signature_path,
            signature_pos,
            pubkey,
            pubkey_pos,
        } => {
            let sig_path = signature_path
                .clone()
                .or(signature_pos.clone())
                .ok_or_else(|| {
                    NockAppError::from(CrownError::Unknown(
                        "--signature or SIGNATURE_FILE positional is required".into(),
                    ))
                })?;
            let pk_b58 = pubkey.clone().or(pubkey_pos.clone()).ok_or_else(|| {
                NockAppError::from(CrownError::Unknown(
                    "--pubkey or PUBKEY positional is required".into(),
                ))
            })?;
            let sig_bytes = fs::read(sig_path)
                .map_err(|e| CrownError::Unknown(format!("Failed to read signature: {}", e)))?;
            Wallet::verify_hash(hash_b58, &sig_bytes, &pk_b58)
        }
        Commands::ImportKeys {
            file,
            key,
            seedphrase,
            version,
            watch_only_pubkey,
        } => {
            if let Some(file_path) = file {
                Wallet::import_keys(file_path)
            } else if let Some(extended_key) = key {
                Wallet::import_extended(extended_key)
            } else if let Some(seed) = seedphrase {
                let version = version.ok_or_else(|| {
                    NockAppError::from(CrownError::Unknown(
                        "--version is required when using --seedphrase".into(),
                    ))
                })?;
                // normalize seedphrase to have exactly one space between words
                let normalized_seed = seed.split_whitespace().collect::<Vec<&str>>().join(" ");
                Wallet::import_seed_phrase(&normalized_seed, version)
            } else if let Some(pubkey) = watch_only_pubkey {
                let _ = SchnorrPubkey::from_base58(pubkey)
                    .map_err(|e| CrownError::Unknown(format!("Invalid public key: {}", e)))?;
                Wallet::import_watch_only_pubkey(&pubkey)
            } else {
                return Err(CrownError::Unknown(
                    "One of --file, --key, --seedphrase, or --master-privkey must be provided for import-keys".to_string(),
                )
                .into());
            }
        }
        Commands::ExportKeys => Wallet::export_keys(),
        Commands::ListNotes => Wallet::list_notes(),
        Commands::ListNotesByPubkey { pubkey } => {
            if let Some(pk) = pubkey {
                Wallet::list_notes_by_pubkey(pk)
            } else {
                return Err(CrownError::Unknown("Public key is required".into()).into());
            }
        }
        Commands::ListNotesByPubkeyCsv { pubkey } => Wallet::list_notes_by_pubkey_csv(pubkey),
        Commands::CreateTx {
            names,
            recipients,
            gifts,
            fee,
            index,
            hardened,
            timelock_intent,
        } => {
            let parsed_timelock_intent = match timelock_intent {
                Some(intent) => {
                    let absolute_range = intent.absolute_range();
                    let relative_range = intent.relative_range();

                    let has_upper_bound = intent.has_upper_bound();

                    if has_upper_bound {
                        confirm_upper_bound_warning()?;
                    }
                    Wallet::timelock_intent_from_ranges(absolute_range, relative_range)
                }
                None => None,
            };

            Wallet::create_tx(
                names.clone(),
                recipients.clone(),
                gifts.clone(),
                *fee,
                *index,
                *hardened,
                parsed_timelock_intent,
            )
        }
        Commands::SendTx { transaction } => Wallet::send_tx(transaction),
        Commands::ShowTx { transaction } => Wallet::show_tx(transaction),
        Commands::ExportMasterPubkey => Wallet::export_master_pubkey(),
        Commands::ImportMasterPubkey { key_path } => Wallet::import_master_pubkey(key_path),
        Commands::ListActiveAddresses => Wallet::list_active_addresses(),
        Commands::SetActiveMasterAddress { address_b58 } => {
            Wallet::set_active_master_address(address_b58)
        }
        Commands::ListMasterAddresses => Wallet::list_master_addresses(),
        Commands::ShowSeedphrase => Wallet::show_seed_phrase(),
        Commands::ShowMasterPubkey => Wallet::show_master_pubkey(),
        Commands::ShowMasterPrivkey => Wallet::show_master_privkey(),
        Commands::TxAccepted { .. } => {
            unreachable!("transaction-accepted handled earlier")
        }
    }?;

    // If this command requires sync, update the balance using a synchronous poke
    if requires_sync {
        info!(
            "Command requires syncing the current balance, connecting to Nockchain gRPC server..."
        );
        let mut pubkey_peek_slab = NounSlab::new();
        let tracked_tag = make_tas(&mut pubkey_peek_slab, "tracked-pubkeys").as_noun();
        let watch_only = cli.include_watch_only.to_noun(&mut pubkey_peek_slab);
        let path = T(&mut pubkey_peek_slab, &[tracked_tag, watch_only, SIG]);
        pubkey_peek_slab.set_root(path);
        let pubkey_slab = wallet.app.peek_handle(pubkey_peek_slab).await?;
        if let Some(slab) = pubkey_slab {
            let pubkeys = slab
                .to_vec()
                .iter()
                .map(|key| String::from_noun(unsafe { key.root() }))
                .collect::<Result<Vec<String>, NounDecodeError>>()?;

            let connection_target = cli.connection.target();
            let pokes =
                connection::sync_wallet_balance(&mut wallet, &connection_target, pubkeys).await?;

            for poke in pokes {
                let _ = wallet.app.poke(SystemWire.to_wire(), poke).await.unwrap();
            }
        } else {
            info!("No pubkeys found, not updating balance")
        }
    }

    wallet
        .app
        .add_io_driver(one_punch_driver(poke.0, poke.1))
        .await;
    wallet.app.add_io_driver(file_driver()).await;
    wallet.app.add_io_driver(markdown_driver()).await;
    wallet.app.add_io_driver(exit_driver()).await;

    match wallet.app.run().await {
        Ok(_) => {
            info!("Command executed successfully");
            Ok(())
        }
        Err(e) => {
            error!("Command failed: {}", e);
            Err(e)
        }
    }
}

fn validate_label(s: &str) -> Result<String, String> {
    if s.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        Ok(s.to_string())
    } else {
        Err("Label must contain only lowercase letters, numbers, and hyphens".to_string())
    }
}

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
    fn new(nockapp: NockApp) -> Self {
        Wallet { app: nockapp }
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

    /// Generates a new key pair. Will be a version 0 key until the wallet supports v1 transactions
    ///
    /// # Arguments
    ///
    /// * `entropy` - The entropy to use for key generation.
    /// * `sal` - The salt to use for key generation.
    fn keygen(entropy: &[u8; 32], sal: &[u8; 16]) -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        let ent: Byts = Byts::new(entropy.to_vec());
        let ent_noun = ent.into_noun(&mut slab);
        let sal: Byts = Byts::new(sal.to_vec());
        let sal_noun = sal.into_noun(&mut slab);
        Self::wallet("keygen", &[ent_noun, sal_noun], Operation::Poke, &mut slab)
    }

    /// Generates a new key pair, specifically for mining pkh.
    ///
    /// # Arguments
    ///
    /// * `entropy` - The entropy to use for key generation.
    /// * `sal` - The salt to use for key generation.
    fn generate_mining_pkh(entropy: &[u8; 32], sal: &[u8; 16]) -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        let ent: Byts = Byts::new(entropy.to_vec());
        let ent_noun = ent.into_noun(&mut slab);
        let sal: Byts = Byts::new(sal.to_vec());
        let sal_noun = sal.into_noun(&mut slab);
        Self::wallet(
            "generate-mining-pkh",
            &[ent_noun, sal_noun],
            Operation::Poke,
            &mut slab,
        )
    }

    ///// Updates the keys in the wallet.
    /////
    ///// # Arguments
    /////
    ///// * `entropy` - The entropy to use for key generation.
    ///// * `salt` - The salt to use for key generation.
    //fn upgrade_keys(entropy: &[u8; 32], salt: &[u8; 16]) -> CommandNoun<NounSlab> {
    //    let mut slab = NounSlab::new();
    //    let ent: Byts = Byts::new(entropy.to_vec());
    //    let ent_noun = ent.into_noun(&mut slab);
    //    let sal: Byts = Byts::new(salt.to_vec());
    //    let sal_noun = sal.into_noun(&mut slab);
    //    Self::wallet(
    //        "upgrade-keys-v2",
    //        &[ent_noun, sal_noun],
    //        Operation::Poke,
    //        &mut slab,
    //    )
    //}

    // Derives a child key from current master key.
    //
    // # Arguments
    //
    // * `index` - The index of the child key to derive
    // * `hardened` - Whether the child key should be hardened
    // * `label` - Optional label for the child key
    fn derive_child(index: u64, hardened: bool, label: &Option<String>) -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        let index_noun = D(index);
        let hardened_noun = if hardened { YES } else { NO };
        let label_noun = label.as_ref().map_or(SIG, |l| {
            let label_noun = l.into_noun(&mut slab);
            T(&mut slab, &[SIG, label_noun])
        });

        Self::wallet(
            "derive-child",
            &[index_noun, hardened_noun, label_noun],
            Operation::Poke,
            &mut slab,
        )
    }

    /// Signs a transaction.
    ///
    /// # Arguments
    ///
    /// * `transaction_path` - Path to the transaction file
    /// * `index` - Optional index of the key to use for signing
    fn sign_tx(
        transaction_path: &str,
        index: Option<u64>,
        hardened: bool,
    ) -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();

        // Validate index is within range (though clap should prevent this)
        if let Some(idx) = index {
            if idx >= 2 << 31 {
                return Err(
                    CrownError::Unknown("Key index must not exceed 2^31 - 1".into()).into(),
                );
            }
        }

        // Read and decode the input bundle
        let transaction_data = fs::read(transaction_path)
            .map_err(|e| CrownError::Unknown(format!("Failed to read transaction: {}", e)))?;

        // Convert the bundle data into a noun using cue
        let transaction_noun = slab
            .cue_into(transaction_data.as_bytes()?)
            .map_err(|e| CrownError::Unknown(format!("Failed to decode transaction: {}", e)))?;

        // Format information about signing key
        let sign_key_noun = match index {
            Some(i) => {
                let inner = D(i);
                let hardened_noun = if hardened { YES } else { NO };
                T(&mut slab, &[D(0), inner, hardened_noun])
            }
            None => D(0),
        };

        // Generate random entropy
        let mut entropy_bytes = [0u8; 32];
        getrandom::fill(&mut entropy_bytes).map_err(|e| CrownError::Unknown(e.to_string()))?;
        let entropy = from_bytes(&mut slab, &entropy_bytes).as_noun();

        Self::wallet(
            "sign-tx",
            &[transaction_noun, sign_key_noun, entropy],
            Operation::Poke,
            &mut slab,
        )
    }

    fn sign_message(
        message_bytes: &[u8],
        index: Option<u64>,
        hardened: bool,
    ) -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();

        if let Some(idx) = index {
            if idx >= 2 << 31 {
                return Err(
                    CrownError::Unknown("Key index must not exceed 2^31 - 1".into()).into(),
                );
            }
        }

        let msg_atom = from_bytes(&mut slab, message_bytes).as_noun();

        let sign_key_noun = match index {
            Some(i) => {
                let inner = D(i);
                let hardened_noun = if hardened { YES } else { NO };
                T(&mut slab, &[D(0), inner, hardened_noun])
            }
            None => D(0),
        };

        Self::wallet(
            "sign-message",
            &[msg_atom, sign_key_noun],
            Operation::Poke,
            &mut slab,
        )
    }

    fn verify_message(
        message_bytes: &[u8],
        signature_jam: &[u8],
        pubkey_b58: &str,
    ) -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        let msg_atom = from_bytes(&mut slab, message_bytes).as_noun();
        let sig_atom = from_bytes(&mut slab, signature_jam).as_noun();
        let pk_noun = make_tas(&mut slab, pubkey_b58).as_noun();

        Self::wallet(
            "verify-message",
            &[msg_atom, sig_atom, pk_noun],
            Operation::Poke,
            &mut slab,
        )
    }

    fn sign_hash(hash_b58: &str, index: Option<u64>, hardened: bool) -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();

        if let Some(idx) = index {
            if idx >= 2 << 31 {
                return Err(
                    CrownError::Unknown("Key index must not exceed 2^31 - 1".into()).into(),
                );
            }
        }

        let hash_noun = make_tas(&mut slab, hash_b58).as_noun();
        let sign_key_noun = match index {
            Some(i) => {
                let inner = D(i);
                let hardened_noun = if hardened { YES } else { NO };
                T(&mut slab, &[D(0), inner, hardened_noun])
            }
            None => D(0),
        };

        Self::wallet(
            "sign-hash",
            &[hash_noun, sign_key_noun],
            Operation::Poke,
            &mut slab,
        )
    }

    fn verify_hash(
        hash_b58: &str,
        signature_jam: &[u8],
        pubkey_b58: &str,
    ) -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        let hash_noun = make_tas(&mut slab, hash_b58).as_noun();
        let sig_atom = from_bytes(&mut slab, signature_jam).as_noun();
        let pk_noun = make_tas(&mut slab, pubkey_b58).as_noun();

        Self::wallet(
            "verify-hash",
            &[hash_noun, sig_atom, pk_noun],
            Operation::Poke,
            &mut slab,
        )
    }

    /// Imports keys from a seed phrase.
    ///
    /// # Arguments
    ///
    /// * `seed_phrase` - The seed phrase to generate the master private key from.
    /// * `version` - The version tag to attach to the generated master key.
    fn import_seed_phrase(seed_phrase: &str, version: u64) -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        let seed_phrase_noun = make_tas(&mut slab, seed_phrase).as_noun();
        let version_noun = D(version);
        Self::wallet(
            "import-seed-phrase",
            &[seed_phrase_noun, version_noun],
            Operation::Poke,
            &mut slab,
        )
    }

    /// Imports keys.
    ///
    /// # Arguments
    ///
    /// * `input_path` - Path to jammed keys file
    fn import_keys(input_path: &str) -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();

        let key_data = fs::read(input_path)
            .map_err(|e| CrownError::Unknown(format!("Failed to read master pubkeys: {}", e)))?;

        let pubkey_noun = slab
            .cue_into(key_data.as_bytes()?)
            .map_err(|e| CrownError::Unknown(format!("Failed to decode master pubkeys: {}", e)))?;

        Self::wallet("import-keys", &[pubkey_noun], Operation::Poke, &mut slab)
    }

    /// Imports an extended key.
    ///
    /// # Arguments
    ///
    /// * `extended_key` - Extended key string (e.g., "zprv..." or "zpub...")
    fn import_extended(extended_key: &str) -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        let key_noun = make_tas(&mut slab, extended_key).as_noun();
        Self::wallet("import-extended", &[key_noun], Operation::Poke, &mut slab)
    }

    /// Imports a watch-only public key.
    ///
    /// # Arguments
    ///
    /// * `watch_pubkey` - Watch-only b58 encoded public key string
    fn import_watch_only_pubkey(watch_pubkey: &str) -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        let key_noun = make_tas(&mut slab, watch_pubkey).as_noun();
        Self::wallet(
            "import-watch-only-pubkey",
            &[key_noun],
            Operation::Poke,
            &mut slab,
        )
    }

    /// Exports keys to a file.
    fn export_keys() -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        Self::wallet("export-keys", &[], Operation::Poke, &mut slab)
    }

    fn timelock_intent_from_ranges(
        absolute: Option<TimelockRangeAbsolute>,
        relative: Option<TimelockRangeRelative>,
    ) -> Option<TimelockIntent> {
        if absolute.is_none() && relative.is_none() {
            None
        } else {
            Some(TimelockIntent {
                absolute: absolute.unwrap_or_else(TimelockRangeAbsolute::none),
                relative: relative.unwrap_or_else(TimelockRangeRelative::none),
            })
        }
    }

    /// Creates a transaction by building transaction inputs from notes.
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
    /// - A `NounSlab` with the encoded create-tx command
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
    /// wallet.create_tx(
    ///     names.to_string(),
    ///     recipients.to_string(),
    ///     gifts.to_string(),
    ///     fee,
    ///     None,
    ///     false,
    ///     None,
    /// )?;
    /// ```
    fn create_tx(
        names: String,
        recipients: String,
        gifts: String,
        fee: u64,
        index: Option<u64>,
        hardened: bool,
        timelock_intent: Option<TimelockIntent>,
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

        // Verify lengths based on single vs multiple mode
        if recipients_vec.len() == 1 && gifts_vec.len() == 1 {
            // Single mode: can spend from multiple notes to single recipient
            // No additional validation needed - any number of names is allowed
        } else {
            // Multiple mode: all lengths must match
            if names_vec.len() != recipients_vec.len() || names_vec.len() != gifts_vec.len() {
                return Err(CrownError::Unknown(
                    "Multiple recipient mode requires names, recipients, and gifts to have the same length"
                        .to_string(),
                )
                .into());
            }
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

        let fee_noun = D(fee);

        // Format information about signing key
        let sign_key_noun = match index {
            Some(i) => {
                let inner = D(i);
                let hardened_noun = if hardened { YES } else { NO };
                T(&mut slab, &[D(0), inner, hardened_noun])
            }
            None => D(0),
        };

        // Create the order noun - use single or multiple mode based on input
        let order_noun = if recipients_vec.len() == 1 && gifts_vec.len() == 1 {
            // Single mode: [%single recipient_data gift_amount]
            let single_tag = make_tas(&mut slab, "single").as_noun();
            let single_recipient = recipients_vec.into_iter().next().unwrap();
            let single_gift = gifts_vec.into_iter().next().unwrap();

            // Create the recipient data [number pubkeys_list] for single case
            let pubkeys_noun = single_recipient
                .1
                .into_iter()
                .rev()
                .fold(D(0), |acc, pubkey| {
                    let pubkey_noun = make_tas(&mut slab, &pubkey).as_noun();
                    Cell::new(&mut slab, pubkey_noun, acc).as_noun()
                });
            let recipient_data = T(&mut slab, &[D(single_recipient.0), pubkeys_noun]);

            T(&mut slab, &[single_tag, recipient_data, D(single_gift)])
        } else {
            // Multiple mode: [%multiple recipients_list gifts_list]
            let multiple_tag = make_tas(&mut slab, "multiple").as_noun();

            // Convert recipients to list
            let recipients_noun =
                recipients_vec
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

            T(&mut slab, &[multiple_tag, recipients_noun, gifts_noun])
        };

        // Convert timelock intent to noun. `~` encodes the absence of intent.
        let timelock_intent_noun = timelock_intent.to_noun(&mut slab);

        if timelock_intent.is_some() {
            tracing::debug!(
                "Converted timelock intent {:?} to noun: {:?}",
                timelock_intent,
                FullDebugCell(&timelock_intent_noun.as_cell()?)
            );
        }

        Self::wallet(
            "create-tx",
            &[names_noun, order_noun, fee_noun, sign_key_noun, timelock_intent_noun],
            Operation::Poke,
            &mut slab,
        )
    }

    async fn update_balance_grpc_public(
        client: &mut public_nockchain::PublicNockchainGrpcClient,
        pubkeys: Vec<String>,
    ) -> Result<Vec<NounSlab>, NockAppError> {
        let mut results = Vec::new();

        for (_index, key) in pubkeys.iter().enumerate() {
            let mut slab = NounSlab::new(); // Define slab - adjust as needed
            let response = client
                .wallet_get_balance(key.to_owned())
                .await
                .map_err(|e| {
                    NockAppError::OtherError(format!("Failed to request current balance: {}", e))
                })?;
            let balance = BalanceUpdate::try_from(response).map_err(|e| {
                NockAppError::OtherError(format!("Failed to parse balance update: {}", e))
            })?;
            let wrapped_balance = Some(Some(balance));
            let balance_noun = wrapped_balance.to_noun(&mut slab);
            let head = make_tas(&mut slab, "update-balance-grpc").as_noun();
            let full = T(&mut slab, &[head, balance_noun]);
            slab.set_root(full);
            results.push(slab);
        }

        Ok(results)
    }

    async fn update_balance_grpc_private(
        client: &mut private_nockapp::PrivateNockAppGrpcClient,
        pubkeys: Vec<String>,
    ) -> Result<Vec<NounSlab>, NockAppError> {
        let mut results = Vec::new();

        for (index, key) in pubkeys.iter().enumerate() {
            let mut slab = NounSlab::new(); // Define slab - adjust as needed
            let peek_path = vec!["balance-by-pubkey".to_string(), key.clone()];
            let mut path_slab = NounSlab::<NockJammer>::new();
            let path_noun = peek_path.to_noun(&mut path_slab);
            path_slab.set_root(path_noun);
            let path_bytes = path_slab.jam().to_vec();

            let response = client.peek(index as i32, path_bytes).await.map_err(|e| {
                NockAppError::OtherError(format!("Failed to peek current balance: {}", e))
            })?;
            let balance = slab.cue_into(response.as_bytes()?)?;
            let head = make_tas(&mut slab, "update-balance-grpc").as_noun();
            let full = T(&mut slab, &[head, balance]);
            slab.set_root(full);
            results.push(slab);
        }

        Ok(results)
    }

    /// Lists all notes in the wallet.
    ///
    /// Retrieves and displays all notes from the wallet's balance, sorted by assets.
    fn list_notes() -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        Self::wallet("list-notes", &[], Operation::Poke, &mut slab)
    }

    /// Exports the master public key.
    ///
    /// # Returns
    ///
    /// Retrieves and displays master public key and chaincode.
    fn export_master_pubkey() -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        Self::wallet("export-master-pubkey", &[], Operation::Poke, &mut slab)
    }

    /// Imports a master public key.
    ///
    /// # Arguments
    ///
    /// * `key` - Base58-encoded public key
    /// * `chain_code` - Base58-encoded chain code
    fn import_master_pubkey(input_path: &str) -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();

        let key_data = fs::read(input_path)
            .map_err(|e| CrownError::Unknown(format!("Failed to read master pubkeys: {}", e)))?;

        let pubkey_noun = slab
            .cue_into(key_data.as_bytes()?)
            .map_err(|e| CrownError::Unknown(format!("Failed to decode master pubkeys: {}", e)))?;

        Self::wallet(
            "import-master-pubkey",
            &[pubkey_noun],
            Operation::Poke,
            &mut slab,
        )
    }

    /// Creates a transaction from a transaction file.
    ///
    /// # Arguments
    ///
    /// * `transaction_path` - Path to the transaction file to create transaction from
    fn send_tx(transaction_path: &str) -> CommandNoun<NounSlab> {
        // Read and decode the transaction file
        let transaction_data = fs::read(transaction_path)
            .map_err(|e| CrownError::Unknown(format!("Failed to read transaction file: {}", e)))?;

        let mut slab = NounSlab::new();
        let transaction_noun = slab.cue_into(transaction_data.as_bytes()?).map_err(|e| {
            CrownError::Unknown(format!("Failed to decode transaction data: {}", e))
        })?;

        Self::wallet("send-tx", &[transaction_noun], Operation::Poke, &mut slab)
    }

    /// Displays a transaction file contents.
    ///
    /// # Arguments
    ///
    /// * `transaction_path` - Path to the transaction file to display
    fn show_tx(transaction_path: &str) -> CommandNoun<NounSlab> {
        // Read and decode the transaction file
        let transaction_data = fs::read(transaction_path)
            .map_err(|e| CrownError::Unknown(format!("Failed to read transaction file: {}", e)))?;

        let mut slab = NounSlab::new();
        let transaction_noun = slab.cue_into(transaction_data.as_bytes()?).map_err(|e| {
            CrownError::Unknown(format!("Failed to decode transaction data: {}", e))
        })?;

        Self::wallet("show-tx", &[transaction_noun], Operation::Poke, &mut slab)
    }

    /// Lists all addresses nested under the active master address.
    fn list_active_addresses() -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        Self::wallet("list-active-addresses", &[], Operation::Poke, &mut slab)
    }

    /// Sets the active master address.
    fn set_active_master_address(address_b58: &str) -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        let address_noun = make_tas(&mut slab, address_b58).as_noun();
        Self::wallet(
            "set-active-master-address",
            &[address_noun],
            Operation::Poke,
            &mut slab,
        )
    }

    /// Lists known master addresses.
    fn list_master_addresses() -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        Self::wallet("list-master-addresses", &[], Operation::Poke, &mut slab)
    }

    /// Lists notes by public key
    fn list_notes_by_pubkey(pubkey: &str) -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        let pubkey_noun = make_tas(&mut slab, pubkey).as_noun();
        Self::wallet(
            "list-notes-by-pubkey",
            &[pubkey_noun],
            Operation::Poke,
            &mut slab,
        )
    }

    /// Lists notes by public key in CSV format
    fn list_notes_by_pubkey_csv(pubkey: &str) -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        let pubkey_noun = make_tas(&mut slab, pubkey).as_noun();
        Self::wallet(
            "list-notes-by-pubkey-csv",
            &[pubkey_noun],
            Operation::Poke,
            &mut slab,
        )
    }

    /// Shows the seed phrase for the current master key.
    fn show_seed_phrase() -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        Self::wallet("show-seed-phrase", &[], Operation::Poke, &mut slab)
    }

    /// Shows the master public key.
    fn show_master_pubkey() -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        Self::wallet("show-master-zpub", &[], Operation::Poke, &mut slab)
    }

    /// Shows the master private key.
    fn show_master_privkey() -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();
        Self::wallet("show-master-zprv", &[], Operation::Poke, &mut slab)
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

fn confirm_upper_bound_warning() -> Result<(), NockAppError> {
    println!(
        "Warning: specifying an upper timelock bound will make the output unspendable after that height. Only use this feature if you know what you're doing."
    );
    print!("Type 'YES' to continue: ");
    io::stdout()
        .flush()
        .map_err(|e| CrownError::Unknown(format!("Failed to flush stdout: {}", e)))?;
    let mut response = String::new();
    io::stdin()
        .read_line(&mut response)
        .map_err(|e| CrownError::Unknown(format!("Failed to read confirmation: {}", e)))?;

    if response.trim() == "YES" {
        Ok(())
    } else {
        Err(CrownError::Unknown(
            "Aborted create-tx because upper bound was not confirmed with YES".into(),
        )
        .into())
    }
}

async fn run_transaction_accepted(
    connection: &connection::ConnectionCli,
    tx_id: &str,
) -> Result<(), NockAppError> {
    if connection.client != ClientType::Public {
        return Err(NockAppError::OtherError(
            "transaction-accepted command requires the public client (--client public)".to_string(),
        ));
    }

    let endpoint = connection.public_grpc_server_addr.to_string();
    let mut client = public_nockchain::PublicNockchainGrpcClient::connect(endpoint.clone())
        .await
        .map_err(|err| {
            NockAppError::OtherError(format!(
                "Failed to connect to public Nockchain gRPC server at {}: {}",
                endpoint, err
            ))
        })?;

    DomainHash::from_base58(tx_id).map_err(|_| {
        NockAppError::OtherError(format!(
            "Invalid transaction ID (expected base58-encoded hash): {}",
            tx_id
        ))
    })?;

    let request = PbBase58Hash {
        hash: tx_id.to_string(),
    };

    let response = client.transaction_accepted(request).await.map_err(|err| {
        NockAppError::OtherError(format!(
            "Transaction accepted query failed for {}: {}",
            tx_id, err
        ))
    })?;

    let accepted = match response.result {
        Some(transaction_accepted_response::Result::Accepted(value)) => value,
        Some(transaction_accepted_response::Result::Error(err)) => {
            return Err(NockAppError::OtherError(format!(
                "Transaction accepted query returned error code {}: {}",
                err.code, err.message
            )))
        }
        None => {
            return Err(NockAppError::OtherError(
                "Transaction accepted query returned an empty result".to_string(),
            ))
        }
    };

    let markdown = format_transaction_accepted_markdown(tx_id, accepted);
    let skin = MadSkin::default_dark();
    println!("{}", skin.term_text(&markdown));

    Ok(())
}

fn format_transaction_accepted_markdown(tx_id: &str, accepted: bool) -> String {
    let status_line = if accepted {
        "- status: **accepted by node**"
    } else {
        "- status: **not yet accepted**"
    };

    [
        "## Transaction Acceptance".to_string(),
        format!("- tx id: `{}`", tx_id),
        status_line.to_string(),
    ]
    .join("\n")
}

pub fn from_bytes(stack: &mut NounSlab, bytes: &[u8]) -> Atom {
    unsafe {
        let mut tas_atom = IndirectAtom::new_raw_bytes(stack, bytes.len(), bytes.as_ptr());
        tas_atom.normalize_as_atom()
    }
}

// TODO: all these tests need to also validate the results and not
// just ensure that the wallet can be poked with the expected noun.
#[allow(warnings)]
#[cfg(test)]
mod tests {
    use std::sync::Once;

    use nockapp::kernel::boot::{self, Cli as BootCli};
    use nockapp::wire::SystemWire;
    use nockapp::{exit_driver, AtomExt, Bytes};
    use nockchain_math::belt::Belt;
    use nockchain_types::{BlockHeight, BlockHeightDelta};
    use tokio::sync::mpsc;

    use super::*;

    static INIT: Once = Once::new();

    fn init_tracing() {
        INIT.call_once(|| {
            let cli = boot::default_boot_cli(true);
            boot::init_default_tracing(&cli);
        });
    }

    #[test]
    fn timelock_cli_accepts_ascending_bound() {
        let range: TimelockRangeCli = "1..5".parse().unwrap();
        let absolute = range.absolute();
        assert_eq!(absolute.min, Some(BlockHeight(Belt(1))));
        assert_eq!(absolute.max, Some(BlockHeight(Belt(5))));
    }

    #[test]
    fn timelock_cli_accepts_open_upper_bound() {
        let range: TimelockRangeCli = "..5".parse().unwrap();
        let absolute = range.absolute();
        assert_eq!(absolute.min, None);
        assert_eq!(absolute.max, Some(BlockHeight(Belt(5))));
    }

    #[test]
    fn timelock_cli_accepts_open_lower_bound() {
        let range: TimelockRangeCli = "7..".parse().unwrap();
        let relative = range.relative();
        assert_eq!(relative.min, Some(BlockHeightDelta(Belt(7))));
        assert_eq!(relative.max, None);
    }

    #[test]
    fn timelock_cli_rejects_descending_bounds() {
        let err = TimelockRangeCli::from_bounds(Some(10), Some(5)).unwrap_err();
        assert!(err.contains("min <= max"));
    }

    #[test]
    fn timelock_cli_allows_fully_open_interval() {
        let range: TimelockRangeCli = "..".parse().unwrap();
        assert!(range.absolute().min.is_none() && range.absolute().max.is_none());
        assert!(range.relative().min.is_none() && range.relative().max.is_none());
        assert!(!range.has_upper_bound());
    }

    #[test]
    fn timelock_intent_from_ranges_handles_none() {
        assert!(Wallet::timelock_intent_from_ranges(None, None).is_none());
        let open_range: TimelockRangeCli = "..".parse().unwrap();

        let explicit_none = Wallet::timelock_intent_from_ranges(
            Some(open_range.absolute()),
            Some(open_range.relative()),
        )
        .expect("expected explicit timelock intent");

        assert_eq!(
            explicit_none,
            TimelockIntent {
                absolute: TimelockRangeAbsolute::none(),
                relative: TimelockRangeRelative::none(),
            }
        );
    }

    #[test]
    fn timelock_intent_from_ranges_accepts_partial_specs() {
        let absolute = TimelockRangeAbsolute::none();
        let intent = Wallet::timelock_intent_from_ranges(Some(absolute.clone()), None)
            .expect("absolute range should produce intent");
        assert_eq!(intent.absolute, absolute);
        assert_eq!(intent.relative, TimelockRangeRelative::none());
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_keygen() -> Result<(), NockAppError> {
        init_tracing();
        let cli = BootCli::parse_from(&["--new"]);

        let prover_hot_state = produce_prover_hot_state();
        let nockapp = boot::setup(
            KERNEL,
            cli.clone(),
            prover_hot_state.as_slice(),
            "wallet",
            None,
        )
        .await
        .map_err(|e| CrownError::Unknown(e.to_string()))?;
        let mut wallet = Wallet::new(nockapp);
        let mut entropy = [0u8; 32];
        let mut salt = [0u8; 16];
        getrandom::fill(&mut entropy).map_err(|e| CrownError::Unknown(e.to_string()))?;
        getrandom::fill(&mut salt).map_err(|e| CrownError::Unknown(e.to_string()))?;
        let (noun, op) = Wallet::keygen(&entropy, &salt)?;

        let wire = WalletWire::Command(Commands::Keygen).to_wire();

        let keygen_result = wallet.app.poke(wire, noun.clone()).await?;

        println!("keygen result: {:?}", keygen_result);
        assert!(
            keygen_result.len() == 2,
            "Expected keygen result to be a list of 2 noun slabs - markdown and exit"
        );
        let exit_cause = unsafe { keygen_result[1].root() };
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
            cli.clone(),
            prover_hot_state.as_slice(),
            "wallet",
            None,
        )
        .await
        .map_err(|e| CrownError::Unknown(e.to_string()))?;
        let mut wallet = Wallet::new(nockapp);

        // Generate a new key pair
        let mut entropy = [0u8; 32];
        let mut salt = [0u8; 16];
        let (noun, op) = Wallet::keygen(&entropy, &salt)?;
        let wire = WalletWire::Command(Commands::Keygen).to_wire();
        let _ = wallet.app.poke(wire, noun.clone()).await?;

        // Derive a child key
        let index = 0;
        let hardened = true;
        let label = None;
        let (noun, op) = Wallet::derive_child(index, hardened, &label)?;

        let wire = WalletWire::Command(Commands::DeriveChild {
            index,
            hardened,
            label,
        })
        .to_wire();

        let derive_result = wallet.app.poke(wire, noun.clone()).await?;

        assert!(
            derive_result.len() == 2,
            "Expected derive result to be a list of 2 noun slabs - markdown and exit"
        );

        let exit_cause = unsafe { derive_result[1].root() };
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
        let nockapp = boot::setup(KERNEL, cli.clone(), &[], "wallet", None)
            .await
            .map_err(|e| CrownError::Unknown(e.to_string()))?;
        let mut wallet = Wallet::new(nockapp);

        // Create a temporary input bundle file
        let bundle_path = "test_bundle.jam";
        let test_data = vec![0u8; 32]; // TODO make this a real input bundle
        fs::write(bundle_path, &test_data).map_err(|e| NockAppError::IoError(e))?;

        let wire = WalletWire::Command(Commands::SignTx {
            transaction: bundle_path.to_string(),
            index: None,
            hardened: false,
        })
        .to_wire();

        // Test signing with valid indices
        let (noun, op) = Wallet::sign_tx(bundle_path, None, false)?;
        let sign_result = wallet.app.poke(wire, noun.clone()).await?;

        println!("sign_result: {:?}", sign_result);

        let wire = WalletWire::Command(Commands::SignTx {
            transaction: bundle_path.to_string(),
            index: Some(1),
            hardened: false,
        })
        .to_wire();

        let (noun, op) = Wallet::sign_tx(bundle_path, Some(1), false)?;
        let sign_result = wallet.app.poke(wire, noun.clone()).await?;

        println!("sign_result: {:?}", sign_result);

        let wire = WalletWire::Command(Commands::SignTx {
            transaction: bundle_path.to_string(),
            index: Some(255),
            hardened: false,
        })
        .to_wire();

        let (noun, op) = Wallet::sign_tx(bundle_path, Some(255), false)?;
        let sign_result = wallet.app.poke(wire, noun.clone()).await?;

        println!("sign_result: {:?}", sign_result);

        // Cleanup
        fs::remove_file(bundle_path).map_err(|e| NockAppError::IoError(e))?;
        Ok(())
    }

    // Tests for Cold Side Commands
    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_gen_master_privkey() -> Result<(), NockAppError> {
        init_tracing();
        let cli = BootCli::parse_from(&[""]);
        let nockapp = boot::setup(KERNEL, cli.clone(), &[], "wallet", None)
            .await
            .map_err(|e| CrownError::Unknown(e.to_string()))?;
        let mut wallet = Wallet::new(nockapp);
        let seedphrase = "correct horse battery staple";
        let version = 1;
        let (noun, op) = Wallet::import_seed_phrase(seedphrase, version)?;
        println!("privkey_slab: {:?}", noun);
        let wire = WalletWire::Command(Commands::ImportKeys {
            file: None,
            key: None,
            seedphrase: Some(seedphrase.to_string()),
            version: Some(version),
            watch_only_pubkey: None,
        })
        .to_wire();
        let privkey_result = wallet.app.poke(wire, noun.clone()).await?;
        println!("privkey_result: {:?}", privkey_result);
        Ok(())
    }

    // Tests for Hot Side Commands
    // TODO: fix this test by adding a real key file
    #[tokio::test]
    #[ignore]
    async fn test_import_keys() -> Result<(), NockAppError> {
        init_tracing();
        let cli = BootCli::parse_from(&["--new"]);
        let nockapp = boot::setup(KERNEL, cli.clone(), &[], "wallet", None)
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

        let (noun, op) = Wallet::import_keys(test_path)?;
        let wire = WalletWire::Command(Commands::ImportKeys {
            file: Some(test_path.to_string()),
            key: None,
            seedphrase: None,
            version: None,
            watch_only_pubkey: None,
        })
        .to_wire();
        let import_result = wallet.app.poke(wire, noun.clone()).await?;

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

    // TODO: fix this test
    #[tokio::test]
    #[ignore]
    async fn test_spend_multisig_format() -> Result<(), NockAppError> {
        init_tracing();
        let cli = BootCli::parse_from(&[""]);
        let nockapp = boot::setup(KERNEL, cli.clone(), &[], "wallet", None)
            .await
            .map_err(|e| CrownError::Unknown(e.to_string()))?;
        let mut wallet = Wallet::new(nockapp);

        let names = "[first1 last1],[first2 last2]".to_string();
        let recipients = "[1 pk1],[2 pk2,pk3,pk4]".to_string();
        let gifts = "1,2".to_string();
        let fee = 1;

        let (noun, op) = Wallet::create_tx(
            names.clone(),
            recipients.clone(),
            gifts.clone(),
            fee,
            None,
            false,
            None,
        )?;
        let wire = WalletWire::Command(Commands::CreateTx {
            names: names.clone(),
            recipients: recipients.clone(),
            gifts: gifts.clone(),
            fee: fee.clone(),
            index: None,
            hardened: false,
            timelock_intent: None,
        })
        .to_wire();
        let spend_result = wallet.app.poke(wire, noun.clone()).await?;
        println!("spend_result: {:?}", spend_result);

        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_spend_single_sig_format() -> Result<(), NockAppError> {
        let cli = BootCli::parse_from(&[""]);
        let nockapp = boot::setup(KERNEL, cli.clone(), &[], "wallet", None)
            .await
            .map_err(|e| CrownError::Unknown(e.to_string()))?;
        init_tracing();
        let mut wallet = Wallet::new(nockapp);

        // these should be valid names of notes in the wallet balance
        let names = "[Amt4GcpYievY4PXHfffiWriJ1sYfTXFkyQsGzbzwMVzewECWDV3Ad8Q BJnaDB3koU7ruYVdWCQqkFYQ9e3GXhFsDYjJ1vSmKFdxzf6Y87DzP4n]".to_string();
        let recipients = "3HKKp7xZgCw1mhzk4iw735S2ZTavCLHc8YDGRP6G9sSTrRGsaPBu1AqJ8cBDiw2LwhRFnQG7S3N9N9okc28uBda6oSAUCBfMSg5uC9cefhrFrvXVGomoGcRvcFZTWuJzm3ch".to_string();

        let gifts = "0".to_string();
        let fee = 0;

        // generate keys
        let version = 1;
        let (genkey_noun, genkey_op) =
            Wallet::import_seed_phrase("correct horse battery staple", version)?;
        let (spend_noun, spend_op) = Wallet::create_tx(
            names.clone(),
            recipients.clone(),
            gifts.clone(),
            fee,
            None,
            false,
            None,
        )?;

        let wire1 = WalletWire::Command(Commands::ImportKeys {
            file: None,
            key: None,
            seedphrase: Some("correct horse battery staple".to_string()),
            version: Some(version),
            watch_only_pubkey: None,
        })
        .to_wire();
        let genkey_result = wallet.app.poke(wire1, genkey_noun.clone()).await?;
        println!("genkey_result: {:?}", genkey_result);

        let wire2 = WalletWire::Command(Commands::CreateTx {
            names: names.clone(),
            recipients: recipients.clone(),
            gifts: gifts.clone(),
            fee: fee.clone(),
            index: None,
            hardened: false,
            timelock_intent: None,
        })
        .to_wire();
        let spend_result = wallet.app.poke(wire2, spend_noun.clone()).await?;
        println!("spend_result: {:?}", spend_result);

        Ok(())
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_list_notes() -> Result<(), NockAppError> {
        init_tracing();
        let cli = BootCli::parse_from(&[""]);
        let nockapp = boot::setup(KERNEL, cli.clone(), &[], "wallet", None)
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
        let nockapp = boot::setup(KERNEL, cli.clone(), &[], "wallet", None)
            .await
            .map_err(|e| CrownError::Unknown(e.to_string()))?;
        let mut wallet = Wallet::new(nockapp);

        // use the transaction in txs/
        let transaction_path = "txs/test_transaction.tx";
        let test_data = vec![0u8; 32]; // TODO: Use real transaction data
        fs::write(transaction_path, &test_data).expect(&format!(
            "Called `expect()` at {}:{} (git sha: {})",
            file!(),
            line!(),
            option_env!("GIT_SHA").unwrap_or("unknown")
        ));

        let (noun, op) = Wallet::send_tx(transaction_path)?;
        let wire = WalletWire::Command(Commands::SendTx {
            transaction: transaction_path.to_string(),
        })
        .to_wire();
        let tx_result = wallet.app.poke(wire, noun.clone()).await?;

        fs::remove_file(transaction_path).expect(&format!(
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

    #[tokio::test]
    #[ignore]
    async fn test_show_tx() -> Result<(), NockAppError> {
        init_tracing();
        let cli = BootCli::parse_from(&[""]);
        let nockapp = boot::setup(KERNEL, cli.clone(), &[], "wallet", None)
            .await
            .map_err(|e| CrownError::Unknown(e.to_string()))?;
        let mut wallet = Wallet::new(nockapp);

        // Create a temporary transaction file
        let transaction_path = "test_show_transaction.tx";
        let test_data = vec![0u8; 32]; // TODO: Use real transaction data
        fs::write(transaction_path, &test_data).expect(&format!(
            "Called `expect()` at {}:{} (git sha: {})",
            file!(),
            line!(),
            option_env!("GIT_SHA").unwrap_or("unknown")
        ));

        let (noun, op) = Wallet::show_tx(transaction_path)?;
        let wire = WalletWire::Command(Commands::ShowTx {
            transaction: transaction_path.to_string(),
        })
        .to_wire();
        let show_result = wallet.app.poke(wire, noun.clone()).await?;

        fs::remove_file(transaction_path).expect(&format!(
            "Called `expect()` at {}:{} (git sha: {})",
            file!(),
            line!(),
            option_env!("GIT_SHA").unwrap_or("unknown")
        ));

        println!("show-tx result: {:?}", show_result);
        assert!(!show_result.is_empty(), "Expected non-empty show-tx result");

        Ok(())
    }

    #[test]
    fn domain_hash_from_base58_accepts_valid_id() {
        let tx_id = "3giXkwW4zbFhoyJu27RbP6VNiYgR6yaTfk2AYnEHvxtVaGbmcVD6jb9";
        DomainHash::from_base58(tx_id).expect("expected valid base58 hash");
    }

    #[test]
    fn domain_hash_from_base58_rejects_invalid_id() {
        let invalid_tx_id = "not-a-valid-hash";
        assert!(DomainHash::from_base58(invalid_tx_id).is_err());
    }
}

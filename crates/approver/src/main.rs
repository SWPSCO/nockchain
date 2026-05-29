use std::error::Error;
use std::fs;
use std::path::PathBuf;

use bytes::Bytes;
use clap::Parser;
use kernels::approver::KERNEL;
use nockapp::kernel::boot;
use nockapp::noun::slab::NounSlab;
use nockapp::{exit_driver, file_driver, one_punch_driver, NockApp};
use nockapp::driver::Operation;
use zkvm_jetpack::hot::produce_prover_hot_state;

use nockvm::noun::T;
use nockapp::utils::make_tas;

#[derive(Parser)]
struct Cli {
    #[command(flatten)]
    boot: boot::Cli,

    /// File to read
    #[arg(long, required = true)]
    file: String,

    /// Extended key
    #[arg(long, required = true)]
    extended_key: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    nockvm::check_endian();

    // Minimal/default boot CLI
    let cli = Cli::parse();
    boot::init_default_tracing(&cli.boot);

    let tx_content = fs::read(&cli.file)?;
    let tx_bytes = Bytes::from(tx_content);

    let prover_hot_state = produce_prover_hot_state();

    // Create the app with default data dir and no extra drivers; approver kernel handles behavior
    let mut app: NockApp = boot::setup(
        KERNEL,
        cli.boot,
        prover_hot_state.as_slice(),
        "approver",
        None,
    )
    .await?;

    let mut slab: NounSlab = NounSlab::new();
    let sign = make_tas(&mut slab, "sign").as_noun();
    let raw_tx = slab.cue_into(tx_bytes)?;
    let extended_key = make_tas(&mut slab, &cli.extended_key).as_noun();
    let signed_path = PathBuf::from(&cli.file).with_extension("signed");
    let save_file = make_tas(&mut slab, &signed_path.to_string_lossy()).as_noun();
    let cause = T(&mut slab, &[sign, raw_tx, extended_key, save_file]);

    slab.set_root(cause);

    app.add_io_driver(one_punch_driver(slab.clone(), Operation::Poke)).await;

    // for writing the tx
    app.add_io_driver(file_driver()).await;

    app.add_io_driver(exit_driver()).await;

    match app.run().await {
        Ok(_) => {
            tracing::info!("Command executed successfully");
            Ok(())
        }
        Err(e) => {
            tracing::error!("Command failed: {}", e);
            Err(e.into())
        }

    }
}

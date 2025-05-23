use std::error::Error;

use clap::Parser;
use kernels::dumb::KERNEL;
use nockapp::kernel::boot;
use zkvm_jetpack::hot::produce_prover_hot_state;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    nockvm::check_endian();
    let cli = nockchain::NockchainCli::parse();
    boot::init_default_tracing(&cli.nockapp_cli);

    let prover_hot_state = produce_prover_hot_state();
    let mut nockchain =
        nockchain::init_with_kernel(Some(cli), KERNEL, prover_hot_state.as_slice()).await?;
    nockchain.run().await?;
    Ok(())
}

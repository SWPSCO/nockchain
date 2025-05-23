use clap::Parser;
use futures::FutureExt;
use hoonc::*;
use nockapp::kernel::boot;
use nockvm::mem::{AllocationError, NewStackError};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cli = ChooCli::parse();

    boot::init_default_tracing(&cli.boot.clone());
    // use tracing_subscriber::layer::SubscriberExt;
    // tracing::subscriber::set_global_default(
    //     tracing_subscriber::registry().with(tracing_tracy::TracyLayer::default()),
    // );
    let result = std::panic::AssertUnwindSafe(async {
        let (mut nockapp, _) = initialize_hoonc(cli).await?;
        nockapp.run().await?;
        Ok::<(), Error>(())
    })
    .catch_unwind()
    .await;

    match result {
        Ok(Ok(_)) => println!("no panic!"),
        Ok(Err(e)) => println!("Error initializing NockApp: {e:?}"),
        Err(e) => {
            println!("Caught panic!");
            // now we downcast the error
            // and print it out
            if let Some(e) = e.downcast_ref::<AllocationError>() {
                println!("Allocation error occurred: {}", e);
            } else if let Some(e) = e.downcast_ref::<NewStackError>() {
                println!("NockStack creation error occurred: {}", e);
            } else {
                println!("Unknown panic: {e:?}");
            }
        }
    }

    Ok(())
}

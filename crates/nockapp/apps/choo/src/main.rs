use choo::*;
use clap::Parser;
use crown::kernel::boot;
use futures::FutureExt;
use sword::mem::{AllocationError, NewStackError};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cli = ChooCli::parse();

    boot::init_default_tracing(&cli.boot.clone());
    let result = std::panic::AssertUnwindSafe(async {
        let (nockapp, _) = initialize_choo(cli).await?;
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

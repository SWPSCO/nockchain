use clap::{CommandFactory, Parser};
use hoonc::*;
use nockapp::kernel::boot;
use nockvm::noun::D;
use nockvm_macros::tas;
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let matches = HoonCli::command().get_matches();
    let mut cli = HoonCli::parse();

    if let None = matches.get_one::<u64>("save-interval") {
        cli.boot.save_interval = hoonc::default_save_interval();
    }

    boot::init_default_tracing(&cli.boot.clone());
    let (nockapp, _) = initialize_hoonc(cli.clone()).await?;

    let (mut nockapp, effects, _) = build_hoon(nockapp, cli.clone()).await?;

    // Save build artifact.
    //   [%file %write path=@t contents=@]
    assert!(effects.len() == 1);
    let effect = effects.last().clone().unwrap();

    let effect_cell = match unsafe { effect.root().as_cell() } {
        Ok(cell) => cell,
        Err(_) => {
            error!("No file effect found");
            // return Err("No file effect found".into());
            return save_and_return_err(nockapp, "No file effect found").await;
        }
    };

    if !unsafe { effect_cell.head().raw_equals(&D(tas!(b"file"))) } {
        error!("No file effect found");
        // return Err("No file effect found".into());
        return save_and_return_err(nockapp, "No file effect found").await;
    }

    //   `[%write path=@t contents=@]`
    let file_cell = effect_cell
        .tail()
        .as_cell()
        .map_err(|_| "Invalid file effect format")?;

    let (operation, _path_atom) = match file_cell.head().as_direct() {
        Ok(tag) if tag.data() == tas!(b"read") => ("read", file_cell.tail().as_atom().ok()),
        Ok(tag) if tag.data() == tas!(b"write") => {
            let write_cell = file_cell
                .tail()
                .as_cell()
                .map_err(|_| "Invalid write effect format")?;
            ("write", write_cell.head().as_atom().ok())
        }
        _ => return Err("Unknown file operation".into()),
    };
    assert!(operation == "write");

    //   [path=@t contents=@]
    //  path: '/Users/myuser/nockchain/out.jam'
    //  contents: build artifact
    let effect_value = file_cell.tail();
    let build_artifact_noun = effect_value.as_cell()?.tail();
    let build_artifact_atom = match build_artifact_noun.as_atom() {
        Ok(atom) => atom,
        Err(_) => {
            error!("Build artifact is not an atom.");
            // return Err("Build artifact is not an atom.".into());
            return save_and_return_err(nockapp, "Build artifact is not an atom.").await;
        }
    };

    let artifact_bytes = build_artifact_atom.as_ne_bytes();

    let jam_path = cli
        .output
        .unwrap_or_else(|| std::env::current_dir().unwrap().join(OUT_JAM_NAME));
    info!("Writing jam file to {}...", jam_path.display());
    match tokio::fs::write(jam_path, artifact_bytes).await {
        Ok(_) => info!("Saved build artifact."),
        Err(e) => error!("Error saving build artifact: {e:?}"),
    }

    // Save checkpoint for hoonc.
    let save_result = nockapp.save_blocking().await;
    match save_result {
        Ok(_) => (),
        Err(e) => error!("Error saving hoonc state: {e:?}"),
    }

    Ok(())
}

async fn save_and_return_err(mut nockapp: nockapp::NockApp, err_msg: &str) -> Result<(), Error> {
    match nockapp.save_blocking().await {
        Ok(_) => info!("Checkpoint saved."),
        Err(e) => error!("Error saving hoonc state: {e:?}"),
    }
    Err(err_msg.into())
}

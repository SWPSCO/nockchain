use std::env::current_dir;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use clap::{arg, command, ColorChoice, Parser};
use nockapp::driver::Operation;
use nockapp::kernel::boot::{self, default_boot_cli, Cli as BootCli};
use nockapp::noun::slab::NounSlab;
use nockapp::one_punch::OnePunchWire;
use nockapp::wire::Wire;
use nockapp::{system_data_dir, AtomExt, Noun, NounExt};
use nockvm::interpreter::{self, Context};
use nockvm::noun::{Atom, D, T};
use nockvm_macros::tas;
use tokio::fs::{self, File};
use tokio::io::AsyncReadExt;
use tracing::{debug, info, instrument, trace};
use walkdir::{DirEntry, WalkDir};

pub const OUT_JAM_NAME: &str = "out.jam";

pub type Error = Box<dyn std::error::Error>;

static KERNEL_JAM: &[u8] = include_bytes!("../bootstrap/hoonc.jam");
static HOON_TXT: &[u8] = include_bytes!("../hoon/hoon-138.hoon");

#[derive(Parser, Debug)]
#[command(about = "Tests various poke types for the kernel", author = "zorp", version, color = ColorChoice::Auto)]
pub struct ChooCli {
    #[command(flatten)]
    pub boot: BootCli,

    //  TODO: REPRODUCIBILITY:
    //  make entry path relative to the dependency directory
    //  we may have to go back to requiring that the entry exists in the dependency directory
    #[arg(help = "Path to file to compile")]
    pub entry: std::path::PathBuf,

    #[arg(help = "Path to root of dependency directory", default_value = "hoon")]
    pub directory: std::path::PathBuf,

    #[arg(
        long,
        help = "Build raw, without file hash injection",
        default_value = "false"
    )]
    pub arbitrary: bool,

    #[arg(long, help = "Output file path", default_value = None)]
    pub output: Option<std::path::PathBuf>,
}

pub async fn hoonc_data_dir() -> PathBuf {
    let hoonc_data_dir = system_data_dir().join("hoonc");
    if !hoonc_data_dir.exists() {
        fs::create_dir_all(&hoonc_data_dir)
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "Panicked at {}:{} (git sha: {:?})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA")
                )
            });
    }
    hoonc_data_dir
}

/// Builds and interprets a Hoon generator.
///
/// This function:
/// 1. Builds the specified Hoon generator into a jam
/// 2. Decodes the jam into a Nock noun
/// 3. Interprets the noun with a kick operation to run the generator
///
/// # Parameters
/// - `context`: The Nock interpreter context
/// - `path`: Path to the Hoon generator file
///
/// # Returns
/// - A noun
pub async fn build_and_kick_jam(
    context: &mut Context,
    path: &str,
    deps_dir: PathBuf,
    out_dir: Option<PathBuf>,
) -> Noun {
    let jam = build_jam(path, deps_dir, out_dir, true, false)
        .await
        .expect("failed to build page");
    debug!("Built jam");
    let generator_trap =
        Noun::cue_bytes_slice(&mut context.stack, &jam).expect("invalid generator jam");

    let kick = T(&mut context.stack, &[D(9), D(2), D(0), D(1)]);
    debug!("Kicking trap");
    interpreter::interpret(context, generator_trap, kick).unwrap_or_else(|_| {
        panic!(
            "Panicked at {}:{} (git sha: {:?})",
            file!(),
            line!(),
            option_env!("GIT_SHA")
        )
    })
}

pub async fn save_generator(
    context: &mut Context,
    path: &str,
    deps_dir: PathBuf,
    out_dir: Option<PathBuf>,
) -> Result<(), Error> {
    let cli = default_boot_cli(true);
    boot::init_default_tracing(&cli);
    let kicked = build_and_kick_jam(context, path, deps_dir, out_dir.clone()).await;
    let jammed = kicked.jam_self(&mut context.stack);

    let file_name = Path::new(path)
        .file_stem()
        .unwrap_or_else(|| OsStr::new("generator"))
        .to_string_lossy()
        .to_string();
    let output_file = out_dir
        .clone()
        .unwrap_or_else(|| current_dir().expect("Failed to get current directory"))
        .join(format!("{}.jam", file_name));

    if let Some(parent) = output_file.parent() {
        fs::create_dir_all(parent).await?;
    }

    fs::write(&output_file, jammed).await?;

    println!("Generator saved to: {}", output_file.display());
    Ok(())
}
/// Builds a jam (serialized Nock noun) from a Hoon source file
///
/// This function:
/// 1. Locates the source file relative to the hoon directory
/// 2. Creates a temporary directory for build artifacts
/// 3. Initializes a Nock app with the hoonc build system
/// 4. Builds the source file and returns the resulting jam as bytes
///
/// # Parameters
/// - `entry`: Path to the Hoon source file, relative to the hoon directory
/// - `arbitrary`: Whether to build with arbitrary mode enabled
/// - `new`: Whether to force a clean build
///
/// # Returns
/// - A Result containing either the jam bytes or a hoonc error
pub async fn build_jam(
    entry: &str,
    deps_dir: PathBuf,
    out_dir: Option<PathBuf>,
    arbitrary: bool,
    new: bool,
) -> Result<Vec<u8>, Error> {
    info!("Dependencies directory: {:?}", deps_dir);
    info!("Entry file: {:?}", entry);
    let (nockapp, out_path) =
        initialize_with_default_cli(entry.into(), deps_dir, out_dir, arbitrary, new).await?;
    info!("Output path: {:?}", out_path);
    run_build(nockapp, Some(out_path.clone())).await
}

pub async fn initialize_hoonc(cli: ChooCli) -> Result<(nockapp::NockApp, PathBuf), Error> {
    initialize_hoonc_(
        cli.entry,
        cli.directory,
        cli.arbitrary,
        cli.output,
        cli.boot.clone(),
    )
    .await
}

pub async fn initialize_with_default_cli(
    entry: std::path::PathBuf,
    deps_dir: std::path::PathBuf,
    out: Option<std::path::PathBuf>,
    arbitrary: bool,
    new: bool,
) -> Result<(nockapp::NockApp, PathBuf), Error> {
    let cli = default_boot_cli(new);
    initialize_hoonc_(entry, deps_dir, arbitrary, out, cli).await
}

pub async fn initialize_hoonc_(
    entry: std::path::PathBuf,
    deps_dir: std::path::PathBuf,
    arbitrary: bool,
    out: Option<std::path::PathBuf>,
    boot_cli: BootCli,
) -> Result<(nockapp::NockApp, PathBuf), Error> {
    debug!("Dependencies directory: {:?}", deps_dir);
    debug!("Entry file: {:?}", entry);
    let data_dir = system_data_dir();
    let mut nockapp = boot::setup(
        KERNEL_JAM,
        Some(boot_cli.clone()),
        &[],
        "hoonc",
        Some(data_dir),
    )
    .await?;
    nockapp.add_io_driver(nockapp::file_driver()).await;
    nockapp.add_io_driver(nockapp::exit_driver()).await;

    let mut slab = NounSlab::new();
    let hoon_cord = Atom::from_value(&mut slab, HOON_TXT)
        .unwrap_or_else(|_| {
            panic!(
                "Panicked at {}:{} (git sha: {:?})",
                file!(),
                line!(),
                option_env!("GIT_SHA")
            )
        })
        .as_noun();
    let bootstrap_poke = T(&mut slab, &[D(tas!(b"boot")), hoon_cord]);
    slab.set_root(bootstrap_poke);

    // It's OK to do a raw poke for boot because it doesn't yield any effects that need to be processed.
    // We do a raw poke here to ensure boot is done before we start the build poke.
    let _boot_result = nockapp.poke(OnePunchWire::Poke.to_wire(), slab).await?;
    let mut slab = NounSlab::new();
    let entry_contents = {
        let mut contents_vec: Vec<u8> = vec![];
        let mut file = File::open(&entry).await?;
        file.read_to_end(&mut contents_vec).await?;
        Atom::from_value(&mut slab, contents_vec)?.as_noun()
    };

    let entry_string = canonicalize_and_string(&entry);
    let entry_path = Atom::from_value(&mut slab, entry_string)?.as_noun();

    let mut directory_noun = D(0);
    let directory = canonicalize_and_string(&deps_dir);

    let walker = WalkDir::new(&directory).follow_links(true).into_iter();
    for entry_result in walker.filter_entry(is_valid_file_or_dir) {
        let entry = entry_result?;
        let is_file = entry.metadata()?.is_file();
        if is_file {
            let path_str = entry
                .path()
                .to_str()
                .expect("Failed to convert path to string")
                .strip_prefix(&directory)
                .expect("Failed to strip prefix");
            debug!("Path: {:?}", path_str);
            let path_cord = Atom::from_value(&mut slab, path_str)?.as_noun();

            let contents = {
                let mut contents_vec: Vec<u8> = vec![];
                let mut file = File::open(entry.path()).await?;
                file.read_to_end(&mut contents_vec).await?;
                Atom::from_value(&mut slab, contents_vec)?.as_noun()
            };

            let entry_cell = T(&mut slab, &[path_cord, contents]);
            directory_noun = T(&mut slab, &[entry_cell, directory_noun]);
        }
    }

    let out_path_string = if let Some(path) = &out {
        let parent = if path.is_dir() {
            path
        } else {
            path.parent().unwrap_or_else(|| Path::new("."))
        };
        let filename = if path.is_dir() {
            OsStr::new(OUT_JAM_NAME)
        } else {
            path.file_name().unwrap_or_else(|| OsStr::new(OUT_JAM_NAME))
        };
        info!("Filename: {:?}", filename);
        let parent_canonical = canonicalize_and_string(parent);
        format!("{}/{}", parent_canonical, filename.to_string_lossy())
    } else {
        let parent_dir = current_dir().expect("Failed to get current directory");
        format!("{}/{}", canonicalize_and_string(&parent_dir), OUT_JAM_NAME)
    };
    debug!("Output path: {:?}", out_path_string);
    let out_path = Atom::from_value(&mut slab, out_path_string.clone())?.as_noun();

    let arbitrary_noun = if arbitrary { D(0) } else { D(1) };

    let poke = T(
        &mut slab,
        &[
            D(tas!(b"build")),
            entry_path,
            entry_contents,
            directory_noun,
            arbitrary_noun,
            out_path,
        ],
    );
    slab.set_root(poke);
    // The build poke yields effects (principally the file write effect), so we need to embed the poke
    // as a one_punch IO driver so that nockapp.run() can process the effects.
    nockapp
        .add_io_driver(nockapp::one_punch_driver(slab, Operation::Poke))
        .await;
    Ok((nockapp, out_path_string.into()))
}

pub fn is_valid_file_or_dir(entry: &DirEntry) -> bool {
    let is_dir = entry
        .metadata()
        .unwrap_or_else(|_| {
            panic!(
                "Panicked at {}:{} (git sha: {:?})",
                file!(),
                line!(),
                option_env!("GIT_SHA")
            )
        })
        .is_dir();

    let is_valid = entry
        .file_name()
        .to_str()
        .map(|s| {
            s.ends_with(".jock")
                || s.ends_with(".hoon")
                || s.ends_with(".txt")
                || s.ends_with(".jam")
        })
        .unwrap_or(false);

    is_dir || is_valid
}

#[instrument]
pub fn canonicalize_and_string(path: &std::path::Path) -> String {
    trace!("Canonicalizing path: {:?}", path);
    let path = path.canonicalize().expect("Failed to canonicalize path");
    debug!("Canonicalized path: {:?}", path);
    let path = path.to_str().expect("Failed to convert path to string");

    path.to_string()
}

/// Run the build and verify the output file, used to build files outside of cli.
pub async fn run_build(
    mut nockapp: nockapp::NockApp,
    out_path: Option<PathBuf>,
) -> Result<Vec<u8>, Error> {
    nockapp.run().await?;
    let out_path = out_path.unwrap_or_else(|| {
        std::env::current_dir()
            .unwrap_or_else(|_| {
                panic!(
                    "Panicked at {}:{} (git sha: {:?})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA")
                )
            })
            .join(OUT_JAM_NAME)
    });
    Ok(fs::read(out_path).await?)
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_canonicalize_and_string() {
        // Create a temp dir that will definitely exist
        let temp_dir = std::env::temp_dir();

        // Use canonicalize_and_string on the temp dir
        let result = super::canonicalize_and_string(&temp_dir);

        // Compare with direct canonicalization
        let canonical = temp_dir.canonicalize().unwrap_or_else(|_| {
            panic!(
                "Panicked at {}:{} (git sha: {:?})",
                file!(),
                line!(),
                option_env!("GIT_SHA")
            )
        });
        assert_eq!(
            result,
            canonical.to_str().unwrap_or_else(|| {
                panic!(
                    "Panicked at {}:{} (git sha: {:?})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA")
                )
            })
        );
    }
}

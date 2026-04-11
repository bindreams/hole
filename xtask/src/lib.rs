//! `xtask` library — workspace task runner core.
//!
//! See `main.rs` for the binary entry point and `bindir.rs` for the canonical
//! BINDIR file list (the single source of truth motivating issue #143).

use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};

pub mod bindir;
pub mod galoshes;
pub mod stage;
pub mod v2ray_plugin;
pub mod wintun;

#[cfg(test)]
#[path = "bindir_tests.rs"]
mod bindir_tests;
#[cfg(test)]
#[path = "stage_tests.rs"]
mod stage_tests;

#[derive(Parser)]
#[command(
    name = "xtask",
    about = "Workspace task runner for the hole project",
    long_about = "Single source of truth for build orchestration that would otherwise be \
                  duplicated across build.rs, scripts/dev.py, and msi-installer."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Stage the runnable BINDIR (hole + sidecars + native libs) into a directory.
    ///
    /// Both `scripts/dev.py` and `msi-installer/__init__.py:stage_files()` call
    /// this. The canonical list of files lives in `xtask/src/bindir.rs`; adding
    /// a new BINDIR file is a one-line change there and both consumers pick it
    /// up automatically.
    Stage {
        /// Cargo profile that produced the binary (`debug` or `release`).
        #[arg(long, default_value = "debug")]
        profile: Profile,

        /// Directory to populate with the staged files. Created if missing.
        #[arg(long)]
        out_dir: PathBuf,
    },
    /// Build the v2ray-plugin sidecar from `external/v2ray-plugin/`.
    ///
    /// Output goes into `<repo>/.cache/v2ray-plugin/`. Replaces the previous
    /// build.rs side effect.
    V2rayPlugin,
    /// Build the galoshes sidecar from `external/galoshes/`.
    ///
    /// Builds galoshes' embedded v2ray-plugin first (independent version),
    /// then the galoshes binary itself in release mode.
    Galoshes,
    /// Download and verify wintun.dll on Windows.
    ///
    /// Output goes into `<repo>/.cache/wintun/`. No-op on non-Windows.
    Wintun,
    /// Run all `cargo xtask <step>` commands required for a runnable build.
    ///
    /// Currently: `v2ray-plugin` + `galoshes` + `wintun`.
    Deps,
    /// Print or validate the workspace version. Replaces scripts/check-version.py.
    Version {
        /// Validate Cargo.toml version against the nearest git tag instead of
        /// printing the display version.
        #[arg(long)]
        check: bool,
        /// With `--check`, require an exact tag/Cargo.toml match (instead of
        /// allowing one bump ahead). Used by the release CI workflow.
        #[arg(long, requires = "check")]
        exact: bool,
    },
}

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
pub enum Profile {
    Debug,
    Release,
}

impl Profile {
    /// The cargo target subdirectory name for this profile.
    pub fn dir_name(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Release => "release",
        }
    }
}

pub fn dispatch(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Stage { profile, out_dir } => run_stage(profile, &out_dir),
        Command::V2rayPlugin => run_v2ray_plugin(),
        Command::Galoshes => run_galoshes(),
        Command::Wintun => run_wintun(),
        Command::Deps => run_deps(),
        Command::Version { check, exact } => run_version(check, exact),
    }
}

pub fn run_stage(profile: Profile, out_dir: &Path) -> Result<()> {
    let repo_root = repo_root()?;
    let files = bindir::bindir_files(profile, &repo_root)?;
    stage::stage(out_dir, &files)?;
    println!("xtask: staged {} files into {}", files.len(), out_dir.display());
    Ok(())
}

pub fn run_v2ray_plugin() -> Result<()> {
    let repo_root = repo_root()?;
    let path = v2ray_plugin::build(&repo_root)?;
    println!("xtask: v2ray-plugin built at {}", path.display());
    Ok(())
}

pub fn run_wintun() -> Result<()> {
    let repo_root = repo_root()?;
    match wintun::ensure(&repo_root)? {
        Some(path) => println!("xtask: wintun.dll at {}", path.display()),
        None => println!("xtask: wintun.dll skipped (not Windows)"),
    }
    Ok(())
}

pub fn run_galoshes() -> Result<()> {
    let repo_root = repo_root()?;
    let path = galoshes::build(&repo_root)?;
    println!("xtask: galoshes built at {}", path.display());
    Ok(())
}

pub fn run_deps() -> Result<()> {
    run_v2ray_plugin()?;
    run_galoshes()?;
    run_wintun()?;
    Ok(())
}

pub fn run_version(check: bool, exact: bool) -> Result<()> {
    let repo_root = repo_root()?;
    if check {
        let v = xtask_lib::version::validate_against_tag(&repo_root, exact)?;
        println!("{v}");
    } else {
        println!("{}", xtask_lib::version::display_version(&repo_root));
    }
    Ok(())
}

/// Locate the workspace root by walking up from the xtask binary's manifest
/// dir until we find a directory containing a `Cargo.toml` with `[workspace]`.
///
/// We deliberately do not call `git rev-parse --show-toplevel` — xtask must
/// work in environments where git is unavailable (CI minimal images, source
/// tarballs, etc.). `CARGO_MANIFEST_DIR` is set by cargo when building xtask
/// itself; its parent is the workspace root. The current_exe walk-up is a
/// fallback for environments where the env var is not present.
pub fn repo_root() -> Result<PathBuf> {
    if let Some(manifest_dir) = std::env::var_os("CARGO_MANIFEST_DIR") {
        let manifest_dir = PathBuf::from(manifest_dir);
        if let Some(parent) = manifest_dir.parent() {
            if parent.join("Cargo.toml").is_file() {
                return Ok(parent.to_path_buf());
            }
        }
    }
    let mut dir = std::env::current_exe()?;
    while dir.pop() {
        let candidate = dir.join("Cargo.toml");
        if candidate.is_file() {
            // Naive [workspace] substring check; the alternative would pull
            // in `toml` just for one read.
            if let Ok(s) = std::fs::read_to_string(&candidate) {
                if s.contains("[workspace]") {
                    return Ok(dir);
                }
            }
        }
    }
    anyhow::bail!("could not locate workspace root from CARGO_MANIFEST_DIR or current_exe walk-up")
}

#[cfg(test)]
fn main() {
    skuld::run_all();
}

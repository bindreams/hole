//! `xtask` library — workspace task runner core.
//!
//! See `main.rs` for the binary entry point and `bindir.rs` for the canonical
//! BINDIR file list (the single source of truth motivating issue #143).

use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};

pub mod bindir;
pub mod stage;

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
    }
}

pub fn run_stage(profile: Profile, out_dir: &Path) -> Result<()> {
    let repo_root = repo_root()?;
    let files = bindir::bindir_files(profile, &repo_root)?;
    stage::stage(out_dir, &files)?;
    println!("xtask: staged {} files into {}", files.len(), out_dir.display());
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

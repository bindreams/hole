//! `xtask` library — workspace task runner core.
//!
//! See `main.rs` for the binary entry point and `bindir.rs` for the canonical
//! BINDIR file list (the single source of truth motivating issue #143).

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

use crate::manifest::{Manifest, Platform};
use crate::orchestrate::{execute, render_list, Plan, Verb};

pub mod bindir;
pub mod galoshes;
pub mod manifest;
pub mod orchestrate;
pub mod stage;
pub mod test_binaries;
pub mod v2ray_plugin;
pub mod wintun;

#[cfg(test)]
#[path = "bindir_tests.rs"]
mod bindir_tests;
#[cfg(test)]
#[path = "manifest_tests.rs"]
mod manifest_tests;
#[cfg(test)]
#[path = "orchestrate_tests.rs"]
mod orchestrate_tests;
#[cfg(test)]
#[path = "stage_tests.rs"]
mod stage_tests;
#[cfg(test)]
#[path = "test_binaries_tests.rs"]
mod test_binaries_tests;

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

        /// Also compile workspace test binaries and stage them at stable paths
        /// under `--tests-out-dir`. See bindreams/hole#210 for motivation.
        #[arg(long)]
        with_tests: bool,

        /// Directory for staged test binaries (`{crate}.test{.exe}`). Required
        /// when `--with-tests` is set. Convention: sibling of `--out-dir`
        /// (e.g. `target/debug/dist/tests` when `--out-dir` is
        /// `target/debug/dist/bin`).
        #[arg(long, requires = "with_tests")]
        tests_out_dir: Option<PathBuf>,
    },
    /// Build the v2ray-plugin sidecar from `external/v2ray-plugin/`.
    ///
    /// Output goes into `<repo>/.cache/v2ray-plugin/`. Replaces the previous
    /// build.rs side effect.
    V2rayPlugin,
    /// Build the galoshes sidecar (workspace member `crates/galoshes/`).
    ///
    /// Expects v2ray-plugin to have been built first into `.cache/v2ray-plugin/`
    /// (the `deps` command runs v2ray-plugin → galoshes in that order).
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
    /// Build a target declared in `build.yaml` (and its transitive deps).
    ///
    /// `cargo xtask build <name>` resolves the dependency DAG, filters to
    /// targets applicable to the host platform, and runs each target's
    /// `build:` steps in topological order. `--all` selects every non-test
    /// target applicable to the host.
    Build {
        /// Target name (e.g. `hole`, `galoshes`, `hole-msi`).
        target: Option<String>,
        /// Build every non-test target applicable to the host platform.
        #[arg(long, conflicts_with = "target")]
        all: bool,
    },
    /// Run a test target declared in `build.yaml` (and build its deps first).
    ///
    /// Test targets are first-class entries with names ending in `-tests`
    /// (`hole-tests`, `galoshes-tests`, etc.). `cargo xtask test <name>`
    /// builds the dep tree (which includes the corresponding `*` build target)
    /// and then runs the test target's steps. `--all` selects every test
    /// target applicable to the host.
    Test {
        /// Test target name (e.g. `hole-tests`).
        target: Option<String>,
        /// Run every test target applicable to the host platform.
        #[arg(long, conflicts_with = "target")]
        all: bool,
    },
    /// List every target declared in `build.yaml` with its platforms and
    /// host-platform applicability.
    List,
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
        Command::Stage {
            profile,
            out_dir,
            with_tests,
            tests_out_dir,
        } => {
            // Validate the flag combination before doing any filesystem work —
            // otherwise `--with-tests` without `--tests-out-dir` would stage
            // the production bindir and then error, wasting the hardlink pass.
            let tests_dir = if with_tests {
                Some(tests_out_dir.ok_or_else(|| anyhow::anyhow!("--with-tests requires --tests-out-dir"))?)
            } else {
                None
            };
            run_stage(profile, &out_dir)?;
            if let Some(tests_dir) = tests_dir {
                test_binaries::stage_test_binaries(profile, &tests_dir)?;
            }
            Ok(())
        }
        Command::V2rayPlugin => run_v2ray_plugin(),
        Command::Galoshes => run_galoshes(),
        Command::Wintun => run_wintun(),
        Command::Deps => run_deps(),
        Command::Version { check, exact } => run_version(check, exact),
        Command::Build { target, all } => run_build(target, all),
        Command::Test { target, all } => run_test(target, all),
        Command::List => run_list(),
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

pub fn run_build(target: Option<String>, all: bool) -> Result<()> {
    run_orchestrated(Verb::Build, target, all)
}

pub fn run_test(target: Option<String>, all: bool) -> Result<()> {
    run_orchestrated(Verb::Test, target, all)
}

pub fn run_list() -> Result<()> {
    let (manifest, _repo_root) = load_manifest()?;
    let host = Platform::host();
    print!("{}", render_list(&manifest, host));
    Ok(())
}

fn run_orchestrated(verb: Verb, target: Option<String>, all: bool) -> Result<()> {
    let (manifest, repo_root) = load_manifest()?;
    let host = Platform::host().ok_or_else(|| {
        anyhow!(
            "host platform not in the known set (windows/darwin/linux × amd64/arm64); \
             cannot orchestrate"
        )
    })?;
    let plan = Plan::new(&manifest)?;

    let roots: Vec<&str> = match (target, all) {
        (Some(name), false) => {
            let target = manifest.get(&name).ok_or_else(|| anyhow!("unknown target: {name:?}"))?;
            // Verb mismatch: explicitly reject `build hole-tests` /
            // `test hole`. Either is a category error.
            match (verb, target.is_test()) {
                (Verb::Build, true) => {
                    return Err(anyhow!("{name:?} is a test target — use `cargo xtask test {name}`"));
                }
                (Verb::Test, false) => {
                    return Err(anyhow!(
                        "{name:?} is not a test target — use `cargo xtask build {name}`"
                    ));
                }
                _ => {}
            }
            vec![target.name.as_str()]
        }
        (None, true) => plan
            .targets_for_verb(verb)
            .into_iter()
            .filter(|name| manifest.get(name).map(|t| t.applies_to(host)).unwrap_or(false))
            .collect(),
        (Some(_), true) => unreachable!("clap rejects --all with a positional target"),
        (None, false) => {
            return Err(anyhow!("specify a target name or pass --all"));
        }
    };

    if roots.is_empty() {
        println!(
            "xtask: no {} targets apply to host platform {host}",
            match verb {
                Verb::Build => "build",
                Verb::Test => "test",
            }
        );
        return Ok(());
    }

    let order = plan.order_for(&roots, host)?;
    execute(&plan, &order, &repo_root)
}

fn load_manifest() -> Result<(Manifest, PathBuf)> {
    let repo_root = repo_root()?;
    let path = repo_root.join("build.yaml");
    let text = std::fs::read_to_string(&path).with_context(|| format!("reading manifest at {}", path.display()))?;
    let manifest = Manifest::parse(&text).with_context(|| format!("parsing manifest at {}", path.display()))?;
    Ok((manifest, repo_root))
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

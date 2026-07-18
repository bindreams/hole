//! `xtask` library — workspace task runner core.
//!
//! See `main.rs` for the binary entry point and `bindir.rs` for the canonical
//! BINDIR file list (the single source of truth motivating issue #143).

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

pub use interrupt::install_transparent_interrupt;

use crate::manifest::{Manifest, Platform};
use crate::orchestrate::{execute, execute_run, relocate_self_if_windows, render_list, Plan};

pub mod bindir;
pub mod ci_coverage;
pub mod dmg_background;
pub mod ex_ray;
pub mod galoshes;
pub mod gen_ui_constants;
pub mod golangci_lint;
pub mod interrupt;
pub mod manifest;
pub mod orchestrate;
pub mod stage;
pub mod target;
pub mod test_binaries;
pub mod upstream_v2ray;
pub mod wintun;

#[cfg(test)]
#[path = "bindir_tests.rs"]
mod bindir_tests;
#[cfg(test)]
#[path = "ci_coverage_tests.rs"]
mod ci_coverage_tests;
#[cfg(test)]
#[path = "dmg_background_tests.rs"]
mod dmg_background_tests;
#[cfg(test)]
#[path = "galoshes_tests.rs"]
mod galoshes_tests;
#[cfg(test)]
#[path = "gen_ui_constants_tests.rs"]
mod gen_ui_constants_tests;
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
#[path = "tauri_bundle_tests.rs"]
mod tauri_bundle_tests;
#[cfg(test)]
#[path = "test_binaries_tests.rs"]
mod test_binaries_tests;

#[derive(Parser)]
#[command(
    name = "xtask",
    about = "Workspace task runner for the hole project",
    long_about = "Single source of truth for build and run orchestration that would otherwise \
                  be duplicated across build.rs, CI yaml, dev-console, and msi-installer."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Stage the runnable BINDIR (hole + sidecars + native libs) into a directory.
    ///
    /// Both dev-console and `msi-installer/__init__.py:stage_files()` call
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
    /// Build the ex-ray sidecar from `crates/ex-ray/`.
    ///
    /// Output goes into `<repo>/.cache/ex-ray/`. Replaces the previous
    /// build.rs side effect.
    ExRay,
    /// Build the galoshes sidecar (workspace member `crates/galoshes/`).
    ///
    /// Expects ex-ray to have been built first into `.cache/ex-ray/`
    /// (the `deps` command runs ex-ray → galoshes in that order).
    Galoshes,
    /// Download and verify wintun.dll on Windows.
    ///
    /// Output goes into `<repo>/.cache/wintun/`. No-op on non-Windows.
    Wintun,
    /// Download and verify the golangci-lint binary for the host platform.
    ///
    /// Output goes into `<repo>/.cache/golangci-lint/<version>/`. Used by the
    /// `go-fmt` / `go-lint` prek hooks against the `crates/ex-ray/` Go module.
    GolangciLint,
    /// Clone + build the pinned upstream shadowsocks/v2ray-plugin for the
    /// ex-ray cross-implementation interop test.
    ///
    /// Output goes into `<repo>/.cache/upstream-v2ray-plugin/<commit>/`. This
    /// is a TEST dependency, deliberately NOT part of `cargo xtask deps` —
    /// keeping the build-deps lean. The `plugin-e2e-tests` build.yaml target
    /// runs it before the interop round-trip tests.
    ProvisionUpstreamV2ray,
    /// Run all `cargo xtask <step>` commands required for a runnable build.
    ///
    /// Currently: `ex-ray` + `galoshes` + `wintun` + `golangci-lint`.
    Deps,
    /// Print or validate the workspace version for a release group.
    ///
    /// Each release group (`hole`, `garter`, `galoshes`, `ex-ray`)
    /// has its own version, declared in member Cargo.tomls via
    /// `[package.metadata.hole-release].group` (or, for `ex-ray`, in
    /// `crates/ex-ray/version.toml`) and validated against the nearest
    /// `releases/<group>/v<X.Y.Z>` git tag.
    Version {
        /// Release group to operate on. Required for `--check`. Without
        /// `--group`, prints a table of every group's resolved version.
        #[arg(long, value_parser = parse_group_arg)]
        group: Option<xtask_lib::version::Group>,
        /// Validate Cargo.toml version against the nearest git tag for
        /// the named group instead of printing it.
        #[arg(long, requires = "group")]
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
    /// `build:` steps in topological order. `--all` builds every target
    /// applicable to the host platform.
    Build {
        /// Target name (e.g. `hole`, `galoshes`, `hole-msi`, `hole-tests`).
        target: Option<String>,
        /// Build every target applicable to the host platform.
        #[arg(long, conflicts_with = "target")]
        all: bool,
    },
    /// Run a target's `run:` steps after invoking the full build cascade for
    /// that target. Targets without `run:` are an error.
    ///
    /// "Run" performs the work the target is named after: `hole-tests` runs
    /// the test binaries, `hole` launches dev mode, `clippy-hole` runs
    /// clippy. Runs do not depend on other runs — `cargo xtask run X` builds
    /// `X` and its deps, then runs only `X`'s `run:` steps. There is no
    /// `--all`: "run everything" is not a meaningful operation.
    Run {
        /// Target name (e.g. `hole`, `hole-tests`, `clippy-hole`, `prek`).
        target: String,
    },
    /// List every target declared in `build.yaml` with its platforms,
    /// host-platform applicability, and a `*` marker for runnables.
    List,
    /// Print the canonical BINDIR filenames for an OS as a JSON array.
    ///
    /// The installer conformance tests consume this so the WiX / Tauri
    /// manifests are checked against the single source of truth
    /// (`bindir::bindir_dest_names`) rather than a hand-restated copy.
    BindirNames {
        /// Target OS (defaults to the host).
        #[arg(long)]
        os: Option<manifest::Os>,
    },
    /// Generate `ui/generated.ts` from Rust constants (single source of truth).
    GenUiConstants {
        /// Verify the committed file is up to date instead of writing it.
        #[arg(long)]
        check: bool,
    },
    /// Render the macOS DMG installer background (`crates/hole/dmg/background.typ`)
    /// to `<out-dir>/background.png` + `background@2x.png` (default `.cache/dmg`).
    DmgBackground {
        /// Output directory (a dedicated dir holding only the PNG pair).
        #[arg(long)]
        out_dir: Option<PathBuf>,
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
        Command::ExRay => run_ex_ray(),
        Command::Galoshes => run_galoshes(),
        Command::Wintun => run_wintun(),
        Command::GolangciLint => run_golangci_lint(),
        Command::ProvisionUpstreamV2ray => run_provision_upstream_v2ray(),
        Command::Deps => run_deps(),
        Command::Version { group, check, exact } => run_version(group, check, exact),
        Command::Build { target, all } => run_build(target, all),
        Command::Run { target } => run_run(target),
        Command::List => run_list(),
        Command::BindirNames { os } => {
            let os = os
                .or_else(manifest::Os::host)
                .ok_or_else(|| anyhow!("unknown host OS"))?;
            println!("{}", render_bindir_names(os));
            Ok(())
        }
        Command::GenUiConstants { check } => gen_ui_constants::write_or_check(&repo_root()?, check),
        Command::DmgBackground { out_dir } => run_dmg_background(out_dir),
    }
}

/// Serialize the canonical BINDIR filenames for `os` as a JSON array. Consumed
/// by `cargo xtask bindir-names` and the installer conformance tests.
pub fn render_bindir_names(os: manifest::Os) -> String {
    serde_json::to_string(&bindir::bindir_dest_names(os)).expect("Vec<String> serializes")
}

pub fn run_stage(profile: Profile, out_dir: &Path) -> Result<()> {
    let repo_root = repo_root()?;
    let files = bindir::bindir_files(profile, &repo_root)?;
    stage::stage(out_dir, &files)?;
    println!("xtask: staged {} files into {}", files.len(), out_dir.display());
    Ok(())
}

pub fn run_ex_ray() -> Result<()> {
    let repo_root = repo_root()?;
    let path = ex_ray::build(&repo_root)?;
    println!("xtask: ex-ray built at {}", path.display());
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

pub fn run_dmg_background(out_dir: Option<PathBuf>) -> Result<()> {
    let repo_root = repo_root()?;
    let out_dir = out_dir.unwrap_or_else(|| repo_root.join(".cache/dmg"));
    dmg_background::build(&repo_root, &out_dir)?;
    println!("xtask: DMG background rendered into {}", out_dir.display());
    Ok(())
}

pub fn run_golangci_lint() -> Result<()> {
    let repo_root = repo_root()?;
    let path = golangci_lint::ensure(&repo_root)?;
    println!("xtask: golangci-lint at {}", path.display());
    Ok(())
}

pub fn run_provision_upstream_v2ray() -> Result<()> {
    let repo_root = repo_root()?;
    let path = upstream_v2ray::ensure(&repo_root)?;
    println!("xtask: upstream v2ray-plugin at {}", path.display());
    Ok(())
}

pub fn run_deps() -> Result<()> {
    run_ex_ray()?;
    run_galoshes()?;
    run_wintun()?;
    run_golangci_lint()?;
    Ok(())
}

pub fn run_build(target: Option<String>, all: bool) -> Result<()> {
    // Move ourselves out of `target/<profile>/xtask.exe` *before* spawning any
    // subprocess that might shell out to `cargo xtask <X>`. Without this,
    // cargo's relink path tries to overwrite our running binary on Windows
    // and fails with ERROR_ACCESS_DENIED. No-op on POSIX.
    relocate_self_if_windows()?;

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
            vec![target.name.as_str()]
        }
        (None, true) => plan
            .target_names()
            .into_iter()
            .filter(|name| manifest.get(name).map(|t| t.applies_to(host)).unwrap_or(false))
            .collect(),
        (Some(_), true) => unreachable!("clap rejects --all with a positional target"),
        (None, false) => {
            return Err(anyhow!("specify a target name or pass --all"));
        }
    };

    if roots.is_empty() {
        println!("xtask: no targets apply to host platform {host}");
        return Ok(());
    }

    let order = plan.order_for(&roots, host)?;
    execute(&plan, &order, &repo_root)
}

pub fn run_run(target: String) -> Result<()> {
    // Same Windows self-relocate dance as `run_build`: build steps may shell
    // out to recursive `cargo xtask <X>` invocations, and on Windows cargo's
    // relink path can't overwrite the running xtask.exe.
    relocate_self_if_windows()?;

    let (manifest, repo_root) = load_manifest()?;
    let host = Platform::host().ok_or_else(|| {
        anyhow!(
            "host platform not in the known set (windows/darwin/linux × amd64/arm64); \
             cannot orchestrate"
        )
    })?;
    let plan = Plan::new(&manifest)?;
    execute_run(&plan, &target, host, &repo_root)
}

pub fn run_list() -> Result<()> {
    let (manifest, _repo_root) = load_manifest()?;
    let host = Platform::host();
    print!("{}", render_list(&manifest, host));
    Ok(())
}

fn load_manifest() -> Result<(Manifest, PathBuf)> {
    let repo_root = repo_root()?;
    let path = repo_root.join("build.yaml");
    let text = std::fs::read_to_string(&path).with_context(|| format!("reading manifest at {}", path.display()))?;
    let manifest = Manifest::parse(&text).with_context(|| format!("parsing manifest at {}", path.display()))?;
    Ok((manifest, repo_root))
}

fn parse_group_arg(s: &str) -> Result<xtask_lib::version::Group, String> {
    xtask_lib::version::Group::parse(s).map_err(|e| e.to_string())
}

pub fn run_version(group: Option<xtask_lib::version::Group>, check: bool, exact: bool) -> Result<()> {
    let repo_root = repo_root()?;
    match (group, check) {
        (Some(group), true) => {
            let v = xtask_lib::version::validate_against_tag(&repo_root, group, exact)?;
            println!("{v}");
        }
        (Some(group), false) => {
            println!("{}", xtask_lib::version::display_version(&repo_root, group));
        }
        (None, _) => {
            // No group: print a table of every group's display version.
            for &group in xtask_lib::version::Group::all() {
                println!("{group}\t{}", xtask_lib::version::display_version(&repo_root, group));
            }
        }
    }
    Ok(())
}

pub use xtask_lib::repo_root::repo_root;

#[cfg(test)]
pub mod test_child;

#[cfg(test)]
fn main() {
    test_child::maybe_run();
    skuld::run_all();
}

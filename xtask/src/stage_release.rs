//! `cargo xtask stage-release`: copy what a release ships out of a CI leg's build into one directory, named as the
//! release names it, so the draft workflow uploads the files the leg's tests ran on.
//!
//! A lane is the point in `ci.yaml` where one kind of shipped file has just passed its tests, and each
//! (group, lane) pair says what to stage there. [`plan`] is the one definition of what a release ships:
//! `cargo xtask release-assets` ([`list`]) derives the asset set the draft workflow checks and the notes' Downloads
//! table from it.

#![allow(clippy::disallowed_methods)] // dev tooling, never privileged

use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context, Result};
use clap::ValueEnum;
use serde::Serialize;
use xtask_lib::version::{parse_release_tag, Group};

use crate::manifest::{Manifest, Os, Platform};
use crate::Profile;

/// Names the MSI the installer tests ran on.
const MSI_ENV: &str = "MSI_UNDER_TEST";
/// Names the DMG the installer tests ran on.
const DMG_ENV: &str = "DMG_UNDER_TEST";

/// Where `msi-installer` stages the BINDIR the MSI is built from, relative to the repo root.
const MSI_STAGE_DIR: [&str; 3] = ["target", "release", "installer-stage"];

/// Where `ci.yaml` calls `stage-release`: right after the tests of the files it stages.
#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
pub enum Lane {
    /// The Windows installer and update archive, after the installer tests.
    Msi,
    /// The macOS installer and update archive, after the DMG tests.
    Dmg,
    /// The galoshes, garter and ex-ray binaries, after plugin-e2e.
    Plugins,
}

impl Lane {
    /// The `build.yaml` target whose platforms are the CI legs that run this lane.
    fn target(self) -> &'static str {
        match self {
            Lane::Msi => "hole-msi",
            Lane::Dmg => "hole-dmg",
            Lane::Plugins => "plugin-e2e-tests",
        }
    }
}

/// A command a shipped executable must survive: exit 0 and, when `prints` is set, print exactly that on stdout.
#[derive(Debug, PartialEq, Eq)]
pub struct Probe {
    pub args: &'static [&'static str],
    pub prints: Option<String>,
}

/// A shipped executable and the probes that run on it.
#[derive(Debug, PartialEq, Eq)]
pub struct Executable {
    pub path: PathBuf,
    pub probes: Vec<Probe>,
}

/// One file to copy into the release directory. `probes` run on the staged copy, when it is an executable.
#[derive(Debug, PartialEq, Eq)]
pub struct Asset {
    pub src: PathBuf,
    pub name: String,
    pub probes: Vec<Probe>,
}

/// Which files an update archive is packed from.
#[derive(Debug, PartialEq, Eq)]
pub enum UpdateArchiveSource {
    /// The BINDIR the MSI was built from.
    StagedBindir(PathBuf),
    /// The `.app` the DMG was built from.
    BuiltApp,
}

/// The Hole update archive that ships beside the installer.
#[derive(Debug, PartialEq, Eq)]
pub struct UpdateArchive {
    pub name: String,
    pub source: UpdateArchiveSource,
}

/// What a (group, lane) pair ships on one platform.
#[derive(Debug, PartialEq, Eq)]
pub struct Shipment {
    pub files: Vec<Asset>,
    pub update_archive: Option<UpdateArchive>,
    /// An executable inside the installer's payload that is probed, since the installer itself cannot be.
    pub payload_binary: Option<Executable>,
    /// The `build.yaml` target to build first, when no earlier lane built the files in the release profile: the probes
    /// are then the only test of the staged file.
    pub build_first: Option<&'static str>,
}

impl Shipment {
    fn nothing() -> Self {
        Self {
            files: Vec::new(),
            update_archive: None,
            payload_binary: None,
            build_first: None,
        }
    }

    /// Every file name the shipment adds to the release.
    fn names(&self) -> impl Iterator<Item = &str> {
        self.files
            .iter()
            .map(|a| a.name.as_str())
            .chain(self.update_archive.iter().map(|a| a.name.as_str()))
    }
}

fn asset_name(group: Group, version: &str, platform: Platform, ext: &str) -> String {
    format!("{group}-{version}-{}-{}{ext}", platform.os, platform.arch)
}

fn exe_suffix(platform: Platform) -> &'static str {
    if platform.os == Os::Windows {
        ".exe"
    } else {
        ""
    }
}

/// A probe that `args` prints `<program> <version>`.
fn version_probe(args: &'static [&'static str], program: &str, version: &str) -> Probe {
    Probe {
        args,
        prints: Some(format!("{program} {version}")),
    }
}

/// `installer` is the MSI or DMG the lane's tests ran on, resolved by the caller (see [`resolve_installer`]).
pub fn plan(
    group: Group,
    lane: Lane,
    version: &str,
    platform: Platform,
    repo_root: &Path,
    installer: impl FnOnce() -> Result<PathBuf>,
) -> Result<Shipment> {
    let binary = |src: PathBuf, probes: Vec<Probe>| Asset {
        src,
        name: asset_name(group, version, platform, exe_suffix(platform)),
        probes,
    };
    let release = repo_root.join("target").join("release");
    let update_archive = |source| UpdateArchive {
        name: format!(
            "{group}-{version}-{}",
            xtask_lib::asset::update_asset_suffix(platform.os, &platform.arch.to_string())
        ),
        source,
    };
    match (group, lane) {
        (Group::Hole, Lane::Msi) => {
            ensure!(
                platform.os == Os::Windows,
                "the msi lane runs on Windows, not {platform}"
            );
            let stage_dir = MSI_STAGE_DIR
                .iter()
                .fold(repo_root.to_path_buf(), |dir, part| dir.join(part));
            Ok(Shipment {
                files: vec![Asset {
                    src: installer()?,
                    name: asset_name(group, version, platform, ".msi"),
                    probes: Vec::new(),
                }],
                // The zip is packed from the directory the MSI was built from, not from whatever `target/release`
                // holds by the time this lane runs.
                update_archive: Some(update_archive(UpdateArchiveSource::StagedBindir(stage_dir.clone()))),
                payload_binary: Some(Executable {
                    path: stage_dir.join("hole.exe"),
                    probes: vec![version_probe(&["version"], "hole", version)],
                }),
                build_first: None,
            })
        }
        // The DMG tests check the shipped version themselves (`test_shipped_version_is_exact`).
        (Group::Hole, Lane::Dmg) => {
            ensure!(platform.os == Os::Darwin, "the dmg lane runs on macOS, not {platform}");
            Ok(Shipment {
                files: vec![Asset {
                    src: installer()?,
                    name: asset_name(group, version, platform, ".dmg"),
                    probes: Vec::new(),
                }],
                update_archive: Some(update_archive(UpdateArchiveSource::BuiltApp)),
                payload_binary: None,
                build_first: None,
            })
        }
        (Group::Galoshes, Lane::Plugins) => Ok(Shipment {
            files: vec![binary(
                release.join(format!("galoshes{}", exe_suffix(platform))),
                Vec::new(),
            )],
            update_archive: None,
            payload_binary: None,
            build_first: None,
        }),
        // See `Shipment::build_first`: the probes are the only test of this file.
        (Group::Garter, Lane::Plugins) => Ok(Shipment {
            files: vec![binary(
                release.join(format!("garter{}", exe_suffix(platform))),
                vec![
                    version_probe(&["--version"], "garter", version),
                    Probe {
                        args: &["--help"],
                        prints: None,
                    },
                ],
            )],
            update_archive: None,
            payload_binary: None,
            build_first: Some("garter-bin"),
        }),
        (Group::ExRay, Lane::Plugins) => Ok(Shipment {
            files: vec![binary(
                repo_root
                    .join(".cache")
                    .join("ex-ray")
                    .join(crate::ex_ray::output_name()),
                Vec::new(),
            )],
            update_archive: None,
            payload_binary: None,
            build_first: None,
        }),
        (Group::Hole, Lane::Plugins)
        | (Group::Galoshes | Group::Garter | Group::ExRay, Lane::Msi)
        | (Group::Galoshes | Group::Garter | Group::ExRay, Lane::Dmg) => Ok(Shipment::nothing()),
    }
}

/// What a release ships for one platform.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct PlatformAssets {
    pub os: String,
    pub arch: String,
    /// The file the release notes link for the platform: its installer, or its binary.
    pub asset: String,
    /// Every file the platform adds to the release.
    pub assets: Vec<String>,
}

/// Every platform a release of `group` ships on and the files it ships there: the union over all lanes of the
/// platforms `build.yaml` runs the lane's target on.
pub fn shipped(group: Group, version: &str, manifest: &Manifest) -> Result<Vec<PlatformAssets>> {
    let mut out: Vec<PlatformAssets> = Vec::new();
    for lane in <Lane as ValueEnum>::value_variants() {
        let target = manifest
            .get(lane.target())
            .with_context(|| format!("build.yaml has no target {}", lane.target()))?;
        for &platform in &target.platforms {
            let shipment = plan(group, *lane, version, platform, Path::new(""), || Ok(PathBuf::new()))?;
            let mut names = shipment.names().map(str::to_owned);
            let Some(primary) = names.next() else { continue };
            let (os, arch) = (platform.os.to_string(), platform.arch.to_string());
            let at = match out.iter().position(|p| p.os == os && p.arch == arch) {
                Some(at) => at,
                None => {
                    out.push(PlatformAssets {
                        os,
                        arch,
                        asset: primary.clone(),
                        assets: Vec::new(),
                    });
                    out.len() - 1
                }
            };
            out[at].assets.push(primary);
            out[at].assets.extend(names);
        }
    }
    Ok(out)
}

/// Print what the release `tag` ships, as the JSON array of [`PlatformAssets`] the draft workflow consumes.
pub fn list(tag: &str) -> Result<()> {
    let (group, version) = parse_release_tag(tag)?;
    let (manifest, _) = crate::load_manifest()?;
    let platforms = shipped(group, &version.to_string(), &manifest)?;
    println!("{}", serde_json::to_string(&platforms)?);
    Ok(())
}

/// The installer a lane stages: the single `.dmg` in the release bundle dir / the release MSI, the build this
/// checkout's update archive and payload probe are taken from.
///
/// `MSI_UNDER_TEST` / `DMG_UNDER_TEST` may be set (a relative path is from the repo root) but only to that same
/// file: staging another installer next to this build's archive would ship two builds as one release.
fn resolve_installer(lane: Lane, repo_root: &Path) -> Result<PathBuf> {
    let release = repo_root.join("target").join("release");
    let (env_var, built) = match lane {
        Lane::Msi => (MSI_ENV, release.join("hole.msi")),
        Lane::Dmg => (DMG_ENV, single_dmg(&release.join("bundle").join("dmg"))?),
        Lane::Plugins => bail!("the plugins lane stages no installer"),
    };
    if let Some(given) = std::env::var_os(env_var).filter(|p| !p.is_empty()) {
        check_installer_override(env_var, &repo_root.join(given), &built)?;
    }
    Ok(built)
}

/// `given` (the value of `env_var`) must be the file `built` names.
fn check_installer_override(env_var: &str, given: &Path, built: &Path) -> Result<()> {
    let resolve = |path: &Path| std::fs::canonicalize(path).with_context(|| format!("resolve {}", path.display()));
    ensure!(
        resolve(given)? == resolve(built)?,
        "{env_var} is {}, but stage-release stages only this checkout's own build, {}: the update archive and the version probe come from that build. Unset {env_var} or point it at that file",
        given.display(),
        built.display()
    );
    Ok(())
}

/// The one `.dmg` in `dir`.
fn single_dmg(dir: &Path) -> Result<PathBuf> {
    let mut dmgs = Vec::new();
    for entry in std::fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == "dmg") {
            dmgs.push(path);
        }
    }
    match <[PathBuf; 1]>::try_from(dmgs) {
        Ok([only]) => Ok(only),
        Err(found) => bail!(
            "expected exactly one .dmg in {}, found {}; remove the stale ones",
            dir.display(),
            found.len()
        ),
    }
}

/// `exe` ran `probe`'s command and printed `stdout`: it must be what the probe says.
fn check_probe_output(exe: &Path, probe: &Probe, stdout: &str) -> Result<()> {
    if let Some(expected) = &probe.prints {
        ensure!(
            stdout.trim() == expected,
            "`{} {}` printed {:?}, expected {expected:?}; a `.dirty` suffix means the build stamped a dirty tree",
            exe.display(),
            probe.args.join(" "),
            stdout.trim()
        );
    }
    Ok(())
}

/// Run each probe on `exe`: it must exit 0 and print what the probe says.
fn run_probes(exe: &Path, probes: &[Probe]) -> Result<()> {
    for probe in probes {
        let output = crate::command::run_captured(std::process::Command::new(exe).args(probe.args))?;
        check_probe_output(exe, probe, &String::from_utf8_lossy(&output.stdout))?;
        println!("xtask: {} {} passed", exe.display(), probe.args.join(" "));
    }
    Ok(())
}

/// Run the shipment's `build_first` target through `build`, then require every file in `files` to exist.
fn ensure_built(shipment: &Shipment, build: impl FnOnce(&str) -> Result<()>) -> Result<()> {
    if let Some(target) = shipment.build_first {
        build(target)?;
    }
    for asset in &shipment.files {
        ensure!(asset.src.is_file(), "{} is not a file", asset.src.display());
    }
    Ok(())
}

/// Stage what `lane` ships for the release `tag` into `out`.
pub fn stage(repo_root: &Path, tag: &str, lane: Lane, out: &Path) -> Result<()> {
    let (group, version) = parse_release_tag(tag)?;
    let platform = Platform::host().context("unknown host platform")?;
    let version = version.to_string();
    let shipment = plan(group, lane, &version, platform, repo_root, || {
        resolve_installer(lane, repo_root)
    })?;
    if shipment.files.is_empty() {
        println!("xtask: {group} ships nothing from the {lane:?} lane on {platform}");
        return Ok(());
    }

    ensure_built(&shipment, |target| crate::build_target_in(repo_root, platform, target))?;

    std::fs::create_dir_all(out).with_context(|| format!("create {}", out.display()))?;
    for asset in &shipment.files {
        let dest = out.join(&asset.name);
        std::fs::copy(&asset.src, &dest)
            .with_context(|| format!("copy {} to {}", asset.src.display(), dest.display()))?;
        println!("xtask: staged {} as {}", asset.src.display(), asset.name);
        run_probes(&dest, &asset.probes)?;
    }
    if let Some(exe) = &shipment.payload_binary {
        run_probes(&exe.path, &exe.probes)?;
    }

    if let Some(update_archive) = &shipment.update_archive {
        let archive = out.join(&update_archive.name);
        match &update_archive.source {
            UpdateArchiveSource::StagedBindir(dir) => {
                crate::update_archive::build_update_archive_from_stage(dir, &archive)?
            }
            UpdateArchiveSource::BuiltApp => {
                crate::update_archive::build_update_archive(Profile::Release, repo_root, &archive)?
            }
        }
        crate::update_archive::verify_update_archive(&archive)?;
        #[cfg(target_os = "macos")]
        crate::update_archive::verify_app_signature(&archive)?;
        println!("xtask: staged and verified {}", archive.display());
    }
    Ok(())
}

#[cfg(test)]
#[path = "stage_release_tests.rs"]
mod stage_release_tests;

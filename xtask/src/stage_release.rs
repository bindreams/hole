//! `cargo xtask stage-release`: copy what a release ships out of a CI leg's build into one directory, named as the
//! release names it, so the draft workflow uploads the files the leg's tests ran on.
//!
//! A lane is the point in `ci.yaml` where one kind of shipped file has just passed its tests, and each
//! (group, lane) pair says what to stage there.

#![allow(clippy::disallowed_methods)] // dev tooling, never privileged

use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context, Result};
use clap::ValueEnum;
use xtask_lib::version::{parse_release_tag, Group};

use crate::manifest::{Os, Platform};
use crate::Profile;

/// Overrides for the installer to stage, the same variables the installer tests read.
const MSI_ENV: &str = "MSI_UNDER_TEST";
const DMG_ENV: &str = "DMG_UNDER_TEST";

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

/// One file to copy into the release directory.
#[derive(Debug, PartialEq, Eq)]
pub struct Asset {
    pub src: PathBuf,
    pub name: String,
}

/// What a (group, lane) pair ships on one platform.
#[derive(Debug, PartialEq, Eq)]
pub struct Shipment {
    /// `build.yaml` target that produces the files, when no earlier lane of the leg built them.
    pub build_target: Option<&'static str>,
    pub files: Vec<Asset>,
    /// Whether the Hole update archive ships beside the installer.
    pub update_archive: bool,
}

impl Shipment {
    fn nothing() -> Self {
        Self {
            build_target: None,
            files: Vec::new(),
            update_archive: false,
        }
    }
}

/// `<group>-<version>-<os>-<arch><ext>`, the name every release asset carries.
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

/// `installer` is the MSI or DMG the lane's tests ran on, resolved by the caller (see [`resolve_installer`]).
pub fn plan(
    group: Group,
    lane: Lane,
    version: &str,
    platform: Platform,
    repo_root: &Path,
    installer: impl FnOnce() -> Result<PathBuf>,
) -> Result<Shipment> {
    let binary = |src: PathBuf| Asset {
        src,
        name: asset_name(group, version, platform, exe_suffix(platform)),
    };
    let release = repo_root.join("target").join("release");
    match (group, lane) {
        (Group::Hole, Lane::Msi) => {
            ensure!(
                platform.os == Os::Windows,
                "the msi lane runs on Windows, not {platform}"
            );
            Ok(Shipment {
                build_target: None,
                files: vec![Asset {
                    src: installer()?,
                    name: asset_name(group, version, platform, ".msi"),
                }],
                update_archive: true,
            })
        }
        (Group::Hole, Lane::Dmg) => {
            ensure!(platform.os == Os::Darwin, "the dmg lane runs on macOS, not {platform}");
            Ok(Shipment {
                build_target: None,
                files: vec![Asset {
                    src: installer()?,
                    name: asset_name(group, version, platform, ".dmg"),
                }],
                update_archive: true,
            })
        }
        (Group::Galoshes, Lane::Plugins) => Ok(Shipment {
            build_target: None,
            files: vec![binary(release.join(format!("galoshes{}", exe_suffix(platform))))],
            update_archive: false,
        }),
        // No earlier lane builds the garter CLI: the archive lane tests the crates in the debug profile.
        (Group::Garter, Lane::Plugins) => Ok(Shipment {
            build_target: Some("garter-bin"),
            files: vec![binary(release.join(format!("garter{}", exe_suffix(platform))))],
            update_archive: false,
        }),
        (Group::ExRay, Lane::Plugins) => Ok(Shipment {
            build_target: None,
            files: vec![binary(
                repo_root
                    .join(".cache")
                    .join("ex-ray")
                    .join(crate::ex_ray::output_name()),
            )],
            update_archive: false,
        }),
        (Group::Hole, Lane::Plugins)
        | (Group::Galoshes | Group::Garter | Group::ExRay, Lane::Msi)
        | (Group::Galoshes | Group::Garter | Group::ExRay, Lane::Dmg) => Ok(Shipment::nothing()),
    }
}

/// The installer a lane stages: `env_var`'s path when set, else the single `.dmg` in the release bundle dir / the
/// release MSI.
fn resolve_installer(lane: Lane, repo_root: &Path) -> Result<PathBuf> {
    let release = repo_root.join("target").join("release");
    let (env_var, default) = match lane {
        Lane::Msi => (MSI_ENV, release.join("hole.msi")),
        Lane::Dmg => (DMG_ENV, release.join("bundle").join("dmg")),
        Lane::Plugins => bail!("the plugins lane stages no installer"),
    };
    if let Some(path) = std::env::var_os(env_var).filter(|p| !p.is_empty()) {
        return Ok(PathBuf::from(path));
    }
    if lane != Lane::Dmg {
        return Ok(default);
    }
    let mut dmgs = Vec::new();
    for entry in std::fs::read_dir(&default).with_context(|| format!("read {}", default.display()))? {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == "dmg") {
            dmgs.push(path);
        }
    }
    match <[PathBuf; 1]>::try_from(dmgs) {
        Ok([only]) => Ok(only),
        Err(found) => bail!(
            "expected exactly one .dmg in {}, found {}; remove stale ones or set {DMG_ENV}",
            default.display(),
            found.len()
        ),
    }
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
    if let Some(target) = shipment.build_target {
        crate::run_build(Some(target.to_string()), false)?;
    }

    std::fs::create_dir_all(out).with_context(|| format!("create {}", out.display()))?;
    for asset in &shipment.files {
        ensure!(asset.src.is_file(), "{} is not a file", asset.src.display());
        let dest = out.join(&asset.name);
        std::fs::copy(&asset.src, &dest)
            .with_context(|| format!("copy {} to {}", asset.src.display(), dest.display()))?;
        println!("xtask: staged {} as {}", asset.src.display(), asset.name);
    }

    if shipment.update_archive {
        // Named from the one suffix source the updater also uses, so it cannot drift from what the updater downloads.
        let archive = out.join(format!(
            "{group}-{version}-{}",
            xtask_lib::asset::host_update_asset_suffix()
        ));
        crate::update_archive::build_update_archive(Profile::Release, repo_root, &archive)?;
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

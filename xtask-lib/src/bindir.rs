//! The canonical *set* of files that comprise a runnable hole BINDIR, plus the
//! [`Os`] enum the set is keyed on.
//!
//! **Single source of truth.** Lives in `xtask-lib` (not `xtask`) so consumers
//! that must not pull `xtask`'s clap/glob/ureq machinery — `crates/hole/build.rs`
//! and the bridge's update-cutover swap — can depend on it directly. `xtask`
//! re-exports both [`Os`] and [`bindir_dest_names`]; its `bindir::bindir_files`
//! resolves each name to a host source path, and the installer-manifest
//! conformance tests derive their expected payload from `bindir_dest_names` (via
//! `cargo xtask bindir-names`).
//!
//! See issue #143 for the motivation.

use std::fmt;
use std::str::FromStr;

use anyhow::{anyhow, Result};

/// Operating system component of a build target.
///
/// Docker / GOOS-style identifiers, matching the release-artifact naming
/// (`hole-<version>-windows-amd64.msi`) and the CI `matrix.os` dimension.
/// The `serde`/`clap` derives are feature-gated so the lightweight consumers
/// (bridge cutover) pull neither.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum Os {
    Windows,
    Darwin,
    Linux,
}

impl Os {
    /// The host OS, or `None` on a platform outside the known set (FreeBSD, etc.).
    pub fn host() -> Option<Self> {
        if cfg!(target_os = "windows") {
            Some(Os::Windows)
        } else if cfg!(target_os = "macos") {
            Some(Os::Darwin)
        } else if cfg!(target_os = "linux") {
            Some(Os::Linux)
        } else {
            None
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Os::Windows => "windows",
            Os::Darwin => "darwin",
            Os::Linux => "linux",
        }
    }
}

impl fmt::Display for Os {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Os {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "windows" => Ok(Os::Windows),
            "darwin" => Ok(Os::Darwin),
            "linux" => Ok(Os::Linux),
            other => Err(anyhow!(
                "unknown os {other:?} (expected one of: windows, darwin, linux)"
            )),
        }
    }
}

/// On-disk filenames that must sit next to the bridge binary on `os`, in staging
/// order. **Single source of truth for the BINDIR payload.** Pure: no disk
/// access, callable for any `os` from any host — so the installer conformance
/// tests (`cargo xtask bindir-names`), `xtask::bindir::bindir_files`, and the
/// Windows update-cutover swap share one definition of what ships.
///
/// Add or remove a BINDIR file here. `bindir_tests.rs` asserts the exact set
/// per OS, and the WiX / Tauri conformance tests fail loudly if a manifest stops
/// covering it.
pub fn bindir_dest_names(os: Os) -> Vec<String> {
    let exe = if os == Os::Windows { ".exe" } else { "" };
    let mut names = vec![format!("hole{exe}")];
    // Debug symbols, staged alongside the binary so panic backtraces resolve
    // frame names + line numbers (else `<unknown>`; see #393). The workspace
    // `[profile.release] debug = "limited"` + `split-debuginfo = "packed"`
    // produce a portable PDB/dSYM for this purpose.
    match os {
        Os::Windows => names.push("hole.pdb".to_string()),
        Os::Darwin => names.push("hole.dSYM".to_string()),
        Os::Linux => {}
    }
    names.push(format!("ex-ray{exe}"));
    names.push(format!("galoshes{exe}"));
    // wintun.dll — Windows-only DLL loaded by the bridge's TUN path.
    if os == Os::Windows {
        names.push("wintun.dll".to_string());
    }
    // NOTICES.md — Apache-2.0 §4(d) attribution for the bundled galoshes/garter
    // components; the installer license dialog shows only GPL-3.0 text, so the
    // NOTICE file must accompany the binaries on disk.
    names.push("NOTICES.md".to_string());
    names
}

/// SIP003 plugin sidecar binaries (no extension) that every installer must ship
/// next to the bridge so `resolve_plugin_path` finds them. Subset of
/// [`bindir_dest_names`]; drives the macOS `externalBin` conformance check.
pub fn plugin_sidecar_names() -> &'static [&'static str] {
    &["ex-ray", "galoshes"]
}

#[cfg(test)]
#[path = "bindir_tests.rs"]
mod bindir_tests;

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

/// What a shipped file is: whether it is an executable and, if so, what builds it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FileKind {
    /// An executable cargo builds from a package whose `build.rs` calls `libsearch_guard::bins()`.
    RustExecutable,
    /// An executable another toolchain builds (ex-ray, from Go).
    ForeignExecutable,
    /// Not run: a library, debug symbols, a notice file.
    NotExecutable,
}

impl FileKind {
    /// Whether a file of this kind is an executable.
    pub fn is_executable(self) -> bool {
        match self {
            FileKind::RustExecutable | FileKind::ForeignExecutable => true,
            FileKind::NotExecutable => false,
        }
    }

    /// Whether `libsearch_guard::verify` must pass on a file of this kind shipped for `os`.
    pub fn is_verified_on(self, os: Os) -> bool {
        match self {
            FileKind::NotExecutable => false,
            FileKind::RustExecutable => true,
            // The Go linker sets no `DEPENDENTLOADFLAG`, so a Windows build of it is not hardened.
            FileKind::ForeignExecutable => os != Os::Windows,
        }
    }
}

/// One file or bundle of the BINDIR: its on-disk name and what it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindirEntry {
    pub name: String,
    pub kind: FileKind,
}

/// The file name of the Hole executable itself in a BINDIR on `os`: the entry of [`bindir_entries`] that is the app, not one
/// of its plugins or data files.
pub fn app_executable_name(os: Os) -> String {
    let exe = if os == Os::Windows { ".exe" } else { "" };
    format!("hole{exe}")
}

/// The BINDIR payload for `os`, in staging order. **Single source of truth for the BINDIR payload and for what each
/// file is.** Pure: no disk access, callable for any `os` from any host.
pub fn bindir_entries(os: Os) -> Vec<BindirEntry> {
    let exe = if os == Os::Windows { ".exe" } else { "" };
    let entry = |name: String, kind| BindirEntry { name, kind };
    let mut entries = vec![entry(app_executable_name(os), FileKind::RustExecutable)];
    // Debug symbols, staged alongside the binary so panic backtraces resolve
    // frame names + line numbers (else `<unknown>`). The workspace
    // `[profile.release] debug = "limited"` + `split-debuginfo = "packed"`
    // produce a portable PDB/dSYM for this purpose.
    match os {
        Os::Windows => entries.push(entry("hole.pdb".to_string(), FileKind::NotExecutable)),
        Os::Darwin => entries.push(entry("hole.dSYM".to_string(), FileKind::NotExecutable)),
        Os::Linux => {}
    }
    entries.push(entry(format!("ex-ray{exe}"), FileKind::ForeignExecutable));
    entries.push(entry(format!("galoshes{exe}"), FileKind::RustExecutable));
    // wintun.dll — Windows-only DLL loaded by the bridge's TUN path.
    if os == Os::Windows {
        entries.push(entry("wintun.dll".to_string(), FileKind::NotExecutable));
    }
    entries
}

/// On-disk filenames that must sit next to the bridge binary on `os`, in staging
/// order: the names of [`bindir_entries`]. The installer conformance tests
/// (`cargo xtask bindir-names`), `xtask::bindir::bindir_files`, and the
/// Windows update-cutover swap share this one definition of what ships.
///
/// Add or remove a BINDIR file in [`bindir_entries`]. `bindir_tests.rs` asserts the exact set
/// per OS, and the WiX / Tauri conformance tests fail loudly if a manifest stops
/// covering it.
pub fn bindir_dest_names(os: Os) -> Vec<String> {
    bindir_entries(os).into_iter().map(|e| e.name).collect()
}

/// SIP003 plugin binaries (no extension) Hole ships. The Windows installer puts them
/// next to the bridge, where its `PluginSource` finds them; on macOS `hole` embeds them
/// ([`embedded_plugin_names`]). Subset of [`bindir_dest_names`].
pub fn plugin_sidecar_names() -> &'static [&'static str] {
    &["ex-ray", "galoshes"]
}

/// The plugin binaries `hole` carries inside itself on `os`, rather than as files beside it: the names of
/// [`plugin_sidecar_names`] on macOS, where the service runs them from a root-owned folder it fills at start, and none
/// elsewhere. The one place this platform difference is stated.
pub fn embedded_plugin_names(os: Os) -> &'static [&'static str] {
    match os {
        Os::Darwin => plugin_sidecar_names(),
        Os::Windows => &[],
        Os::Linux => &[],
    }
}

/// The entries of [`bindir_entries`] `hole` embeds on `os` ([`embedded_plugin_names`]).
pub fn embedded_plugin_entries(os: Os) -> Vec<BindirEntry> {
    let embedded = embedded_plugin_names(os);
    bindir_entries(os)
        .into_iter()
        .filter(|e| embedded.contains(&e.name.as_str()))
        .collect()
}

/// What the app bundle holds on `os`: [`bindir_entries`] without the plugins `hole` embeds.
pub fn bundle_payload_entries(os: Os) -> Vec<BindirEntry> {
    let embedded = embedded_plugin_names(os);
    bindir_entries(os)
        .into_iter()
        .filter(|e| !embedded.contains(&e.name.as_str()))
        .collect()
}

/// The names of [`bundle_payload_entries`].
pub fn bundle_payload_names(os: Os) -> Vec<String> {
    bundle_payload_entries(os).into_iter().map(|e| e.name).collect()
}

/// The file name a plugin takes in `.cache/<name>/`: `<name>-<triple>{.exe}`, what Tauri appends to an `externalBin`
/// entry and what `hole`'s build embeds.
pub fn cache_sidecar_file_name(name: &str, triple: &str, windows: bool) -> String {
    let exe = if windows { ".exe" } else { "" };
    format!("{name}-{triple}{exe}")
}

/// Where `cargo xtask deps` leaves the plugin `name` for `triple`: `<repo>/.cache/<name>/<name>-<triple>{.exe}`.
pub fn cache_sidecar_path(repo_root: &std::path::Path, name: &str, triple: &str, windows: bool) -> std::path::PathBuf {
    repo_root
        .join(".cache")
        .join(name)
        .join(cache_sidecar_file_name(name, triple, windows))
}

#[cfg(test)]
#[path = "bindir_tests.rs"]
mod bindir_tests;

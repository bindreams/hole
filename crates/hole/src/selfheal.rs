//! GUI ↔ bridge version-lockstep self-heal.
//!
//! When the GUI detects (via the `X-Hole-Bridge-Version` header) that the
//! bridge runs a different version, it must not operate the mismatched pair.
//! [`decide`] is the pure, `#[cfg]`-free policy; the OS-specific bits live
//! behind the [`canonical_install_exe`](capture_startup_identity)/identity
//! seam and [`crate::relaunch`]. Inert until an update produces a mismatch.

use std::path::{Path, PathBuf};

/// What the GUI should do about an observed version mismatch.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SelfHealAction {
    /// Versions match — operate normally.
    Operate,
    /// The installed image changed under us (an update) — relaunch it.
    Relaunch,
    /// We are the installed image but the bridge differs — genuine
    /// misconfiguration; prompt the user to reinstall.
    Reinstall,
    /// The installed file is transiently absent (mid-swap) — retry later.
    Transient,
}

/// Pure self-heal policy. `bridge` is the bridge's reported version, or
/// `None` for an old bridge predating the version stamp (treated as a
/// mismatch). `running` is our startup image identity; `canonical` is the
/// identity of the file at that same path *now*, or `None` if it is
/// transiently absent. Generic over the identity token so it is fully
/// table-testable without touching the filesystem.
pub fn decide<T: PartialEq>(own: &str, bridge: Option<&str>, running: T, canonical: Option<T>) -> SelfHealAction {
    if bridge == Some(own) {
        return SelfHealAction::Operate;
    }
    match canonical {
        None => SelfHealAction::Transient,
        Some(c) if c != running => SelfHealAction::Relaunch,
        Some(_) => SelfHealAction::Reinstall,
    }
}

/// The GUI image identity captured at startup, before any update can rename
/// it. Compared later against the file at the same path: a difference means
/// an update swapped the binary underneath us. The path is derived from
/// `current_exe` (not a hardcoded `Program Files` location), so a custom
/// install directory is handled automatically.
pub struct StartupIdentity {
    pub exe: PathBuf,
    pub id: same_file::Handle,
}

/// Capture the running image's identity once at startup. Returns `None` for
/// dev/snapshot builds (built in lockstep — never self-heal) or if the exe
/// identity cannot be read.
pub fn capture_startup_identity() -> Option<StartupIdentity> {
    if is_dev_build() {
        return None;
    }
    let exe = std::env::current_exe().ok()?;
    let id = same_file::Handle::from_path(&exe).ok()?;
    Some(StartupIdentity { exe, id })
}

/// Dev/snapshot builds are built in lockstep and must never self-heal.
fn is_dev_build() -> bool {
    matches!(
        hole_common::version::ReleaseVersion::from_build_version(crate::version::VERSION),
        Ok((_, true)) // is_snapshot
    )
}

/// File identity via the cross-platform `same_file` crate (volume serial +
/// file index on Windows; device + inode on Unix). No FFI, no `#[cfg]`.
pub fn file_identity(p: &Path) -> std::io::Result<same_file::Handle> {
    same_file::Handle::from_path(p)
}

#[cfg(test)]
#[path = "selfheal_tests.rs"]
mod selfheal_tests;

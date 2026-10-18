//! Workspace-root discovery shared by xtask and dev-console.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// The variable `cargo xtask` sets, on the commands its `process:` steps
/// launch, to the root it pinned.
pub const DEV_REPO_ROOT_ENV: &str = "HOLE_DEV_REPO_ROOT";

/// Locate the workspace root: walk up from `CARGO_MANIFEST_DIR` (set by
/// `cargo run` at runtime for the binary's own crate dir) and, failing that,
/// from the executable's location, until a `Cargo.toml` containing
/// `[workspace]` is found.
///
/// Deliberately no `git rev-parse --show-toplevel` — this must work where
/// git is unavailable (CI minimal images, source tarballs).
///
/// A relative or empty `CARGO_MANIFEST_DIR` is an error naming it.
pub fn repo_root() -> Result<PathBuf> {
    let manifest_dir = std::env::var_os("CARGO_MANIFEST_DIR").map(PathBuf::from);
    workspace_root_for(manifest_dir.as_deref(), || {
        let exe = std::env::current_exe().context("current_exe")?;
        Ok(exe.parent().map(Path::to_path_buf))
    })
}

/// [`repo_root`] over explicit locations, so tests need not touch the process
/// environment. A relative or empty `CARGO_MANIFEST_DIR` is an error, not a
/// skipped candidate: the root it yields is relative to the cwd, and callers
/// `join` onto it after changing directory. `exe_dir` is asked only when the
/// manifest dir does not answer, so a host where `current_exe` fails still
/// resolves through it.
pub(crate) fn workspace_root_for(
    manifest_dir: Option<&Path>,
    exe_dir: impl FnOnce() -> Result<Option<PathBuf>>,
) -> Result<PathBuf> {
    if let Some(dir) = manifest_dir {
        ensure_absolute_manifest_dir(dir)?;
        if let Ok(root) = repo_root_from(dir) {
            return Ok(root);
        }
    }
    repo_root_from(exe_dir()?.as_deref().unwrap_or(Path::new("/")))
}

/// Cargo always sets `CARGO_MANIFEST_DIR` absolute, so only a hand-set value
/// trips this; the exe and cwd come from the OS and are absolute.
fn ensure_absolute_manifest_dir(dir: &Path) -> Result<()> {
    anyhow::ensure!(
        dir.is_absolute(),
        "CARGO_MANIFEST_DIR is \"{}\", which is not an absolute path",
        dir.display()
    );
    Ok(())
}

/// The hole checkout a binary a build driver launched belongs to.
///
/// `HOLE_DEV_REPO_ROOT` ([`DEV_REPO_ROOT_ENV`]) comes first: `cargo xtask`
/// sets it on the commands its `process:` steps launch to the root it pinned.
/// Only xtask knows that root; no ambient signal can stand in for it, because
/// a hand run of one checkout's binary from another checkout and a launch
/// with `target/` redirected into another checkout present the same
/// executable and working directory. A set value must itself be an absolute
/// path to a hole root (`[workspace]` manifest and `crates/hole`); anything
/// else is an error naming it, never a fallback.
///
/// Unset (a standalone run), it is the first of `CARGO_MANIFEST_DIR`, the
/// executable's location and the working directory whose enclosing workspace
/// is a hole root. Only a hole root is accepted, so a launch from inside some
/// other workspace cannot redirect the lookup, and a binary run by hand
/// belongs to the checkout it sits in. A relative or empty `CARGO_MANIFEST_DIR`
/// is an error naming it.
///
/// Errors name each location tried.
pub fn repo_root_from_launch_dir() -> Result<PathBuf> {
    let handoff = std::env::var_os(DEV_REPO_ROOT_ENV).map(PathBuf::from);
    let manifest_dir = std::env::var_os("CARGO_MANIFEST_DIR").map(PathBuf::from);
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf));
    let cwd = std::env::current_dir().ok();
    hole_root_for_launch(
        handoff.as_deref(),
        manifest_dir.as_deref(),
        exe_dir.as_deref(),
        cwd.as_deref(),
    )
}

/// [`repo_root_from_launch_dir`] over explicit locations (`None`: unavailable),
/// so tests need not touch the process environment. The parameter order is the
/// lookup order.
pub(crate) fn hole_root_for_launch(
    handoff: Option<&Path>,
    manifest_dir: Option<&Path>,
    exe_dir: Option<&Path>,
    cwd: Option<&Path>,
) -> Result<PathBuf> {
    if let Some(root) = handoff {
        // Absolute only: a relative value would resolve against the cwd here and
        // again after dev-console changes into it.
        anyhow::ensure!(
            root.is_absolute() && is_hole_root(root),
            "{DEV_REPO_ROOT_ENV} is \"{}\", which is not an absolute path to a hole root (needs a [workspace] Cargo.toml and crates/hole)",
            root.display()
        );
        return Ok(root.to_path_buf());
    }
    if let Some(dir) = manifest_dir {
        ensure_absolute_manifest_dir(dir)?;
    }
    let candidates = [
        ("CARGO_MANIFEST_DIR", manifest_dir),
        ("executable", exe_dir),
        ("working directory", cwd),
    ];
    let mut tried = Vec::new();
    for (what, start) in candidates {
        let Some(start) = start else {
            tried.push(format!("{what}: unavailable"));
            continue;
        };
        match repo_root_from(start) {
            Ok(root) if root.join("crates").join("hole").is_dir() => return Ok(root),
            Ok(root) => tried.push(format!(
                "{what} {}: workspace {} is not the hole root (no crates/hole)",
                start.display(),
                root.display()
            )),
            Err(_) => tried.push(format!("{what} {}: no workspace above it", start.display())),
        }
    }
    anyhow::bail!("could not locate the hole root; tried {}", tried.join("; "))
}

/// Is `dir` itself (no walk-up) a hole root?
fn is_hole_root(dir: &Path) -> bool {
    is_workspace_root(dir) && dir.join("crates").join("hole").is_dir()
}

/// Does `dir` hold a `Cargo.toml` that declares a workspace?
///
/// Naive `[workspace]` substring check; the alternative would pull in `toml`
/// parsing for one read. (Same trade as the original xtask fn this generalizes.)
fn is_workspace_root(dir: &Path) -> bool {
    std::fs::read_to_string(dir.join("Cargo.toml")).is_ok_and(|s| s.contains("[workspace]"))
}

/// Walk-up core, separated for tests.
pub fn repo_root_from(start: &Path) -> Result<PathBuf> {
    let mut dir = start.to_path_buf();
    loop {
        if is_workspace_root(&dir) {
            return Ok(dir);
        }
        if !dir.pop() {
            anyhow::bail!(
                "could not locate the workspace root walking up from {}",
                start.display()
            );
        }
    }
}

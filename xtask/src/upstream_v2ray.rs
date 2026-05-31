//! Provision a pinned upstream shadowsocks/v2ray-plugin build for the
//! ex-ray cross-implementation interop test. Cached + hash-verified under
//! `.cache/upstream-v2ray-plugin/<commit>/` so re-runs are near-instant.
//!
//! Unlike [`crate::wintun`] / [`crate::golangci_lint`] — which download a
//! pre-built artifact and verify it against a PINNED HASH of the published
//! file — there is no pre-known binary hash for a from-source build (the Go
//! toolchain version, host triple, and trimpath settings all influence the
//! output bytes). So the integrity model is inverted: we PIN THE SOURCE
//! COMMIT, build it ourselves, and write a `.verified` sentinel recording the
//! sha256 of the binary WE produced. A cache hit ("binary present + sentinel
//! matches the recorded hash") therefore means "we already built this commit
//! and the cached binary hasn't been corrupted since" — the cheap re-run
//! skip. The pinned commit, not a pinned hash, is the supply-chain anchor.
//!
//! The pin is `e9af1cd…` — the `shadowsocks/v2ray-plugin` upstream revision
//! that Hole vendored before #414 replaced the vendored subrepo with the
//! first-party `crates/ex-ray/` shim. Building stock upstream at exactly that
//! revision makes this the cleanest interop baseline: an ex-ray-vs-stock
//! round-trip compares ex-ray against the exact upstream revision its
//! v2ray-core shim tracks. (Pre-#414 this commit was recorded in
//! `external/v2ray-plugin/.gitrepo`; that subrepo is now deleted, so the pin
//! + rationale live here as the single durable anchor.)
//!
//! Output: `<repo>/.cache/upstream-v2ray-plugin/<commit>/v2ray-plugin-<host-triple>{.exe}`.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};

/// Pinned upstream `shadowsocks/v2ray-plugin` commit
/// (`e9af1cdd2549d528deb20a4ab8d61c5fbe51f306`) — the revision Hole vendored
/// before #414 (see the module docstring for why this is the interop
/// baseline). Bumping this is a deliberate one-line change: update the SHA,
/// delete the `.cache/upstream-v2ray-plugin/<old>` entry, and re-run
/// `cargo xtask provision-upstream-v2ray` to clone, build, and regenerate the
/// `.verified` sentinel for the new commit.
pub const PINNED_COMMIT: &str = "e9af1cdd2549d528deb20a4ab8d61c5fbe51f306";

/// Upstream repository cloned to obtain the pinned commit.
const UPSTREAM_REPO: &str = "https://github.com/shadowsocks/v2ray-plugin";

/// Host-triple output filename for the provisioned binary, mirroring
/// [`crate::ex_ray::output_name`]'s triple→filename map but with the
/// `v2ray-plugin-` prefix. Includes the trailing `.exe` on Windows.
///
/// Covers the same target-triple set as the rest of the workspace CI matrix.
pub fn output_name() -> &'static str {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        "v2ray-plugin-x86_64-pc-windows-msvc.exe"
    }
    #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
    {
        "v2ray-plugin-aarch64-pc-windows-msvc.exe"
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        "v2ray-plugin-aarch64-apple-darwin"
    }
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        "v2ray-plugin-x86_64-apple-darwin"
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        "v2ray-plugin-x86_64-unknown-linux-gnu"
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        "v2ray-plugin-aarch64-unknown-linux-gnu"
    }
    #[cfg(not(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "windows", target_arch = "aarch64"),
        all(target_os = "macos", target_arch = "aarch64"),
        all(target_os = "macos", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "aarch64"),
    )))]
    compile_error!("unsupported platform for upstream v2ray-plugin provisioning");
}

/// Directory the provisioned binary + sentinel live in:
/// `<repo>/.cache/upstream-v2ray-plugin/<PINNED_COMMIT>/`. Commit-scoped so a
/// `PINNED_COMMIT` bump lands in a fresh directory and never collides with a
/// stale build.
pub fn cache_dir(repo_root: &Path) -> PathBuf {
    repo_root
        .join(".cache")
        .join("upstream-v2ray-plugin")
        .join(PINNED_COMMIT)
}

/// The absolute path the provisioned binary is (or will be) cached at. The
/// bridge interop test reads this to locate the binary without re-running the
/// (network-touching) provisioning — it asserts the path `is_file()` and fails
/// loudly with a remediation hint if not.
pub fn cached_binary_path(repo_root: &Path) -> PathBuf {
    cache_dir(repo_root).join(output_name())
}

/// Clone + build the pinned upstream v2ray-plugin if not already cached.
/// Returns the path to the built binary. A cache hit (binary present +
/// sentinel matches the recorded hash) returns immediately with no network
/// access and no rebuild.
pub fn ensure(repo_root: &Path) -> Result<PathBuf> {
    let dir = cache_dir(repo_root);
    let bin_path = dir.join(output_name());
    let sentinel = dir.join("v2ray-plugin.verified");

    std::fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;

    // Cache hit: the sentinel records the sha256 of the binary we previously
    // built for this commit; if it still matches the on-disk binary, the
    // cached artifact is intact and we skip clone + build entirely.
    if bin_path.exists() && sentinel.exists() {
        let recorded = std::fs::read_to_string(&sentinel).unwrap_or_default();
        let recorded = recorded.trim();
        if !recorded.is_empty() {
            let actual = sha256_file(&bin_path)?;
            if actual == recorded {
                return Ok(bin_path);
            }
            // Recorded hash present but the binary changed on disk — corrupted
            // or partially-written cache. Fall through to a clean rebuild.
            eprintln!(
                "xtask: cached upstream v2ray-plugin at {} failed its integrity check \
                 (recorded {recorded}, got {actual}); rebuilding",
                bin_path.display()
            );
        }
    }

    // Cache miss / corrupt cache: clone into a sibling `.build-<commit>` dir,
    // check out the pinned commit, build, then remove the checkout. Keeping
    // the checkout under `.cache/` (not a system tmp dir or the worktree)
    // means it never pollutes the working tree and is naturally gitignored
    // along with the rest of `.cache/`.
    let build_dir = repo_root
        .join(".cache")
        .join("upstream-v2ray-plugin")
        .join(format!(".build-{PINNED_COMMIT}"));
    // A leftover checkout from a previous interrupted run would make `git
    // clone` fail ("destination path already exists"); clear it first.
    if build_dir.exists() {
        std::fs::remove_dir_all(&build_dir)
            .with_context(|| format!("failed to remove stale build dir {}", build_dir.display()))?;
    }

    let result = clone_build_and_install(repo_root, &build_dir, &bin_path);

    // Always clean up the checkout, success or failure — it's large (full Go
    // module tree + git history) and serves no purpose after the build.
    if build_dir.exists() {
        if let Err(e) = std::fs::remove_dir_all(&build_dir) {
            eprintln!(
                "xtask: warning: failed to remove build dir {} after build: {e}",
                build_dir.display()
            );
        }
    }

    result?;

    // Record the sha256 of the binary we built. This is the integrity anchor
    // the cache-hit path verifies against on the next run.
    let hash = sha256_file(&bin_path)?;
    std::fs::write(&sentinel, &hash).with_context(|| format!("failed to write {}", sentinel.display()))?;

    eprintln!(
        "xtask: upstream v2ray-plugin built at {} (commit {PINNED_COMMIT}, sha256 {hash})",
        bin_path.display()
    );
    Ok(bin_path)
}

/// Clone the upstream repo into `build_dir`, check out [`PINNED_COMMIT`], run
/// the Go build, and copy the resulting binary to `bin_path`.
fn clone_build_and_install(repo_root: &Path, build_dir: &Path, bin_path: &Path) -> Result<()> {
    eprintln!("xtask: cloning {UPSTREAM_REPO} (commit {PINNED_COMMIT}) for the ex-ray interop test");

    // `git clone` (full, not --depth 1): a depth-1 clone only fetches the tip
    // of the default branch, and a later `git checkout <arbitrary-sha>` would
    // fail because the commit isn't in the shallow history. A full clone is
    // simple and reliable; the checkout is removed immediately after the
    // build, so the disk cost is transient.
    run_git(repo_root, &["clone", UPSTREAM_REPO, &build_dir.to_string_lossy()])
        .context("failed to clone upstream v2ray-plugin")?;
    run_git(build_dir, &["checkout", PINNED_COMMIT])
        .with_context(|| format!("failed to check out pinned commit {PINNED_COMMIT}"))?;

    // Same Go invocation as `crate::ex_ray::build`: trimpath + stripped
    // symbols, CGO disabled, build the package in the current dir.
    let status = Command::new("go")
        .args(["build", "-trimpath", "-ldflags=-s -w", "-o"])
        .arg(bin_path)
        .arg(".")
        .current_dir(build_dir)
        .env("CGO_ENABLED", "0")
        .status();

    match status {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => bail!(
            "go build of upstream v2ray-plugin failed with exit code {}",
            s.code().unwrap_or(-1)
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(anyhow!("Go toolchain not found. Install from https://go.dev/dl/"))
        }
        Err(e) => Err(anyhow!("failed to run go build for upstream v2ray-plugin: {e}")),
    }
}

/// Run `git <args>` in `cwd`, erroring with captured stderr on failure.
fn run_git(cwd: &Path, args: &[&str]) -> Result<()> {
    let output = Command::new("git").args(args).current_dir(cwd).output().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            anyhow!("git not found on PATH (required to provision upstream v2ray-plugin)")
        } else {
            anyhow!("failed to run git {args:?}: {e}")
        }
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git {args:?} failed: {}", stderr.trim());
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    Ok(sha256_hex(&bytes))
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    let hash = sha2::Sha256::digest(data);
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

//! Download + verify the `golangci-lint` binary for the host platform.
//!
//! `golangci-lint` is the single Go quality gate for the `crates/ex-ray/` Go
//! module (it subsumes `go vet` via the `govet` linter and `gofmt`/`gofumpt`
//! via its v2 `formatters` section). The `go-fmt` / `go-lint` prek hooks in
//! `prek.toml` invoke the cached binary by absolute path, so provisioning it
//! through `cargo xtask deps` makes it available identically at pre-commit and
//! in CI (CI's `Lint` job runs `setup-build` → `cargo xtask deps` →
//! `cargo xtask run prek`). No `go install` and no PATH dependency.
//!
//! Mirrors `wintun.rs`: pin a version + per-platform archive SHA256, download
//! via `ureq`, verify, extract the binary into
//! `<repo>/.cache/golangci-lint/<version>/golangci-lint{.exe}`, and write a
//! `.verified` hash sentinel so a second `cargo xtask deps` is a no-network
//! cache hit.
//!
//! Cross-platform unlike `wintun.rs`: golangci-lint ships per-OS/arch archives
//! (`.tar.gz` for linux/darwin, `.zip` for windows). The binary lives inside a
//! top-level `golangci-lint-<version>-<os>-<arch>/` directory in every archive.

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};

/// Pinned golangci-lint version. v2 schema (single gate: `run` lints, `fmt`
/// formats). v2.12.2 was built with go1.26.x and its bundled Go analysis is
/// compatible with the `crates/ex-ray/go.mod` `go 1.25.5` directive. Bump this
/// const AND every per-platform SHA256 in [`asset_for`] together; the
/// `.verified` sentinel invalidates the cache on a version dir change.
const VERSION: &str = "2.12.2";

/// One release archive: its download URL filename and the SHA256 pinned from
/// the upstream `golangci-lint-<version>-checksums.txt`.
struct Asset {
    /// Archive filename, e.g. `golangci-lint-2.12.2-linux-amd64.tar.gz`.
    file_name: String,
    /// Lowercase-hex SHA256 of the archive.
    sha256: &'static str,
    /// Archive container kind, drives extraction.
    kind: ArchiveKind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ArchiveKind {
    TarGz,
    Zip,
}

impl Asset {
    /// `https://github.com/.../v<version>/<file_name>`.
    fn url(&self) -> String {
        format!(
            "https://github.com/golangci/golangci-lint/releases/download/v{VERSION}/{}",
            self.file_name
        )
    }

    /// Path of the `golangci-lint` binary inside the archive. Every archive
    /// nests it under a top-level `golangci-lint-<version>-<os>-<arch>/` dir
    /// (verified against the published windows-amd64 zip layout).
    fn binary_inner_path(&self, dir_stem: &str) -> String {
        format!("{dir_stem}/golangci-lint{}", binary_ext())
    }
}

/// Binary extension for the host: `.exe` on Windows, empty elsewhere.
fn binary_ext() -> &'static str {
    if cfg!(target_os = "windows") {
        ".exe"
    } else {
        ""
    }
}

/// Resolve the host OS/arch to its release [`Asset`]. Covers the full 6-way CI
/// matrix: {windows, darwin, linux} × {amd64, arm64}. Any other host is a hard
/// error — golangci-lint does not ship for it and we will not guess.
fn asset_for() -> Result<Asset> {
    // (os, arch) → (suffix, sha256, kind). `suffix` is the
    // `<os>-<arch>.<ext>` tail of the asset name.
    let (suffix, sha256, kind): (&str, &str, ArchiveKind) = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("windows", "x86_64") => (
            "windows-amd64.zip",
            "bd42e3ebc8cb4ececb86941983baaf1dc221bbb04d838e94ce63b49cc91e02bb",
            ArchiveKind::Zip,
        ),
        ("windows", "aarch64") => (
            "windows-arm64.zip",
            "947b9a5bf762d465710b376c156f0184abb2168378b0826af1899e0ee7183742",
            ArchiveKind::Zip,
        ),
        ("macos", "x86_64") => (
            "darwin-amd64.tar.gz",
            "f6f06d94b6241521c53d15450c5209b028270bf966f842afb11c030c79f5bc16",
            ArchiveKind::TarGz,
        ),
        ("macos", "aarch64") => (
            "darwin-arm64.tar.gz",
            "a9c54498731b3128f79e090be6110f3e5fffccc617b08142ed244d4126c73f29",
            ArchiveKind::TarGz,
        ),
        ("linux", "x86_64") => (
            "linux-amd64.tar.gz",
            "8df580d2670fed8fa984aac0507099af8df275e665215f5c7a2ae3943893a553",
            ArchiveKind::TarGz,
        ),
        ("linux", "aarch64") => (
            "linux-arm64.tar.gz",
            "44cd40a8c76c86755375adfeea52cfd3533cb43d7bd647771e0ae065e166df3a",
            ArchiveKind::TarGz,
        ),
        (os, arch) => bail!("no pinned golangci-lint v{VERSION} asset for host {os}/{arch}"),
    };
    Ok(Asset {
        file_name: format!("golangci-lint-{VERSION}-{suffix}"),
        sha256,
        kind,
    })
}

/// Download (if not cached) and verify golangci-lint, returning the path to the
/// extracted binary. A cache hit (binary present + sentinel matches the pinned
/// hash) returns immediately with no network access.
pub fn ensure(repo_root: &Path) -> Result<PathBuf> {
    let asset = asset_for()?;

    // Version-scoped cache dir so a VERSION bump lands in a fresh directory and
    // never collides with a stale binary.
    let cache_dir = repo_root.join(".cache").join("golangci-lint").join(VERSION);
    let bin_path = cache_dir.join(format!("golangci-lint{}", binary_ext()));
    let sentinel = cache_dir.join("golangci-lint.verified");

    std::fs::create_dir_all(&cache_dir).with_context(|| format!("failed to create {}", cache_dir.display()))?;

    // Cache check: sentinel matching the pinned hash means the on-disk binary
    // is the verified one — skip the network round-trip.
    if bin_path.exists() && sentinel.exists() {
        let stored = std::fs::read_to_string(&sentinel).unwrap_or_default();
        if stored.trim() == asset.sha256 {
            return Ok(bin_path);
        }
        // Hash mismatch — stale cache from a different version, re-download.
    }

    let url = asset.url();
    eprintln!("xtask: downloading golangci-lint v{VERSION} from {url}");
    let response = ureq::get(&url)
        .call()
        .with_context(|| format!("failed to download {url}"))?;
    // ureq's `read_to_vec` defaults to a 10 MiB cap; the golangci-lint archives
    // are ~40 MiB. 128 MiB is a generous ceiling above any plausible archive
    // size — a guard against a runaway/malicious server, not a tuning knob.
    let archive_bytes = response
        .into_body()
        .into_with_config()
        .limit(128 * 1024 * 1024)
        .read_to_vec()
        .context("failed to read golangci-lint archive response body")?;

    let actual = sha256_hex(&archive_bytes);
    if actual != asset.sha256 {
        bail!(
            "golangci-lint archive {} hash mismatch: expected {}, got {actual}",
            asset.file_name,
            asset.sha256
        );
    }

    // The binary nests under `golangci-lint-<version>-<os>-<arch>/` — the
    // archive filename minus its extension.
    let dir_stem = asset
        .file_name
        .trim_end_matches(".tar.gz")
        .trim_end_matches(".zip")
        .to_string();
    let inner = asset.binary_inner_path(&dir_stem);

    let bin_bytes = match asset.kind {
        ArchiveKind::Zip => extract_from_zip(&archive_bytes, &inner)?,
        ArchiveKind::TarGz => extract_from_tar_gz(&archive_bytes, &inner)?,
    };

    std::fs::write(&bin_path, &bin_bytes).with_context(|| format!("failed to write {}", bin_path.display()))?;
    make_executable(&bin_path)?;
    std::fs::write(&sentinel, asset.sha256).with_context(|| format!("failed to write {}", sentinel.display()))?;

    eprintln!(
        "xtask: golangci-lint v{VERSION} downloaded and verified ({} bytes)",
        bin_bytes.len()
    );
    Ok(bin_path)
}

/// Extract a single named entry from an in-memory zip archive.
fn extract_from_zip(archive_bytes: &[u8], inner: &str) -> Result<Vec<u8>> {
    let cursor = std::io::Cursor::new(archive_bytes);
    let mut archive = zip::ZipArchive::new(cursor).context("failed to open golangci-lint zip")?;
    let mut file = archive
        .by_name(inner)
        .with_context(|| format!("{inner} not found in golangci-lint zip"))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {inner} from golangci-lint zip"))?;
    Ok(bytes)
}

/// Extract a single named entry from an in-memory gzip-compressed tar archive.
fn extract_from_tar_gz(archive_bytes: &[u8], inner: &str) -> Result<Vec<u8>> {
    let decoder = flate2::read::GzDecoder::new(std::io::Cursor::new(archive_bytes));
    let mut tar = tar::Archive::new(decoder);
    for entry in tar.entries().context("failed to read golangci-lint tar entries")? {
        let mut entry = entry.context("failed to read a golangci-lint tar entry")?;
        let path = entry.path().context("non-utf8 path in golangci-lint tar")?;
        if path.to_string_lossy() == inner {
            let mut bytes = Vec::new();
            entry
                .read_to_end(&mut bytes)
                .with_context(|| format!("failed to read {inner} from golangci-lint tar"))?;
            return Ok(bytes);
        }
    }
    Err(anyhow!("{inner} not found in golangci-lint tar.gz"))
}

/// Set the owner-executable bit on Unix; no-op on Windows.
fn make_executable(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)
            .with_context(|| format!("failed to stat {}", path.display()))?
            .permissions();
        // rwxr-xr-x
        perms.set_mode(0o755);
        std::fs::set_permissions(path, perms).with_context(|| format!("failed to chmod {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    let hash = sha2::Sha256::digest(data);
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

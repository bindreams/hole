use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

pub struct EmbeddedBinary {
    pub name: &'static str,
    pub data: &'static [u8],
    pub sha256: [u8; 32],
}

pub struct VerifiedBinary {
    fs_path: PathBuf,
    exec_path: PathBuf,
    #[cfg(unix)]
    _fd: std::os::unix::io::OwnedFd,
    #[cfg(windows)]
    _handle: std::fs::File,
}

impl VerifiedBinary {
    pub fn exec_path(&self) -> &Path {
        &self.exec_path
    }

    pub fn fs_path(&self) -> &Path {
        &self.fs_path
    }
}

impl EmbeddedBinary {
    /// Extract to the platform-specific runtime directory.
    pub fn prepare(&self) -> Result<VerifiedBinary> {
        let dir = runtime_dir()?;
        self.prepare_in(&dir)
    }

    /// Extract to a specific directory (useful for testing).
    pub fn prepare_in(&self, dir: &Path) -> Result<VerifiedBinary> {
        fs::create_dir_all(dir).with_context(|| format!("failed to create directory {}", dir.display()))?;

        #[cfg(unix)]
        set_dir_permissions(dir)?;

        let target = dir.join(self.name);

        // Warm start: try to verify the existing file first.
        if target.exists() {
            match self.try_verify(&target) {
                Ok(verified) => return Ok(verified),
                Err(_) => {
                    // Hash mismatch or other error — re-extract.
                }
            }
        }

        // Cold start (or re-extract after mismatch): extract and verify.
        self.extract(&target)
            .with_context(|| format!("failed to extract {}", self.name))?;
        self.try_verify(&target)
            .with_context(|| format!("verification failed after extraction of {}", self.name))
    }

    /// Verify embedded hash, write via tempfile, set permissions, atomic rename.
    fn extract(&self, target: &Path) -> Result<()> {
        // Verify that our embedded data matches the expected hash.
        let actual_hash = sha256_bytes(self.data);
        if actual_hash != self.sha256 {
            bail!(
                "embedded data hash mismatch for {}: expected {}, got {}",
                self.name,
                hex(&self.sha256),
                hex(&actual_hash),
            );
        }

        let parent = target.parent().context("target path has no parent directory")?;

        // Write to a temporary file in the same directory (for atomic rename).
        let mut tmp = tempfile::NamedTempFile::new_in(parent).context("failed to create temporary file")?;
        tmp.write_all(self.data).context("failed to write embedded data")?;
        tmp.flush().context("failed to flush temporary file")?;

        #[cfg(unix)]
        set_file_permissions(tmp.path())?;

        // Atomic rename into place.
        tmp.persist(target)
            .context("failed to atomically rename temporary file")?;

        Ok(())
    }

    /// Read the file at `path`, check its SHA256, and open with deny-write.
    fn try_verify(&self, path: &Path) -> Result<VerifiedBinary> {
        let content = fs::read(path).context("failed to read file for verification")?;
        let actual_hash = sha256_bytes(&content);
        if actual_hash != self.sha256 {
            bail!(
                "hash mismatch for {}: expected {}, got {}",
                self.name,
                hex(&self.sha256),
                hex(&actual_hash),
            );
        }

        open_verified(path)
    }
}

// Helpers =====

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// Platform: runtime_dir =====

#[cfg(target_os = "linux")]
fn runtime_dir() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
        Ok(PathBuf::from(dir).join("galoshes"))
    } else {
        Ok(std::env::temp_dir().join("galoshes"))
    }
}

#[cfg(target_os = "macos")]
fn runtime_dir() -> Result<PathBuf> {
    if let Ok(home) = std::env::var("HOME") {
        Ok(PathBuf::from(home).join("Library").join("Caches").join("galoshes"))
    } else {
        Ok(std::env::temp_dir().join("galoshes"))
    }
}

#[cfg(target_os = "windows")]
fn runtime_dir() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("LOCALAPPDATA") {
        Ok(PathBuf::from(dir).join("galoshes"))
    } else {
        Ok(std::env::temp_dir().join("galoshes"))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn runtime_dir() -> Result<PathBuf> {
    Ok(std::env::temp_dir().join("galoshes"))
}

// Platform: permissions =====

#[cfg(unix)]
fn set_dir_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("failed to set permissions on {}", path.display()))
}

#[cfg(unix)]
fn set_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o500))
        .with_context(|| format!("failed to set permissions on {}", path.display()))
}

// Platform: open_verified =====

#[cfg(unix)]
fn open_verified(path: &Path) -> Result<VerifiedBinary> {
    use std::os::unix::io::{AsRawFd, OwnedFd};

    let file = fs::File::open(path).context("failed to open file for verification")?;
    let raw_fd = file.as_raw_fd();
    let fd: OwnedFd = file.into();

    // Use /proc/self/fd/N on Linux, /dev/fd/N on macOS.
    let exec_path = if cfg!(target_os = "linux") {
        PathBuf::from(format!("/proc/self/fd/{raw_fd}"))
    } else {
        PathBuf::from(format!("/dev/fd/{raw_fd}"))
    };

    Ok(VerifiedBinary {
        fs_path: path.to_path_buf(),
        exec_path,
        _fd: fd,
    })
}

#[cfg(windows)]
fn open_verified(path: &Path) -> Result<VerifiedBinary> {
    use std::os::windows::fs::OpenOptionsExt;

    // FILE_SHARE_READ = 1 (deny write + delete)
    let handle = fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(path)
        .context("failed to open file with deny-write sharing")?;

    let fs_path = path.to_path_buf();
    let exec_path = fs_path.clone();

    Ok(VerifiedBinary {
        fs_path,
        exec_path,
        _handle: handle,
    })
}

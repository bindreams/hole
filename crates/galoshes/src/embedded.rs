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

        check_dir_executable(dir)?;

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
        match self.extract(&target) {
            Ok(()) => {}
            Err(extract_err) => {
                // Another process may have completed extraction concurrently.
                // All concurrent galoshes instances embed identical binary data
                // (same compile), so a file written by another process is valid.
                // Retry warm start before giving up.
                if let Ok(verified) = self.try_verify(&target) {
                    return Ok(verified);
                }
                return Err(extract_err.context(format!("failed to extract {}", self.name)));
            }
        }
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

// Helpers =============================================================================================================

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// Platform: runtime_dir ===============================================================================================

pub fn runtime_dir() -> Result<PathBuf> {
    let xdg = std::env::var("XDG_RUNTIME_DIR").ok();
    let default_root = platform_default_env().ok();
    resolve(xdg.as_deref(), default_root.as_deref())
}

#[cfg(unix)]
fn platform_default_env() -> Result<String, std::env::VarError> {
    std::env::var("HOME")
}

#[cfg(target_os = "windows")]
fn platform_default_env() -> Result<String, std::env::VarError> {
    std::env::var("LOCALAPPDATA")
}

#[cfg(target_os = "linux")]
pub(crate) fn resolve(xdg: Option<&str>, default_root: Option<&str>) -> Result<PathBuf> {
    if let Some(dir) = xdg {
        return Ok(PathBuf::from(dir).join("galoshes"));
    }
    if let Some(home) = default_root {
        return Ok(PathBuf::from(home).join(".cache").join("galoshes"));
    }
    bail!(
        "cannot resolve galoshes runtime directory: neither XDG_RUNTIME_DIR nor HOME is set. \
         Set XDG_RUNTIME_DIR to a directory on an exec-capable mount."
    );
}

#[cfg(target_os = "macos")]
pub(crate) fn resolve(xdg: Option<&str>, default_root: Option<&str>) -> Result<PathBuf> {
    if let Some(dir) = xdg {
        return Ok(PathBuf::from(dir).join("galoshes"));
    }
    if let Some(home) = default_root {
        return Ok(PathBuf::from(home).join("Library").join("Caches").join("galoshes"));
    }
    bail!(
        "cannot resolve galoshes runtime directory: neither XDG_RUNTIME_DIR nor HOME is set. \
         Set XDG_RUNTIME_DIR to a directory on an exec-capable mount."
    );
}

#[cfg(target_os = "windows")]
pub(crate) fn resolve(xdg: Option<&str>, default_root: Option<&str>) -> Result<PathBuf> {
    if let Some(dir) = xdg {
        return Ok(PathBuf::from(dir).join("galoshes"));
    }
    if let Some(local) = default_root {
        return Ok(PathBuf::from(local).join("galoshes"));
    }
    bail!(
        "cannot resolve galoshes runtime directory: neither XDG_RUNTIME_DIR nor LOCALAPPDATA is set. \
         Set XDG_RUNTIME_DIR to a directory on an exec-capable mount."
    );
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(crate) fn resolve(xdg: Option<&str>, _default_root: Option<&str>) -> Result<PathBuf> {
    if let Some(dir) = xdg {
        return Ok(PathBuf::from(dir).join("galoshes"));
    }
    bail!("cannot resolve galoshes runtime directory: XDG_RUNTIME_DIR is not set");
}

// Platform: permissions ===============================================================================================

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

// Platform: check_dir_executable ======================================================================================

fn check_dir_executable(dir: &Path) -> Result<()> {
    if is_noexec_mount(dir)? {
        bail!(
            "runtime directory {} is mounted noexec; galoshes cannot exec the embedded \
             ex-ray plugin from this location. Set XDG_RUNTIME_DIR to a directory on an \
             exec-capable mount, or remount this filesystem with the exec option.",
            dir.display(),
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn is_noexec_mount(dir: &Path) -> Result<bool> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(dir.as_os_str().as_bytes())
        .with_context(|| format!("path {} contains a NUL byte", dir.display()))?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        return Err(anyhow::Error::from(err)).with_context(|| format!("statvfs({}) failed", dir.display()));
    }
    Ok(check_noexec_linux(stat.f_flag))
}

#[cfg(target_os = "linux")]
pub(crate) fn check_noexec_linux(flag: libc::c_ulong) -> bool {
    flag & libc::ST_NOEXEC == libc::ST_NOEXEC
}

#[cfg(target_os = "macos")]
fn is_noexec_mount(dir: &Path) -> Result<bool> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(dir.as_os_str().as_bytes())
        .with_context(|| format!("path {} contains a NUL byte", dir.display()))?;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statfs(c_path.as_ptr(), &mut stat) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        return Err(anyhow::Error::from(err)).with_context(|| format!("statfs({}) failed", dir.display()));
    }
    Ok(check_noexec_macos(stat.f_flags))
}

#[cfg(target_os = "macos")]
pub(crate) fn check_noexec_macos(flags: u32) -> bool {
    let mask = libc::MNT_NOEXEC as u32;
    flags & mask == mask
}

// Windows has no noexec filesystem flag. Read-only attributes, AppLocker, and
// Defender quarantine fail at runtime — those paths surface through anyhow
// context on the existing fs / persist / spawn calls. Other Unixes (FreeBSD,
// OpenBSD, …) fall through to the same noop; their MNT_NOEXEC semantics differ
// per kernel and galoshes is not currently shipped there.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn is_noexec_mount(_dir: &Path) -> Result<bool> {
    Ok(false)
}

// Platform: open_verified =============================================================================================

#[cfg(unix)]
fn open_verified(path: &Path) -> Result<VerifiedBinary> {
    use std::os::unix::io::{AsRawFd, OwnedFd};

    let file = fs::File::open(path).context("failed to open file for verification")?;
    let raw_fd = file.as_raw_fd();
    let fd: OwnedFd = file.into();

    // Linux: /proc/self/fd/N is a kernel-resolved symlink — works even after
    // CLOEXEC closes the fd in the child process.
    // Non-Linux Unix (macOS, FreeBSD, etc.): /dev/fd/N is a device node that
    // requires the fd to be live in the process's fd table. Rust's Command
    // sets CLOEXEC on all fds, so the fd is closed before execve and
    // /dev/fd/N becomes invalid. Fall back to the filesystem path.
    let exec_path = if cfg!(target_os = "linux") {
        PathBuf::from(format!("/proc/self/fd/{raw_fd}"))
    } else {
        path.to_path_buf()
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

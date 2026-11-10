use std::ffi::OsStr;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use util::dir::{Dir, EntryKind, OpenFile, Refusal};
use util::retry::is_file_contention;

mod sealed_dir;
#[cfg(unix)]
pub use sealed_dir::check as check_sealed_dir;
use sealed_dir::SealedDir;
pub use sealed_dir::SealedDirRefusal;

pub struct EmbeddedBinary {
    pub name: &'static str,
    pub data: &'static [u8],
    pub sha256: [u8; 32],
}

/// An extracted binary whose bytes were hashed through `_file`, which stays open for as long as this does.
///
/// Linux execs `_file` itself, so what runs is what was hashed. Windows execs the file's real path, which the handle
/// pins by denying write, delete and rename of the file and of the folders above it. Elsewhere the name is exec'd, and
/// [`sealed_dir`] is what keeps anyone else from swapping it.
pub struct VerifiedBinary {
    fs_path: PathBuf,
    exec_path: PathBuf,
    _file: fs::File,
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
    ///
    /// Instances starting together take turns through a lock file beside the binary, held until this returns, so none
    /// meets a file another has just published and still holds open for writing (Windows: the pin fails; Linux:
    /// `execve` fails with `ETXTBSY`). The lock is taken through the directory handle already held. Anyone who can
    /// write the directory can make a start wait (the wait ends with their process); none can change what runs.
    pub fn prepare_in(&self, dir: &Path) -> Result<VerifiedBinary> {
        let dir = sealed_dir::prepare(dir)?;

        check_dir_executable(&dir)?;

        let _turn = file_lock::Exclusive::acquire_in(dir.dir(), OsStr::new(&format!("{}.lock", self.name)), None)
            .context("failed to lock the runtime directory")?;

        // Warm start: try to verify the existing file first. A missing file, a mismatch, or anything that is not a
        // file we may use means re-extract; a failure of the OS is returned.
        if let VerifyOutcome::Verified(verified) = self.try_verify(&dir)? {
            return Ok(verified);
        }

        // Cold start (or re-extract after mismatch): extract and verify.
        self.extract(dir.dir())
            .with_context(|| format!("failed to extract {}", self.name))?;
        match self
            .try_verify(&dir)
            .with_context(|| format!("verification failed after extraction of {}", self.name))?
        {
            VerifyOutcome::Verified(verified) => Ok(verified),
            VerifyOutcome::Stale(why) => {
                Err(why.context(format!("{} is not usable right after extraction", self.name)))
            }
        }
    }

    /// Verify the embedded hash, then stage the bytes in `dir` and rename them into place.
    fn extract(&self, dir: &Dir) -> Result<()> {
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

        dir.stage(OsStr::new(self.name), self.data, None, make_executable)
            .context("failed to stage the embedded binary")?
            .publish()
            .context("failed to atomically rename the staged binary")
    }

    /// Open the binary in `dir`, check the SHA256 of what the handle reads, and keep the handle: the bytes hashed are
    /// the inode that is held, whatever the name is made to mean afterwards. A file that is missing, not one we may
    /// use, or not these bytes is [`VerifyOutcome::Stale`]; a failure of the OS is the error.
    fn try_verify(&self, dir: &SealedDir) -> Result<VerifyOutcome> {
        let name = OsStr::new(self.name);
        let mut file = match dir.dir().open_file(name, OpenFile::ReadPinned) {
            Ok(file) => file,
            Err(err) if names_no_file_to_use(dir.dir(), name, &err) => {
                return Ok(VerifyOutcome::Stale(
                    anyhow::Error::from(err).context("failed to open file for verification"),
                ));
            }
            Err(err) => return Err(anyhow::Error::from(err).context("failed to open file for verification")),
        };
        let path = dir.path().join(self.name);
        // Windows has nothing to check: the pin is the guarantee. It fails while anything can still write the file, a
        // writable mapped view of it included, so no one holds a way to change what runs.
        #[cfg(unix)]
        if let Runnability::Refused(why) = check_runnable(&file, &path)? {
            return Ok(VerifyOutcome::Stale(anyhow::anyhow!(why)));
        }
        let actual_hash = sha256_reader(&mut file).context("failed to read file for verification")?;
        if actual_hash != self.sha256 {
            return Ok(VerifyOutcome::Stale(anyhow::anyhow!(
                "hash mismatch for {}: expected {}, got {}",
                self.name,
                hex(&self.sha256),
                hex(&actual_hash),
            )));
        }

        VerifiedBinary::new(path, file).map(VerifyOutcome::Verified)
    }
}

/// Whether the open of the binary's name failed because there is nothing there this process can use: no file, a link,
/// something that is not a regular file, or a file some other process holds (Windows: open for writing, which the replace of the
/// name then waits out if the holder shares delete and fails with its cause if not). Anything else is the OS failing.
fn names_no_file_to_use(dir: &Dir, name: &OsStr, err: &std::io::Error) -> bool {
    // What a link at the name looks like differs by OS (`ELOOP`, `EMLINK`, `EFTYPE`; Windows a `Refusal`), so the name is
    // asked what it is rather than the error.
    let link = || matches!(dir.kind_of(name), Ok(Some(EntryKind::Symlink)));
    err.kind() == std::io::ErrorKind::NotFound
        || is_file_contention(err)
        || Refusal::from_error(err).is_some()
        || link()
}

/// What [`EmbeddedBinary::try_verify`] found in the runtime directory.
enum VerifyOutcome {
    Verified(VerifiedBinary),
    /// Not a file to run, and the reason: extract again.
    Stale(anyhow::Error),
}

/// Whether a file in the runtime directory is one galoshes may run.
#[cfg(unix)]
enum Runnability {
    Runnable,
    Refused(String),
}

// Helpers =============================================================================================================

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn sha256_reader(reader: &mut impl Read) -> std::io::Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => return Ok(hasher.finalize().into()),
            Ok(n) => hasher.update(&buf[..n]),
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Sweeps the crash markers an earlier run left in `dir`, then attaches the crash handler, which writes this run's
/// marker there. Best-effort: a folder that cannot be used here fails the extraction, which meets it next.
///
/// The folder is made by the extraction's own `sealed_dir::prepare` first, so it is the extraction's own (`0o700`) and not one the crash
/// handler would make with the umask's mode, which the macOS seal refuses on every start.
pub fn attach_crash_handler(dir: &Path) {
    if sealed_dir::prepare(dir).is_err() {
        return;
    }
    tombstone::sweep(dir);
    tombstone::attach("galoshes", dir);
}

// Platform: runtime_dir ===============================================================================================

#[cfg(not(any(unix, windows)))]
compile_error!("galoshes has no runtime directory for this target: it supports unix and Windows only");

/// The directory is one per principal: a run as root under `sudo -E` or an elevation prompt inherits the invoking
/// user's `XDG_RUNTIME_DIR`, and must never share a path with, or leave anything in, the user's.
pub fn runtime_dir() -> Result<PathBuf> {
    let xdg = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
    #[cfg(unix)]
    {
        let euid = euid();
        resolve(
            xdg.as_deref(),
            || default_home(euid, std::env::var_os("HOME").map(PathBuf::from)),
            euid,
        )
    }
    #[cfg(windows)]
    resolve(
        xdg.as_deref(),
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from).as_deref(),
    )
}

/// The effective uid of this process.
#[cfg(unix)]
fn euid() -> u32 {
    // SAFETY: geteuid takes no arguments and cannot fail.
    unsafe { libc::geteuid() }
}

/// The home of the account `uid`; `$HOME` is whoever launched the process (`sudo` and an administrator-privileges
/// prompt both leave it at the invoking user's home). `None` for a uid with no account.
#[cfg(unix)]
pub(crate) fn account_home(uid: u32) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt;

    let mut buf = vec![0u8; 1024];
    loop {
        // SAFETY: an all-zero `passwd` is a valid out-parameter for getpwuid_r.
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: `pwd`, `buf` and `result` outlive the call.
        let rc = unsafe {
            libc::getpwuid_r(
                uid,
                &mut pwd,
                buf.as_mut_ptr().cast::<libc::c_char>(),
                buf.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if rc != 0 || result.is_null() || pwd.pw_dir.is_null() {
            return None;
        }
        // SAFETY: `pw_dir` is a valid C string for a non-null result, and `buf` is alive.
        let dir = unsafe { std::ffi::CStr::from_ptr(pwd.pw_dir) };
        return Some(PathBuf::from(std::ffi::OsStr::from_bytes(dir.to_bytes())));
    }
}

/// The home to put the default root under: the account's own, and `$HOME` only for a uid with no account (a container
/// run with `--user <n>`), where it is the only home there is.
#[cfg(unix)]
pub(crate) fn default_home(uid: u32, env_home: Option<PathBuf>) -> Option<PathBuf> {
    account_home(uid).or(env_home)
}

#[cfg(target_os = "macos")]
const DEFAULT_ROOT_BELOW_HOME: &str = "Library/Caches";
#[cfg(all(unix, not(target_os = "macos")))]
const DEFAULT_ROOT_BELOW_HOME: &str = ".cache";

#[cfg(unix)]
pub(crate) fn resolve(xdg: Option<&Path>, home: impl FnOnce() -> Option<PathBuf>, euid: u32) -> Result<PathBuf> {
    let name = format!("galoshes-{euid}");
    if let Some(dir) = xdg {
        return Ok(dir.join(name));
    }
    if let Some(home) = home() {
        return Ok(home.join(DEFAULT_ROOT_BELOW_HOME).join(name));
    }
    bail!(
        "cannot resolve galoshes runtime directory: XDG_RUNTIME_DIR is not set, the running user has no account home directory and HOME is not set. \
         Set XDG_RUNTIME_DIR to a directory on an exec-capable mount."
    );
}

#[cfg(windows)]
pub(crate) fn resolve(xdg: Option<&Path>, local_app_data: Option<&Path>) -> Result<PathBuf> {
    if let Some(dir) = xdg {
        return Ok(dir.join("galoshes"));
    }
    if let Some(local) = local_app_data {
        return Ok(local.join("galoshes"));
    }
    bail!(
        "cannot resolve galoshes runtime directory: neither XDG_RUNTIME_DIR nor LOCALAPPDATA is set. \
         Set XDG_RUNTIME_DIR to a directory on an exec-capable mount."
    );
}

// Platform: permissions ===============================================================================================

/// Gives the staged file the mode the binary is run with: the owner may read and execute it, and no one can write it.
#[cfg(unix)]
fn make_executable(file: &fs::File) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o500))
}

/// No ACL: [`OpenFile::ReadPinned`] fails while anything can still write the file, so what is pinned cannot change.
#[cfg(windows)]
fn make_executable(_file: &fs::File) -> std::io::Result<()> {
    Ok(())
}

// Platform: check_dir_executable ======================================================================================

fn check_dir_executable(dir: &SealedDir) -> Result<()> {
    if is_noexec_mount(dir.dir())? {
        bail!(
            "runtime directory {} is mounted noexec; galoshes cannot exec the embedded \
             ex-ray plugin from this location. Set XDG_RUNTIME_DIR to a directory on an \
             exec-capable mount, or remount this filesystem with the exec option.",
            dir.path().display(),
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn is_noexec_mount(dir: &Dir) -> Result<bool> {
    use std::os::unix::io::AsRawFd;
    // SAFETY: an all-zero `statvfs` is a valid out-parameter.
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: the descriptor is open and `stat` outlives the call.
    let rc = unsafe { libc::fstatvfs(dir.file().as_raw_fd(), &mut stat) };
    if rc != 0 {
        return Err(anyhow::Error::from(std::io::Error::last_os_error()))
            .context("fstatvfs of the runtime directory failed");
    }
    Ok(check_noexec_linux(stat.f_flag))
}

#[cfg(target_os = "linux")]
pub(crate) fn check_noexec_linux(flag: libc::c_ulong) -> bool {
    flag & libc::ST_NOEXEC == libc::ST_NOEXEC
}

#[cfg(target_os = "macos")]
fn is_noexec_mount(dir: &Dir) -> Result<bool> {
    use std::os::unix::io::AsRawFd;
    // SAFETY: an all-zero `statfs` is a valid out-parameter.
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: the descriptor is open and `stat` outlives the call.
    let rc = unsafe { libc::fstatfs(dir.file().as_raw_fd(), &mut stat) };
    if rc != 0 {
        return Err(anyhow::Error::from(std::io::Error::last_os_error()))
            .context("fstatfs of the runtime directory failed");
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
fn is_noexec_mount(_dir: &Dir) -> Result<bool> {
    Ok(false)
}

// Platform: the file that is run ======================================================================================

impl VerifiedBinary {
    fn new(path: PathBuf, file: fs::File) -> Result<Self> {
        Ok(Self {
            exec_path: exec_path_of(&path, &file)?,
            fs_path: path,
            _file: file,
        })
    }
}

/// Refuses a file that is not one galoshes may run: one whose bytes another principal can still change (such a writer
/// can alter what the held handle runs after the hash), or one that cannot be executed (a warm start that took it
/// would fail to spawn on every start after). The caller replaces it. The handle is an [`OpenFile::ReadPinned`] one,
/// so it is already a regular file the name did not lead through a link to.
#[cfg(unix)]
fn check_runnable(file: &fs::File, path: &Path) -> Result<Runnability> {
    use std::os::unix::fs::MetadataExt;

    let meta = file.metadata().context("failed to stat the opened file")?;
    let euid = euid();
    if meta.uid() != euid || meta.mode() & 0o022 != 0 || meta.mode() & 0o100 == 0 {
        return Ok(Runnability::Refused(format!(
            "{} is owned by uid {} with mode {:o}; refusing a file others can write or the owner cannot execute",
            path.display(),
            meta.uid(),
            meta.mode() & 0o7777,
        )));
    }
    Ok(Runnability::Runnable)
}

/// Linux execs the descriptor itself: `/proc/self/fd/N` is a kernel-resolved symlink to the held inode, so it works
/// even after CLOEXEC closes the fd in the child. Elsewhere on unix `/dev/fd/N` needs the fd live in the child, which
/// `Command`'s CLOEXEC prevents, so the name is exec'd and the directory holding it is what is trusted
/// ([`sealed_dir::EXEC_BY_PATH`]).
#[cfg(unix)]
fn exec_path_of(path: &Path, file: &fs::File) -> Result<PathBuf> {
    use std::os::unix::io::AsRawFd;

    if sealed_dir::EXEC_BY_PATH {
        Ok(path.to_path_buf())
    } else {
        Ok(PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd())))
    }
}

/// The file's real path, read off the pinned handle: the handle denies write, delete and rename of the file and of
/// every folder above it, so the path cannot come to mean another file while the handle is held. The name it was
/// opened by may have gone through a junction or a link, which is not pinned. A volume with no drive letter has no
/// such path and is an error.
#[cfg(windows)]
fn exec_path_of(_path: &Path, file: &fs::File) -> Result<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{
        GetFinalPathNameByHandleW, FILE_NAME_NORMALIZED, GETFINALPATHNAMEBYHANDLE_FLAGS, VOLUME_NAME_DOS,
    };

    let handle = HANDLE(file.as_raw_handle());
    let mut buf = vec![0u16; 1024];
    loop {
        // SAFETY: `handle` is open for as long as `file` is, and `buf` is a writable slice.
        let len = unsafe {
            GetFinalPathNameByHandleW(
                handle,
                &mut buf,
                GETFINALPATHNAMEBYHANDLE_FLAGS(FILE_NAME_NORMALIZED.0 | VOLUME_NAME_DOS.0),
            )
        } as usize;
        if len == 0 {
            return Err(anyhow::Error::from(std::io::Error::last_os_error()))
                .context("failed to read the real path of the verified binary");
        }
        // A result that does not fit says how many units it needs, terminator included.
        if len > buf.len() {
            buf.resize(len, 0);
            continue;
        }
        return Ok(PathBuf::from(std::ffi::OsString::from_wide(&buf[..len])));
    }
}

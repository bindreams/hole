//! The escape from a fail-closed cover a test engaged on the real host.

use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use crate::routing::failclosed::release_all;

/// What one test's recovery record is called and what it says may be engaged.
/// A file name per test so two lanes never overwrite each other's evidence.
pub struct RecordSpec {
    pub file_name: &'static str,
    pub what: &'static str,
}

/// The command that clears a stranded cover by hand.
pub fn recovery_command() -> &'static str {
    if cfg!(target_os = "macos") {
        // NEVER `hole bridge unlock` here: that resolves the fixed production
        // `service_state_dir()`, not a test's tempdir, and would report
        // success while the real cover (engaged into OUR state dir) stays live.
        "sudo pfctl -f /etc/pf.conf"
    } else {
        // Windows recovers its WFP filters by fixed GUID and reads no state
        // directory, so the production escape clears a test's cover too.
        "hole bridge unlock"
    }
}

fn open_controlling_terminal() -> io::Result<std::fs::File> {
    let path = if cfg!(target_os = "windows") {
        "CONOUT$"
    } else {
        "/dev/tty"
    };
    std::fs::OpenOptions::new().write(true).open(path)
}

/// Put `message` where a developer will actually see it: stderr AND the
/// controlling terminal (best-effort — no terminal in CI is not an error).
/// nextest renders its captured stderr only when the test completes, so a run
/// killed mid-flight shows the terminal write and nothing else.
pub fn announce(message: &str) {
    eprintln!("{message}");
    if let Ok(mut tty) = open_controlling_terminal() {
        let _ = writeln!(tty, "{message}");
    }
}

/// Write the escape record BEFORE the first engage — never from a `Drop`,
/// which is absent on any path that skips destructors (SIGINT, a double-panic
/// abort). The file is fixed and predictable so it can be named in advance;
/// [`announce`] puts the same text in front of an interactive developer.
pub fn write_recovery_record(spec: &RecordSpec, state_dir: &Path) -> io::Result<PathBuf> {
    let path = std::env::temp_dir().join(spec.file_name);
    let text = format!(
        "{}: a real system-wide fail-closed cover may be engaged.\n\
         State directory: {}\n\
         If this file still exists and the test process is gone, the host may be stranded\n\
         fail-closed. Recover with:\n\
         \n    {}\n\n",
        spec.what,
        state_dir.display(),
        recovery_command(),
    );
    std::fs::write(&path, &text)?;
    announce(&text);
    Ok(path)
}

/// The state directory a cover was engaged into, and whether this guard is
/// the one that made it.
enum StateDir {
    /// Made here, and kept (not deleted) if the release fails. `None` only
    /// after [`EscapeGuard::drop`] has taken it to keep it.
    Owned(Option<tempfile::TempDir>),
    /// Made by the caller — a spawned bridge's state directory — which must
    /// outlive this guard.
    Borrowed(PathBuf),
}

/// Unconditional escape from a cover a test engaged: `release_all` over the
/// test's OWN state directory, from a `Drop` that runs on every unwind.
///
/// Owning the directory is load-bearing when this guard made it (macOS reads
/// it to decide what to clear, and an ABSENT state file reads as a clean
/// host): owning the `TempDir` itself, not just its path, guarantees
/// `release_all` never runs against a directory some other cleanup already
/// deleted, which would silently report success over a live cover.
pub struct EscapeGuard {
    dir: StateDir,
    record_path: PathBuf,
    what: &'static str,
}

impl EscapeGuard {
    /// A guard over a fresh state directory of its own, with the record
    /// written before it returns — so nothing can be engaged before the
    /// escape exists.
    ///
    /// One directory for the whole test, reused by every engage. A fresh one
    /// per engage would let a silently-failed teardown (macOS
    /// `engage_pf_action`'s `FreshEnable` snapshots whatever is LIVE when it
    /// sees no persisted state) capture a PRIOR cover's block-everything
    /// ruleset as "the host", and every later restore — including this
    /// guard's — would then reload block-everything as the host.
    pub fn with_temp_dir(spec: &RecordSpec) -> Self {
        let dir = tempfile::tempdir().expect("HARNESS: create state tempdir");
        let record_path = write_recovery_record(spec, dir.path()).expect("HARNESS: write recovery record");
        Self {
            dir: StateDir::Owned(Some(dir)),
            record_path,
            what: spec.what,
        }
    }

    /// A guard over a state directory the caller owns (a spawned bridge's),
    /// with the record written before it returns. The caller's directory must
    /// outlive the guard: releasing over an already-deleted directory would
    /// read a clean host over a possibly-live cover.
    pub fn over(spec: &RecordSpec, dir: &Path) -> Self {
        let record_path = write_recovery_record(spec, dir).expect("HARNESS: write recovery record");
        Self {
            dir: StateDir::Borrowed(dir.to_path_buf()),
            record_path,
            what: spec.what,
        }
    }

    /// The directory to engage covers into.
    pub fn state_dir(&self) -> &Path {
        match &self.dir {
            StateDir::Owned(d) => d.as_ref().expect("state dir kept only in Drop").path(),
            StateDir::Borrowed(p) => p,
        }
    }
}

impl Drop for EscapeGuard {
    fn drop(&mut self) {
        // Must not panic: this may run during an unwind.
        let dir = self.state_dir().to_path_buf();
        let Err(e) = release_all(&dir) else {
            if let Err(e) = std::fs::remove_file(&self.record_path) {
                eprintln!("HARNESS: failed to remove recovery record {:?}: {e}", self.record_path);
            }
            return;
        };

        // The release failed, so the host may still be covered — which is the
        // one situation the record exists for. KEEP it, and keep the state
        // directory it names with it: a retried release needs that directory,
        // and deleting the evidence of a lockout while announcing the lockout
        // leaves the user nothing to act on.
        let state = match &mut self.dir {
            StateDir::Owned(d) => d
                .take()
                .map(tempfile::TempDir::keep)
                .map(|p| format!("{p:?} (kept, not deleted)")),
            StateDir::Borrowed(_) => None,
        }
        .unwrap_or_else(|| format!("{dir:?} (the caller's)"));
        announce(&format!(
            "HARNESS: {} — release_all FAILED: {e}. The host may still be fail-closed. Recovery record kept at \
             {:?}; state directory {state}. Clear the cover with `{}`.",
            self.what,
            self.record_path,
            recovery_command(),
        ));
    }
}

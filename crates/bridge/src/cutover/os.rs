//! Cutover effects seam, mirroring the GUI's self-heal OS seam: the OS-mutating
//! steps go through a trait so the recording stub asserts the exact per-OS
//! sequence. Real FFI (rename/SCM/launchctl/renamex_np) lives in the
//! `os::{windows, macos}` impls behind the bindreams/hole#165 isolation
//! contract.

#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "windows")]
pub mod windows;

/// The OS steps a cutover performs. Each method may block. The cover is owned
/// by the bridge process (standing guard); this trait deliberately exposes NO
/// cover-mutating method, so a cutover structurally cannot engage or disengage
/// it — cover persistence is handled by the bridge's marker-conditional
/// shutdown disarm (`stop_with`).
pub trait CutoverOs {
    /// Swap the bare binaries into place by rename (running images keep their
    /// old inode; the canonical path flips, which `same_file::Handle` identity
    /// and the GUI self-heal depend on).
    fn swap_images(&mut self) -> std::io::Result<()>;
    /// Stop the bridge service and wait until it is really stopped (Windows:
    /// `ControlService(STOP)` + `NotifyServiceStatusChange(STOPPED)`; macOS:
    /// `launchctl kill SIGTERM` + kqueue `NOTE_EXIT`).
    fn stop_service_wait_stopped(&mut self) -> std::io::Result<()>;
    /// Start the bridge service and wait until it is really running (Windows:
    /// `StartService` + `NotifyServiceStatusChange(RUNNING)`; macOS: `launchctl
    /// start`).
    fn start_service_wait_running(&mut self) -> std::io::Result<()>;
}

/// Drive the cutover sequence. Ordering is OS-asymmetric:
/// - Windows: stop -> swap (while no bridge runs) -> start. Stopping first
///   bounds the gap and lets the new bridge boot from the new image
///   deterministically.
/// - macOS: swap both images FIRST, then SIGTERM-stop (graceful `pm.stop()`
///   runs, so the marker-conditional disarm fires) + wait-exit, then start.
///   launchd re-execs the (now swapped) plist path on start.
pub fn run_cutover<O: CutoverOs>(os: &mut O) -> std::io::Result<()> {
    #[cfg(target_os = "windows")]
    {
        os.stop_service_wait_stopped()?;
        os.swap_images()?;
        os.start_service_wait_running()?;
    }
    #[cfg(target_os = "macos")]
    {
        os.swap_images()?;
        os.stop_service_wait_stopped()?;
        os.start_service_wait_running()?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "os_tests.rs"]
mod os_tests;

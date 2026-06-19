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
///
/// The trait is OS-asymmetric: Windows drives an external SCM stop/swap/start
/// from a detached child (a service cannot restart itself), so it needs both
/// `stop_service_wait_stopped` and `start_service_wait_running`. macOS runs the
/// actor INLINE in the bridge, so the stop step SIGTERMs its own process and the
/// restart is launchd's `KeepAlive` respawn — the start method is never called.
pub trait CutoverOs {
    /// Swap the bare binaries into place by rename (running images keep their
    /// old inode; the canonical path flips, which `same_file::Handle` identity
    /// and the GUI self-heal depend on).
    fn swap_images(&mut self) -> std::io::Result<()>;
    /// Trigger the bridge to stop after the swap. On Windows the detached child
    /// runs `ControlService(STOP)` + `NotifyServiceStatusChange(STOPPED)` and
    /// waits for a real STOPPED. On macOS this `launchctl kill SIGTERM`s its own
    /// process — a graceful shutdown that rides `pm.stop()` so the
    /// marker-conditional disarm fires; it does not wait (a self-wait is
    /// unreachable) and `KeepAlive` respawns the new binary.
    fn stop_service_wait_stopped(&mut self) -> std::io::Result<()>;
    /// Start the bridge service and wait until it is really running
    /// (`StartService` + `NotifyServiceStatusChange(RUNNING)`). WINDOWS ONLY —
    /// macOS restart is `KeepAlive`-driven and never calls this.
    #[cfg(target_os = "windows")]
    fn start_service_wait_running(&mut self) -> std::io::Result<()>;
}

/// Drive the cutover sequence. Ordering is OS-asymmetric:
/// - Windows: stop -> swap (while no bridge runs) -> start. Stopping first
///   bounds the gap and lets the new bridge boot from the new image
///   deterministically. The detached child outlives the stopped service.
/// - macOS: swap both images FIRST, then trigger the bridge's own graceful
///   shutdown (SIGTERM rides `pm.stop()`, so the marker-conditional disarm
///   fires). It returns there: the inline actor SIGTERMs its own process, so a
///   self-wait + explicit start would be unreachable. launchd's `KeepAlive=true`
///   respawns the now-swapped binary (swap precedes shutdown), and the standing
///   pf cover + Adopt hold the gap.
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
    }
    Ok(())
}

#[cfg(test)]
#[path = "os_tests.rs"]
mod os_tests;

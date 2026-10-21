//! Cutover effects seam, mirroring the GUI's self-heal OS seam: the OS-mutating
//! steps go through a trait so the recording stub asserts the exact per-OS
//! sequence. Real FFI (rename/SCM/launchctl/renamex_np) lives in the
//! `os::{windows, macos}` impls behind the bindreams/hole#165 isolation
//! contract.

#[cfg(target_os = "windows")]
use crate::service_start::RepairStep;

#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "windows")]
pub mod windows;

/// What a cutover holds on the service from before its stop to after its
/// start: on Windows the start-type lock, with the service hardened against a
/// restart. Dropping it lets go of the lock; the hardening stays until
/// [`restore`](Self::restore).
#[cfg(target_os = "windows")]
pub trait ServiceHold {
    /// Puts back what holding the service changed: restart-on-failure, the
    /// start type, the record. A failure is a warning, because the repair
    /// step that follows finds and undoes what it left.
    fn restore(&mut self);
}

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
    /// Take the service for the cutover: the start-type lock, then the record,
    /// a Disabled start type and restart-on-failure off, so that the stop is
    /// final and nothing restarts the old image under the swap. WINDOWS ONLY.
    #[cfg(target_os = "windows")]
    fn hold_service(&mut self) -> std::io::Result<Box<dyn ServiceHold>>;
    /// Trigger the bridge to stop after the swap. On Windows the detached child
    /// runs `ControlService(STOP)` + `NotifyServiceStatusChange(STOPPED)` and
    /// waits for a real STOPPED. On macOS this `launchctl kill SIGTERM`s its own
    /// process — a graceful shutdown that rides `pm.stop()` so the
    /// marker-conditional disarm fires; it does not wait (a self-wait is
    /// unreachable) and `KeepAlive` respawns the new binary.
    fn stop_service_wait_stopped(&mut self) -> std::io::Result<()>;
    /// Put the service's start type right for the start that follows, and say
    /// what was found: an interrupted uninstall's Disabled start type is reset,
    /// an administrator's is not. WINDOWS ONLY, like the start.
    #[cfg(target_os = "windows")]
    fn repair_start_type(&mut self) -> std::io::Result<RepairStep>;
    /// Start the bridge service and wait until it is really running
    /// (`StartService` + `NotifyServiceStatusChange(RUNNING)`). WINDOWS ONLY —
    /// macOS restart is `KeepAlive`-driven and never calls this.
    #[cfg(target_os = "windows")]
    fn start_service_wait_running(&mut self) -> std::io::Result<()>;
}

/// How a cutover that ran without error ended. The caller's marker policy is a
/// match on this type, so a new outcome cannot inherit an answer chosen for
/// another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CutoverOutcome {
    /// The new images are in place and the restart is under way: a new bridge
    /// will bind and sweep the update marker.
    Started,
    /// The new images are in place, and the service was left stopped because an
    /// administrator disabled it. No bridge will bind, so nothing else clears
    /// the update marker.
    LeftDisabled,
}

impl CutoverOutcome {
    /// Whether the update marker stays for the new bridge's post-bind sweep.
    pub fn leaves_marker_for_new_bridge(self) -> bool {
        match self {
            CutoverOutcome::Started => true,
            CutoverOutcome::LeftDisabled => false,
        }
    }
}

/// Drive the cutover sequence. Ordering is OS-asymmetric:
/// - Windows: hold and harden the service -> stop -> swap (while no bridge
///   runs) -> put the hardening back -> repair the start type -> start. Stopping
///   first bounds the gap and lets the new bridge boot from the new image
///   deterministically; hardening first makes the stop final, so the SCM's
///   restart-on-failure cannot start the old image under the swap. The detached child outlives the stopped
///   service. A service an administrator disabled is not started (the start
///   would fail): the update did install, so that is `LeftDisabled`, not an
///   error.
/// - macOS: swap both images FIRST, then trigger the bridge's own graceful
///   shutdown (SIGTERM rides `pm.stop()`, so the marker-conditional disarm
///   fires). It returns there: the inline actor SIGTERMs its own process, so a
///   self-wait + explicit start would be unreachable. launchd's `KeepAlive=true`
///   respawns the now-swapped binary (swap precedes shutdown), and the standing
///   pf cover + Adopt hold the gap.
pub fn run_cutover<O: CutoverOs>(os: &mut O) -> std::io::Result<CutoverOutcome> {
    #[cfg(target_os = "windows")]
    {
        // Held from before the stop to after the start, so no retirement, repair
        // or enable interleaves; hardened, so the SCM restarts nothing under the
        // swap. Put back before the repair step, which finds what a restore
        // that failed left. Dropped last, on every path out.
        let mut hold = os.hold_service()?;
        let stopped_and_swapped = os.stop_service_wait_stopped().and_then(|()| os.swap_images());
        hold.restore();
        stopped_and_swapped?;
        let repaired = os.repair_start_type()?;
        if !repaired.starts_service() {
            return Ok(CutoverOutcome::LeftDisabled);
        }
        os.start_service_wait_running()?;
    }
    #[cfg(target_os = "macos")]
    {
        os.swap_images()?;
        os.stop_service_wait_stopped()?;
    }
    Ok(CutoverOutcome::Started)
}

#[cfg(test)]
#[path = "os_tests.rs"]
mod os_tests;

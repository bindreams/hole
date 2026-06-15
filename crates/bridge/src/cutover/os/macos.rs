//! Real macOS `CutoverOs`: swap both images (`renamex_np` for the `.app`, plain
//! rename for `HELPER_PATH`), then trigger the bridge's own graceful shutdown.
//!
//! The actor runs INLINE in the bridge, so its stop step SIGTERMs its own
//! process. SIGTERM rides `foreground::shutdown_signal` -> `pm.stop()`, so the
//! marker-conditional `stop_with(Cutover)` disarms the standing cover (it
//! persists) and routes/DNS tear down. The process then exits and launchd's
//! `KeepAlive=true` respawns the now-swapped binary (the swap precedes the
//! shutdown); the persistent pf cover + the new bridge's `Adopt` hold the gap.
//! There is deliberately no self-wait-for-exit and no explicit `launchctl start`
//! — both would be unreachable past the self-SIGTERM.
//!
//! Raw `launchctl` invocation is the sanctioned restart primitive (the bridge is
//! root); no libc FFI is needed here.

use crate::cutover::os::CutoverOs;
use crate::platform::os::LAUNCHD_LABEL;
use crate::platform::swap::{execute_swap, SwapPlan};

pub struct MacosCutoverOs {
    pub plan: SwapPlan,
}

impl MacosCutoverOs {
    fn launchctl(args: &[&str]) -> std::io::Result<()> {
        let out = std::process::Command::new("launchctl").args(args).output()?;
        if !out.status.success() {
            return Err(std::io::Error::other(format!(
                "launchctl {args:?} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        Ok(())
    }
}

impl CutoverOs for MacosCutoverOs {
    fn swap_images(&mut self) -> std::io::Result<()> {
        execute_swap(&self.plan)
    }

    fn stop_service_wait_stopped(&mut self) -> std::io::Result<()> {
        // Graceful SIGTERM (NOT `kickstart -k`'s SIGKILL): rides
        // `shutdown_signal` -> `pm.stop()`, so the marker-conditional disarm
        // fires and routes/DNS tear down. This SIGTERMs THIS process, so there
        // is no return past it to wait on or to issue a start — KeepAlive=true
        // respawns the swapped binary.
        Self::launchctl(&["kill", "SIGTERM", &format!("system/{LAUNCHD_LABEL}")])
    }
}

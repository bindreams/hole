//! Service-manager update cutover. The privileged bridge swaps its own running
//! binary by rename and restarts the bridge service; the standing lockdown cover
//! holds the gap and every GUI self-heals onto the new image. Pure planners live
//! in `plan`; the OS effects seam in `os`; the apply handler logic in `apply`;
//! binary extraction in `extract`.

pub mod apply;
pub mod extract;
pub mod os;
pub mod plan;

#[cfg(target_os = "windows")]
pub mod scm_wait;

//! A host-wide scan for the processes that carry the service's token.
//!
//! The SCM's state says nothing about a process once the service is STOPPED
//! (its id is never valid), so "no process is left" is concluded from the
//! processes themselves: every live process on the host whose token carries
//! the service SID, descendants included, other than the calling one.

use std::io;

use tracing::warn;

use super::hold::Opened;

/// A process the scan could not decide ([`Verdict::Undetermined`](super::hold::Verdict)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Undetermined {
    pub pid: u32,
    /// The Win32 code the probe failed with, if it carried one.
    pub code: Option<u32>,
}

/// What a scan found.
pub struct ScanResult<P> {
    /// The live processes that carry the service's token, each with its id.
    pub alive: Vec<(u32, P)>,
    /// The processes the probe failed on in a way no table row decides.
    pub undetermined: Vec<Undetermined>,
}

/// The host's processes and the probes on them, behind a seam so the scan is
/// testable without one.
pub trait ProcessEnumerator {
    /// An open process; closes when dropped.
    type Process;
    /// Every process id on the host now.
    fn pids(&mut self) -> io::Result<Vec<u32>>;
    /// The id of the calling process, which a scan never waits on.
    fn this_process(&self) -> u32;
    /// Open process `pid` and read its token for the service SID, resolving a
    /// failure by the [`Basis::Scanned`](super::hold::Basis) table.
    fn open(&mut self, pid: u32) -> io::Result<Opened<Self::Process>>;
    /// Whether `process` has exited. A state read, never a wait.
    fn has_exited(&mut self, process: &Self::Process) -> io::Result<bool>;
}

/// Open every process on the host but the calling one and keep those that
/// carry the service's token and have not exited.
///
/// A process that cannot be told is reported (warned, and returned), never
/// fatal: an unrelated process must not fail an uninstall.
pub fn scan<E: ProcessEnumerator>(host: &mut E) -> io::Result<ScanResult<E::Process>> {
    let this = host.this_process();
    let mut result = ScanResult {
        alive: Vec::new(),
        undetermined: Vec::new(),
    };
    for pid in host.pids()? {
        if pid == this {
            continue;
        }
        match host.open(pid)? {
            Opened::NoSuchProcess => {}
            Opened::NotTheService => {}
            Opened::Service(process) => {
                if !host.has_exited(&process)? {
                    result.alive.push((pid, process));
                }
            }
            Opened::Undetermined { code } => {
                warn!(
                    pid,
                    ?code,
                    "a process on the host could not be told from the service's: not waited on"
                );
                result.undetermined.push(Undetermined { pid, code });
            }
        }
    }
    Ok(result)
}

#[cfg(test)]
#[path = "scan_tests.rs"]
mod scan_tests;

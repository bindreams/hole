//! A host-wide scan for the processes that carry the service's token.
//!
//! The SCM's state says nothing about a process once the service is STOPPED
//! (its id is never valid), so "no process is left" is concluded from the
//! processes themselves: every live process on the host whose token carries
//! the service SID, descendants included, other than the calling one.
//!
//! The listing is a snapshot, and a process can start another after it. So a
//! wait ends only on a scan that found nothing alive and lost no listed
//! process: one that is gone or exited by its probe may have started a child
//! the listing does not show, and the next scan, listed after its exit, does
//! ([`ScanFinding`]).

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
    /// The ids the listing named that no process had any more at the probe, or
    /// whose process had exited by then. Each may have started a process after
    /// the listing.
    pub vanished: Vec<u32>,
}

/// What a scan leaves to do, from what it found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanFinding {
    /// No process of the service is alive, and every listed one was probed.
    Nothing,
    /// A process of the service is alive: wait for it, then scan again.
    Alive,
    /// A listed process was gone by its probe: scan again.
    Vanished,
}

impl ScanFinding {
    /// Whether a wait that rests on this scan is over. The one place that says
    /// so: a wait never concludes "nothing is left" from anything but a scan
    /// of its own that found nothing.
    pub fn ends_the_wait(self) -> bool {
        match self {
            ScanFinding::Nothing => true,
            ScanFinding::Alive => false,
            ScanFinding::Vanished => false,
        }
    }
}

impl<P> ScanResult<P> {
    /// What this scan leaves to do. A live process outranks a vanished one:
    /// either way the wait goes on, and the next scan sees both.
    pub fn finding(&self) -> ScanFinding {
        if !self.alive.is_empty() {
            ScanFinding::Alive
        } else if !self.vanished.is_empty() {
            ScanFinding::Vanished
        } else {
            ScanFinding::Nothing
        }
    }
}

/// The host's processes and the probes on them, behind a seam so the scan is
/// testable without one.
pub trait ProcessEnumerator {
    /// An open process; closes when dropped.
    type Process;
    /// Every process id on the host now, every one: a listing that stops early
    /// is an error, never a short list. No id in it may be one that never
    /// opens, or the scan would report it vanished forever.
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
/// fatal: an unrelated process must not fail an uninstall. A listed id that is
/// gone, or a process of the service that has exited, by its probe is
/// reported in `vanished`.
pub fn scan<E: ProcessEnumerator>(host: &mut E) -> io::Result<ScanResult<E::Process>> {
    let this = host.this_process();
    let mut result = ScanResult {
        alive: Vec::new(),
        undetermined: Vec::new(),
        vanished: Vec::new(),
    };
    for pid in host.pids()? {
        if pid == this {
            continue;
        }
        match host.open(pid)? {
            Opened::NoSuchProcess => result.vanished.push(pid),
            Opened::NotTheService => {}
            Opened::Service(process) => {
                if host.has_exited(&process)? {
                    result.vanished.push(pid);
                } else {
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

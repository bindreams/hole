//! What a probe's result says about the network stack.

use std::io;

/// The one distinction every firewall assertion in the privileged lanes rests
/// on: did the probe reach the network stack at all?
///
/// A probe that reached the stack yields a verdict — the frame log (or the
/// absence of a connection) then says whether a cover blocked it. A probe
/// that never reached it says nothing about any cover, and reporting one as
/// the other sends the reader to the wrong side of the harness/product line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeFate {
    /// The syscall succeeded: a `connect` completed its handshake, a
    /// `send_to` left the process. No firewall drop can manufacture this.
    Delivered,
    /// The probe reached the stack and was rejected there. Covers every shape
    /// a block takes — Windows WFP denies at `ALE_AUTH_CONNECT` with
    /// `WSAEACCES` (`PermissionDenied`), a silent drop reads as `TimedOut` —
    /// and the abort/reset/refused shapes an unanswered destination produces
    /// with no cover engaged at all. Which of those happened is for the
    /// caller's own evidence (a captured frame, a phase baseline) to decide;
    /// this variant only certifies that the packet was the stack's to judge.
    Rejected(io::ErrorKind),
    /// Bind, address, or route-resolution failure — including a network or
    /// host with no route at all: the probe never reached the stack. A
    /// harness fault, never a verdict; the kind is carried so the failure is
    /// diagnosable from the first run.
    NeverLeft(io::ErrorKind),
}

impl ProbeFate {
    /// Whether this outcome can be judged against a cover at all.
    pub fn is_verdict(self) -> bool {
        !matches!(self, ProbeFate::NeverLeft(_))
    }
}

/// Classify a probe's result. Borrows, so the caller keeps the value (a
/// connected `TcpStream`, the original error) for its own assertions.
pub fn classify<T>(r: &io::Result<T>) -> ProbeFate {
    let kind = match r {
        Ok(_) => return ProbeFate::Delivered,
        Err(e) => e.kind(),
    };
    match kind {
        io::ErrorKind::PermissionDenied
        | io::ErrorKind::TimedOut
        | io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted => ProbeFate::Rejected(kind),
        other => ProbeFate::NeverLeft(other),
    }
}

#[cfg(test)]
#[path = "probe_tests.rs"]
mod probe_tests;

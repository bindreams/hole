//! What a probe's result says about the network stack.
//!
//! Two call shapes need two types here, not one. A `connect` (TCP) proves
//! delivery by its very success: `Ok` hands back a stream only after a
//! completed three-way handshake, which no firewall drop can manufacture —
//! [`classify`]/[`ProbeFate`] is for exactly that shape, and `Delivered` is
//! sound. A connectionless `send_to` (UDP) proves nothing of the kind: the
//! kernel accepts the datagram for local transmission and returns `Ok`
//! *whether or not* a cover then drops it at `ALE_AUTH_CONNECT` — `Ok(22)` is
//! exactly what a successfully blocked datagram looks like from that call.
//! [`classify_send`]/[`SendFate`] is for that shape, and has no
//! `Delivered`-equivalent variant to reach for: the wire is the only oracle
//! an unconnected UDP send has (`test_utils::pktmon`'s capture-based one).
//! Calling [`classify`] on a `send_to` result would compile — `T` is
//! unconstrained — but every such call site in this tree now goes through
//! [`classify_send`] instead, so `ProbeFate::Delivered` is never actually
//! reached from one.

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
    /// A `connect` completed its three-way handshake. No firewall drop can
    /// manufacture this — see the module doc for why this variant is sound
    /// only for a connect-shaped probe, never a connectionless `send_to`.
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

/// [`ProbeFate`]'s connectionless-send counterpart — see the module doc.
/// Structurally identical to `ProbeFate` in its harness-fault/reached-the-
/// stack distinction, deliberately WITHOUT a `Delivered`-shaped variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendFate {
    /// The kernel accepted the datagram for local transmission. NOT proof it
    /// left the box — a cover can still drop it downstream of this. Never
    /// compare this for a permit/leak verdict; capture the wire instead.
    Accepted,
    /// Same meaning as [`ProbeFate::Rejected`].
    Rejected(io::ErrorKind),
    /// Same meaning as [`ProbeFate::NeverLeft`].
    NeverLeft(io::ErrorKind),
}

impl SendFate {
    /// Whether this outcome can be judged against a cover at all.
    pub fn is_verdict(self) -> bool {
        !matches!(self, SendFate::NeverLeft(_))
    }
}

/// The `Err` half every probe shape classifies the same way — factored out so
/// [`classify`] and [`classify_send`] cannot drift into disjoint notions of
/// which `io::ErrorKind`s are a rejection versus a harness fault.
enum ErrShape {
    Rejected(io::ErrorKind),
    NeverLeft(io::ErrorKind),
}

fn classify_err(kind: io::ErrorKind) -> ErrShape {
    match kind {
        io::ErrorKind::PermissionDenied
        | io::ErrorKind::TimedOut
        | io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted => ErrShape::Rejected(kind),
        other => ErrShape::NeverLeft(other),
    }
}

/// Classify a connect-shaped probe's result. Borrows, so the caller keeps the
/// value (a connected `TcpStream`, the original error) for its own
/// assertions. See the module doc for why this is unsound for a `send_to`
/// result — use [`classify_send`] for that shape instead.
pub fn classify<T>(r: &io::Result<T>) -> ProbeFate {
    let kind = match r {
        Ok(_) => return ProbeFate::Delivered,
        Err(e) => e.kind(),
    };
    match classify_err(kind) {
        ErrShape::Rejected(k) => ProbeFate::Rejected(k),
        ErrShape::NeverLeft(k) => ProbeFate::NeverLeft(k),
    }
}

/// Classify a connectionless-send probe's result — see the module doc and
/// [`SendFate`].
pub fn classify_send<T>(r: &io::Result<T>) -> SendFate {
    let kind = match r {
        Ok(_) => return SendFate::Accepted,
        Err(e) => e.kind(),
    };
    match classify_err(kind) {
        ErrShape::Rejected(k) => SendFate::Rejected(k),
        ErrShape::NeverLeft(k) => SendFate::NeverLeft(k),
    }
}

#[cfg(test)]
#[path = "probe_tests.rs"]
mod probe_tests;

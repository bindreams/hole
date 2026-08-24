//! The TCP accept verdict, as a pure decision.

use std::net::SocketAddr;

use smoltcp::iface::SocketHandle;

/// A listener socket that has left `State::Listen` and awaits a verdict.
pub(crate) enum Handshake {
    /// The socket has a peer: `src` is the client, `dst` the address it dialled.
    Pending {
        handle: SocketHandle,
        port: u16,
        src: SocketAddr,
        dst: SocketAddr,
    },
    /// The socket has no peer left to answer.
    Stale { handle: SocketHandle, port: u16 },
}

/// What the datapath does with a [`Handshake`].
#[derive(Debug, PartialEq)]
pub(crate) enum Admission<P> {
    /// Complete the handshake, carrying the resource `P` the connection holds.
    Admit(P),
    /// Answer the client with a reset.
    Refuse,
    /// Drop the socket; there is no peer to answer.
    Discard,
}

/// Decide a handshake's fate, acquiring the connection resource at most once.
///
/// `acquire` is a closure so the resource — an `OwnedSemaphorePermit` that must
/// move into the spawned router task — stays out of this function's types. A
/// peerless handshake never calls it, so it never burns a permit.
pub(crate) fn decide_admission<P>(handshake: &Handshake, acquire: impl FnOnce() -> Option<P>) -> Admission<P> {
    match handshake {
        Handshake::Stale { .. } => Admission::Discard,
        Handshake::Pending { .. } => match acquire() {
            Some(resource) => Admission::Admit(resource),
            None => Admission::Refuse,
        },
    }
}

#[cfg(test)]
#[path = "admission_tests.rs"]
mod admission_tests;

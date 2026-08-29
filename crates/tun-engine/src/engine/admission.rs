//! The TCP accept verdict, as a pure decision.

use std::net::SocketAddr;

use smoltcp::iface::SocketHandle;

/// A listener socket that has left `State::Listen` and awaits a verdict.
///
/// Leaving `Listen` always sets a tuple (smoltcp sets it in the same match arm
/// that transitions the state), so a handshake always has a peer.
pub(crate) enum Handshake {
    /// The socket has a peer: `src` is the client, `dst` the address it dialled.
    Pending {
        handle: SocketHandle,
        port: u16,
        src: SocketAddr,
        dst: SocketAddr,
        /// The 4-tuple's previous owner, if this SYN's ISN proves it is a new
        /// connection rather than that owner's retransmit (RFC 9293
        /// §3.10.7.4). Torn down before this handshake is admitted or
        /// refused.
        supersedes: Option<SocketHandle>,
    },
    /// The socket's 4-tuple already belongs to another socket carrying the
    /// same ISN, so its SYN is a retransmission of a connection the datapath
    /// already owns.
    Duplicate { handle: SocketHandle, port: u16 },
}

/// What the datapath does with a [`Handshake`].
#[derive(Debug, PartialEq)]
pub(crate) enum Admission<P> {
    /// Complete the handshake, carrying the resource `P` the connection holds.
    Admit(P),
    /// Answer the client with a reset.
    Refuse,
    /// Drop the socket without answering; its 4-tuple already has an owner and
    /// the client is waiting on that one.
    Duplicate,
}

/// Decide a handshake's fate, acquiring the connection resource at most once.
///
/// `acquire` is a closure so the resource — an `OwnedSemaphorePermit` that must
/// move into the spawned router task — stays out of this function's types. A
/// duplicate handshake never calls it, so it never burns a permit.
pub(crate) fn decide_admission<P>(handshake: &Handshake, acquire: impl FnOnce() -> Option<P>) -> Admission<P> {
    match handshake {
        Handshake::Duplicate { .. } => Admission::Duplicate,
        Handshake::Pending { .. } => match acquire() {
            Some(resource) => Admission::Admit(resource),
            None => Admission::Refuse,
        },
    }
}

#[cfg(test)]
#[path = "admission_tests.rs"]
mod admission_tests;

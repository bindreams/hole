//! `SocketStack` — the smoltcp interface, socket set, and TCP listener
//! bookkeeping.
//!
//! Owns no tokio, no TUN handle, and no clock: packets arrive and leave through
//! plain queues, and [`poll`](SocketStack::poll) takes the current time as a
//! parameter.
//!
//! Listeners are created with their SYN-ACK paused, so the accept verdict is
//! reached while the socket is still in `SynReceived` and nothing has left the
//! interface. [`admit`](SocketStack::admit) releases the SYN-ACK;
//! [`refuse`](SocketStack::refuse) turns the same socket into an RST.
//!
//! A 4-tuple has one owner. Slot order can put a re-armed listener below its own
//! connection, where it takes that client's retransmitted SYN, so
//! [`take_handshakes`](SocketStack::take_handshakes) reports the second socket
//! for a tuple as `Duplicate` rather than as a new connection.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::time::{Duration as SmoltcpDuration, Instant as SmoltcpInstant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};
use tracing::warn;

pub(crate) use super::admission::Handshake;
use super::config::EngineConfig;
use super::virtual_device::VirtualTunDevice;
use crate::device::DeviceConfig;

/// A TCP listener socket in smoltcp waiting for incoming SYN packets.
struct TcpListener {
    handle: SocketHandle,
    port: u16,
}

pub(crate) struct SocketStack {
    device: VirtualTunDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    listeners: Vec<TcpListener>,
    listened_ports: HashSet<u16>,
    /// Sockets the datapath is done with, held in the set until smoltcp is
    /// finished with their peer.
    retiring: Vec<SocketHandle>,
    tcp_rx_buf_size: usize,
    tcp_tx_buf_size: usize,
    keep_alive_interval: SmoltcpDuration,
    peer_timeout: SmoltcpDuration,
}

impl SocketStack {
    pub(crate) fn new(device_config: &DeviceConfig, config: &EngineConfig) -> Self {
        let mut device = VirtualTunDevice::new(device_config.mtu as usize);

        let iface_config = Config::new(HardwareAddress::Ip);
        let mut iface = Interface::new(iface_config, &mut device, SmoltcpInstant::from_millis(0));
        iface.set_any_ip(true);
        iface.update_ip_addrs(|addrs| {
            if let Some(v4) = device_config.ipv4 {
                addrs.push(IpCidr::Ipv4(v4)).unwrap();
            }
            if let Some(v6) = device_config.ipv6 {
                addrs.push(IpCidr::Ipv6(v6)).unwrap();
            }
        });

        Self {
            device,
            iface,
            sockets: SocketSet::new(vec![]),
            listeners: Vec::new(),
            listened_ports: HashSet::new(),
            retiring: Vec::new(),
            tcp_rx_buf_size: config.tcp_rx_buf_size,
            tcp_tx_buf_size: config.tcp_tx_buf_size,
            keep_alive_interval: SmoltcpDuration::from(config.tcp_keep_alive_interval),
            peer_timeout: SmoltcpDuration::from(config.tcp_peer_timeout),
        }
    }

    /// Hand smoltcp a packet read from the real TUN device.
    pub(crate) fn enqueue_rx(&mut self, packet: Vec<u8>) {
        self.device.enqueue_rx(packet);
    }

    /// Take everything smoltcp wants written to the real TUN device.
    pub(crate) fn dequeue_tx(&mut self) -> Vec<Vec<u8>> {
        self.device.dequeue_tx()
    }

    /// Drive smoltcp, then reap every retired socket smoltcp has finished with.
    ///
    /// `remote_endpoint()` going `None` is that signal: `dispatch` clears the
    /// 4-tuple only once it has emitted the socket's last packet. A retired
    /// socket whose peer is still live stays in the set.
    pub(crate) fn poll(&mut self, now: SmoltcpInstant) {
        self.iface.poll(now, &mut self.device, &mut self.sockets);

        let mut retiring = std::mem::take(&mut self.retiring);
        retiring.retain(|&handle| {
            if self.sockets.get::<tcp::Socket>(handle).remote_endpoint().is_some() {
                return true;
            }
            self.remove(handle);
            false
        });
        self.retiring = retiring;
    }

    pub(crate) fn ensure_listener(&mut self, port: u16) {
        if self.listened_ports.contains(&port) {
            return;
        }
        let rx_buf = tcp::SocketBuffer::new(vec![0u8; self.tcp_rx_buf_size]);
        let tx_buf = tcp::SocketBuffer::new(vec![0u8; self.tcp_tx_buf_size]);
        let mut socket = tcp::Socket::new(rx_buf, tx_buf);
        if let Err(e) = socket.listen(port) {
            warn!("failed to listen on port {port}: {e:?}");
            return;
        }
        socket.pause_synack(true);
        // An ACK smoltcp defers is an ACK a removed socket never sends —
        // see `remove`'s assert.
        socket.set_ack_delay(None);
        let handle = self.sockets.add(socket);
        self.listeners.push(TcpListener { handle, port });
        self.listened_ports.insert(port);
    }

    /// Whether a socket other than `handle` already holds the 4-tuple
    /// `local`/`remote`.
    ///
    /// Only a listener can pick up a packet whose tuple is already taken:
    /// smoltcp matches a connected socket on the full 4-tuple, but a `Listen`
    /// socket matches a bare SYN on the local port alone, and it is reached
    /// first whenever it sits in a lower slot.
    fn tuple_is_taken(&self, handle: SocketHandle, local: IpEndpoint, remote: IpEndpoint) -> bool {
        self.sockets.iter().any(|(other, socket)| {
            let smoltcp::socket::Socket::Tcp(socket) = socket else {
                return false;
            };
            other != handle && socket.local_endpoint() == Some(local) && socket.remote_endpoint() == Some(remote)
        })
    }

    /// Listener sockets that have left `State::Listen`. Each is dropped from
    /// the listener bookkeeping, so a handshake is reported exactly once.
    pub(crate) fn take_handshakes(&mut self) -> Vec<Handshake> {
        let started: Vec<(SocketHandle, u16)> = self
            .listeners
            .iter()
            .filter(|l| self.sockets.get::<tcp::Socket>(l.handle).state() != tcp::State::Listen)
            .map(|l| (l.handle, l.port))
            .collect();

        let mut handshakes = Vec::with_capacity(started.len());
        for (handle, port) in started {
            self.listeners.retain(|l| l.handle != handle);
            self.listened_ports.remove(&port);

            let socket = self.sockets.get::<tcp::Socket>(handle);
            handshakes.push(match (socket.local_endpoint(), socket.remote_endpoint()) {
                (Some(local), Some(remote)) if self.tuple_is_taken(handle, local, remote) => {
                    Handshake::Duplicate { handle, port }
                }
                (Some(local), Some(remote)) => Handshake::Pending {
                    handle,
                    port,
                    src: SocketAddr::new(smoltcp_to_std_ip(remote.addr), remote.port),
                    dst: SocketAddr::new(smoltcp_to_std_ip(local.addr), local.port),
                },
                _ => Handshake::Stale { handle, port },
            });
        }
        handshakes
    }

    /// Release the socket's held SYN-ACK, bound its client's silence, and
    /// re-arm the port.
    ///
    /// The bound is the only thing that reclaims a connection whose client
    /// vanishes mid-flight: smoltcp's retransmit backs off forever, and
    /// `decide_disposal` has no verdict for `SynReceived`, `FinWait2` or
    /// `CloseWait`. On the timeout smoltcp resets the socket to `Closed`, where
    /// it has one.
    pub(crate) fn admit(&mut self, handle: SocketHandle, port: u16) {
        let socket = self.sockets.get_mut::<tcp::Socket>(handle);
        socket.set_keep_alive(Some(self.keep_alive_interval));
        socket.set_timeout(Some(self.peer_timeout));
        socket.pause_synack(false);
        self.ensure_listener(port);
    }

    /// Answer the socket's peer with an RST instead of a SYN-ACK, and re-arm
    /// the port. The RST leaves on the next [`poll`](Self::poll).
    pub(crate) fn refuse(&mut self, handle: SocketHandle, port: u16) {
        self.sockets.get_mut::<tcp::Socket>(handle).abort();
        self.retire(handle);
        self.ensure_listener(port);
    }

    /// Drop a handshake with no peer left to answer, and re-arm the port.
    /// smoltcp has already cleared the 4-tuple, so there is no address to
    /// answer and nothing pending — the socket goes straight out of the set.
    pub(crate) fn discard(&mut self, handle: SocketHandle, port: u16) {
        debug_assert_eq!(
            self.sockets.get::<tcp::Socket>(handle).state(),
            tcp::State::Closed,
            "every path that clears a non-listening socket's tuple leaves it Closed",
        );
        self.remove(handle);
        self.ensure_listener(port);
    }

    /// Drop a second socket for a 4-tuple another socket already owns, and
    /// re-arm the port.
    ///
    /// It leaves without a packet, and that is the point: any segment from here
    /// reaches a client that is transacting with the *other* socket. An RST
    /// acknowledging the client's SYN is one it must accept while in SYN-SENT,
    /// so answering would kill the connection this SYN is retransmitting for.
    pub(crate) fn drop_duplicate(&mut self, handle: SocketHandle, port: u16) {
        self.remove(handle);
        self.ensure_listener(port);
    }

    /// Park a socket the datapath is done with. It stays in the set until
    /// [`poll`](Self::poll) sees smoltcp finish with its peer.
    ///
    /// A handle must not be retired twice — the second reap would call
    /// `SocketSet::remove` on an empty slot and panic. Every caller retires a
    /// handle it has just taken out of the map that owned it, so the list
    /// cannot come to hold a duplicate.
    pub(crate) fn retire(&mut self, handle: SocketHandle) {
        self.retiring.push(handle);
    }

    /// Drop a socket now, without waiting for smoltcp to finish with its peer.
    pub(crate) fn remove(&mut self, handle: SocketHandle) {
        debug_assert!(
            self.sockets.get::<tcp::Socket>(handle).ack_delay().is_none(),
            "a socket that defers its ACK can still owe one when it is removed",
        );
        self.sockets.remove(handle);
    }

    pub(crate) fn socket(&self, handle: SocketHandle) -> &tcp::Socket<'static> {
        self.sockets.get::<tcp::Socket>(handle)
    }

    pub(crate) fn socket_mut(&mut self, handle: SocketHandle) -> &mut tcp::Socket<'static> {
        self.sockets.get_mut::<tcp::Socket>(handle)
    }
}

/// Read-only lookups for tests in sibling modules, which lack the handles
/// production callers keep.
#[cfg(test)]
impl SocketStack {
    /// The listener armed on `port`, if any.
    pub(crate) fn listener(&self, port: u16) -> Option<SocketHandle> {
        self.listeners.iter().find(|l| l.port == port).map(|l| l.handle)
    }

    /// Whether `handle` still names a socket in the set. A reaped or removed
    /// slot can be refilled, so this answers about the slot, not the socket
    /// that was in it.
    pub(crate) fn holds(&self, handle: SocketHandle) -> bool {
        self.sockets.iter().any(|(h, _)| h == handle)
    }
}

/// How a connection socket leaves the set once the datapath is done with it.
#[derive(Debug, PartialEq)]
pub(crate) enum Disposal {
    /// Hold it until smoltcp finishes with its peer.
    Retire,
    /// Drop it now.
    Remove,
}

/// How to dispose of a connection socket in `state`, or `None` while it is
/// still live.
///
/// `Listen` is a finished state because a socket in the connection map reaches
/// it by exactly one route: the client answered our SYN-ACK with an RST, and
/// smoltcp flipped it back without clearing the listen endpoint that would
/// otherwise hijack every later SYN on that port. An `Established` socket that
/// receives an RST goes to `Closed` instead, so `Listen` here is unambiguous.
/// Both it and `Closed` retire, which costs at most one poll: their tuple is
/// either already clear or clears as soon as the last packet is out.
///
/// `TimeWait` is removed at once instead. Retiring it would hold the socket,
/// and both its buffers, for smoltcp's 10 s `CLOSE_DELAY` — the tuple survives
/// until the close timer fires. That retention buys nothing here: every
/// socket this stack creates has its delayed ACK disabled, so it owes its
/// peer nothing by the time it reaches `TimeWait`, and removing it strands no
/// segment.
pub(crate) fn decide_disposal(state: tcp::State) -> Option<Disposal> {
    match state {
        tcp::State::Closed | tcp::State::Listen => Some(Disposal::Retire),
        tcp::State::TimeWait => Some(Disposal::Remove),
        _ => None,
    }
}

fn smoltcp_to_std_ip(addr: IpAddress) -> IpAddr {
    match addr {
        IpAddress::Ipv4(v4) => IpAddr::V4(v4),
        IpAddress::Ipv6(v6) => IpAddr::V6(v6),
    }
}

#[cfg(test)]
#[path = "socket_stack_tests.rs"]
mod socket_stack_tests;

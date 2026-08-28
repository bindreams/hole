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
//! connection, where it takes that client's retransmitted SYN;
//! [`take_handshakes`](SocketStack::take_handshakes) tells that retransmit apart
//! from a *new* connection reusing the tuple (RFC 9293 §3.10.7.4) by ISN: same
//! ISN as the owner reports `Duplicate` and is dropped silently, a different
//! ISN reports `Pending` with `supersedes` set to the stale owner.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::socket::tcp;
use smoltcp::time::{Duration as SmoltcpDuration, Instant as SmoltcpInstant};
use smoltcp::wire::{
    HardwareAddress, IpCidr, IpEndpoint, IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6ExtHeader, Ipv6ExtHeaderRepr,
    Ipv6Packet, Ipv6Repr, TcpPacket,
};
use tracing::warn;

pub(crate) use super::admission::Handshake;
use super::config::EngineConfig;
use super::emit::smoltcp_to_std_ip;
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
    /// The ISN each live connection was admitted with, keyed by handle. What
    /// [`take_handshakes`](Self::take_handshakes) compares a same-tuple SYN's
    /// ISN against to tell a retransmit from a new connection.
    owner_isn: HashMap<SocketHandle, u32>,
    /// The 4-tuple and ISN of the SYN most recently handed to
    /// [`enqueue_rx`](Self::enqueue_rx), if it was one. Read and cleared by
    /// the next [`take_handshakes`](Self::take_handshakes) call, so it can
    /// never be read stale by the one after that.
    pending_syn: Option<(SocketAddr, SocketAddr, u32)>,
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
            owner_isn: HashMap::new(),
            pending_syn: None,
            tcp_rx_buf_size: config.tcp_rx_buf_size,
            tcp_tx_buf_size: config.tcp_tx_buf_size,
            keep_alive_interval: SmoltcpDuration::from(config.tcp_keep_alive_interval),
            peer_timeout: SmoltcpDuration::from(config.tcp_peer_timeout),
        }
    }

    /// Hand smoltcp a packet read from the real TUN device.
    ///
    /// If the packet is a SYN, its 4-tuple and ISN are captured here — off the
    /// wire, since smoltcp exposes no ISN accessor — for the `take_handshakes`
    /// call that follows the next `poll`.
    pub(crate) fn enqueue_rx(&mut self, packet: Vec<u8>) {
        self.pending_syn = parse_syn(&packet);
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
            self.sockets.remove(handle);
            self.owner_isn.remove(&handle);
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
        let handle = self.sockets.add(socket);
        self.listeners.push(TcpListener { handle, port });
        self.listened_ports.insert(port);
    }

    /// The handle of a socket other than `handle` that already holds the
    /// 4-tuple `local`/`remote`, if any.
    ///
    /// Only a listener can pick up a packet whose tuple is already taken:
    /// smoltcp matches a connected socket on the full 4-tuple, but a `Listen`
    /// socket matches a bare SYN on the local port alone, and it is reached
    /// first whenever it sits in a lower slot.
    fn tuple_owner(&self, handle: SocketHandle, local: IpEndpoint, remote: IpEndpoint) -> Option<SocketHandle> {
        self.sockets.iter().find_map(|(other, socket)| {
            let smoltcp::socket::Socket::Tcp(socket) = socket else {
                return None;
            };
            let holds =
                other != handle && socket.local_endpoint() == Some(local) && socket.remote_endpoint() == Some(remote);
            holds.then_some(other)
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

        // Taken once, up front: cleared here so it can never be read a second
        // time by a later call, however many handshakes this one reports.
        let pending_syn = self.pending_syn.take();

        let mut handshakes = Vec::with_capacity(started.len());
        for (handle, port) in started {
            self.listeners.retain(|l| l.handle != handle);
            self.listened_ports.remove(&port);

            let socket = self.sockets.get::<tcp::Socket>(handle);
            let (local, remote) = (
                socket
                    .local_endpoint()
                    .expect("a SYN that left Listen always sets a tuple (smoltcp sets it in the same match arm)"),
                socket
                    .remote_endpoint()
                    .expect("a SYN that left Listen always sets a tuple (smoltcp sets it in the same match arm)"),
            );
            let src = SocketAddr::new(smoltcp_to_std_ip(remote.addr), remote.port);
            let dst = SocketAddr::new(smoltcp_to_std_ip(local.addr), local.port);

            let owner = self.tuple_owner(handle, local, remote);
            let observed_isn = pending_syn
                .filter(|&(s, d, _)| (s, d) == (src, dst))
                .map(|(.., isn)| isn);

            handshakes.push(match owner {
                Some(owner) => {
                    let owners_isn = self.owner_isn.get(&owner).copied();
                    // A tuple's owner is duplicated whenever this SYN's ISN
                    // cannot be told apart from the owner's. That needs both
                    // sides readable and equal — if either this SYN's ISN or
                    // the ISN its owner was admitted with could not be read
                    // off the wire, falling back to the historically-safe
                    // `Duplicate` means a parsing gap on either side can
                    // never mint a spurious connection, nor tear down a live
                    // one on its own harmless retransmit.
                    let is_retransmit = match (observed_isn, owners_isn) {
                        (Some(a), Some(b)) => a == b,
                        _ => true,
                    };
                    if is_retransmit {
                        Handshake::Duplicate { handle, port }
                    } else {
                        self.owner_isn.insert(
                            handle,
                            observed_isn
                                .expect("is_retransmit is false only when both ISNs are Some, per the match above"),
                        );
                        Handshake::Pending {
                            handle,
                            port,
                            src,
                            dst,
                            supersedes: Some(owner),
                        }
                    }
                }
                None => {
                    if let Some(isn) = observed_isn {
                        self.owner_isn.insert(handle, isn);
                    }
                    Handshake::Pending {
                        handle,
                        port,
                        src,
                        dst,
                        supersedes: None,
                    }
                }
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

    /// Drop a second socket for a 4-tuple another socket already owns, and
    /// re-arm the port.
    ///
    /// It leaves without a packet, and that is the point: any segment from here
    /// reaches a client that is transacting with the *other* socket. An RST
    /// acknowledging the client's SYN is one it must accept while in SYN-SENT,
    /// so answering would kill the connection this SYN is retransmitting for.
    pub(crate) fn drop_duplicate(&mut self, handle: SocketHandle, port: u16) {
        self.sockets.remove(handle);
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
        debug_assert!(!self.retiring.contains(&handle), "handle retired twice");
        self.retiring.push(handle);
    }

    /// Drop a socket now, without waiting for smoltcp to finish with its peer.
    ///
    /// Also drops `handle` from `retiring`: a socket a caller is removing may
    /// already be parked there (superseding a stale owner mid-teardown, not
    /// yet reaped) and `poll`'s reap loop panics on a handle whose slot is
    /// already gone.
    pub(crate) fn remove(&mut self, handle: SocketHandle) {
        self.sockets.remove(handle);
        self.owner_isn.remove(&handle);
        self.retiring.retain(|&h| h != handle);
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
/// until the close timer fires. Trading that retention for the ACK the socket
/// still owes its peer is not decided here.
pub(crate) fn decide_disposal(state: tcp::State) -> Option<Disposal> {
    match state {
        tcp::State::Closed | tcp::State::Listen => Some(Disposal::Retire),
        tcp::State::TimeWait => Some(Disposal::Remove),
        _ => None,
    }
}

/// The 4-tuple and ISN of `packet`, if it is a bare SYN (no ACK) directly over
/// IP — i.e. `IpProtocol::Tcp` immediately, or after a single Hop-by-Hop
/// extension header on IPv6, never a TCP-shaped payload carried under any
/// other protocol, which smoltcp would never hand to the TCP layer.
///
/// IPv6's Hop-by-Hop header is the one extension header smoltcp itself
/// strips before dispatching on what follows (`Interface::poll`'s private
/// `process_hopbyhop`); anything else between the fixed header and TCP is, on
/// both IP versions, a protocol smoltcp would reject just as this does.
///
/// Reads `TcpPacket`'s raw field accessors, never `TcpRepr::parse`: that
/// additionally verifies the checksum and walks TCP options end to end,
/// neither of which bears on whether a segment is a bare SYN, and both of
/// which can `Err` on an option-parsing detail unrelated to that question. A
/// real inbound packet's checksum is never verified on receipt (see
/// `VirtualTunDevice::capabilities`), so this asks nothing of it either.
fn parse_syn(packet: &[u8]) -> Option<(SocketAddr, SocketAddr, u32)> {
    let (src_ip, dst_ip, tcp_payload) = match packet.first()? >> 4 {
        4 => {
            let ip_packet = Ipv4Packet::new_checked(packet).ok()?;
            let ip_repr = Ipv4Repr::parse(&ip_packet, &ChecksumCapabilities::ignored()).ok()?;
            if ip_repr.next_header != IpProtocol::Tcp {
                return None;
            }
            (
                IpAddr::V4(ip_repr.src_addr),
                IpAddr::V4(ip_repr.dst_addr),
                ip_packet.payload(),
            )
        }
        6 => {
            let ip_packet = Ipv6Packet::new_checked(packet).ok()?;
            let ip_repr = Ipv6Repr::parse(&ip_packet).ok()?;

            let (next_header, tcp_payload) = if ip_repr.next_header == IpProtocol::HopByHop {
                let ext_header = Ipv6ExtHeader::new_checked(ip_packet.payload()).ok()?;
                let ext_repr = Ipv6ExtHeaderRepr::parse(&ext_header).ok()?;
                let skip = ext_repr.header_len() + ext_repr.data.len();
                (ext_repr.next_header, &ip_packet.payload()[skip..])
            } else {
                (ip_repr.next_header, ip_packet.payload())
            };
            if next_header != IpProtocol::Tcp {
                return None;
            }
            (IpAddr::V6(ip_repr.src_addr), IpAddr::V6(ip_repr.dst_addr), tcp_payload)
        }
        _ => return None,
    };

    let tcp_packet = TcpPacket::new_checked(tcp_payload).ok()?;
    if !tcp_packet.syn() || tcp_packet.ack() {
        return None;
    }
    Some((
        SocketAddr::new(src_ip, tcp_packet.src_port()),
        SocketAddr::new(dst_ip, tcp_packet.dst_port()),
        tcp_packet.seq_number().0 as u32,
    ))
}

#[cfg(test)]
#[path = "socket_stack_tests.rs"]
mod socket_stack_tests;

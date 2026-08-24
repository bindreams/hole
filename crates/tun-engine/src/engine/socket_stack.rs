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

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmoltcpInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use tracing::warn;

use super::config::EngineConfig;
use super::virtual_device::VirtualTunDevice;
use crate::device::DeviceConfig;

/// A TCP listener socket in smoltcp waiting for incoming SYN packets.
struct TcpListener {
    handle: SocketHandle,
    port: u16,
}

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
            self.sockets.remove(handle);
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

    /// Release the socket's held SYN-ACK and re-arm the port.
    pub(crate) fn admit(&mut self, handle: SocketHandle, port: u16) {
        self.sockets.get_mut::<tcp::Socket>(handle).pause_synack(false);
        self.ensure_listener(port);
    }

    /// Answer the socket's peer with an RST instead of a SYN-ACK, and re-arm
    /// the port. The RST leaves on the next [`poll`](Self::poll).
    pub(crate) fn refuse(&mut self, handle: SocketHandle, port: u16) {
        self.sockets.get_mut::<tcp::Socket>(handle).abort();
        self.retire(handle);
        self.ensure_listener(port);
    }

    /// Park a socket the datapath is done with. It stays in the set until
    /// [`poll`](Self::poll) sees smoltcp finish with its peer.
    pub(crate) fn retire(&mut self, handle: SocketHandle) {
        self.retiring.push(handle);
    }

    pub(crate) fn socket(&self, handle: SocketHandle) -> &tcp::Socket<'static> {
        self.sockets.get::<tcp::Socket>(handle)
    }

    pub(crate) fn socket_mut(&mut self, handle: SocketHandle) -> &mut tcp::Socket<'static> {
        self.sockets.get_mut::<tcp::Socket>(handle)
    }

    pub(crate) fn remove(&mut self, handle: SocketHandle) {
        self.sockets.remove(handle);
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

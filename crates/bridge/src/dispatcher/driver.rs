//! TUN driver main loop — bridges the OS TUN device with the smoltcp
//! userspace TCP/IP stack, dispatches new TCP connections to handler tasks,
//! and serves port-53 DNS via a smoltcp UDP socket when fake DNS is active.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant as StdInstant;

use arc_swap::ArcSwap;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmoltcpInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Semaphore};
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

use super::device::VirtualTunDevice;
use super::smoltcp_stream::SmoltcpStream;
use super::tcp_handler::{self, TcpHandlerContext};
use crate::filter::rules::RuleSet;
use crate::filter::FakeDns;

// Constants ===========================================================================================================

/// MTU for the virtual smoltcp device (and the TUN). Slightly below
/// typical Ethernet MTU to leave room for encapsulation.
pub(crate) const MTU: usize = 1400;

/// Maximum concurrent TCP connections.
const MAX_CONNECTIONS: usize = 4096;

/// Maximum concurrent sniffer peek operations.
const MAX_SNIFFERS: usize = 1024;

/// smoltcp TCP socket buffer sizes (per direction).
const TCP_RX_BUF_SIZE: usize = 65536;
const TCP_TX_BUF_SIZE: usize = 65536;

/// smoltcp UDP socket buffer sizes (per direction, for DNS).
const UDP_RX_META_SLOTS: usize = 32;
const UDP_RX_PAYLOAD_SIZE: usize = 8192;
const UDP_TX_META_SLOTS: usize = 32;
const UDP_TX_PAYLOAD_SIZE: usize = 8192;

/// TUN read buffer size — one IP packet.
const TUN_BUF_SIZE: usize = MTU + 64;

// Types ===============================================================================================================

/// Tracks a TCP connection that the driver is relaying data for between
/// the smoltcp socket and a handler task.
struct TcpConn {
    /// Send data TO the handler task (handler reads from SmoltcpStream).
    to_handler: mpsc::Sender<Vec<u8>>,
    /// Receive data FROM the handler task (handler writes to SmoltcpStream).
    from_handler: mpsc::Receiver<Vec<u8>>,
}

/// Tracks a TCP listener socket in smoltcp waiting for incoming SYN packets.
struct TcpListener {
    handle: SocketHandle,
    port: u16,
}

/// The main TUN driver, owning the smoltcp Interface, socket set, and TUN device.
pub struct TunDriver {
    tun: tun::AsyncDevice,
    device: VirtualTunDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    fake_dns: Option<Arc<FakeDns>>,
    udp_dns_handle: Option<SocketHandle>,
    listeners: Vec<TcpListener>,
    connections: HashMap<SocketHandle, TcpConn>,
    /// Ports that already have a listener.
    listened_ports: std::collections::HashSet<u16>,
    cancel: CancellationToken,
    conn_semaphore: Arc<Semaphore>,
    sniffer_semaphore: Arc<Semaphore>,
    rules: Arc<ArcSwap<RuleSet>>,
    handler_ctx: Arc<TcpHandlerContext>,
    /// Reference time for converting std::time::Instant to smoltcp::time::Instant.
    epoch: StdInstant,
}

impl TunDriver {
    /// Create a new TUN driver.
    ///
    /// The TUN device must already be created and configured by the caller.
    pub fn new(
        tun: tun::AsyncDevice,
        fake_dns: Option<Arc<FakeDns>>,
        rules: Arc<ArcSwap<RuleSet>>,
        handler_ctx: Arc<TcpHandlerContext>,
        cancel: CancellationToken,
    ) -> Self {
        let mut device = VirtualTunDevice::new(MTU);

        let config = Config::new(HardwareAddress::Ip);
        let epoch = StdInstant::now();
        let now = SmoltcpInstant::from_millis(0);
        let mut iface = Interface::new(config, &mut device, now);
        iface.set_any_ip(true);
        iface.update_ip_addrs(|addrs| {
            addrs.push(IpCidr::new(IpAddress::v4(10, 255, 0, 1), 24)).unwrap();
            addrs
                .push(IpCidr::new(IpAddress::v6(0xfd00, 0, 0, 0xff00, 0, 0, 0, 1), 64))
                .unwrap();
        });

        let mut sockets = SocketSet::new(vec![]);

        // If fake DNS is active, create a UDP socket bound to port 53.
        let udp_dns_handle = if fake_dns.is_some() {
            let rx_buf = udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; UDP_RX_META_SLOTS],
                vec![0u8; UDP_RX_PAYLOAD_SIZE],
            );
            let tx_buf = udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; UDP_TX_META_SLOTS],
                vec![0u8; UDP_TX_PAYLOAD_SIZE],
            );
            let mut udp_socket = udp::Socket::new(rx_buf, tx_buf);
            udp_socket.bind(53).expect("binding smoltcp UDP :53");
            let handle = sockets.add(udp_socket);
            Some(handle)
        } else {
            None
        };

        Self {
            tun,
            device,
            iface,
            sockets,
            fake_dns,
            udp_dns_handle,
            listeners: Vec::new(),
            connections: HashMap::new(),
            listened_ports: std::collections::HashSet::new(),
            cancel,
            conn_semaphore: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            sniffer_semaphore: Arc::new(Semaphore::new(MAX_SNIFFERS)),
            rules,
            handler_ctx,
            epoch,
        }
    }

    /// Run the main driver loop. Returns when the cancellation token fires
    /// or the TUN device is closed.
    pub async fn run(mut self) {
        let mut tun_buf = vec![0u8; TUN_BUF_SIZE];

        loop {
            // Phase 1: Read from TUN (non-blocking) or wait for events.
            let read_result = tokio::select! {
                biased;
                _ = self.cancel.cancelled() => {
                    debug!("TUN driver cancelled");
                    break;
                }
                result = self.tun.read(&mut tun_buf) => result,
            };

            match read_result {
                Ok(0) => {
                    debug!("TUN device closed (read 0 bytes)");
                    break;
                }
                Ok(n) => {
                    let packet = &tun_buf[..n];

                    // Before feeding to smoltcp, parse the packet to set up
                    // TCP listeners dynamically. This ensures smoltcp has a
                    // socket ready to accept the SYN.
                    if let Some((dst_port, proto)) = parse_ip_dst(packet) {
                        if proto == IpProto::Tcp {
                            self.ensure_listener(dst_port);
                        }
                        // Port 53 UDP is handled by the smoltcp UDP socket.
                    }

                    self.device.enqueue_rx(packet.to_vec());
                }
                Err(e) => {
                    warn!("TUN read error: {e}");
                    break;
                }
            }

            // Phase 2: Poll smoltcp.
            self.poll_smoltcp();

            // Phase 3: Handle UDP DNS (port 53).
            self.handle_dns_udp();

            // Phase 4: Accept new TCP connections from listeners that
            // transitioned out of LISTEN state.
            self.accept_tcp_connections();

            // Phase 5: Relay data between smoltcp TCP sockets and handler channels.
            self.relay_tcp_data();

            // Phase 6: Clean up finished connections.
            self.cleanup_finished_connections();

            // Phase 7: Poll smoltcp again (handler data may have produced new output).
            self.poll_smoltcp();

            // Phase 8: Flush smoltcp output to the TUN device.
            self.flush_to_tun().await;
        }

        // Drain phase: abort remaining handler tasks by dropping channels.
        debug!(
            "TUN driver shutting down, {} active connections",
            self.connections.len()
        );
    }

    // Internal methods ================================================================================================

    fn smoltcp_now(&self) -> SmoltcpInstant {
        let elapsed = self.epoch.elapsed();
        SmoltcpInstant::from_millis(elapsed.as_millis() as i64)
    }

    fn poll_smoltcp(&mut self) {
        let now = self.smoltcp_now();
        self.iface.poll(now, &mut self.device, &mut self.sockets);
    }

    fn handle_dns_udp(&mut self) {
        let Some(handle) = self.udp_dns_handle else {
            return;
        };
        let Some(fake_dns) = &self.fake_dns else {
            return;
        };

        let udp_socket = self.sockets.get_mut::<udp::Socket>(handle);

        // Process all queued datagrams.
        while udp_socket.can_recv() {
            let (payload, meta) = match udp_socket.recv() {
                Ok(v) => v,
                Err(udp::RecvError::Truncated) => continue,
                Err(udp::RecvError::Exhausted) => break,
            };

            let response = fake_dns.handle_udp(payload);
            if response.is_empty() {
                continue;
            }

            // Reply to the sender.
            let reply_endpoint = IpEndpoint {
                addr: meta.endpoint.addr,
                port: meta.endpoint.port,
            };
            if let Err(e) = udp_socket.send_slice(&response, reply_endpoint) {
                trace!("DNS UDP reply send error: {e:?}");
            }
        }
    }

    fn accept_tcp_connections(&mut self) {
        // Check each listener to see if it has accepted a connection
        // (transitioned from LISTEN to ESTABLISHED or SYN-RECEIVED).
        let mut accepted = Vec::new();

        for listener in &self.listeners {
            let socket = self.sockets.get::<tcp::Socket>(listener.handle);
            if socket.state() != tcp::State::Listen {
                accepted.push((listener.handle, listener.port));
            }
        }

        for (handle, port) in accepted {
            // Remove this listener.
            self.listeners.retain(|l| l.handle != handle);
            self.listened_ports.remove(&port);

            let socket = self.sockets.get::<tcp::Socket>(handle);

            // The local endpoint is the destination the client intended
            // to connect to (since any_ip is enabled, smoltcp accepted
            // the packet to an arbitrary IP).
            let (dst_ip, dst_port) = match socket.local_endpoint() {
                Some(ep) => (smoltcp_to_std_ip(ep.addr), ep.port),
                None => {
                    warn!("accepted TCP connection with no local endpoint on port {port}");
                    let socket = self.sockets.get_mut::<tcp::Socket>(handle);
                    socket.abort();
                    self.sockets.remove(handle);
                    self.ensure_listener(port);
                    continue;
                }
            };

            // Try to acquire a connection semaphore permit.
            let permit = match self.conn_semaphore.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    warn!("connection limit reached, rejecting {dst_ip}:{dst_port}");
                    let socket = self.sockets.get_mut::<tcp::Socket>(handle);
                    socket.abort();
                    self.sockets.remove(handle);
                    self.ensure_listener(port);
                    continue;
                }
            };

            // Create SmoltcpStream channels.
            let (stream, to_handler, from_handler) = SmoltcpStream::new();

            // Register the connection for relay.
            self.connections.insert(
                handle,
                TcpConn {
                    to_handler,
                    from_handler,
                },
            );

            // Spawn handler task.
            let env = tcp_handler::ConnEnv {
                ctx: Arc::clone(&self.handler_ctx),
                rules: Arc::clone(&self.rules),
                fake_dns: self.fake_dns.clone(),
                sniffer_semaphore: Arc::clone(&self.sniffer_semaphore),
                cancel: self.cancel.clone(),
            };

            tokio::spawn(async move {
                let result = tcp_handler::handle_tcp_connection(stream, dst_ip, dst_port, env).await;
                if let Err(e) = result {
                    trace!("TCP handler error for {dst_ip}:{dst_port}: {e}");
                }
                drop(permit);
            });

            // Re-create listener for this port for subsequent connections.
            // Known limitation: 1-poll-interval SYN race window.
            self.ensure_listener(port);
        }
    }

    fn relay_tcp_data(&mut self) {
        let handles: Vec<SocketHandle> = self.connections.keys().copied().collect();

        for handle in handles {
            let conn = match self.connections.get_mut(&handle) {
                Some(c) => c,
                None => continue,
            };

            let socket = self.sockets.get_mut::<tcp::Socket>(handle);

            // Direction: smoltcp → handler (recv from socket, send to handler).
            if socket.may_recv() {
                let _ = socket.recv(|buf| {
                    if buf.is_empty() {
                        return (0, ());
                    }
                    // Try to send to handler via channel. If the channel is
                    // full, don't dequeue from the socket — this naturally
                    // constrains the recv window.
                    match conn.to_handler.try_send(buf.to_vec()) {
                        Ok(()) => (buf.len(), ()),
                        Err(mpsc::error::TrySendError::Full(_)) => (0, ()),
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            // Handler dropped. The cleanup pass will handle this.
                            (0, ())
                        }
                    }
                });
            }

            // Direction: handler → smoltcp (recv from handler, send to socket).
            if socket.may_send() {
                while socket.can_send() {
                    match conn.from_handler.try_recv() {
                        Ok(data) => match socket.send_slice(&data) {
                            Ok(sent) => {
                                if sent < data.len() {
                                    trace!("partial smoltcp send: {sent}/{} bytes", data.len());
                                }
                            }
                            Err(_) => break,
                        },
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => {
                            // Handler finished writing. Close the smoltcp socket's
                            // send half so FIN gets sent.
                            socket.close();
                            break;
                        }
                    }
                }
            }
        }
    }

    fn cleanup_finished_connections(&mut self) {
        let finished: Vec<SocketHandle> = self
            .connections
            .keys()
            .copied()
            .filter(|&handle| {
                let socket = self.sockets.get::<tcp::Socket>(handle);
                matches!(socket.state(), tcp::State::Closed | tcp::State::TimeWait)
            })
            .collect();

        for handle in finished {
            self.connections.remove(&handle);
            self.sockets.remove(handle);
        }
    }

    async fn flush_to_tun(&mut self) {
        let packets = self.device.dequeue_tx();
        for pkt in packets {
            if let Err(e) = self.tun.write_all(&pkt).await {
                trace!("TUN write error: {e}");
                break;
            }
        }
    }

    /// Ensure a TCP listener socket exists for the given port.
    fn ensure_listener(&mut self, port: u16) {
        if self.listened_ports.contains(&port) {
            return;
        }
        let rx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUF_SIZE]);
        let tx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUF_SIZE]);
        let mut socket = tcp::Socket::new(rx_buf, tx_buf);
        if let Err(e) = socket.listen(port) {
            warn!("failed to listen on port {port}: {e:?}");
            return;
        }
        let handle = self.sockets.add(socket);
        self.listeners.push(TcpListener { handle, port });
        self.listened_ports.insert(port);
    }
}

// Helpers =============================================================================================================

/// Parse an incoming IP packet and return the destination port and protocol
/// for TCP/UDP. Used to dynamically create smoltcp listeners.
fn parse_ip_dst(packet: &[u8]) -> Option<(u16, IpProto)> {
    if packet.is_empty() {
        return None;
    }
    let version = packet[0] >> 4;
    match version {
        4 => parse_ipv4_dst(packet),
        6 => parse_ipv6_dst(packet),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpProto {
    Tcp,
    Udp,
}

fn parse_ipv4_dst(packet: &[u8]) -> Option<(u16, IpProto)> {
    // Minimum IPv4 header is 20 bytes.
    if packet.len() < 20 {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    let protocol = packet[9];
    if packet.len() < ihl + 4 {
        return None;
    }
    let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
    match protocol {
        6 => Some((dst_port, IpProto::Tcp)),
        17 => Some((dst_port, IpProto::Udp)),
        _ => None,
    }
}

fn parse_ipv6_dst(packet: &[u8]) -> Option<(u16, IpProto)> {
    // IPv6 header is 40 bytes fixed.
    if packet.len() < 40 + 4 {
        return None;
    }
    let next_header = packet[6];
    // We only handle TCP/UDP in the base header (no extension header chasing).
    let dst_port = u16::from_be_bytes([packet[42], packet[43]]);
    match next_header {
        6 => Some((dst_port, IpProto::Tcp)),
        17 => Some((dst_port, IpProto::Udp)),
        _ => None,
    }
}

/// Convert a smoltcp `IpAddress` to a `std::net::IpAddr`.
///
/// smoltcp 0.12 re-exports `core::net::Ipv4Addr`/`Ipv6Addr` as its
/// address types, so this is a trivial wrapping.
fn smoltcp_to_std_ip(addr: IpAddress) -> IpAddr {
    match addr {
        IpAddress::Ipv4(v4) => IpAddr::V4(v4),
        IpAddress::Ipv6(v6) => IpAddr::V6(v6),
    }
}

#[cfg(test)]
#[path = "driver_tests.rs"]
mod driver_tests;

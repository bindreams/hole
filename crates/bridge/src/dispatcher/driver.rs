//! TUN driver main loop — bridges the OS TUN device with the smoltcp
//! userspace TCP/IP stack, dispatches new TCP connections to handler tasks,
//! and serves port-53 DNS via a smoltcp UDP socket when fake DNS is active.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant as StdInstant};

use arc_swap::ArcSwap;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmoltcpInstant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr, UdpPacket,
    UdpRepr,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Semaphore};
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

use super::device::VirtualTunDevice;
use super::smoltcp_stream::SmoltcpStream;
use super::tcp_handler::{self, HandlerContext};
use super::udp_flow::{FlowEntry, FlowHandle, FlowKey, FlowTable};
use super::udp_handler::{self, UdpReply};
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
    /// Buffered remainder from a partial `smoltcp::send_slice` call.
    /// Drained on the next relay pass before reading new data from the channel.
    pending_send: Vec<u8>,
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
    handler_ctx: Arc<HandlerContext>,
    /// Reference time for converting std::time::Instant to smoltcp::time::Instant.
    epoch: StdInstant,

    // UDP flow dispatching --------------------------------------------------------------------------------------------
    flow_table: FlowTable,
    /// Channel for async flow-creation tasks to send completed entries back.
    new_flow_tx: mpsc::Sender<(FlowKey, FlowEntry)>,
    new_flow_rx: mpsc::Receiver<(FlowKey, FlowEntry)>,
    /// Channel for per-flow reader tasks to send reply datagrams.
    reply_tx: mpsc::Sender<UdpReply>,
    reply_rx: mpsc::Receiver<UdpReply>,
    /// Pending reply packets to write to TUN (built from `UdpReply`).
    pending_tun_writes: Vec<Vec<u8>>,
    /// Last time idle UDP flows were swept.
    last_sweep: StdInstant,
}

impl TunDriver {
    /// Create a new TUN driver.
    ///
    /// The TUN device must already be created and configured by the caller.
    pub fn new(
        tun: tun::AsyncDevice,
        fake_dns: Option<Arc<FakeDns>>,
        rules: Arc<ArcSwap<RuleSet>>,
        handler_ctx: Arc<HandlerContext>,
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

        let (new_flow_tx, new_flow_rx) = mpsc::channel(256);
        let (reply_tx, reply_rx) = mpsc::channel(1024);

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
            flow_table: FlowTable::new(),
            new_flow_tx,
            new_flow_rx,
            reply_tx,
            reply_rx,
            pending_tun_writes: Vec::new(),
            last_sweep: StdInstant::now(),
        }
    }

    /// Run the main driver loop. Returns when the cancellation token fires
    /// or the TUN device is closed.
    pub async fn run(mut self) {
        let mut tun_buf = vec![0u8; TUN_BUF_SIZE];
        // Poll interval ensures handler→smoltcp data is relayed even
        // when no TUN packets are arriving (e.g. response data for
        // established connections).
        let mut poll_interval = tokio::time::interval(std::time::Duration::from_millis(1));
        poll_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            // Phase 1: Read from TUN OR poll interval tick OR cancel.
            let read_result = tokio::select! {
                biased;
                _ = self.cancel.cancelled() => {
                    debug!("TUN driver cancelled");
                    break;
                }
                result = self.tun.read(&mut tun_buf) => Some(result),
                _ = poll_interval.tick() => None,
            };

            if let Some(read_result) = read_result {
                match read_result {
                    Ok(0) => {
                        debug!("TUN device closed (read 0 bytes)");
                        break;
                    }
                    Ok(n) => {
                        let packet = &tun_buf[..n];

                        // General UDP: dispatch before smoltcp sees the packet.
                        // Returns true if the packet was consumed (non-DNS UDP).
                        let consumed = self.handle_general_udp(packet);

                        if !consumed {
                            // TCP or DNS-UDP: set up listeners and feed to smoltcp.
                            if let Some((dst_port, proto)) = parse_ip_dst(packet) {
                                if proto == IpProto::Tcp {
                                    self.ensure_listener(dst_port);
                                }
                            }
                            self.device.enqueue_rx(packet.to_vec());
                        }
                    }
                    Err(e) => {
                        warn!("TUN read error: {e}");
                        break;
                    }
                }
            }
            // If read_result is None, it was a poll-interval tick — we
            // still need to run phases 2-8 to relay handler data.

            // Phase 2: Poll smoltcp.
            self.poll_smoltcp();

            // Phase 3: Handle UDP DNS (port 53).
            self.handle_dns_udp();

            // Phase 3.5: Drain completed UDP flow creations.
            self.drain_new_flows();

            // Phase 4: Accept new TCP connections from listeners that
            // transitioned out of LISTEN state.
            self.accept_tcp_connections();

            // Phase 5: Relay data between smoltcp TCP sockets and handler channels.
            self.relay_tcp_data();

            // Phase 6: Clean up finished connections.
            self.cleanup_finished_connections();

            // Phase 6.5: Process UDP reply datagrams into pending TUN writes.
            self.process_udp_replies();

            // Phase 7: Poll smoltcp again (handler data may have produced new output).
            self.poll_smoltcp();

            // Phase 8: Flush smoltcp output AND pending UDP replies to TUN.
            self.flush_to_tun().await;

            // Phase 9: Sweep idle UDP flows periodically.
            if self.last_sweep.elapsed() >= Duration::from_secs(5) {
                self.sweep_udp_flows();
                self.last_sweep = StdInstant::now();
            }
        }

        // Drain phase: abort remaining handler tasks by dropping channels.
        debug!(
            "TUN driver shutting down, {} active TCP connections, {} active UDP flows",
            self.connections.len(),
            self.flow_table.len(),
        );
        self.flow_table.clear();
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
                    pending_send: Vec::new(),
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
                    debug!("TCP handler error for {dst_ip}:{dst_port}: {e}");
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
                // First, drain any pending partial send from the previous pass.
                if !conn.pending_send.is_empty() && socket.can_send() {
                    if let Ok(sent) = socket.send_slice(&conn.pending_send) {
                        if sent >= conn.pending_send.len() {
                            conn.pending_send.clear();
                        } else {
                            conn.pending_send.drain(..sent);
                        }
                    }
                }

                // Then read new data from the handler channel.
                while conn.pending_send.is_empty() && socket.can_send() {
                    match conn.from_handler.try_recv() {
                        Ok(data) => match socket.send_slice(&data) {
                            Ok(sent) if sent < data.len() => {
                                // Partial send: buffer the remainder for next pass.
                                conn.pending_send = data[sent..].to_vec();
                                break;
                            }
                            Ok(_) => {} // fully sent
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
        // Flush smoltcp output (TCP + DNS UDP).
        let packets = self.device.dequeue_tx();
        for pkt in packets {
            if let Err(e) = self.tun.write_all(&pkt).await {
                trace!("TUN write error: {e}");
                break;
            }
        }
        // Flush general UDP reply packets.
        for pkt in self.pending_tun_writes.drain(..) {
            if let Err(e) = self.tun.write_all(&pkt).await {
                trace!("TUN write error (UDP reply): {e}");
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

    // UDP flow dispatching ============================================================================================

    /// Handle a general (non-DNS) UDP packet. Returns `true` if the packet
    /// was consumed and should NOT be fed to smoltcp.
    fn handle_general_udp(&mut self, packet: &[u8]) -> bool {
        let parsed = match parse_ip_packet_full(packet) {
            Some(p) if p.proto == IpProto::Udp => p,
            _ => return false,
        };

        // DNS (port 53) when fake DNS is active goes through smoltcp.
        if parsed.dst_port == 53 && self.fake_dns.is_some() {
            return false;
        }

        let key = FlowKey {
            src_ip: parsed.src_ip,
            src_port: parsed.src_port,
            dst_ip: parsed.dst_ip,
            dst_port: parsed.dst_port,
        };

        let payload_start = parsed.payload_offset.min(packet.len());
        let payload_end = (parsed.payload_offset + parsed.payload_len).min(packet.len());
        let payload = &packet[payload_start..payload_end];

        // Existing flow: forward the datagram.
        if let Some(entry) = self.flow_table.get_mut(&key) {
            entry.last_activity = std::time::Instant::now();
            match &entry.handle {
                FlowHandle::Proxy { tx } | FlowHandle::Bypass { tx } => {
                    let _ = tx.try_send(payload.to_vec());
                }
                FlowHandle::Blocked => {} // silently drop
            }
            return true;
        }

        // New flow: spawn async creation. The first datagram(s) during
        // setup are dropped (UDP is lossy). If a second packet races while
        // creation is in-flight, a duplicate task spawns — the later insert
        // overwrites the earlier one harmlessly.
        let ctx = Arc::clone(&self.handler_ctx);
        let rules = self.rules.load_full();
        let fake_dns = self.fake_dns.clone();
        let reply_tx = self.reply_tx.clone();
        let cancel = self.cancel.clone();
        let new_flow_tx = self.new_flow_tx.clone();

        tokio::spawn(async move {
            match udp_handler::create_udp_flow(
                key.src_ip,
                key.src_port,
                key.dst_ip,
                key.dst_port,
                &ctx,
                &rules,
                &fake_dns,
                reply_tx,
                cancel,
            )
            .await
            {
                Ok(entry) => {
                    let _ = new_flow_tx.send((key, entry)).await;
                }
                Err(e) => {
                    debug!(error = %e, dst_ip = %key.dst_ip, dst_port = key.dst_port, "failed to create UDP flow");
                }
            }
        });

        true
    }

    /// Drain completed async flow creations into the flow table.
    fn drain_new_flows(&mut self) {
        while let Ok((key, entry)) = self.new_flow_rx.try_recv() {
            self.flow_table.insert(key, entry);
        }
    }

    /// Drain upstream UDP replies and build raw IP packets for TUN injection.
    fn process_udp_replies(&mut self) {
        while let Ok(reply) = self.reply_rx.try_recv() {
            let packet = build_udp_packet(
                reply.src_ip,
                reply.src_port,
                reply.dst_ip,
                reply.dst_port,
                &reply.payload,
            );
            if !packet.is_empty() {
                self.pending_tun_writes.push(packet);
            }
        }
    }

    /// Evict idle UDP flows and unpin their fake DNS entries.
    fn sweep_udp_flows(&mut self) {
        let evicted = self.flow_table.sweep(Duration::from_secs(30));
        let count = evicted.len();
        for entry in evicted {
            if let (Some(ref fdns), Some(ip)) = (&self.fake_dns, entry.pinned_ip) {
                fdns.unpin(ip);
            }
        }
        if count > 0 {
            debug!(count, "swept idle UDP flows");
        }
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

// Full packet parsing (for UDP flow dispatching) ----------------------------------------------------------------------

/// Parsed fields from an IP+TCP/UDP packet header.
struct ParsedPacket {
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    proto: IpProto,
    /// Byte offset where the L4 payload starts (after IP + TCP/UDP headers).
    payload_offset: usize,
    /// Length of the L4 payload in bytes.
    payload_len: usize,
}

/// Parse an IP packet into its full 5-tuple + payload location.
fn parse_ip_packet_full(packet: &[u8]) -> Option<ParsedPacket> {
    if packet.is_empty() {
        return None;
    }
    let version = packet[0] >> 4;
    match version {
        4 => parse_ipv4_full(packet),
        6 => parse_ipv6_full(packet),
        _ => None,
    }
}

fn parse_ipv4_full(packet: &[u8]) -> Option<ParsedPacket> {
    if packet.len() < 20 {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    let protocol = packet[9];
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;

    // Need at least IP header + 8 bytes for TCP/UDP ports + lengths.
    if packet.len() < ihl + 8 || total_len < ihl + 8 {
        return None;
    }

    let proto = match protocol {
        6 => IpProto::Tcp,
        17 => IpProto::Udp,
        _ => return None,
    };

    let src_ip = IpAddr::V4(std::net::Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]));
    let dst_ip = IpAddr::V4(std::net::Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]));
    let src_port = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
    let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);

    // For UDP the payload starts right after the 8-byte UDP header.
    // For TCP the data offset is in the TCP header itself, but we only
    // need full parsing for UDP here.
    let (payload_offset, payload_len) = if proto == IpProto::Udp {
        let udp_len = u16::from_be_bytes([packet[ihl + 4], packet[ihl + 5]]) as usize;
        let hdr = 8; // UDP header size
        (ihl + hdr, udp_len.saturating_sub(hdr))
    } else {
        // TCP: we don't use payload_offset for TCP flow dispatching,
        // but compute it for completeness.
        let data_offset = ((packet[ihl + 12] >> 4) as usize) * 4;
        let tcp_payload = total_len.saturating_sub(ihl + data_offset);
        (ihl + data_offset, tcp_payload)
    };

    Some(ParsedPacket {
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        proto,
        payload_offset,
        payload_len,
    })
}

fn parse_ipv6_full(packet: &[u8]) -> Option<ParsedPacket> {
    // IPv6 fixed header is 40 bytes; need at least 8 more for L4 ports.
    if packet.len() < 48 {
        return None;
    }
    let next_header = packet[6];
    let payload_length = u16::from_be_bytes([packet[4], packet[5]]) as usize;

    let proto = match next_header {
        6 => IpProto::Tcp,
        17 => IpProto::Udp,
        _ => return None,
    };

    let mut src_octets = [0u8; 16];
    src_octets.copy_from_slice(&packet[8..24]);
    let mut dst_octets = [0u8; 16];
    dst_octets.copy_from_slice(&packet[24..40]);

    let src_ip = IpAddr::V6(std::net::Ipv6Addr::from(src_octets));
    let dst_ip = IpAddr::V6(std::net::Ipv6Addr::from(dst_octets));

    let l4_start = 40; // fixed IPv6 header
    let src_port = u16::from_be_bytes([packet[l4_start], packet[l4_start + 1]]);
    let dst_port = u16::from_be_bytes([packet[l4_start + 2], packet[l4_start + 3]]);

    let (payload_offset, payload_len) = if proto == IpProto::Udp {
        let udp_len = u16::from_be_bytes([packet[l4_start + 4], packet[l4_start + 5]]) as usize;
        let hdr = 8;
        (l4_start + hdr, udp_len.saturating_sub(hdr))
    } else {
        let data_offset = ((packet[l4_start + 12] >> 4) as usize) * 4;
        let tcp_payload = payload_length.saturating_sub(data_offset);
        (l4_start + data_offset, tcp_payload)
    };

    Some(ParsedPacket {
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        proto,
        payload_offset,
        payload_len,
    })
}

// Reply packet construction -------------------------------------------------------------------------------------------

/// Build a raw IP+UDP packet from the given fields, with correct checksums.
fn build_udp_packet(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let checksums = ChecksumCapabilities::default(); // compute all checksums

    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let ip_repr = Ipv4Repr {
                src_addr: src,
                dst_addr: dst,
                next_header: IpProtocol::Udp,
                payload_len: udp_len,
                hop_limit: 64,
            };
            let total = ip_repr.buffer_len() + udp_len;
            let mut buf = vec![0u8; total];

            let mut ip_pkt = Ipv4Packet::new_unchecked(&mut buf);
            ip_repr.emit(&mut ip_pkt, &checksums);

            let ip_hdr_len = ip_repr.buffer_len();
            let mut udp_pkt = UdpPacket::new_unchecked(&mut buf[ip_hdr_len..]);
            let udp_repr = UdpRepr { src_port, dst_port };
            udp_repr.emit(
                &mut udp_pkt,
                &IpAddress::Ipv4(src),
                &IpAddress::Ipv4(dst),
                payload.len(),
                |buf| buf.copy_from_slice(payload),
                &checksums,
            );

            buf
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let ip_repr = Ipv6Repr {
                src_addr: src,
                dst_addr: dst,
                next_header: IpProtocol::Udp,
                payload_len: udp_len,
                hop_limit: 64,
            };
            let total = ip_repr.buffer_len() + udp_len;
            let mut buf = vec![0u8; total];

            let mut ip_pkt = Ipv6Packet::new_unchecked(&mut buf);
            ip_repr.emit(&mut ip_pkt);

            let ip_hdr_len = ip_repr.buffer_len();
            let mut udp_pkt = UdpPacket::new_unchecked(&mut buf[ip_hdr_len..]);
            let udp_repr = UdpRepr { src_port, dst_port };
            udp_repr.emit(
                &mut udp_pkt,
                &IpAddress::Ipv6(src),
                &IpAddress::Ipv6(dst),
                payload.len(),
                |buf| buf.copy_from_slice(payload),
                &checksums,
            );

            buf
        }
        _ => {
            // Mismatched IP versions — should never happen.
            debug!("mismatched IP versions in UDP reply");
            Vec::new()
        }
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

//! Driver — the smoltcp-backed packet loop.
//!
//! Owns the real TUN device, the wall clock, the connection map, and the
//! UDP flow table; the smoltcp layer lives in
//! [`SocketStack`](super::socket_stack::SocketStack). Reads packets,
//! dispatches TCP accepts + UDP flows to the caller-supplied
//! [`Router`](super::Router), handles port-53 UDP via the optional
//! [`DnsInterceptor`](super::DnsInterceptor).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant as StdInstant;

use smoltcp::iface::SocketHandle;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::time::Instant as SmoltcpInstant;
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr, UdpPacket, UdpRepr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Semaphore};
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

use super::admission::{decide_admission, Admission};
use super::config::EngineConfig;
use super::dns::DnsInterceptor;
use super::router::{Router, TcpMeta, UdpMeta};
use super::socket_stack::{decide_disposal, Disposal, Handshake, SocketStack};
use super::tcp_flow::TcpFlow;
use super::udp_flow::{FlowKey, FlowTable, UdpReply};
use crate::device::DeviceConfig;

// Internal state ======================================================================================================

/// Tracks a TCP connection that the driver is relaying data for between
/// the smoltcp socket and the Router task.
struct TcpConn {
    /// Send data TO the Router (the Router reads via `flow.read()`).
    to_handler: mpsc::Sender<Vec<u8>>,
    /// Receive data FROM the Router (the Router wrote via `flow.write()`).
    from_handler: mpsc::Receiver<Vec<u8>>,
    /// Buffered remainder from a partial `smoltcp::send_slice` call.
    /// Drained on the next relay pass before reading new data from the channel.
    pending_send: Vec<u8>,
}

pub(crate) struct Driver {
    tun: tun::AsyncDevice,
    stack: SocketStack,
    dns_interceptor: Option<Arc<dyn DnsInterceptor>>,
    connections: HashMap<SocketHandle, TcpConn>,
    cancel: CancellationToken,
    conn_semaphore: Arc<Semaphore>,
    sniffer_semaphore: Arc<Semaphore>,
    router: Arc<dyn Router>,
    config: Arc<EngineConfig>,
    /// Reference time for converting `std::time::Instant` to
    /// `smoltcp::time::Instant`.
    epoch: StdInstant,

    // UDP flow dispatching --------------------------------------------------------------------------------------------
    flow_table: FlowTable,
    /// Channel per-flow Router tasks use to inject reply datagrams.
    reply_tx: mpsc::Sender<UdpReply>,
    reply_rx: mpsc::Receiver<UdpReply>,
    /// Pending reply packets to write to TUN (built from `UdpReply`).
    pending_tun_writes: Vec<Vec<u8>>,
    /// Last time idle UDP flows were swept.
    last_sweep: StdInstant,
}

impl Driver {
    pub(crate) fn new(
        tun: tun::AsyncDevice,
        device_config: DeviceConfig,
        router: Arc<dyn Router>,
        config: Arc<EngineConfig>,
        cancel: CancellationToken,
    ) -> Self {
        let stack = SocketStack::new(&device_config, &config);
        let epoch = StdInstant::now();
        let (reply_tx, reply_rx) = mpsc::channel(1024);

        Self {
            tun,
            stack,
            dns_interceptor: config.dns_interceptor.clone(),
            connections: HashMap::new(),
            cancel,
            conn_semaphore: Arc::new(Semaphore::new(config.max_connections)),
            sniffer_semaphore: Arc::new(Semaphore::new(config.max_sniffers)),
            router,
            config,
            epoch,
            flow_table: FlowTable::new(),
            reply_tx,
            reply_rx,
            pending_tun_writes: Vec::new(),
            last_sweep: StdInstant::now(),
        }
    }

    pub(crate) async fn run(mut self) {
        let tun_buf_size = self.config.tcp_rx_buf_size.max(2048); // safe upper bound for a single IP packet
        let mut tun_buf = vec![0u8; tun_buf_size];
        // Poll interval ensures handler→smoltcp data is relayed even when
        // no TUN packets are arriving.
        let mut poll_interval = tokio::time::interval(self.config.poll_interval);
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
                        let consumed = self.handle_udp_packet(packet).await;

                        if !consumed {
                            if let Some((dst_port, proto)) = parse_ip_dst(packet) {
                                if proto == IpProto::Tcp {
                                    self.stack.ensure_listener(dst_port);
                                }
                            }
                            self.stack.enqueue_rx(packet.to_vec());
                        }
                    }
                    Err(e) => {
                        warn!("TUN read error: {e}");
                        break;
                    }
                }
            }

            // Phase 2: poll smoltcp.
            self.poll_smoltcp();
            self.accept_tcp_connections();
            self.relay_tcp_data();
            self.cleanup_finished_connections();
            self.process_udp_replies();
            self.poll_smoltcp();
            self.flush_to_tun().await;

            if self.last_sweep.elapsed() >= self.config.idle_sweep_interval {
                let evicted = self.flow_table.sweep(self.config.udp_flow_idle_timeout);
                if evicted > 0 {
                    debug!(count = evicted, "swept idle UDP flows");
                }
                self.last_sweep = StdInstant::now();
            }
        }

        debug!(
            "TUN driver shutting down, {} active TCP connections, {} active UDP flows",
            self.connections.len(),
            self.flow_table.len(),
        );
        self.flow_table.clear();
    }

    // smoltcp polling =================================================================================================

    fn smoltcp_now(&self) -> SmoltcpInstant {
        let elapsed = self.epoch.elapsed();
        SmoltcpInstant::from_millis(elapsed.as_millis() as i64)
    }

    fn poll_smoltcp(&mut self) {
        let now = self.smoltcp_now();
        self.stack.poll(now);
    }

    // TCP =============================================================================================================

    fn accept_tcp_connections(&mut self) {
        for handshake in self.stack.take_handshakes() {
            let semaphore = Arc::clone(&self.conn_semaphore);
            let verdict = decide_admission(&handshake, move || semaphore.try_acquire_owned().ok());

            let (handle, port, peer) = match handshake {
                Handshake::Pending { handle, port, src, dst } => (handle, port, Some((src, dst))),
                // A contract branch: `take_handshakes` classifies on an Option
                // pair the type system does not narrow. Neither verdict answers
                // its socket, so neither needs an address.
                Handshake::Stale { handle, port } | Handshake::Duplicate { handle, port } => (handle, port, None),
            };

            let permit = match verdict {
                Admission::Discard => {
                    warn!("accepted TCP connection with no endpoint on port {port}");
                    self.stack.discard(handle, port);
                    continue;
                }
                Admission::Duplicate => {
                    debug!("retransmitted SYN for a connection already owned on port {port}");
                    self.stack.drop_duplicate(handle, port);
                    continue;
                }
                Admission::Refuse => {
                    let (_, dst) = peer.expect("decide_admission refuses only a handshake with a peer");
                    warn!("connection limit reached, rejecting {}:{}", dst.ip(), dst.port());
                    self.stack.refuse(handle, port);
                    continue;
                }
                Admission::Admit(permit) => permit,
            };
            let (src, dst) = peer.expect("decide_admission admits only a handshake with a peer");
            let (dst_ip, dst_port) = (dst.ip(), dst.port());

            let (flow, to_handler, from_handler) = TcpFlow::new(Arc::clone(&self.sniffer_semaphore));

            self.connections.insert(
                handle,
                TcpConn {
                    to_handler,
                    from_handler,
                    pending_send: Vec::new(),
                },
            );

            let meta = TcpMeta { src, dst };
            let router = Arc::clone(&self.router);
            let cancel = self.cancel.clone();
            tokio::spawn(async move {
                let result = tokio::select! {
                    biased;
                    _ = cancel.cancelled() => Ok(()),
                    r = router.route_tcp(meta, flow) => r,
                };
                if let Err(e) = result {
                    debug!("TCP Router error for {dst_ip}:{dst_port}: {e}");
                }
                drop(permit);
            });

            self.stack.admit(handle, port);
        }
    }

    fn relay_tcp_data(&mut self) {
        let handles: Vec<SocketHandle> = self.connections.keys().copied().collect();

        for handle in handles {
            let conn = match self.connections.get_mut(&handle) {
                Some(c) => c,
                None => continue,
            };
            let socket = self.stack.socket_mut(handle);

            // Direction: smoltcp → Router.
            if socket.may_recv() {
                let _ = socket.recv(|buf| {
                    if buf.is_empty() {
                        return (0, ());
                    }
                    match conn.to_handler.try_send(buf.to_vec()) {
                        Ok(()) => (buf.len(), ()),
                        Err(mpsc::error::TrySendError::Full(_)) => (0, ()),
                        Err(mpsc::error::TrySendError::Closed(_)) => (0, ()),
                    }
                });
            }

            // Direction: Router → smoltcp.
            if socket.may_send() {
                if !conn.pending_send.is_empty() && socket.can_send() {
                    if let Ok(sent) = socket.send_slice(&conn.pending_send) {
                        if sent >= conn.pending_send.len() {
                            conn.pending_send.clear();
                        } else {
                            conn.pending_send.drain(..sent);
                        }
                    }
                }

                while conn.pending_send.is_empty() && socket.can_send() {
                    match conn.from_handler.try_recv() {
                        Ok(data) => match socket.send_slice(&data) {
                            Ok(sent) if sent < data.len() => {
                                conn.pending_send = data[sent..].to_vec();
                                break;
                            }
                            Ok(_) => {}
                            Err(_) => break,
                        },
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => {
                            socket.close();
                            break;
                        }
                    }
                }
            }
        }
    }

    fn cleanup_finished_connections(&mut self) {
        let finished: Vec<(SocketHandle, Disposal)> = self
            .connections
            .keys()
            .copied()
            .filter_map(|handle| Some((handle, decide_disposal(self.stack.socket(handle).state())?)))
            .collect();

        for (handle, disposal) in finished {
            // Dropping the entry closes the channels, which ends the router
            // task and releases its permit.
            self.connections.remove(&handle);
            match disposal {
                Disposal::Retire => self.stack.retire(handle),
                Disposal::Remove => self.stack.remove(handle),
            }
        }
    }

    // UDP =============================================================================================================

    /// Handle a UDP packet before smoltcp sees it. Returns `true` if the
    /// packet was consumed (dispatched to the Router, or handled by the
    /// DNS interceptor), in which case the caller must NOT feed it to
    /// smoltcp.
    async fn handle_udp_packet(&mut self, packet: &[u8]) -> bool {
        let parsed = match parse_ip_packet_full(packet) {
            Some(p) if p.proto == IpProto::Udp => p,
            _ => return false,
        };

        let payload_start = parsed.payload_offset.min(packet.len());
        let payload_end = (parsed.payload_offset + parsed.payload_len).min(packet.len());
        let payload = &packet[payload_start..payload_end];

        // Port-53 DNS interception.
        if parsed.dst.port() == 53 {
            if let Some(interceptor) = self.dns_interceptor.clone() {
                if let Some(reply) = interceptor.intercept(payload).await {
                    // Construct reply packet with swapped 5-tuple.
                    let pkt = build_udp_packet(parsed.dst, parsed.src, &reply);
                    if !pkt.is_empty() {
                        self.pending_tun_writes.push(pkt);
                    }
                    return true;
                }
                // Interceptor returned None — fall through to Router dispatch.
            }
        }

        let key = FlowKey {
            src: parsed.src,
            dst: parsed.dst,
        };

        // Existing flow: forward the datagram.
        if let Some(entry) = self.flow_table.get_mut(&key) {
            entry.last_activity = StdInstant::now();
            // Best-effort push; if the flow's channel is full, drop (UDP is lossy).
            let _ = entry.tx.try_send(payload.to_vec());
            return true;
        }

        // New flow: create a UdpFlow and spawn the Router task.
        let flow = self.flow_table.insert_new(key, self.reply_tx.clone());
        // Seed the first datagram into the flow.
        if let Some(entry) = self.flow_table.get_mut(&key) {
            let _ = entry.tx.try_send(payload.to_vec());
        }

        let meta = UdpMeta {
            src: parsed.src,
            dst: parsed.dst,
        };
        let router = Arc::clone(&self.router);
        let cancel = self.cancel.clone();
        tokio::spawn(async move {
            let result = tokio::select! {
                biased;
                _ = cancel.cancelled() => Ok(()),
                r = router.route_udp(meta, flow) => r,
            };
            if let Err(e) = result {
                debug!("UDP Router error for {}: {e}", parsed.dst);
            }
        });

        true
    }

    fn process_udp_replies(&mut self) {
        while let Ok(reply) = self.reply_rx.try_recv() {
            let pkt = build_udp_packet(reply.src, reply.dst, &reply.payload);
            if !pkt.is_empty() {
                self.pending_tun_writes.push(pkt);
            }
        }
    }

    // TUN I/O =========================================================================================================

    async fn flush_to_tun(&mut self) {
        // smoltcp output (TCP).
        let packets = self.stack.dequeue_tx();
        for pkt in packets {
            if let Err(e) = self.tun.write_all(&pkt).await {
                trace!("TUN write error: {e}");
                break;
            }
        }
        // UDP replies + DNS intercepts.
        for pkt in self.pending_tun_writes.drain(..) {
            if let Err(e) = self.tun.write_all(&pkt).await {
                trace!("TUN write error (UDP reply): {e}");
                break;
            }
        }
    }
}

// Packet parsing ======================================================================================================

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
    if packet.len() < 40 + 4 {
        return None;
    }
    let next_header = packet[6];
    let dst_port = u16::from_be_bytes([packet[42], packet[43]]);
    match next_header {
        6 => Some((dst_port, IpProto::Tcp)),
        17 => Some((dst_port, IpProto::Udp)),
        _ => None,
    }
}

struct ParsedPacket {
    src: SocketAddr,
    dst: SocketAddr,
    proto: IpProto,
    payload_offset: usize,
    payload_len: usize,
}

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

    let (payload_offset, payload_len) = if proto == IpProto::Udp {
        let udp_len = u16::from_be_bytes([packet[ihl + 4], packet[ihl + 5]]) as usize;
        let hdr = 8;
        (ihl + hdr, udp_len.saturating_sub(hdr))
    } else {
        let data_offset = ((packet[ihl + 12] >> 4) as usize) * 4;
        let tcp_payload = total_len.saturating_sub(ihl + data_offset);
        (ihl + data_offset, tcp_payload)
    };

    Some(ParsedPacket {
        src: SocketAddr::new(src_ip, src_port),
        dst: SocketAddr::new(dst_ip, dst_port),
        proto,
        payload_offset,
        payload_len,
    })
}

fn parse_ipv6_full(packet: &[u8]) -> Option<ParsedPacket> {
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

    let l4_start = 40;
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
        src: SocketAddr::new(src_ip, src_port),
        dst: SocketAddr::new(dst_ip, dst_port),
        proto,
        payload_offset,
        payload_len,
    })
}

// Reply packet construction ===========================================================================================

/// Build a raw IP+UDP packet from the given fields, with correct checksums.
fn build_udp_packet(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    debug_assert!(src.is_ipv4() == dst.is_ipv4(), "src/dst IP family mismatch");

    let udp_len = 8 + payload.len();
    let checksums = ChecksumCapabilities::default();
    let src_port = src.port();
    let dst_port = dst.port();

    match (src.ip(), dst.ip()) {
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
            debug!("mismatched IP versions in UDP reply");
            Vec::new()
        }
    }
}

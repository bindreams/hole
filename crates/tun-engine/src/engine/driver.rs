//! Driver — the smoltcp-backed packet loop.
//!
//! Owns the real TUN device, the wall clock, the connection map, and the
//! UDP flow table; the smoltcp layer lives in
//! [`SocketStack`](super::socket_stack::SocketStack). Reads packets,
//! dispatches TCP accepts + UDP flows to the caller-supplied
//! [`Router`](super::Router), handles port-53 UDP via the optional
//! [`DnsInterceptor`](super::DnsInterceptor).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant as StdInstant;

use smoltcp::iface::SocketHandle;
use smoltcp::time::Instant as SmoltcpInstant;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Semaphore};
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

use super::admission::{decide_admission, Admission};
use super::config::EngineConfig;
use super::dns::DnsInterceptor;
use super::emit::build_udp_packet;
use super::parse::{parse_ip_dst, parse_ip_packet_full, IpProto};
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

/// `T` is the TUN device. It is a parameter, not `tun::AsyncDevice` outright,
/// so a test can drive the accept and disposal dispatch over an in-memory pipe
/// — opening a real TUN needs elevation.
pub(crate) struct Driver<T = tun::AsyncDevice> {
    tun: T,
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

impl<T: AsyncRead + AsyncWrite + Unpin> Driver<T> {
    pub(crate) fn new(
        tun: T,
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

            let mut settle: Option<Vec<u8>> = None;
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
                            settle = Some(packet.to_vec());
                        }
                    }
                    Err(e) => {
                        warn!("TUN read error: {e}");
                        break;
                    }
                }
            }

            // Phase 2: settle the packet (if any) and flush what it produced.
            let now = self.smoltcp_now();
            self.settle_packet(settle.as_deref(), now);
            self.process_udp_replies();
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

    /// Feed at most one packet through smoltcp and settle every consequence of
    /// it — TCP admission, data relay, and retirement — before returning.
    ///
    /// Two packets' verdicts must never straddle one `poll()`: a socket
    /// mid-retirement, still bound to its port, would intercept the next SYN
    /// with no accept path able to see it
    /// (`a_reverted_socket_would_hijack_a_later_syn`). Bundling enqueue, both
    /// polls, admission, relay and retirement into one call with no seam
    /// between them makes that impossible regardless of how many packets a
    /// future `run()` reads per iteration.
    fn settle_packet(&mut self, packet: Option<&[u8]>, now: SmoltcpInstant) {
        if let Some(packet) = packet {
            if let Some((dst_port, IpProto::Tcp)) = parse_ip_dst(packet) {
                self.stack.ensure_listener(dst_port);
            }
            self.stack.enqueue_rx(packet.to_vec());
        }
        self.stack.poll(now);
        self.accept_tcp_connections();
        self.relay_tcp_data();
        self.cleanup_finished_connections();
        self.stack.poll(now);
    }

    // TCP =============================================================================================================

    fn accept_tcp_connections(&mut self) {
        for handshake in self.stack.take_handshakes() {
            let semaphore = Arc::clone(&self.conn_semaphore);
            let verdict = decide_admission(&handshake, move || semaphore.try_acquire_owned().ok());

            let (handle, port, peer, supersedes) = match handshake {
                Handshake::Pending {
                    handle,
                    port,
                    src,
                    dst,
                    supersedes,
                } => (handle, port, Some((src, dst)), supersedes),
                // A duplicate answers no socket, so it needs no address.
                Handshake::Duplicate { handle, port } => (handle, port, None, None),
            };

            if let Some(stale) = supersedes {
                warn!("new SYN on port {port} carries an ISN its tuple's owner never sent; the stale connection is torn down");
                self.connections.remove(&stale);
                self.stack.remove(stale);
            }

            let permit = match verdict {
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

        let payload = parsed.payload;

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
        let dst = parsed.dst;
        let router = Arc::clone(&self.router);
        let cancel = self.cancel.clone();
        tokio::spawn(async move {
            let result = tokio::select! {
                biased;
                _ = cancel.cancelled() => Ok(()),
                r = router.route_udp(meta, flow) => r,
            };
            if let Err(e) = result {
                debug!("UDP Router error for {}: {e}", dst);
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

#[cfg(test)]
#[path = "driver_tests.rs"]
mod driver_tests;

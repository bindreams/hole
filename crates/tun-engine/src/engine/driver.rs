//! Driver — the smoltcp-backed packet loop.
//!
//! Owns the real TUN device, the smoltcp `Interface`, socket set, and
//! UDP flow table. Reads packets, dispatches TCP accepts + UDP flows to
//! the caller-supplied [`Router`](super::Router), handles port-53 UDP via
//! the optional [`DnsInterceptor`](super::DnsInterceptor).

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant as StdInstant;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmoltcpInstant;
use smoltcp::wire::{HardwareAddress, IpCidr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Semaphore};
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

use super::config::EngineConfig;
use super::dns::DnsInterceptor;
use super::emit::{build_udp_packet, smoltcp_to_std_ip};
use super::parse::{parse_ip_dst, parse_ip_packet_full, IpProto};
use super::router::{Router, TcpMeta, UdpMeta};
use super::tcp_flow::TcpFlow;
use super::udp_flow::{FlowKey, FlowTable, UdpReply};
use super::virtual_device::VirtualTunDevice;
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

/// Tracks a TCP listener socket in smoltcp waiting for incoming SYN packets.
struct TcpListener {
    handle: SocketHandle,
    port: u16,
}

pub(crate) struct Driver {
    tun: tun::AsyncDevice,
    device: VirtualTunDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    dns_interceptor: Option<Arc<dyn DnsInterceptor>>,
    listeners: Vec<TcpListener>,
    connections: HashMap<SocketHandle, TcpConn>,
    listened_ports: HashSet<u16>,
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
        let mtu = device_config.mtu as usize;
        let mut device = VirtualTunDevice::new(mtu);

        let iface_config = Config::new(HardwareAddress::Ip);
        let epoch = StdInstant::now();
        let now = SmoltcpInstant::from_millis(0);
        let mut iface = Interface::new(iface_config, &mut device, now);
        iface.set_any_ip(true);
        iface.update_ip_addrs(|addrs| {
            if let Some(v4) = device_config.ipv4 {
                addrs.push(IpCidr::Ipv4(v4)).unwrap();
            }
            if let Some(v6) = device_config.ipv6 {
                addrs.push(IpCidr::Ipv6(v6)).unwrap();
            }
        });

        let sockets = SocketSet::new(vec![]);

        let (reply_tx, reply_rx) = mpsc::channel(1024);

        Self {
            tun,
            device,
            iface,
            sockets,
            dns_interceptor: config.dns_interceptor.clone(),
            listeners: Vec::new(),
            connections: HashMap::new(),
            listened_ports: HashSet::new(),
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
        self.iface.poll(now, &mut self.device, &mut self.sockets);
    }

    // TCP =============================================================================================================

    fn ensure_listener(&mut self, port: u16) {
        if self.listened_ports.contains(&port) {
            return;
        }
        let rx_buf = tcp::SocketBuffer::new(vec![0u8; self.config.tcp_rx_buf_size]);
        let tx_buf = tcp::SocketBuffer::new(vec![0u8; self.config.tcp_tx_buf_size]);
        let mut socket = tcp::Socket::new(rx_buf, tx_buf);
        if let Err(e) = socket.listen(port) {
            warn!("failed to listen on port {port}: {e:?}");
            return;
        }
        let handle = self.sockets.add(socket);
        self.listeners.push(TcpListener { handle, port });
        self.listened_ports.insert(port);
    }

    fn accept_tcp_connections(&mut self) {
        let mut accepted = Vec::new();
        for listener in &self.listeners {
            let socket = self.sockets.get::<tcp::Socket>(listener.handle);
            if socket.state() != tcp::State::Listen {
                accepted.push((listener.handle, listener.port));
            }
        }

        for (handle, port) in accepted {
            self.listeners.retain(|l| l.handle != handle);
            self.listened_ports.remove(&port);

            let socket = self.sockets.get::<tcp::Socket>(handle);
            let (dst_ip, dst_port, src_ip, src_port) = match (socket.local_endpoint(), socket.remote_endpoint()) {
                (Some(local), Some(remote)) => (
                    smoltcp_to_std_ip(local.addr),
                    local.port,
                    smoltcp_to_std_ip(remote.addr),
                    remote.port,
                ),
                _ => {
                    warn!("accepted TCP connection with no endpoint on port {port}");
                    let socket = self.sockets.get_mut::<tcp::Socket>(handle);
                    socket.abort();
                    self.sockets.remove(handle);
                    self.ensure_listener(port);
                    continue;
                }
            };

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

            let (flow, to_handler, from_handler) = TcpFlow::new(Arc::clone(&self.sniffer_semaphore));

            self.connections.insert(
                handle,
                TcpConn {
                    to_handler,
                    from_handler,
                    pending_send: Vec::new(),
                },
            );

            let meta = TcpMeta {
                src: SocketAddr::new(src_ip, src_port),
                dst: SocketAddr::new(dst_ip, dst_port),
            };
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
        let packets = self.device.dequeue_tx();
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

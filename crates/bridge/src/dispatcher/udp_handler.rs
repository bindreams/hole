//! Per-datagram UDP handler: filter decision + flow creation.

use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::filter::engine::{decide, ConnInfo, L4Proto};
use crate::filter::rules::RuleSet;
use crate::filter::FakeDns;
use hole_common::config::FilterAction;

use super::bypass::create_bypass_udp;
use super::socks5_udp::Socks5UdpRelay;
use super::tcp_handler::HandlerContext;
use super::udp_flow::{FlowEntry, FlowHandle};

/// Channel capacity for per-flow datagram forwarding. Full -> drop (UDP is lossy).
const FLOW_CHANNEL_CAPACITY: usize = 128;

/// A reply datagram from an upstream socket, to be written back to the TUN.
pub struct UdpReply {
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub payload: Vec<u8>,
}

/// Create a new UDP flow: run filter engine, create upstream socket, spawn reader task.
///
/// Returns the `FlowEntry` to be inserted into the flow table by the driver.
#[allow(clippy::too_many_arguments)]
pub async fn create_udp_flow(
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    ctx: &HandlerContext,
    rules: &RuleSet,
    fake_dns: &Option<Arc<FakeDns>>,
    reply_tx: mpsc::Sender<UdpReply>,
    cancel: CancellationToken,
) -> std::io::Result<FlowEntry> {
    // 1. Fake DNS reverse lookup.
    let mut domain: Option<String> = None;
    let mut pinned_ip: Option<IpAddr> = None;
    if let Some(ref fdns) = fake_dns {
        if let Some(d) = fdns.reverse_lookup(dst_ip) {
            domain = Some(d.to_string());
            fdns.pin(dst_ip);
            pinned_ip = Some(dst_ip);
        }
    }

    // 2. Build ConnInfo and decide.
    let result = create_udp_flow_inner(
        src_ip, src_port, dst_ip, dst_port, &domain, pinned_ip, ctx, rules, fake_dns, reply_tx, cancel,
    )
    .await;

    // Unpin on failure so the fake DNS slot is not leaked.
    if result.is_err() {
        if let (Some(ref fdns), Some(ip)) = (fake_dns, pinned_ip) {
            fdns.unpin(ip);
        }
    }

    result
}

#[allow(clippy::too_many_arguments)]
async fn create_udp_flow_inner(
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    domain: &Option<String>,
    pinned_ip: Option<IpAddr>,
    ctx: &HandlerContext,
    rules: &RuleSet,
    fake_dns: &Option<Arc<FakeDns>>,
    reply_tx: mpsc::Sender<UdpReply>,
    cancel: CancellationToken,
) -> std::io::Result<FlowEntry> {
    let conn_info = ConnInfo {
        dst_ip,
        dst_port,
        domain: domain.clone(),
        proto: L4Proto::Udp,
    };
    let decision = decide(rules, &conn_info);
    let mut action = decision.action;

    // 3. Plugin incompatibility: downgrade Proxy -> Bypass when UDP relay
    //    is unavailable (v2ray-plugin does not support UDP).
    if action == FilterAction::Proxy && !ctx.udp_proxy_available {
        let mut block_log = ctx.block_log.lock().unwrap();
        if block_log.should_log(decision.rule_index.unwrap_or(0) as u32, dst_ip, dst_port) {
            warn!(dst_ip = %dst_ip, dst_port, "UDP proxy unavailable (v2ray-plugin), bypassing");
        }
        action = FilterAction::Bypass;
    }

    // 4. Resolve bypass IP if needed.
    let real_ip = if action == FilterAction::Bypass {
        resolve_bypass_ip(dst_ip, domain.as_deref(), fake_dns, ctx).await?
    } else {
        dst_ip
    };

    // 5. Check IPv6 bypass availability.
    if action == FilterAction::Bypass && real_ip.is_ipv6() && !ctx.ipv6_available {
        if !ctx.ipv6_bypass_warned.swap(true, Ordering::Relaxed) {
            warn!("IPv6 bypass unavailable for UDP, blocking");
        }
        action = FilterAction::Block;
    }

    // 6. Create the flow.
    let domain = domain.clone();
    let now = std::time::Instant::now();
    match action {
        FilterAction::Proxy => {
            create_proxy_flow(
                src_ip, src_port, dst_ip, dst_port, real_ip, domain, pinned_ip, ctx, reply_tx, cancel, now,
            )
            .await
        }
        FilterAction::Bypass => {
            create_bypass_flow(
                src_ip, src_port, dst_ip, dst_port, real_ip, domain, pinned_ip, ctx, reply_tx, cancel, now,
            )
            .await
        }
        FilterAction::Block => {
            let rule_index = decision.rule_index.unwrap_or(0) as u32;
            let mut block_log = ctx.block_log.lock().unwrap();
            if block_log.should_log(rule_index, dst_ip, dst_port) {
                info!(dst_ip = %dst_ip, dst_port, domain = ?domain, "blocked UDP flow");
            }
            Ok(FlowEntry {
                handle: FlowHandle::Blocked,
                last_activity: now,
                domain,
                pinned_ip,
            })
        }
    }
}

// Flow creation helpers ===============================================================================================

#[allow(clippy::too_many_arguments)]
async fn create_proxy_flow(
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    real_ip: IpAddr,
    domain: Option<String>,
    pinned_ip: Option<IpAddr>,
    ctx: &HandlerContext,
    reply_tx: mpsc::Sender<UdpReply>,
    cancel: CancellationToken,
    now: std::time::Instant,
) -> std::io::Result<FlowEntry> {
    let relay = Arc::new(Socks5UdpRelay::associate(ctx.local_port).await?);
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(FLOW_CHANNEL_CAPACITY);

    // Reader task: recv from SOCKS5 relay, send reply back to TUN.
    let relay2 = Arc::clone(&relay);
    let cancel2 = cancel.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            tokio::select! {
                biased;
                _ = cancel2.cancelled() => break,
                result = relay2.recv_from(&mut buf) => {
                    match result {
                        Ok((n, _src_ip, _src_port)) => {
                            let _ = reply_tx.try_send(UdpReply {
                                dst_ip: src_ip,
                                dst_port: src_port,
                                src_ip: dst_ip,
                                src_port: dst_port,
                                payload: buf[..n].to_vec(),
                            });
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    });

    // Forwarder task: read from channel, send via relay.
    let domain2 = domain.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                msg = rx.recv() => {
                    match msg {
                        Some(payload) => {
                            let _ = relay.send_to(real_ip, dst_port, domain2.as_deref(), &payload).await;
                        }
                        None => break,
                    }
                }
            }
        }
    });

    Ok(FlowEntry {
        handle: FlowHandle::Proxy { tx },
        last_activity: now,
        domain,
        pinned_ip,
    })
}

#[allow(clippy::too_many_arguments)]
async fn create_bypass_flow(
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    real_ip: IpAddr,
    domain: Option<String>,
    pinned_ip: Option<IpAddr>,
    ctx: &HandlerContext,
    reply_tx: mpsc::Sender<UdpReply>,
    cancel: CancellationToken,
    now: std::time::Instant,
) -> std::io::Result<FlowEntry> {
    let socket = create_bypass_udp(ctx.iface_index, real_ip.is_ipv6()).await?;
    socket.connect(std::net::SocketAddr::new(real_ip, dst_port)).await?;
    let socket = Arc::new(socket);

    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(FLOW_CHANNEL_CAPACITY);

    // Reader task: recv from bypass socket, send reply.
    let socket2 = Arc::clone(&socket);
    let cancel2 = cancel.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            tokio::select! {
                biased;
                _ = cancel2.cancelled() => break,
                result = socket2.recv(&mut buf) => {
                    match result {
                        Ok(n) => {
                            let _ = reply_tx.try_send(UdpReply {
                                dst_ip: src_ip,
                                dst_port: src_port,
                                src_ip: dst_ip,
                                src_port: dst_port,
                                payload: buf[..n].to_vec(),
                            });
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    });

    // Forwarder task: read from channel, send via socket.
    let socket3 = Arc::clone(&socket);
    tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                msg = rx.recv() => {
                    match msg {
                        Some(payload) => { let _ = socket3.send(&payload).await; }
                        None => break,
                    }
                }
            }
        }
    });

    Ok(FlowEntry {
        handle: FlowHandle::Bypass { tx },
        last_activity: now,
        domain,
        pinned_ip,
    })
}

// Helpers =============================================================================================================

/// Resolve the real IP for a bypass-path connection.
async fn resolve_bypass_ip(
    dst_ip: IpAddr,
    domain: Option<&str>,
    fake_dns: &Option<Arc<FakeDns>>,
    ctx: &HandlerContext,
) -> std::io::Result<IpAddr> {
    let is_fake = fake_dns.as_ref().is_some_and(|fdns| fdns.is_fake_ip(dst_ip));
    if !is_fake {
        return Ok(dst_ip);
    }

    let domain =
        domain.ok_or_else(|| std::io::Error::other("bypass: dst_ip is in fake DNS pool but no domain available"))?;
    let addrs = ctx.upstream_resolver.resolve(domain).await?;
    addrs
        .into_iter()
        .next()
        .ok_or_else(|| std::io::Error::other(format!("bypass: no addresses resolved for {domain}")))
}

#[cfg(test)]
#[path = "udp_handler_tests.rs"]
mod udp_handler_tests;

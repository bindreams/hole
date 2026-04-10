//! Per-TCP-connection handler task. Each connection runs through:
//! 1. Port 53 fast path (DNS over TCP)
//! 2. Fake DNS reverse lookup (pin on success)
//! 3. Optional sniffer peek (2 KiB, 100 ms budget)
//! 4. Filter engine decision
//! 5. Dispatch: proxy / bypass / block

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use super::block_log::BlockLog;
use super::bypass::create_bypass_tcp;
use super::smoltcp_stream::SmoltcpStream;
use super::socks5_client::socks5_connect;
use super::upstream_dns::UpstreamResolver;
use crate::filter::engine::{ConnInfo, L4Proto};
use crate::filter::rules::RuleSet;
use crate::filter::{self, FakeDns};
use hole_common::config::FilterAction;

// Constants ===========================================================================================================

/// Maximum bytes to peek for the sniffer (TLS ClientHello + HTTP request line).
const PEEK_BUF_SIZE: usize = 2048;

/// Maximum time to wait for the first payload bytes (for sniffer).
const PEEK_TIMEOUT: Duration = Duration::from_millis(100);

// Context shared across all handler tasks =============================================================================

/// Shared state for all TCP handler tasks. Created once by the Dispatcher
/// and passed (via Arc) to each spawned handler.
pub struct TcpHandlerContext {
    /// SS SOCKS5 local port on 127.0.0.1.
    pub local_port: u16,
    /// Upstream interface index for bypass sockets.
    pub iface_index: u32,
    /// Whether the upstream interface has IPv6 connectivity.
    pub ipv6_available: bool,
    /// Upstream DNS resolver for the bypass path.
    pub upstream_resolver: UpstreamResolver,
    /// Rate-limited block log. Uses `std::sync::Mutex` because the
    /// critical section is sub-microsecond and never held across .await.
    pub block_log: std::sync::Mutex<BlockLog>,
    /// One-time flag: emitted when IPv6 bypass falls back to block.
    pub ipv6_bypass_warned: AtomicBool,
}

// Handler entry point =================================================================================================

/// Per-connection environment, bundled to avoid clippy::too_many_arguments.
pub struct ConnEnv {
    pub ctx: Arc<TcpHandlerContext>,
    pub rules: Arc<ArcSwap<RuleSet>>,
    pub fake_dns: Option<Arc<FakeDns>>,
    pub sniffer_semaphore: Arc<Semaphore>,
    pub cancel: CancellationToken,
}

/// Handle a single TCP connection from smoltcp.
pub async fn handle_tcp_connection(
    mut stream: SmoltcpStream,
    dst_ip: IpAddr,
    dst_port: u16,
    env: ConnEnv,
) -> std::io::Result<()> {
    // Run the handler with cancellation support.
    tokio::select! {
        biased;
        _ = env.cancel.cancelled() => Ok(()),
        result = handle_inner(
            &mut stream, dst_ip, dst_port, &env.ctx, &env.rules,
            env.fake_dns.as_deref(), &env.sniffer_semaphore
        ) => result,
    }
}

async fn handle_inner(
    stream: &mut SmoltcpStream,
    dst_ip: IpAddr,
    dst_port: u16,
    ctx: &TcpHandlerContext,
    rules: &ArcSwap<RuleSet>,
    fake_dns: Option<&FakeDns>,
    sniffer_semaphore: &Semaphore,
) -> std::io::Result<()> {
    // Step 1: Port 53 fast path — DNS over TCP.
    if dst_port == 53 {
        if let Some(dns) = fake_dns {
            return dns.handle_tcp(stream).await;
        }
    }

    // Step 2: Fake DNS reverse lookup.
    let mut domain: Option<String> = None;
    let mut pinned = false;

    if let Some(dns) = fake_dns {
        if let Some(d) = dns.reverse_lookup(dst_ip) {
            domain = Some(d.to_string());
            dns.pin(dst_ip);
            pinned = true;
        }
    }

    // Ensure we unpin on all exit paths if we pinned.
    let denv = DispatchEnv {
        ctx,
        rules,
        fake_dns,
        sniffer_semaphore,
    };
    let result = dispatch(stream, dst_ip, dst_port, &mut domain, &denv).await;

    if pinned {
        if let Some(dns) = fake_dns {
            dns.unpin(dst_ip);
        }
    }

    result
}

/// Bundled dispatch environment (avoids too_many_arguments).
struct DispatchEnv<'a> {
    ctx: &'a TcpHandlerContext,
    rules: &'a ArcSwap<RuleSet>,
    fake_dns: Option<&'a FakeDns>,
    sniffer_semaphore: &'a Semaphore,
}

async fn dispatch(
    stream: &mut SmoltcpStream,
    dst_ip: IpAddr,
    dst_port: u16,
    domain: &mut Option<String>,
    env: &DispatchEnv<'_>,
) -> std::io::Result<()> {
    // Step 3: Sniffer peek — only when domain is unknown AND domain rules exist.
    let mut peek_buf = Vec::new();
    let current_rules = env.rules.load();

    if domain.is_none() && current_rules.has_domain_rules {
        // Acquire sniffer semaphore (bounded concurrency for peeks).
        if let Ok(_permit) = env.sniffer_semaphore.try_acquire() {
            let mut buf = [0u8; PEEK_BUF_SIZE];
            match tokio::time::timeout(PEEK_TIMEOUT, stream.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    peek_buf = buf[..n].to_vec();
                    if let Some(sni) = filter::peek(&peek_buf) {
                        *domain = Some(sni);
                    }
                }
                Ok(Ok(_)) => {} // EOF or 0 bytes
                Ok(Err(e)) => return Err(e),
                Err(_) => {} // timeout — proceed without domain
            }
        }
    }

    // Step 4: Filter engine decision.
    let conn_info = ConnInfo {
        dst_ip,
        dst_port,
        domain: domain.clone(),
        proto: L4Proto::Tcp,
    };
    let decision = filter::decide(&current_rules, &conn_info);
    drop(current_rules);

    // Step 5: Dispatch.
    match decision.action {
        FilterAction::Proxy => dispatch_proxy(stream, dst_ip, dst_port, domain, env.ctx, &peek_buf).await,
        FilterAction::Bypass => {
            dispatch_bypass(stream, dst_ip, dst_port, domain, env.ctx, env.fake_dns, &peek_buf).await
        }
        FilterAction::Block => {
            dispatch_block(dst_ip, dst_port, domain.as_deref(), env.ctx, &decision);
            Ok(())
        }
    }
}

// Dispatch paths ======================================================================================================

async fn dispatch_proxy(
    stream: &mut SmoltcpStream,
    dst_ip: IpAddr,
    dst_port: u16,
    domain: &Option<String>,
    ctx: &TcpHandlerContext,
    peek_buf: &[u8],
) -> std::io::Result<()> {
    let mut upstream = socks5_connect(ctx.local_port, dst_ip, dst_port, domain.as_deref()).await?;

    // Write peek buffer if non-empty.
    if !peek_buf.is_empty() {
        upstream.write_all(peek_buf).await?;
    }

    tokio::io::copy_bidirectional(stream, &mut upstream).await?;
    Ok(())
}

async fn dispatch_bypass(
    stream: &mut SmoltcpStream,
    dst_ip: IpAddr,
    dst_port: u16,
    domain: &Option<String>,
    ctx: &TcpHandlerContext,
    fake_dns: Option<&FakeDns>,
    peek_buf: &[u8],
) -> std::io::Result<()> {
    // Resolve the real IP if dst_ip is a fake DNS address.
    let real_ip = resolve_bypass_ip(dst_ip, domain.as_deref(), ctx, fake_dns).await?;

    // Check IPv6 availability for bypass.
    if real_ip.is_ipv6() && !ctx.ipv6_available {
        if !ctx.ipv6_bypass_warned.swap(true, Ordering::Relaxed) {
            warn!("IPv6 bypass requested but upstream has no IPv6; falling back to block");
        }
        return Ok(());
    }

    let mut upstream = create_bypass_tcp(real_ip, dst_port, ctx.iface_index).await?;

    // Write peek buffer if non-empty.
    if !peek_buf.is_empty() {
        upstream.write_all(peek_buf).await?;
    }

    tokio::io::copy_bidirectional(stream, &mut upstream).await?;
    Ok(())
}

fn dispatch_block(
    dst_ip: IpAddr,
    dst_port: u16,
    domain: Option<&str>,
    ctx: &TcpHandlerContext,
    decision: &filter::Decision,
) {
    let rule_index = decision.rule_index.unwrap_or(0) as u32;
    let should_log = ctx.block_log.lock().unwrap().should_log(rule_index, dst_ip, dst_port);

    if should_log {
        match domain {
            Some(d) => debug!("blocked {d} ({dst_ip}:{dst_port}) by rule #{rule_index}"),
            None => debug!("blocked {dst_ip}:{dst_port} by rule #{rule_index}"),
        }
    }
    // Connection is dropped → smoltcp sends RST.
}

// Helpers =============================================================================================================

/// Determine the real IP address for a bypass connection.
///
/// If `dst_ip` is in the fake DNS pool, resolve the domain via the
/// upstream resolver. Otherwise use `dst_ip` directly (the sniffer
/// recovered the domain but the IP is already real).
async fn resolve_bypass_ip(
    dst_ip: IpAddr,
    domain: Option<&str>,
    ctx: &TcpHandlerContext,
    fake_dns: Option<&FakeDns>,
) -> std::io::Result<IpAddr> {
    // Only resolve if the IP is a fake DNS synthetic IP.
    let is_fake = fake_dns.is_some_and(|dns| dns.is_fake_ip(dst_ip));

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
#[path = "tcp_handler_tests.rs"]
mod tcp_handler_tests;

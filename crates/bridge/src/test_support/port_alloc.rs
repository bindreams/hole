//! Ephemeral port allocation + liveness probe helpers for tests.
//!
//! Port allocation delegates to [`hole_common::port_alloc::free_port`],
//! which runs one bind probe per transport and retries Windows-specific
//! bind races (WSAEACCES, EADDRINUSE, EADDRNOTAVAIL) internally. Callers
//! needing cross-test serialization still use the `PORT_ALLOC` skuld
//! label — `free_port`'s TOCTOU window (between probe drop and the real
//! owner's bind) is identical to the kernel allocator's.
//!
//! For callers that bind in-process and can use a closure shape, prefer
//! [`hole_common::port_alloc::bind_with_retry`] instead — it absorbs
//! the residual probe-drop-to-bind TOCTOU by retrying on `is_bind_race`
//! errors. This module's [`allocate_ephemeral_port`] is reserved for
//! the case where the port is handed across a process boundary (e.g.
//! to a `DistHarness` subprocess via JSON config) before the real bind
//! happens; the closure shape can't fit there. See bindreams/hole#285.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use hole_common::port_alloc::{self, Protocols};

/// Pre-allocate a port number on loopback verified free for every
/// transport in `protocols`, and immediately drop the holder. The port
/// is used to construct a bind address before the real owner binds.
/// There is a tiny TOCTOU window between drop and the real bind;
/// `PORT_ALLOC`-serialized fixtures don't race each other for the same
/// port.
///
/// Callers must declare the right `protocols` set: a TCP-only probe
/// followed by a TCP+UDP bind invites the Windows independent
/// excluded-port-range race that #285 exists to prevent. For SOCKS5
/// listener ports use `Protocols::TCP | Protocols::UDP` (the bridge
/// SOCKS5 listener is structurally `Mode::TcpAndUdp`); for HTTP CONNECT
/// listener ports use `Protocols::TCP`.
///
/// Direct delegation to `free_port` is suppressed-disallowed (see
/// workspace `clippy.toml`) — this helper is the explicit exception
/// because the port must be returned to the caller for external
/// configuration before the bind happens.
#[allow(
    clippy::disallowed_methods,
    reason = "this helper is the canonical exception to the bind_with_retry rule: the port is handed across a process boundary via JSON config"
)]
pub(crate) async fn allocate_ephemeral_port(protocols: Protocols) -> u16 {
    port_alloc::free_port(IpAddr::V4(Ipv4Addr::LOCALHOST), protocols)
        .await
        .expect("allocate ephemeral port")
}

/// Poll-connect to `addr` until either a TCP connection succeeds or
/// `timeout` elapses. Used by tests that spawn a child process which binds
/// asynchronously after the parent function returns. Panics on timeout
/// with a per-attempt error histogram for diagnostics.
///
/// Each connect attempt is wrapped in a 500 ms `tokio::time::timeout`. On
/// Windows, `TcpStream::connect` to a port that fails to SYN-ACK can block
/// for the OS connect-timer (~21 s default), which would let only 1–2
/// attempts fit in a 10 s budget. The wrapper forces fast retries so the
/// histogram reflects the actual attempt distribution.
///
/// Diagnostics use `eprintln!` (not `tracing::*`) on purpose: installing a
/// global tracing subscriber in the bridge test binary triggers the #147
/// LogTracer regression that times out `server_test_tests` on Windows CI.
/// See `crates/bridge/src/ipc_tests.rs:827-844`.
pub(crate) async fn wait_for_port(addr: SocketAddr, timeout: Duration) {
    let start = Instant::now();
    let mut attempts: u32 = 0;
    let mut first_err: Option<(Option<i32>, String)> = None;
    let mut last_err: Option<(Option<i32>, String)> = None;
    let mut error_counts: BTreeMap<Option<i32>, u32> = BTreeMap::new();

    while start.elapsed() < timeout {
        attempts += 1;
        let attempt_start = Instant::now();
        let outcome = tokio::time::timeout(Duration::from_millis(500), tokio::net::TcpStream::connect(addr)).await;
        match outcome {
            Ok(Ok(_stream)) => {
                eprintln!(
                    "[wait_for_port] connect OK to {addr} after {attempts} attempts, {}ms total",
                    start.elapsed().as_millis()
                );
                return;
            }
            Ok(Err(e)) => {
                let code = e.raw_os_error();
                let pair = (code, e.to_string());
                eprintln!(
                    "[wait_for_port] attempt {attempts} to {addr} failed in {}ms: os_code={:?} kind={:?} {}",
                    attempt_start.elapsed().as_millis(),
                    code,
                    e.kind(),
                    e
                );
                *error_counts.entry(code).or_default() += 1;
                if first_err.is_none() {
                    first_err = Some(pair.clone());
                }
                last_err = Some(pair);
            }
            Err(_) => {
                let pair = (None, "per-attempt 500ms timeout".to_string());
                eprintln!("[wait_for_port] attempt {attempts} to {addr} hit per-attempt 500ms timeout");
                *error_counts.entry(None).or_default() += 1;
                if first_err.is_none() {
                    first_err = Some(pair.clone());
                }
                last_err = Some(pair);
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    eprintln!(
        "[wait_for_port] TIMEOUT on {addr} after {}s, {attempts} attempts, error_counts={error_counts:?}, first={first_err:?}, last={last_err:?}",
        timeout.as_secs()
    );

    // Capture OS-level state before we die. Best-effort.
    #[cfg(windows)]
    capture_windows_tcp_state(addr.port());

    panic!(
        "port {addr} did not become connectable within {timeout:?} \
        ({attempts} attempts, error counts: {error_counts:?}, \
        first: {first_err:?}, last: {last_err:?})"
    );
}

/// Dump Windows TCP table state for `port` to stderr. Called from
/// `wait_for_port` immediately before `panic!` to disambiguate H1–H5 in
/// #200: shows whether the port is in LISTEN state at the moment the test
/// gives up, and on which address family.
///
/// Synchronous `std::process::Command::output()` is acceptable here — we
/// are about to panic and the test has already failed. A stuck PowerShell
/// is self-limiting: nextest hard-kills the process at its 30 s
/// `terminate-after`. Also dumps `netstat -ano -p tcp` as a secondary
/// source — different code path (kernel NETSTAT IOCTL vs NetTCPIP WMI),
/// rules out PowerShell-module corruption.
#[cfg(windows)]
fn capture_windows_tcp_state(port: u16) {
    // Primary: PowerShell Get-NetTCPConnection.
    let ps_cmd = format!(
        "Get-NetTCPConnection -LocalPort {port} -ErrorAction SilentlyContinue \
         | Format-Table -AutoSize | Out-String"
    );
    match std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &ps_cmd])
        .output()
    {
        Ok(o) => {
            eprintln!(
                "[wait_for_port] Get-NetTCPConnection stdout:\n{}",
                String::from_utf8_lossy(&o.stdout)
            );
            if !o.stderr.is_empty() {
                eprintln!(
                    "[wait_for_port] Get-NetTCPConnection stderr:\n{}",
                    String::from_utf8_lossy(&o.stderr)
                );
            }
        }
        Err(e) => eprintln!("[wait_for_port] powershell spawn failed: {e}"),
    }

    // Secondary: netstat.
    match std::process::Command::new("netstat")
        .args(["-ano", "-p", "tcp"])
        .output()
    {
        Ok(o) => {
            let out = String::from_utf8_lossy(&o.stdout);
            let needle = format!(":{port}");
            for line in out.lines().filter(|l| l.contains(&needle)) {
                eprintln!("[wait_for_port] netstat: {line}");
            }
        }
        Err(e) => eprintln!("[wait_for_port] netstat spawn failed: {e}"),
    }

    // Belt-and-suspenders for H4 (IPv6 listener bound while we connect IPv4).
    let ps6 = format!(
        "Get-NetTCPConnection -LocalPort {port} -AddressFamily IPv6 -ErrorAction SilentlyContinue \
         | Format-Table -AutoSize | Out-String"
    );
    if let Ok(o) = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &ps6])
        .output()
    {
        if !o.stdout.is_empty() {
            eprintln!(
                "[wait_for_port] IPv6 Get-NetTCPConnection stdout:\n{}",
                String::from_utf8_lossy(&o.stdout)
            );
        }
    }

    // Routing table — critical for #200 root cause. If the previous
    // TUN-mode test left a stale `0.0.0.0/1` route pointing at a
    // destroyed TUN adapter, SYNs to 127.0.0.1 never reach the loopback
    // adapter. `route print -4` shows the IPv4 routing table including
    // interface indices so we can spot rows referencing a vanished
    // hole-tun.
    match std::process::Command::new("route").args(["print", "-4"]).output() {
        Ok(o) => {
            eprintln!(
                "[wait_for_port] route print -4:\n{}",
                String::from_utf8_lossy(&o.stdout)
            );
        }
        Err(e) => eprintln!("[wait_for_port] route print spawn failed: {e}"),
    }

    // Interface list — shows which interface indices currently exist,
    // so we can correlate route print's interface column with live
    // adapters (a route referencing a non-existent interface index is
    // the #200 smoking gun).
    match std::process::Command::new("netsh")
        .args(["interface", "ipv4", "show", "interfaces"])
        .output()
    {
        Ok(o) => {
            eprintln!(
                "[wait_for_port] netsh interface ipv4 show interfaces:\n{}",
                String::from_utf8_lossy(&o.stdout)
            );
        }
        Err(e) => eprintln!("[wait_for_port] netsh show interfaces spawn failed: {e}"),
    }

    // WFP state for this failure is captured by the bridge itself via
    // `crate::diagnostics::wfp::log_snapshot("startup")` and
    // `log_snapshot("post-teardown")` — emitted through the same tracing
    // subscriber as the rest of the bridge log, so it reaches users via
    // `hole bridge log` and CI via the panic-hook's bridge-log tail
    // dump. Keeping the diagnostic in the bridge (which runs elevated)
    // also avoids the `show filters` admin-elevation requirement for
    // the test process. See crates/bridge/src/diagnostics/wfp.rs.
    //
    // The test-process TCP control-loopback probe that used to live
    // here served its purpose (CI run 3 on PR #207 showed loopback is
    // broken machine-wide, ruling out H8). Removing it now keeps the
    // failure capture focused on cheap evidence we don't already have.

    // ICMP loopback probe. If ping 127.0.0.1 succeeds while TCP
    // connects hang, we're seeing the SYN-not-transmitted shape
    // documented in microsoft/Windows-Containers#620 (Windows Server
    // 2025 regression). If ping also hangs, the loopback adapter
    // itself is broken.
    //
    // `-n 3` = 3 echo requests; `-w 500` = 500 ms per-request timeout
    // (1.5 s total upper bound). `-4` forces IPv4 — we only care about
    // the v4 loopback path.
    match std::process::Command::new("ping")
        .args(["-4", "-n", "3", "-w", "500", "127.0.0.1"])
        .output()
    {
        Ok(o) => {
            eprintln!(
                "[wait_for_port] ping 127.0.0.1 (exit={}):\n{}",
                o.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&o.stdout)
            );
        }
        Err(e) => eprintln!("[wait_for_port] ping spawn failed: {e}"),
    }

    // UDP loopback probe. `bind 127.0.0.1:0` + `send_to
    // 127.0.0.1:<target>` emits a datagram regardless of whether
    // anything is listening on <target>. The outcomes differentiate:
    //
    //   - `Ok(n)` → packet left the socket into loopback. If TCP is
    //     still hung, the kernel-level split is between UDP and TCP
    //     send paths, not an adapter-wide outage.
    //   - `Err(WSAECONNRESET)` → kernel delivered an ICMP
    //     port-unreachable for the UDP packet. Loopback is intact;
    //     TCP-specific state is broken.
    //   - Blocking / hang → UDP path is broken too; the break is
    //     deeper than transport layer.
    match std::net::UdpSocket::bind("127.0.0.1:0") {
        Ok(sock) => {
            let _ = sock.set_write_timeout(Some(Duration::from_millis(500)));
            let target = format!("127.0.0.1:{port}");
            let start = Instant::now();
            match sock.send_to(b"hole-probe", &target) {
                Ok(n) => eprintln!(
                    "[wait_for_port] UDP probe: send_to {target} OK ({n} bytes, {}ms)",
                    start.elapsed().as_millis()
                ),
                Err(e) => eprintln!(
                    "[wait_for_port] UDP probe: send_to {target} err: os_code={:?} kind={:?} ({}ms): {e}",
                    e.raw_os_error(),
                    e.kind(),
                    start.elapsed().as_millis()
                ),
            }
        }
        Err(e) => eprintln!("[wait_for_port] UDP probe: bind 127.0.0.1:0 failed: {e}"),
    }
}

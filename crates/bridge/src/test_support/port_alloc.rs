//! Ephemeral TCP port allocation helpers.
//!
//! Tests need unique ephemeral ports for SOCKS5 local binds, v2ray-plugin
//! public-facing bindings, and similar. The kernel's own ephemeral-port
//! allocator is the source of truth; these helpers wrap the "bind to 0,
//! read port, drop" pattern with a consistent TOCTOU caveat.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;

/// Pre-allocate a TCP port number and immediately drop the listener. The
/// port is used to construct a bind address before the real owner binds.
/// There is a tiny TOCTOU window between drop and the real bind; in practice
/// the kernel does not reissue freshly-released ports immediately.
pub(crate) async fn allocate_ephemeral_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// Synchronous version for use from non-async test bodies. Same TOCTOU
/// semantics as [`allocate_ephemeral_port`].
pub(crate) fn allocate_ephemeral_port_sync() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
    // listener drops here — port is released.
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
}

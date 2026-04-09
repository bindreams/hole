//! Diagnostic test-only module for issue #165 — Windows CI loopback
//! timeout regression. **All code in this module is throwaway** and is
//! scheduled for deletion in the same PR that ships the root-cause fix.
//!
//! The investigation plan lives in
//! `~/.claude/plans/luminous-honking-cascade.md` (local-only). In short:
//! PR #163 (filter engine Plan 1) triggers 9 pre-existing Windows CI
//! test failures in `server_test_tests.rs` with `WSAETIMEDOUT` on raw
//! `TcpStream::connect` to a port `SsServerBuilder::build()` just
//! returned. Main CI passes the same tests on the same runner image.
//!
//! This module contains three diagnostic experiments that discriminate
//! between kernel-side causes (WFP/Defender filtering by PID or image
//! hash) and user-space causes (`Server::run` spawn path, tokio-on-
//! Windows IOCP race). It also contains a diagnostic helper for
//! capturing Windows-side state cheaply at checkpoints and more
//! aggressively on test failure.
//!
//! All captures are bounded to avoid observer effects: happy-path
//! logging is in-process only, expensive PowerShell captures fire only
//! on test failure.

use shadowsocks::config::{Mode, ServerConfig};
use shadowsocks::crypto::CipherKind;
use shadowsocks_service::server::ServerBuilder as SsServerBuilder;
use std::time::{Duration, Instant};

// Test constants ======================================================================================================

const TEST_METHOD: CipherKind = CipherKind::AES_256_GCM;
const TEST_PASSWORD: &str = "test-password-1234";

/// Fresh multi-thread runtime per test. Mirrors the pattern in
/// `server_test_tests::rt()` so this module doesn't accidentally share
/// a runtime across tests.
fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().unwrap()
}

// Windows diagnostics helpers =========================================================================================

#[cfg(target_os = "windows")]
mod diag {
    //! In-process and spawned-PowerShell diagnostic helpers.
    //!
    //! - `log_checkpoint` is cheap (in-process only) and safe to call
    //!   on the happy path.
    //! - `log_failure_snapshot` spawns PowerShell and is only safe to
    //!   call on the failure path (when a test is about to panic).

    use std::time::Instant;

    pub fn log_checkpoint(context: &str, bound_port: Option<u16>) {
        let handles = process_handle_count();
        let port_info = match bound_port {
            Some(port) => format!(" port={port}"),
            None => String::new(),
        };
        eprintln!("[diag:{context}] handles={handles}{port_info}");
    }

    pub fn log_failure_snapshot(context: &str, bound_port: Option<u16>) {
        let snapshot_start = Instant::now();
        let handles = process_handle_count();

        let port_filter = bound_port
            .map(|p| format!("| Where-Object LocalPort -eq {p}"))
            .unwrap_or_default();

        let ps_script = format!(
            r#"
            $ErrorActionPreference = 'Stop'
            $tcp = Get-NetTCPConnection
            $port_rows = @($tcp {port_filter})
            $snapshot = [PSCustomObject]@{{
                tcp_total     = $tcp.Count
                tcp_listen    = ($tcp | Where-Object State -eq 'Listen').Count
                tcp_estab     = ($tcp | Where-Object State -eq 'Established').Count
                tcp_time_wait = ($tcp | Where-Object State -eq 'TimeWait').Count
                port_rows     = $port_rows.Count
                port_states   = ($port_rows | ForEach-Object {{ $_.State }}) -join ','
                defender_rtp  = try {{ (Get-MpComputerStatus).RealTimeProtectionEnabled }} catch {{ 'unknown' }}
                fw_profiles   = (Get-NetFirewallProfile | ForEach-Object {{ $_.Enabled }}) -join ','
                dyn_tcp       = (Get-NetTCPSetting | Where-Object SettingName -eq 'InternetCustom' | ForEach-Object {{ $_.DynamicPortRangeStartPort }})
            }}
            $snapshot | ConvertTo-Json -Compress
            "#
        );

        let output = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &ps_script])
            .output()
            .expect(
                "failed to spawn powershell.exe for failure snapshot; \
                 diagnostic instrumentation is broken",
            );

        if !output.status.success() {
            eprintln!(
                "[diag:{context}] WARNING: powershell exited {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim(),
            );
            return;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        eprintln!(
            "[diag:{context}] FAILURE snapshot (took {:?}, handles={handles}) {}",
            snapshot_start.elapsed(),
            stdout.trim(),
        );
    }

    fn process_handle_count() -> u32 {
        use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessHandleCount};
        let mut count = 0u32;
        // SAFETY: GetCurrentProcess returns a pseudo-handle that's always
        // valid. GetProcessHandleCount writes to a valid u32 pointer we
        // own. Both calls are infallible under well-formed arguments; the
        // Result represents a BOOL → error mapping from `windows`.
        let result = unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut count) };
        result.expect("GetProcessHandleCount failed; diagnostic instrumentation is broken");
        count
    }
}

#[cfg(not(target_os = "windows"))]
mod diag {
    pub fn log_checkpoint(_context: &str, _bound_port: Option<u16>) {}
    pub fn log_failure_snapshot(_context: &str, _bound_port: Option<u16>) {}
}

// Primary experiment: bind and hold ===================================================================================

/// Primary experiment (per investigation plan). Build the SS server and
/// **keep it alive** (never call `run()`, never drop it), then attempt a
/// `TcpStream::connect` to the address that `build().await` returned.
/// This directly tests whether the bound-but-not-accepting listener is
/// reachable from within the same process.
///
/// Expected outcomes are enumerated in the result-to-diagnosis matrix
/// in the investigation plan. The most important distinction is:
/// - `Ok(_)` fast → kernel listener is reachable; bug is in `run()`
///   spawn path or tokio scheduling.
/// - `Err(TimedOut)` / WSAETIMEDOUT → kernel-side: bound listener exists
///   but SYNs aren't reaching it. Look at WFP/Defender filtering.
#[skuld::test]
fn diag_bind_and_hold() {
    rt().block_on(async {
        let mut svr_cfg = ServerConfig::new(("127.0.0.1", 0u16), TEST_PASSWORD.to_string(), TEST_METHOD).unwrap();
        svr_cfg.set_mode(Mode::TcpOnly);

        let build_start = Instant::now();
        let server = SsServerBuilder::new(svr_cfg).build().await.unwrap();
        let build_elapsed = build_start.elapsed();

        let svr_addr = server
            .tcp_server()
            .expect("TCP mode is enabled, tcp_server should exist")
            .local_addr()
            .unwrap();

        debug_assert!(svr_addr.ip().is_loopback(), "bound addr not loopback: {svr_addr}");
        debug_assert_ne!(svr_addr.port(), 0, "ephemeral port not assigned");

        diag::log_checkpoint("bind_and_hold:post-build", Some(svr_addr.port()));
        eprintln!(
            "[diag:bind_and_hold] built in {build_elapsed:?} at {svr_addr}; \
             server held alive, run() NOT called"
        );

        // NOTE: `server` is intentionally NOT dropped or moved here. It
        // remains alive on the stack for the duration of the connect
        // attempt. Because we never called `server.run()`, no accept
        // loop task exists — the kernel holds SYNs in the listen(1024)
        // backlog; Windows AFD completes the 3WHS from the backlog
        // without user-space accept.
        //
        // Expected on a healthy system: connect succeeds in < 1 ms.

        let connect_start = Instant::now();
        let result = tokio::time::timeout(Duration::from_secs(15), tokio::net::TcpStream::connect(svr_addr)).await;
        let elapsed = connect_start.elapsed();

        match result {
            Ok(Ok(_stream)) => {
                eprintln!("[diag:bind_and_hold] connect OK in {elapsed:?}");
            }
            Ok(Err(io_err)) => {
                eprintln!(
                    "[diag:bind_and_hold] connect failed after {elapsed:?}: \
                     kind={:?} raw_os_error={:?} msg={io_err}",
                    io_err.kind(),
                    io_err.raw_os_error()
                );
                diag::log_failure_snapshot("bind_and_hold:connect-failed", Some(svr_addr.port()));
                panic!("diag_bind_and_hold failed: see diagnostics above");
            }
            Err(_elapsed) => {
                eprintln!("[diag:bind_and_hold] connect did not return within 15s");
                diag::log_failure_snapshot("bind_and_hold:connect-hung", Some(svr_addr.port()));
                panic!("diag_bind_and_hold hung: see diagnostics above");
            }
        }

        // Explicit drop after the connect completes so the log timestamp
        // order is clear. Without this, `server` would drop at the end
        // of the async block, which is fine but less obvious.
        drop(server);
    });
}

// Supporting experiment S1: external probe ============================================================================

/// Spawn a PowerShell child process that probes the SS server address
/// from outside this process. Timestamp-correlated to prove the
/// listener was alive at the moment of the probe.
///
/// If the external probe succeeds while the in-process `diag_bind_and_hold`
/// fails → PID/image-hash firewall filter (H10/H11 confirmed).
/// If the external probe also fails → kernel-wide drop on this port.
#[cfg(target_os = "windows")]
#[skuld::test]
fn diag_external_probe() {
    rt().block_on(async {
        let mut svr_cfg = ServerConfig::new(("127.0.0.1", 0u16), TEST_PASSWORD.to_string(), TEST_METHOD).unwrap();
        svr_cfg.set_mode(Mode::TcpOnly);
        let server = SsServerBuilder::new(svr_cfg).build().await.unwrap();
        let svr_addr = server
            .tcp_server()
            .expect("TCP mode is enabled, tcp_server should exist")
            .local_addr()
            .unwrap();

        let t0 = Instant::now();
        eprintln!("[diag:external_probe] t0=0ms bound at {svr_addr}");

        let t1_offset = t0.elapsed();
        let output = std::process::Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!(
                    r#"
                    $ErrorActionPreference = 'Stop'
                    try {{
                      $r = Test-NetConnection -ComputerName 127.0.0.1 -Port {} -WarningAction SilentlyContinue
                      'ok=' + $r.TcpTestSucceeded + ' remote_addr=' + $r.RemoteAddress
                    }} catch {{
                      'err=' + $_.Exception.Message
                    }}
                    "#,
                    svr_addr.port()
                ),
            ])
            .output()
            .expect("failed to spawn powershell.exe for external probe");
        let t2_offset = t0.elapsed();

        eprintln!(
            "[diag:external_probe] t1={:?} t2={:?} dur={:?} \
             status={} stdout={:?} stderr={:?}",
            t1_offset,
            t2_offset,
            t2_offset - t1_offset,
            output.status,
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim(),
        );

        // Additionally run the in-process connect for direct comparison
        // — this is the same experiment as `diag_bind_and_hold` but
        // immediately after the external probe so the timestamp order
        // is `external then internal`.
        let t3 = Instant::now();
        let result = tokio::time::timeout(Duration::from_secs(15), tokio::net::TcpStream::connect(svr_addr)).await;
        eprintln!(
            "[diag:external_probe] in-process connect after {:?}: {:?}",
            t3.elapsed(),
            match &result {
                Ok(Ok(_)) => "Ok(stream)".to_string(),
                Ok(Err(e)) => format!("Err(kind={:?} raw_os_error={:?})", e.kind(), e.raw_os_error()),
                Err(_) => "timeout".to_string(),
            }
        );

        if !matches!(result, Ok(Ok(_))) {
            diag::log_failure_snapshot("external_probe:internal-failed", Some(svr_addr.port()));
        }

        drop(server);
    });
}

// Supporting experiment S2: dual-socket parity ========================================================================

/// Bind a bare `tokio::net::TcpListener` alongside an `SsServerBuilder`
/// listener in the same test process, then connect to each.
///
/// If the bare listener passes and the SS listener fails → the bug is
/// *specific to SS's bind path* (socket2 options, dual-stack, accept
/// opts). If both fail → environmental.
#[skuld::test]
fn diag_dual_socket_parity() {
    rt().block_on(async {
        // --- bare tokio listener path ---
        let bare = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bare_addr = bare.local_addr().unwrap();
        let bare_start = Instant::now();
        let bare_result = tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(bare_addr)).await;
        eprintln!(
            "[diag:parity] bare addr={bare_addr} elapsed={:?} result={}",
            bare_start.elapsed(),
            match &bare_result {
                Ok(Ok(_)) => "Ok(stream)".to_string(),
                Ok(Err(e)) => format!("Err(kind={:?} raw={:?})", e.kind(), e.raw_os_error()),
                Err(_) => "timeout".to_string(),
            }
        );

        // --- SS bind path ---
        let mut svr_cfg = ServerConfig::new(("127.0.0.1", 0u16), TEST_PASSWORD.to_string(), TEST_METHOD).unwrap();
        svr_cfg.set_mode(Mode::TcpOnly);
        let server = SsServerBuilder::new(svr_cfg).build().await.unwrap();
        let ss_addr = server
            .tcp_server()
            .expect("TCP mode is enabled, tcp_server should exist")
            .local_addr()
            .unwrap();
        let ss_start = Instant::now();
        let ss_result = tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(ss_addr)).await;
        eprintln!(
            "[diag:parity] ss addr={ss_addr} elapsed={:?} result={}",
            ss_start.elapsed(),
            match &ss_result {
                Ok(Ok(_)) => "Ok(stream)".to_string(),
                Ok(Err(e)) => format!("Err(kind={:?} raw={:?})", e.kind(), e.raw_os_error()),
                Err(_) => "timeout".to_string(),
            }
        );

        // Emit a combined summary so log-scraping is straightforward.
        let bare_ok = matches!(bare_result, Ok(Ok(_)));
        let ss_ok = matches!(ss_result, Ok(Ok(_)));
        eprintln!(
            "[diag:parity] SUMMARY bare_ok={bare_ok} ss_ok={ss_ok} \
             bare_addr={bare_addr} ss_addr={ss_addr}"
        );

        if !ss_ok {
            diag::log_failure_snapshot("parity:ss-failed", Some(ss_addr.port()));
        }

        // Hold both listeners alive until end of scope so neither path's
        // result is affected by its sibling's teardown.
        drop(bare);
        drop(server);
    });
}

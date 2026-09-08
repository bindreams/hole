//! Foreground bridge runner for development.

use std::path::Path;

use tun_engine::routing::SystemRouting;

use tokio_util::sync::CancellationToken;

use crate::proxy::ShadowsocksProxy;
use crate::proxy_manager::ProxyManager;

/// Run the bridge in foreground mode (for development).
///
/// Bypasses the platform service manager and shuts down on Ctrl+C. Uses
/// the production `IpcServer::bind` + `apply_socket_permissions` path, so
/// dev exercises the real DACL/group/SDDL code — see the `dev-console` /
/// `bridge grant-access` orchestration. Requires elevation for TUN +
/// routing.
///
/// `log_dir` is the same directory that the global tracing subscriber
/// writes `bridge.log` into — so all bridge-owned files land in one
/// place and the CI artifact-upload step can glob for them.
pub fn run(
    socket_path: &Path,
    state_dir: &Path,
    log_dir: &Path,
    ready_notify: Option<&str>,
    version: &str,
    owner: Option<(u32, u32)>,
) -> Result<(), Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_inner(socket_path, state_dir, log_dir, ready_notify, version, owner))
}

/// Resolve when a shutdown signal arrives: Ctrl+C (SIGINT) everywhere,
/// SIGTERM on Unix, or CTRL_BREAK on Windows. dev-console terminates the
/// bridge with SIGTERM (relayed through sudo); without a SIGTERM handler the
/// bridge would die on the default disposition and leak routes/DNS
/// (bindreams/hole#452). The dev supervisor's Windows graceful stop is
/// CTRL_BREAK (bindreams/hole#454).
///
/// Returns a future but installs the SIGTERM/CTRL_BREAK handlers EAGERLY
/// when called (not lazily on first poll), so a caller that raises the
/// signal immediately after still observes it. Must be called within a
/// Tokio runtime — it is, from `run_inner`, the `lib.rs` test child hook,
/// and the test's `block_on`.
pub(crate) fn shutdown_signal() -> impl std::future::Future<Output = ()> {
    #[cfg(unix)]
    let sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
    // Windows: Ctrl+C (interactive) or CTRL_BREAK (the dev supervisor's
    // graceful stop — taskkill /F gave the bridge no chance to tear down
    // routes; CTRL_BREAK + this handler is the SIGTERM equivalent, #454).
    // ctrl_break() registers eagerly here, matching the unix SIGTERM arm.
    #[cfg(not(unix))]
    let ctrl_break = tokio::signal::windows::ctrl_break();
    async move {
        #[cfg(unix)]
        match sigterm {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => tracing::info!("shutdown signal (SIGINT) received"),
                    _ = sigterm.recv() => tracing::info!("shutdown signal (SIGTERM) received"),
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to install SIGTERM handler; Ctrl+C only");
                let _ = tokio::signal::ctrl_c().await;
                tracing::info!("shutdown signal (SIGINT) received");
            }
        }
        #[cfg(not(unix))]
        match ctrl_break {
            Ok(mut ctrl_break) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => tracing::info!("shutdown signal (Ctrl+C) received"),
                    _ = ctrl_break.recv() => tracing::info!("shutdown signal (CTRL_BREAK) received"),
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to install CTRL_BREAK handler; Ctrl+C only");
                let _ = tokio::signal::ctrl_c().await;
                tracing::info!("shutdown signal (Ctrl+C) received");
            }
        }
    }
}

/// Connect to `spec` = `"<host:port>/<token>"` and write `<token>\n`.
/// Best-effort by contract: every failure is a warn — the supervisor's
/// bounded wait is the human-facing failure signal, and a bridge that runs
/// fine but cannot notify should not die for it.
async fn notify_ready(spec: &str) {
    let Some((addr, token)) = spec.rsplit_once('/') else {
        tracing::warn!(spec, "malformed --ready-notify (expected ADDR/TOKEN)");
        return;
    };
    match tokio::net::TcpStream::connect(addr).await {
        Ok(mut conn) => {
            use tokio::io::AsyncWriteExt as _;
            if let Err(e) = conn.write_all(format!("{token}\n").as_bytes()).await {
                tracing::warn!(error = %e, "ready-notify write failed");
            }
            let _ = conn.shutdown().await;
        }
        Err(e) => tracing::warn!(error = %e, addr, "ready-notify connect failed"),
    }
}

/// Map an update-in-progress marker's presence to the session event: present
/// means a cutover is mid-flight (`SessionEvent::CutoverRestart`); absent
/// means a clean machine shutdown (`SessionEvent::ProcessExiting`) — neither
/// is `UserStopped`, which is reserved for an actual user-initiated
/// disconnect. Pure so the decision is table-testable. Shared by all three
/// entry points (this module, `platform::macos`, `platform::windows`) so the
/// same shutdown-tail bug can't recur independently in one of them.
pub(crate) fn shutdown_reason(marker_present: bool) -> crate::target::SessionEvent {
    if marker_present {
        crate::target::SessionEvent::CutoverRestart
    } else {
        crate::target::SessionEvent::ProcessExiting
    }
}

/// Clear a stale update-in-progress marker on the new bridge's post-bind sweep.
/// The marker's presence is co-extensive with "a cutover during which no bridge
/// answered"; once this bridge binds, the cutover is done. Remove-by-path so a
/// from->to schema bump across the cutover cannot strand it. Mirrors the
/// service-path `platform::{macos,windows}::sweep_marker`.
fn sweep_marker(log_dir: &Path) {
    if let Err(e) = hole_common::update_marker::clear(log_dir) {
        tracing::warn!(error = %e, "failed to clear update-in-progress marker");
    }
}

async fn run_inner(
    socket_path: &Path,
    state_dir: &Path,
    log_dir: &Path,
    ready_notify: Option<&str>,
    version: &str,
    owner: Option<(u32, u32)>,
) -> Result<(), Box<dyn std::error::Error>> {
    let proxy = std::sync::Arc::new(tokio::sync::Mutex::new(
        ProxyManager::new(
            ShadowsocksProxy::new(),
            SystemRouting::new(state_dir.to_path_buf(), owner),
        )
        .with_state_dir(state_dir.to_path_buf())
        .with_state_owner(owner),
    ));
    let proxy_shutdown = std::sync::Arc::clone(&proxy);

    // Bind BEFORE the liveness acquire and BEFORE recovery. If a second
    // bridge instance tries to run, the bind() fails and we exit without
    // touching any routing state or contending on the liveness lock —
    // matching crate::liveness's documented invariant (BridgeLiveness::acquire's
    // doc: "a second real bridge instance never reaches this call — the IPC
    // socket bind already refuses it first").
    let server = crate::ipc::IpcServer::bind_with_dirs(
        socket_path,
        proxy,
        version,
        log_dir.to_path_buf(),
        state_dir.to_path_buf(),
        owner,
    )?;

    // Held for this bridge's entire run, from just after the socket bind to
    // process exit — see crate::liveness's module doc. Blocks (in
    // spawn_blocking, off the runtime worker) rather than failing, so a boot
    // racing an in-flight `hole bridge unlock` waits for it instead of
    // interleaving.
    let state_dir_liveness = state_dir.to_path_buf();
    let _liveness =
        tokio::task::spawn_blocking(move || crate::liveness::BridgeLiveness::acquire(&state_dir_liveness, owner))
            .await??;

    // First-party readiness signal (#454): the dev supervisor pre-binds a
    // localhost listener and passes `--ready-notify ADDR/TOKEN`; we connect
    // and echo the token only now — after IpcServer::bind, which also ran
    // apply_socket_permissions — so a waiter can never observe the socket
    // before its permissions are final (the DACL race dev.py's socket-file
    // poll had).
    if let Some(spec) = ready_notify {
        notify_ready(spec).await;
    }

    // DNS recovery runs *before* route recovery. Rationale: mid-recovery
    // crash leaves the user with functional DNS + broken routes (easier
    // diagnosis path) instead of broken DNS + functional routes. See
    // crate::dns::recovery module docs.
    let state_dir_dns = state_dir.to_path_buf();
    if let Err(e) = tokio::task::spawn_blocking(move || crate::dns::recovery::recover_dns_config(&state_dir_dns)).await
    {
        tracing::warn!(error = %e, "recover_dns_config task panicked");
    }

    // Root cancellation token for this process, created BEFORE reconciliation
    // and wired to the signal source immediately: `shutdown_signal()`
    // registers its handlers eagerly, so installing the bridge here (rather
    // than at the `select!` below) is also what closes the boot window in
    // which a SIGTERM had nothing to reach.
    #[allow(clippy::disallowed_methods)]
    // Process entry point — the root every bridge cancel scope descends from.
    // See clippy.toml's CancellationToken::new sanctioned-sites list.
    let shutdown = CancellationToken::new();
    {
        // `shutdown_signal()` is called HERE, on the current task, not inside
        // the `async move` below. Its handler registration
        // (`signal(SignalKind::terminate())` / `ctrl_break()`) happens eagerly
        // when the function runs, but `tokio::spawn` only QUEUES a task — it
        // does not poll it. Constructing the future inside the spawn would
        // defer registration to the runtime's first poll, leaving exactly the
        // boot window this wiring exists to close: a SIGTERM arriving during
        // `recover_and_record`/`reconcile_once` would hit the default
        // disposition and kill the process with routes and cover half-installed.
        let signal = shutdown_signal();
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            signal.await;
            shutdown.cancel();
        });
    }

    crate::route_recovery::recover_and_record(state_dir, &proxy_shutdown).await;
    // Reconcile the persisted target now, before any GUI or client has had a
    // chance to connect (closes #617) — must run after recovery above, see
    // crate::reconciler::reconcile_once's own doc.
    crate::reconciler::reconcile_once(state_dir, owner, &proxy_shutdown, &shutdown).await;
    let state_dir_plugins = state_dir.to_path_buf();
    if let Err(e) =
        tokio::task::spawn_blocking(move || crate::plugin_recovery::reap_recorded_plugins(&state_dir_plugins)).await
    {
        tracing::warn!(error = %e, "reap_recorded_plugins task panicked");
    }

    // Capture WFP + NDIS state after recovery has had a chance to clean
    // up. Each probe emits a one-line INFO (always) + WARN on anomaly +
    // DEBUG detail (gated).
    #[cfg(target_os = "windows")]
    {
        if let Err(e) = tokio::task::spawn_blocking(|| crate::diagnostics::wfp::log_snapshot("startup")).await {
            tracing::warn!(error = %e, "wfp startup snapshot task panicked");
        }
        if let Err(e) = tokio::task::spawn_blocking(|| crate::diagnostics::ndis::log_snapshot("startup")).await {
            tracing::warn!(error = %e, "ndis startup snapshot task panicked");
        }
    }

    // Start the always-on ETW consumer. Held for the server's lifetime;
    // Drop stops the session and joins the processing thread. Failure
    // logs at error (not warn) — a silent ETW-broken customer machine
    // is the opposite of the diagnostic goal. See diagnostics::etw.
    #[cfg(target_os = "windows")]
    let _etw_guard = match crate::diagnostics::etw::start_consumer() {
        Ok(g) => Some(g),
        Err(e) => {
            tracing::error!(error = %e, "etw consumer failed to start");
            None
        }
    };

    // Native-crash observability (bindreams/hole#438): report + delete any
    // crash marker a previously-crashed bridge left in log_dir. Offloaded to
    // a blocking thread to match the sibling recover_* calls (it is pure file
    // I/O — no netsh/route hazard — but spawn_blocking keeps the pattern
    // uniform and off the runtime worker). The marker is written next to
    // bridge.log, NOT in state_dir.
    let log_dir_sweep = log_dir.to_path_buf();
    if let Err(e) = tokio::task::spawn_blocking(move || tombstone::sweep(&log_dir_sweep)).await {
        tracing::warn!(error = %e, "crash sweep task panicked");
    }

    // Cutover-marker parity with the service paths: once this bridge has bound it
    // is authoritative, so any update-in-progress marker is a completed cutover.
    // DISTINCT from the crash-marker sweep above (tombstone) — this is the
    // GUI-readable cutover marker (`hole_common::update_marker`).
    let log_dir_marker = log_dir.to_path_buf();
    if let Err(e) = tokio::task::spawn_blocking(move || sweep_marker(&log_dir_marker)).await {
        tracing::warn!(error = %e, "marker sweep task panicked");
    }

    tokio::select! {
        result = server.run() => {
            if let Err(e) = result {
                tracing::error!(error = %e, "IPC server error");
            }
        }
        _ = shutdown.cancelled() => {}
    }

    // Neither event `shutdown_reason` can produce is a user disconnect, so
    // the target is left unchanged either way (unlike a plain `pm.stop()`,
    // which is `SessionEvent::UserStopped` and would wrongly move the
    // target to `Off`, releasing a standing lockdown cover on a plain
    // SIGTERM/Ctrl+C — e.g. from a machine shutdown or dev-console relay).
    let mut pm = proxy_shutdown.lock().await;
    let event = shutdown_reason(hole_common::update_marker::is_present(log_dir));
    if let Err(e) = pm.stop_with(event).await {
        tracing::error!(error = %e, "error stopping proxy during shutdown");
    }

    Ok(())
}

#[cfg(test)]
#[path = "foreground_tests.rs"]
mod foreground_tests;

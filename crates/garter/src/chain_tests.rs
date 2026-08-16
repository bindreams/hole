// `CancellationToken::new` is the cancel-test harness root; module-level
// allow per the hole workspace clippy.toml's "Bridge cancellation contract"
// sanctioned-test-file exception.
#![allow(clippy::disallowed_methods)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use crate::chain::{allocate_ports, ChainRunner};
use crate::plugin::ChainPlugin;
use crate::sitrep::{PluginReady, StartError, Transports};

// Port allocation tests ===============================================================================================

#[skuld::test]
fn allocate_zero_ports() {
    let ports = allocate_ports(0).unwrap();
    assert!(ports.is_empty());
}

#[skuld::test]
fn allocate_one_port() {
    let ports = allocate_ports(1).unwrap();
    assert_eq!(ports.len(), 1);
    assert!(ports[0].port() > 0);
    assert_eq!(ports[0].ip(), "127.0.0.1".parse::<std::net::IpAddr>().unwrap());
}

#[skuld::test]
fn allocate_multiple_ports_are_unique() {
    let ports = allocate_ports(5).unwrap();
    assert_eq!(ports.len(), 5);
    let unique: std::collections::HashSet<u16> = ports.iter().map(|a| a.port()).collect();
    assert_eq!(unique.len(), 5, "all allocated ports should be unique");
}

/// A transient `WSAEACCES` at the rebind step inside `allocate_one_port` must
/// be absorbed (retry on a fresh ephemeral port, return `Ok`), the same as
/// `WSAEADDRINUSE`. The test forces the `WSAEACCES` path deterministically via
/// the asymmetric Winsock rule (a wildcard `SO_EXCLUSIVEADDRUSE` holder makes a
/// later specific-address bind return `WSAEACCES`); see `allocate_one_port` in
/// chain.rs for the full excluded-port-range rationale.
///
/// Serialized against the rest of the suite because the hook runs between
/// `drop(listener)` and the holder's `bind`; a concurrent test that probed
/// the same ephemeral port in that tiny window could take it before the
/// holder can claim it, causing the holder's `bind` to spuriously fail.
#[cfg(windows)]
#[skuld::test(serial)]
fn allocate_one_port_absorbs_transient_wsaeacces() {
    use crate::chain::test_hook;
    use socket2::{Domain, Protocol, Socket, Type};
    use std::cell::{Cell, RefCell};
    use std::net::SocketAddr;
    use std::os::windows::io::AsRawSocket;
    use std::rc::Rc;
    use windows::Win32::Networking::WinSock::{setsockopt, SOCKET, SOL_SOCKET, SO_EXCLUSIVEADDRUSE};

    /// Binds `0.0.0.0:port` with `SO_EXCLUSIVEADDRUSE`. A subsequent
    /// non-exclusive bind to `127.0.0.1:port` will then return `WSAEACCES`
    /// per the documented Winsock matrix.
    fn hold_wildcard_exclusive(port: u16) -> Socket {
        let s = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).expect("create socket");
        let raw = SOCKET(s.as_raw_socket() as usize);
        let enable = 1i32.to_ne_bytes();
        // Safety: the FFI call — `raw` is a valid SOCKET owned by `s`, and
        // `&enable` is a live `[u8; 4]` on this stack frame.
        let rc = unsafe { setsockopt(raw, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, Some(&enable)) };
        assert_eq!(rc, 0, "setsockopt SO_EXCLUSIVEADDRUSE failed");
        let addr: SocketAddr = format!("0.0.0.0:{port}").parse().unwrap();
        s.bind(&addr.into())
            .expect("bind 0.0.0.0:port with SO_EXCLUSIVEADDRUSE");
        s
    }

    let holder: Rc<RefCell<Option<Socket>>> = Rc::new(RefCell::new(None));
    let holder_cb = holder.clone();
    let hook_count = Rc::new(Cell::new(0u32));
    let hook_count_cb = hook_count.clone();

    let _guard = test_hook::set(move |port| {
        let n = hook_count_cb.get() + 1;
        hook_count_cb.set(n);
        if n == 1 {
            *holder_cb.borrow_mut() = Some(hold_wildcard_exclusive(port));
        }
    });

    let ports = allocate_ports(1).expect(
        "allocate_ports must retry past a transient WSAEACCES; propagated error here means \
         the retry arm does not yet cover ErrorKind::PermissionDenied — see GitHub #20",
    );

    assert_eq!(ports.len(), 1);
    assert!(
        hook_count.get() >= 2,
        "expected at least one retry after the injected WSAEACCES; got {} hook fire(s)",
        hook_count.get()
    );
    // `holder` drops at end-of-scope, releasing the exclusive bind; `_guard`
    // drops after it, clearing the thread-local hook.
}

// Test helpers ========================================================================================================

fn test_env() -> crate::sip003::PluginEnv {
    crate::sip003::PluginEnv {
        local_host: "127.0.0.1".parse().unwrap(),
        local_port: 0, // will be overridden by allocate_ports
        remote_host: "127.0.0.1".into(),
        remote_port: 20000,
        plugin_options: None,
    }
}

/// Plugin that exits immediately with Ok(()).
struct InstantPlugin {
    name: String,
}

#[async_trait::async_trait]
impl ChainPlugin for InstantPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    async fn run(
        self: Box<Self>,
        _local: SocketAddr,
        _remote: SocketAddr,
        _shutdown: CancellationToken,
        _ready: oneshot::Sender<Result<PluginReady, StartError>>,
    ) -> crate::Result<()> {
        // Exits immediately without ever readying; dropping `_ready` unsent
        // is the "exited before ready" backstop the aggregator handles.
        Ok(())
    }
}

/// Plugin that binds a TCP listener and waits for shutdown.
struct ListeningPlugin {
    name: String,
}

#[async_trait::async_trait]
impl ChainPlugin for ListeningPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    async fn run(
        self: Box<Self>,
        local: SocketAddr,
        _remote: SocketAddr,
        shutdown: CancellationToken,
        ready: oneshot::Sender<Result<PluginReady, StartError>>,
    ) -> crate::Result<()> {
        let listener = tokio::net::TcpListener::bind(local).await?;
        let actual = listener.local_addr().unwrap_or(local);
        let _ = ready.send(Ok(PluginReady {
            listen: actual,
            transports: Transports::TCP,
        }));
        let _listener = listener;
        shutdown.cancelled().await;
        Ok(())
    }
}

/// Plugin that binds a TCP listener, reports a caller-chosen transport
/// set on readiness, then waits for shutdown. Used to exercise the
/// aggregator's transports-intersection across hops without a real
/// subprocess.
struct TransportsPlugin {
    name: String,
    transports: Transports,
}

#[async_trait::async_trait]
impl ChainPlugin for TransportsPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    async fn run(
        self: Box<Self>,
        local: SocketAddr,
        _remote: SocketAddr,
        shutdown: CancellationToken,
        ready: oneshot::Sender<Result<PluginReady, StartError>>,
    ) -> crate::Result<()> {
        let listener = tokio::net::TcpListener::bind(local).await?;
        let actual = listener.local_addr().unwrap_or(local);
        let _ = ready.send(Ok(PluginReady {
            listen: actual,
            transports: self.transports,
        }));
        let _listener = listener;
        shutdown.cancelled().await;
        Ok(())
    }
}

/// Plugin that exits immediately with an error.
struct FailingPlugin;

#[async_trait::async_trait]
impl ChainPlugin for FailingPlugin {
    fn name(&self) -> &str {
        "failing"
    }

    async fn run(
        self: Box<Self>,
        _local: SocketAddr,
        _remote: SocketAddr,
        _shutdown: CancellationToken,
        _ready: oneshot::Sender<Result<PluginReady, StartError>>,
    ) -> crate::Result<()> {
        // Fails before readying; dropping `_ready` unsent is the
        // "exited before ready" backstop.
        Err(crate::Error::PluginExit {
            name: "failing".into(),
            code: 1,
        })
    }
}

/// Plugin that never exits and deliberately ignores `shutdown`. Models a
/// long-running plugin (e.g. v2ray-plugin) for drain-timeout regression
/// tests.
struct StubbornPlugin {
    name: String,
}

#[async_trait::async_trait]
impl ChainPlugin for StubbornPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    async fn run(
        self: Box<Self>,
        _local: SocketAddr,
        _remote: SocketAddr,
        _shutdown: CancellationToken,
        _ready: oneshot::Sender<Result<PluginReady, StartError>>,
    ) -> crate::Result<()> {
        std::future::pending::<crate::Result<()>>().await
    }
}

/// Plugin that panics immediately. Exercises the `JoinError` arm of
/// `record_exit`.
struct PanickingPlugin;

#[async_trait::async_trait]
impl ChainPlugin for PanickingPlugin {
    fn name(&self) -> &str {
        "panicking"
    }

    async fn run(
        self: Box<Self>,
        _local: SocketAddr,
        _remote: SocketAddr,
        _shutdown: CancellationToken,
        _ready: oneshot::Sender<Result<PluginReady, StartError>>,
    ) -> crate::Result<()> {
        panic!("deliberate panic for testing")
    }
}

// ChainRunner basic tests =============================================================================================

#[skuld::test]
async fn chain_runner_single_plugin() {
    let runner = ChainRunner::new().add(Box::new(InstantPlugin { name: "test".into() }));
    let mut env = test_env();
    env.local_port = 10000;
    let result = runner.run(env).await;
    assert!(result.is_ok());
}

#[skuld::test]
async fn chain_runner_multiple_plugins() {
    let runner = ChainRunner::new()
        .add(Box::new(InstantPlugin { name: "first".into() }))
        .add(Box::new(InstantPlugin { name: "second".into() }))
        .add(Box::new(InstantPlugin { name: "third".into() }));

    let mut env = test_env();
    env.local_port = 10000;
    let result = runner.run(env).await;
    assert!(result.is_ok());
}

// Readiness tests =====================================================================================================

#[skuld::test]
async fn on_ready_fires_with_local_addr() {
    let (tx, rx) = oneshot::channel();

    let runner = ChainRunner::new()
        .add(Box::new(ListeningPlugin {
            name: "listener".into(),
        }))
        .on_ready(tx);

    let mut env = test_env();
    // Use an ephemeral port so the plugin can actually bind.
    let addr = allocate_ports(1).unwrap().pop().unwrap();
    env.local_port = addr.port();

    let handle = tokio::spawn(runner.run(env));

    // rx fires with the chain-ready payload once every plugin is listening.
    let chain_ready = rx
        .await
        .expect("ready_tx was dropped without sending")
        .expect("chain should be ready, not a start error");

    assert_eq!(chain_ready.listen.port(), addr.port());

    // Clean up: abort the chain (it's waiting for shutdown).
    handle.abort();
}

#[skuld::test]
async fn on_ready_dropped_on_plugin_failure() {
    let (tx, rx) = oneshot::channel();

    let runner = ChainRunner::new().add(Box::new(FailingPlugin)).on_ready(tx);

    let mut env = test_env();
    env.local_port = 10000;

    let handle = tokio::spawn(runner.run(env));

    // The plugin exits before readying, so the aggregator synthesizes a
    // process-exit `StartError::Fatal` and sends it through ready_tx.
    let outcome = rx.await.expect("aggregator should report a start error, not drop");
    match outcome {
        Err(StartError::Fatal { detail, .. }) => {
            assert!(
                detail.contains("exited before becoming ready"),
                "expected exited-before-ready Fatal, got: {detail}"
            );
        }
        other => panic!("expected StartError::Fatal, got {other:?}"),
    }

    // The chain should have returned an error.
    let chain_result = handle.await.unwrap();
    assert!(chain_result.is_err());
}

/// The aggregator reports the end-to-end transports as the intersection
/// across every hop: a transport is carried only if EVERY plugin serves
/// it. Here a TCP|UDP hop and a TCP-only hop must intersect to TCP. The
/// `listen` must be the position-0 plugin's (Client mode), not whichever
/// readied first.
#[skuld::test]
async fn on_ready_transports_are_intersection_across_hops() {
    let (tx, rx) = oneshot::channel();

    // Position 0 is the chain-public hop; it serves TCP+UDP. Position 1
    // (downstream) is TCP-only, so the end-to-end set narrows to TCP.
    let addrs = allocate_ports(1).unwrap();
    let public_addr = addrs[0];

    let runner = ChainRunner::new()
        .add(Box::new(TransportsPlugin {
            name: "public".into(),
            transports: Transports::TCP | Transports::UDP,
        }))
        .add(Box::new(TransportsPlugin {
            name: "downstream".into(),
            transports: Transports::TCP,
        }))
        .on_ready(tx);

    let mut env = test_env();
    env.local_port = public_addr.port();

    let handle = tokio::spawn(runner.run(env));

    let chain_ready = rx
        .await
        .expect("ready_tx dropped")
        .expect("chain should be ready, not a start error");

    assert_eq!(
        chain_ready.transports,
        Transports::TCP,
        "end-to-end transports must be the intersection (TCP+UDP ∩ TCP = TCP)"
    );
    assert_eq!(
        chain_ready.listen.port(),
        public_addr.port(),
        "Client-mode listen must be the position-0 (public) plugin's bind, not whichever readied first"
    );

    handle.abort();
}

// External cancellation tests =========================================================================================

#[skuld::test]
async fn cancel_token_triggers_graceful_shutdown() {
    let cancel = CancellationToken::new();
    let (ready_tx, ready_rx) = oneshot::channel();

    let runner = ChainRunner::new()
        .add(Box::new(ListeningPlugin {
            name: "listener".into(),
        }))
        .cancel_token(cancel.clone())
        .on_ready(ready_tx);

    let mut env = test_env();
    let addr = allocate_ports(1).unwrap().pop().unwrap();
    env.local_port = addr.port();

    let handle = tokio::spawn(runner.run(env));

    // Wait for the plugin to actually bind (no sleep race).
    ready_rx
        .await
        .expect("ready_tx dropped")
        .expect("plugin should become ready");

    // Cancel externally.
    cancel.cancel();

    // The chain exits cleanly. If cancellation regresses, handle.await
    // hangs and the test framework's timeout surfaces it.
    let result = handle.await.unwrap();
    assert!(result.is_ok(), "chain should exit Ok on external cancellation");
}

// Mode tests ==========================================================================================================

/// Plugin that records its `(local, remote)` args and exits cleanly. Used
/// to assert address wiring without doing real I/O. Backing storage is
/// `Mutex<Option<(SocketAddr, SocketAddr)>>` initialized to `None` so a
/// plugin that was never invoked is distinguishable from one whose
/// recorded value happens to equal a sentinel; the assertion sites
/// `.expect("...")` the `Option` before asserting the values.
struct RecordingPlugin {
    name: String,
    record: Arc<Mutex<Option<(SocketAddr, SocketAddr)>>>,
}

#[async_trait::async_trait]
impl ChainPlugin for RecordingPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    async fn run(
        self: Box<Self>,
        local: SocketAddr,
        remote: SocketAddr,
        _shutdown: CancellationToken,
        _ready: oneshot::Sender<Result<PluginReady, StartError>>,
    ) -> crate::Result<()> {
        *self.record.lock().unwrap() = Some((local, remote));
        Ok(())
    }
}

#[skuld::test]
async fn mode_default_is_client() {
    // Pin behavioral default. If someone removes the `#[default]` on
    // `Mode::Client`, this fails before any wiring-dependent test does.
    assert_eq!(crate::chain::Mode::default(), crate::chain::Mode::Client);
}

#[skuld::test]
async fn chain_runner_server_mode_inverts_address_wiring() {
    let ss_local: SocketAddr = "127.0.0.1:11111".parse().unwrap();
    let ss_remote_port = allocate_ports(1).unwrap().pop().unwrap().port();
    let ss_remote: SocketAddr = format!("127.0.0.1:{ss_remote_port}").parse().unwrap();

    let rec0 = Arc::new(Mutex::new(None));
    let rec1 = Arc::new(Mutex::new(None));

    let runner = ChainRunner::new()
        .mode(crate::chain::Mode::Server)
        .add(Box::new(RecordingPlugin {
            name: "inner".into(),
            record: rec0.clone(),
        }))
        .add(Box::new(RecordingPlugin {
            name: "outer".into(),
            record: rec1.clone(),
        }));

    let env = crate::sip003::PluginEnv {
        local_host: ss_local.ip(),
        local_port: ss_local.port(),
        remote_host: "127.0.0.1".into(),
        remote_port: ss_remote_port,
        plugin_options: None,
    };

    runner.run(env).await.unwrap();

    let (l0, r0) = rec0.lock().unwrap().expect("inner plugin must have been invoked");
    let (l1, r1) = rec1.lock().unwrap().expect("outer plugin must have been invoked");

    // Inner plugin (position 0) faces the ssserver side: forwards to SS_LOCAL.
    assert_eq!(r0, ss_local, "inner plugin must forward to SS_LOCAL in Server mode");
    // Outer plugin (position N-1) faces the public side: listens on SS_REMOTE.
    assert_eq!(l1, ss_remote, "outer plugin must listen on SS_REMOTE in Server mode");
    // Inner listens on the intermediate; outer forwards to the same intermediate.
    assert_eq!(
        l0, r1,
        "shared intermediate must match between inner.local and outer.remote"
    );
    // Concretely: the intermediate is neither SS_LOCAL nor SS_REMOTE.
    assert_ne!(l0, ss_local);
    assert_ne!(l0, ss_remote);
}

#[skuld::test]
async fn chain_runner_server_mode_inverts_on_ready_probe_target() {
    let (tx, rx) = oneshot::channel();
    let listen_addr = allocate_ports(1).unwrap()[0];

    // `ListeningPlugin` binds whatever `local` it is given. In Server mode
    // the OUTER (position 1) plugin gets `local = SS_REMOTE`, so on_ready
    // must probe THAT address. The probe's TCP-connect either succeeds
    // (correct probe target) or never fires (wrong probe target — the
    // test then hangs and skuld's runtime drop bounds it).
    let runner = ChainRunner::new()
        .mode(crate::chain::Mode::Server)
        .add(Box::new(ListeningPlugin {
            name: "inner-listener".into(),
        }))
        .add(Box::new(ListeningPlugin {
            name: "outer-listener".into(),
        }))
        .on_ready(tx);

    let ss_local_port = allocate_ports(1).unwrap()[0].port();
    let env = crate::sip003::PluginEnv {
        local_host: "127.0.0.1".parse().unwrap(),
        local_port: ss_local_port,
        remote_host: "127.0.0.1".into(),
        remote_port: listen_addr.port(),
        plugin_options: None,
    };

    let handle = tokio::spawn(runner.run(env));
    let chain_ready = rx.await.expect("ready_tx dropped").expect("chain should be ready");
    assert_eq!(
        chain_ready.listen.port(),
        listen_addr.port(),
        "on_ready in Server mode must report SS_REMOTE (outer's local), not SS_LOCAL (inner's remote)"
    );
    handle.abort();
}

#[skuld::test]
async fn chain_runner_default_matches_explicit_client_mode() {
    let ss_local: SocketAddr = "127.0.0.1:22222".parse().unwrap();
    let ss_remote_port = allocate_ports(1).unwrap().pop().unwrap().port();
    let ss_remote: SocketAddr = format!("127.0.0.1:{ss_remote_port}").parse().unwrap();

    let rec_default = Arc::new(Mutex::new(None));
    let rec_explicit = Arc::new(Mutex::new(None));

    // Default: no .mode() call
    let runner = ChainRunner::new().add(Box::new(RecordingPlugin {
        name: "p".into(),
        record: rec_default.clone(),
    }));
    let env = crate::sip003::PluginEnv {
        local_host: ss_local.ip(),
        local_port: ss_local.port(),
        remote_host: "127.0.0.1".into(),
        remote_port: ss_remote_port,
        plugin_options: None,
    };
    runner.run(env).await.unwrap();

    // Explicit Client
    let runner = ChainRunner::new()
        .mode(crate::chain::Mode::Client)
        .add(Box::new(RecordingPlugin {
            name: "p".into(),
            record: rec_explicit.clone(),
        }));
    let env = crate::sip003::PluginEnv {
        local_host: ss_local.ip(),
        local_port: ss_local.port(),
        remote_host: "127.0.0.1".into(),
        remote_port: ss_remote_port,
        plugin_options: None,
    };
    runner.run(env).await.unwrap();

    let default_rec = rec_default
        .lock()
        .unwrap()
        .expect("default plugin must have been invoked");
    let explicit_rec = rec_explicit
        .lock()
        .unwrap()
        .expect("explicit-Client plugin must have been invoked");

    assert_eq!(
        default_rec, explicit_rec,
        "no .mode() call must behave identically to .mode(Mode::Client)"
    );
    // Pin the actual wiring values too, so a future bug where both modes
    // accidentally got the same (inverted) wiring would be caught.
    assert_eq!(
        default_rec,
        (ss_local, ss_remote),
        "Client mode (default): position-0 plugin must listen on SS_LOCAL, forward to SS_REMOTE"
    );
}

// Mode::from_plugin_options tests -------------------------------------------------------------------------------------

#[skuld::test]
async fn mode_from_plugin_options_detects_bare_server_keyword() {
    use crate::chain::Mode;
    assert_eq!(Mode::from_plugin_options(Some("server")).unwrap(), Mode::Server);
    assert_eq!(Mode::from_plugin_options(Some("server;path=/")).unwrap(), Mode::Server);
    assert_eq!(
        Mode::from_plugin_options(Some("path=/;server;host=h")).unwrap(),
        Mode::Server
    );
}

#[skuld::test]
async fn mode_from_plugin_options_false_when_server_only_appears_as_substring() {
    use crate::chain::Mode;
    assert_eq!(
        Mode::from_plugin_options(Some("servername=cdn.example.com")).unwrap(),
        Mode::Client
    );
    assert_eq!(
        Mode::from_plugin_options(Some("path=/serverlist")).unwrap(),
        Mode::Client
    );
    assert_eq!(Mode::from_plugin_options(Some("path=/server")).unwrap(), Mode::Client);
    assert_eq!(
        Mode::from_plugin_options(Some("path=/serverlist;servername=foo")).unwrap(),
        Mode::Client
    );
}

#[skuld::test]
async fn mode_from_plugin_options_false_when_options_missing() {
    use crate::chain::Mode;
    assert_eq!(Mode::from_plugin_options(None).unwrap(), Mode::Client);
    assert_eq!(Mode::from_plugin_options(Some("")).unwrap(), Mode::Client);
}

#[skuld::test]
async fn mode_from_plugin_options_handles_mixed_options() {
    use crate::chain::Mode;
    // Realistic server-side `plugin_opts`:
    // `server;fast-open;path=/t/<token>;host=<fqdn>`.
    let opts = "server;fast-open;path=/t/abc123;host=hole-stgn.binarydreams.me";
    assert_eq!(Mode::from_plugin_options(Some(opts)).unwrap(), Mode::Server);
}

#[skuld::test]
async fn mode_from_plugin_options_false_for_capitalized_keyword() {
    use crate::chain::Mode;
    // SIP003 keys are lowercase per v2ray-plugin convention; pin the
    // case-sensitive behavior so a future "be lenient about case" patch
    // is a conscious decision rather than drift.
    assert_eq!(Mode::from_plugin_options(Some("Server")).unwrap(), Mode::Client);
    assert_eq!(Mode::from_plugin_options(Some("SERVER;path=/")).unwrap(), Mode::Client);
}

#[skuld::test]
async fn mode_from_plugin_options_true_when_key_has_value() {
    use crate::chain::Mode;
    // SIP003 convention treats `server` as a bare key, but v2ray-plugin's
    // own parser uses `opts.Get("server")` which matches `server=value`
    // (value ignored). Mirror that semantics: presence of the key triggers
    // server mode regardless of value.
    assert_eq!(
        Mode::from_plugin_options(Some("server=1;path=/")).unwrap(),
        Mode::Server
    );
    assert_eq!(Mode::from_plugin_options(Some("server=true")).unwrap(), Mode::Server);
}

#[skuld::test]
async fn mode_from_plugin_options_true_for_escaped_server() {
    use crate::chain::Mode;
    // A backslash escapes whatever byte follows, so `\server` IS the bare
    // key `server` — to ex-ray, and here.
    assert_eq!(Mode::from_plugin_options(Some(r"\server")).unwrap(), Mode::Server);
}

#[skuld::test]
async fn mode_from_plugin_options_errors_on_malformed_options() {
    use crate::chain::Mode;
    // See Mode::from_plugin_options's doc comment for why neither Client
    // nor Server is a safe default here.
    assert!(Mode::from_plugin_options(Some(r"server;path=/a\")).is_err());
    assert!(Mode::from_plugin_options(Some("server;;path=/a")).is_err());
}

#[skuld::test]
async fn mode_from_plugin_options_unaffected_by_a_duplicate_non_deciding_key() {
    use crate::chain::Mode;
    // `server` is decided by presence (`.any(...)`), not by ex-ray's
    // first-wins `Get` — a duplicate, unrelated key elsewhere in the string
    // must not perturb that.
    assert_eq!(
        Mode::from_plugin_options(Some("path=/a;path=/b;server")).unwrap(),
        Mode::Server
    );
}

// Drain-timeout semantics tests =======================================================================================

/// A long-running plugin that ignores `shutdown` must not be killed before
/// shutdown is requested — `drain_timeout` bounds only the drain phase, not
/// the full chain lifetime.
///
/// Uses `tokio::time::pause` + `advance` to simulate elapsed virtual time
/// without real wall-clock sleep; any internal timer that would have bounded
/// the chain at drain_timeout fires under virtual time, and we then assert the
/// chain is still alive.
#[skuld::test]
async fn long_running_plugin_survives_past_drain_timeout() {
    tokio::time::pause();
    let cancel = CancellationToken::new();
    let drain_timeout = std::time::Duration::from_millis(200);

    let runner = ChainRunner::new()
        .add(Box::new(StubbornPlugin {
            name: "stubborn".into(),
        }))
        .cancel_token(cancel.clone())
        .drain_timeout(drain_timeout);

    let mut env = test_env();
    env.local_port = allocate_ports(1).unwrap().pop().unwrap().port();

    let handle = tokio::spawn(runner.run(env));

    // Advance virtual time past drain_timeout; no timer bounds the chain
    // lifetime, so it must stay running.
    tokio::time::advance(drain_timeout * 3).await;
    assert!(
        !handle.is_finished(),
        "chain must still be running — drain_timeout must not bound the full lifetime"
    );

    // Cancel; chain should abort the stubborn plugin within drain_timeout
    // (+ scheduler slack, advanced under virtual time) and return the
    // drain-timeout error.
    cancel.cancel();
    tokio::time::advance(drain_timeout + std::time::Duration::from_millis(500)).await;
    // Resume real time for the join so any non-tokio work can complete.
    tokio::time::resume();
    let result = handle.await.expect("no JoinError");

    match result {
        Err(crate::Error::Chain(msg)) if msg.contains("drain timeout expired") => {}
        other => panic!("expected drain-timeout error, got {other:?}"),
    }
}

/// When a plugin errors — triggering shutdown — and another plugin in the
/// chain outlives the drain budget, the plugin-level error must take
/// precedence over the drain-timeout error. The plugin error is the more
/// diagnostic of the two.
#[skuld::test]
async fn first_error_preserved_across_drain() {
    let drain_timeout = std::time::Duration::from_millis(200);

    let runner = ChainRunner::new()
        .add(Box::new(FailingPlugin))
        .add(Box::new(StubbornPlugin {
            name: "stubborn".into(),
        }))
        .drain_timeout(drain_timeout);

    let mut env = test_env();
    env.local_port = allocate_ports(1).unwrap().pop().unwrap().port();

    let handle = tokio::spawn(runner.run(env));
    let result = handle.await.expect("no JoinError");

    match result {
        Err(crate::Error::PluginExit { code: 1, .. }) => {}
        other => panic!("expected FailingPlugin's PluginExit error to be preserved, got {other:?}"),
    }
}

/// A single instant-exit plugin: the chain should return `Ok(())` as soon
/// as the plugin exits, regardless of `drain_timeout`. Exercises the
/// Phase 1 → Phase 2 transition with an empty JoinSet — the drain phase
/// must not block on an empty set nor introduce a minimum wait time.
#[skuld::test]
async fn external_cancel_drains_empty_joinset_immediately() {
    let cancel = CancellationToken::new();
    let drain_timeout = std::time::Duration::from_secs(5);

    let runner = ChainRunner::new()
        .add(Box::new(InstantPlugin { name: "instant".into() }))
        .cancel_token(cancel.clone())
        .drain_timeout(drain_timeout);

    let mut env = test_env();
    env.local_port = allocate_ports(1).unwrap().pop().unwrap().port();

    let start = std::time::Instant::now();
    let result = runner.run(env).await;
    let elapsed = start.elapsed();

    assert!(result.is_ok(), "single InstantPlugin chain should return Ok(())");
    assert!(
        elapsed < std::time::Duration::from_millis(500),
        "chain should return promptly (well before drain_timeout), took {elapsed:?}"
    );

    // Cancelling after the chain already exited is a no-op.
    cancel.cancel();
}

/// External cancel fires concurrently with a plugin errors — the plugin's
/// error must still win over any drain-timeout wrapping, regardless of
/// which wins the Phase 1 `select!` race.
#[skuld::test]
async fn external_cancel_concurrent_with_plugin_error_preserves_plugin_error() {
    let cancel = CancellationToken::new();
    let drain_timeout = std::time::Duration::from_millis(200);

    let runner = ChainRunner::new()
        .add(Box::new(FailingPlugin))
        .add(Box::new(StubbornPlugin {
            name: "stubborn".into(),
        }))
        .cancel_token(cancel.clone())
        .drain_timeout(drain_timeout);

    let mut env = test_env();
    env.local_port = allocate_ports(1).unwrap().pop().unwrap().port();

    // Fire the external cancel as close as we can to the plugin error. Whether
    // Phase 1 observes the plugin exit first, or `shutdown.cancelled()` first,
    // `record_exit` must still have captured `first_error` by the time the
    // chain returns.
    let handle = tokio::spawn(runner.run(env));
    cancel.cancel();

    let result = handle.await.expect("no JoinError");

    match result {
        Err(crate::Error::PluginExit { code: 1, .. }) => {}
        other => panic!("expected FailingPlugin's PluginExit error to be preserved, got {other:?}"),
    }
}

// record_exit structured-field tests ==================================================================================

/// `record_exit` must emit a structured `exit_code` field on a `PluginExit`
/// error so the mid-run death is machine-parseable in bridge.log.
///
/// The test asserts the FIELD NAME `exit_code` appears in the rendered output
/// (not just via the error string that incidentally contains the code).
#[skuld::test]
async fn record_exit_logs_structured_exit_code() {
    use crate::test_utils::WaitableWriter;
    use crate::tracing_test::set_default_in_current_thread;
    use tokio_util::sync::CancellationToken;

    let writer = WaitableWriter::new();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer.clone())
        .with_ansi(false)
        .with_target(true)
        .finish();
    let _g = set_default_in_current_thread(subscriber);
    let rx = writer.wait_for("exited with error");

    let mut first_error = None;
    let shutdown = CancellationToken::new();
    let result = Ok((
        "ex-ray".to_string(),
        Err(crate::Error::PluginExit {
            name: "ex-ray".to_string(),
            code: 139,
        }),
    ));
    crate::chain::record_exit(result, &mut first_error, &shutdown);

    rx.recv().expect("breadcrumb emitted");
    let snap = writer.snapshot();
    assert!(snap.contains("exit_code"), "structured exit_code field: {snap}");
    assert!(snap.contains("139"), "exit code value surfaced: {snap}");
    assert!(snap.contains("ex-ray"), "plugin name: {snap}");
}

/// `record_exit` must emit `killed=true` and no numeric `exit_code` on a
/// `PluginKilled` error (signal death / SIGKILL / TerminateProcess).
#[skuld::test]
async fn record_exit_logs_killed_for_signal_death() {
    use crate::test_utils::WaitableWriter;
    use crate::tracing_test::set_default_in_current_thread;
    use tokio_util::sync::CancellationToken;

    let writer = WaitableWriter::new();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer.clone())
        .with_ansi(false)
        .with_target(true)
        .finish();
    let _g = set_default_in_current_thread(subscriber);
    let rx = writer.wait_for("exited with error");

    let mut first_error = None;
    let shutdown = CancellationToken::new();
    let result = Ok((
        "ex-ray".to_string(),
        Err(crate::Error::PluginKilled {
            name: "ex-ray".to_string(),
        }),
    ));
    crate::chain::record_exit(result, &mut first_error, &shutdown);

    rx.recv().expect("breadcrumb emitted");
    let snap = writer.snapshot();
    assert!(snap.contains("killed=true"), "killed field must be true: {snap}");
    assert!(snap.contains("ex-ray"), "plugin name: {snap}");
    // PluginKilled carries no exit code; tracing's fmt omits Option::None
    // fields entirely — `exit_code` does not appear in the output at all.
    assert!(!snap.contains("exit_code"), "no exit_code field for killed: {snap}");
}

/// A plugin panic surfaces through `record_exit`'s `JoinError` arm as a
/// `Chain` error whose message identifies the panic.
#[skuld::test]
async fn plugin_panic_surfaces_as_chain_error() {
    let runner = ChainRunner::new()
        .add(Box::new(PanickingPlugin))
        .drain_timeout(std::time::Duration::from_millis(200));

    let mut env = test_env();
    env.local_port = allocate_ports(1).unwrap().pop().unwrap().port();

    // Suppress the panic's backtrace noise in the test output.
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = runner.run(env).await;
    std::panic::set_hook(prev_hook);

    match result {
        Err(crate::Error::Chain(msg)) if msg.contains("panicked") => {}
        other => panic!("expected Chain(\"...panicked...\") error, got {other:?}"),
    }
}

use crate::chain::run_readiness_aggregator;

/// `BindConflict` is the only retryable class, so discarding one that the
/// plugin already delivered turns a transient port collision into a hard
/// start failure.
#[skuld::test]
async fn aggregator_reports_a_start_error_delivered_before_shutdown_won_the_race() {
    let (tx0, rx0) = oneshot::channel();
    let (ready_tx, ready_rx) = oneshot::channel();
    let shutdown = CancellationToken::new();

    tx0.send(Err(StartError::BindConflict {
        errno: 98,
        addr: "127.0.0.1:1080".parse().unwrap(),
    }))
    .unwrap();
    shutdown.cancel();

    run_readiness_aggregator(vec![(0, rx0)], 1, crate::chain::Mode::Client, shutdown, ready_tx).await;

    match ready_rx
        .await
        .expect("a delivered StartError must be reported, not discarded")
    {
        Err(StartError::BindConflict { errno, .. }) => assert_eq!(errno, 98),
        other => panic!("expected the delivered BindConflict, got {other:?}"),
    }
}

/// A delivered `Ok(PluginReady)` must NOT be rescued (see the shutdown
/// arm's comment for why).
#[skuld::test]
async fn aggregator_never_reports_ready_once_shutdown_won_the_race() {
    let (tx0, rx0) = oneshot::channel();
    let (ready_tx, ready_rx) = oneshot::channel();
    let shutdown = CancellationToken::new();

    tx0.send(Ok(PluginReady {
        listen: "127.0.0.1:1080".parse().unwrap(),
        transports: Transports::TCP,
    }))
    .unwrap();
    shutdown.cancel();

    run_readiness_aggregator(vec![(0, rx0)], 1, crate::chain::Mode::Client, shutdown, ready_tx).await;

    assert!(
        ready_rx.await.is_err(),
        "a chain whose plugin already exited must never be reported ready"
    );
}

/// Shutdown preempting a plugin that delivered nothing: `ready_tx` is still
/// dropped. Covers `TryRecvError::Empty` — the sender is alive but unused.
#[skuld::test]
async fn aggregator_drops_ready_tx_when_shutdown_preempts_an_empty_receiver() {
    let (tx0, rx0) = oneshot::channel::<Result<PluginReady, StartError>>();
    let (ready_tx, ready_rx) = oneshot::channel();
    let shutdown = CancellationToken::new();

    shutdown.cancel();

    run_readiness_aggregator(vec![(0, rx0)], 1, crate::chain::Mode::Client, shutdown, ready_tx).await;

    assert!(ready_rx.await.is_err(), "nothing delivered must still drop ready_tx");
    drop(tx0);
}

/// Covers `TryRecvError::Closed` — the sender was dropped unsent BEFORE the
/// arm runs. Distinct from the empty case above, and pinned so a later PR
/// that gives `Closed` its own meaning has to do so deliberately.
#[skuld::test]
async fn aggregator_drops_ready_tx_when_shutdown_preempts_a_closed_receiver() {
    let (tx0, rx0) = oneshot::channel::<Result<PluginReady, StartError>>();
    let (ready_tx, ready_rx) = oneshot::channel();
    let shutdown = CancellationToken::new();

    drop(tx0);
    shutdown.cancel();

    run_readiness_aggregator(vec![(0, rx0)], 1, crate::chain::Mode::Client, shutdown, ready_tx).await;

    assert!(
        ready_rx.await.is_err(),
        "a sender dropped unsent must not become a synthesized Fatal in this arm"
    );
}

/// A typed error in a LATER plugin's channel must not wait on an earlier plugin
/// that has neither reported nor dropped its sender.
#[skuld::test]
async fn aggregator_reports_a_later_plugins_error_while_an_earlier_one_is_still_starting() {
    let (_tx0, rx0) = oneshot::channel::<Result<PluginReady, StartError>>();
    let (tx1, rx1) = oneshot::channel();
    let (ready_tx, ready_rx) = oneshot::channel();
    let shutdown = CancellationToken::new();

    tx1.send(Err(StartError::BindConflict {
        errno: 98,
        addr: "127.0.0.1:1080".parse().unwrap(),
    }))
    .unwrap();

    run_readiness_aggregator(
        vec![(0, rx0), (1, rx1)],
        2,
        crate::chain::Mode::Client,
        shutdown,
        ready_tx,
    )
    .await;

    match ready_rx.await.expect("a later plugin's error must be reported") {
        Err(StartError::BindConflict { errno, .. }) => assert_eq!(errno, 98),
        other => panic!("expected the later plugin's BindConflict, got {other:?}"),
    }
}

/// A plugin exiting unsent must not bury a sibling's real failure under the
/// generic placeholder. Both receivers are resolvable at the first poll, so the
/// assertion holds under either completion order.
#[skuld::test]
async fn aggregator_prefers_a_delivered_error_over_a_siblings_exit() {
    let (tx0, rx0) = oneshot::channel::<Result<PluginReady, StartError>>();
    let (tx1, rx1) = oneshot::channel();
    let (ready_tx, ready_rx) = oneshot::channel();
    let shutdown = CancellationToken::new();

    tx1.send(Err(StartError::BindConflict {
        errno: 98,
        addr: "127.0.0.1:1080".parse().unwrap(),
    }))
    .unwrap();
    drop(tx0);

    run_readiness_aggregator(
        vec![(0, rx0), (1, rx1)],
        2,
        crate::chain::Mode::Client,
        shutdown,
        ready_tx,
    )
    .await;

    match ready_rx.await.expect("a delivered error outranks a bare exit") {
        Err(StartError::BindConflict { errno, .. }) => assert_eq!(errno, 98),
        other => panic!("expected the sibling's BindConflict, got {other:?}"),
    }
}

/// Shutdown preempting the scan must still find an error further down the
/// chain, not just in the receiver that happened to be next.
#[skuld::test]
async fn aggregator_rescues_a_later_plugins_error_when_shutdown_won_the_race() {
    let (tx0, rx0) = oneshot::channel::<Result<PluginReady, StartError>>();
    let (tx1, rx1) = oneshot::channel();
    let (ready_tx, ready_rx) = oneshot::channel();
    let shutdown = CancellationToken::new();

    tx1.send(Err(StartError::BindConflict {
        errno: 98,
        addr: "127.0.0.1:1080".parse().unwrap(),
    }))
    .unwrap();
    drop(tx0);
    shutdown.cancel();

    run_readiness_aggregator(
        vec![(0, rx0), (1, rx1)],
        2,
        crate::chain::Mode::Client,
        shutdown,
        ready_tx,
    )
    .await;

    match ready_rx.await.expect("the scan must reach index 1") {
        Err(StartError::BindConflict { errno, .. }) => assert_eq!(errno, 98),
        other => panic!("expected the later plugin's BindConflict, got {other:?}"),
    }
}

/// Two typed errors at once resolve to the lowest plugin index.
#[skuld::test]
async fn aggregator_reports_the_lowest_index_error_when_two_plugins_both_fail() {
    let (tx0, rx0) = oneshot::channel();
    let (tx1, rx1) = oneshot::channel();
    let (ready_tx, ready_rx) = oneshot::channel();
    let shutdown = CancellationToken::new();

    tx0.send(Err(StartError::Fatal {
        detail: "first".into(),
        errno: None,
    }))
    .unwrap();
    tx1.send(Err(StartError::BindConflict {
        errno: 98,
        addr: "127.0.0.1:1080".parse().unwrap(),
    }))
    .unwrap();

    run_readiness_aggregator(
        vec![(0, rx0), (1, rx1)],
        2,
        crate::chain::Mode::Client,
        shutdown,
        ready_tx,
    )
    .await;

    match ready_rx.await.expect("aggregator should send") {
        Err(StartError::Fatal { detail, .. }) => assert_eq!(detail, "first"),
        other => panic!("expected the lowest-index error, got {other:?}"),
    }
}

/// The regression guard for deferral. A higher-index plugin's bare exit must not
/// be reported while a lower-index plugin's sender is still alive — its typed
/// error may be one poll behind, and reporting early destroys the only retryable
/// class.
#[skuld::test]
async fn aggregator_defers_an_exit_until_a_live_sibling_answers() {
    let (tx0, rx0) = oneshot::channel();
    let (tx1, rx1) = oneshot::channel::<Result<PluginReady, StartError>>();
    let (ready_tx, ready_rx) = oneshot::channel();
    let shutdown = CancellationToken::new();

    // Index 1 exits unsent; index 0 answers only afterwards.
    drop(tx1);
    let sender = tokio::spawn(async move {
        tx0.send(Err(StartError::BindConflict {
            errno: 98,
            addr: "127.0.0.1:1080".parse().unwrap(),
        }))
    });

    run_readiness_aggregator(
        vec![(0, rx0), (1, rx1)],
        2,
        crate::chain::Mode::Client,
        shutdown,
        ready_tx,
    )
    .await;
    sender.await.expect("sender task joined").expect("index 0 sent");

    match ready_rx.await.expect("aggregator should send") {
        Err(StartError::BindConflict { errno, .. }) => assert_eq!(errno, 98),
        other => panic!("a live sibling's typed error must outrank a bare exit, got {other:?}"),
    }
}

/// Deferral must not swallow the failure: once every sibling has resolved with
/// nothing typed, the synthesized exit is reported.
#[skuld::test]
async fn aggregator_reports_the_exit_once_every_sibling_has_resolved() {
    let (tx0, rx0) = oneshot::channel::<Result<PluginReady, StartError>>();
    let (tx1, rx1) = oneshot::channel();
    let (ready_tx, ready_rx) = oneshot::channel();
    let shutdown = CancellationToken::new();

    drop(tx0);
    tx1.send(Ok(PluginReady {
        listen: "127.0.0.1:1081".parse().unwrap(),
        transports: Transports::TCP,
    }))
    .unwrap();

    run_readiness_aggregator(
        vec![(0, rx0), (1, rx1)],
        2,
        crate::chain::Mode::Client,
        shutdown,
        ready_tx,
    )
    .await;

    match ready_rx.await.expect("a deferred exit must still be reported") {
        Err(StartError::Fatal { detail, .. }) => {
            assert_eq!(detail, "plugin exited before becoming ready");
        }
        other => panic!("expected the synthesized exit failure, got {other:?}"),
    }
}

/// The one case where the sweep must walk past — and consume — a delivered
/// readiness to reach an error further down.
#[skuld::test]
async fn aggregator_finds_an_error_behind_an_already_ready_plugin_on_shutdown() {
    let (tx0, rx0) = oneshot::channel();
    let (_tx1, rx1) = oneshot::channel::<Result<PluginReady, StartError>>();
    let (tx2, rx2) = oneshot::channel();
    let (ready_tx, ready_rx) = oneshot::channel();
    let shutdown = CancellationToken::new();

    tx0.send(Ok(PluginReady {
        listen: "127.0.0.1:1080".parse().unwrap(),
        transports: Transports::TCP,
    }))
    .unwrap();
    tx2.send(Err(StartError::BindConflict {
        errno: 98,
        addr: "127.0.0.1:1082".parse().unwrap(),
    }))
    .unwrap();
    shutdown.cancel();

    run_readiness_aggregator(
        vec![(0, rx0), (1, rx1), (2, rx2)],
        3,
        crate::chain::Mode::Client,
        shutdown,
        ready_tx,
    )
    .await;

    match ready_rx.await.expect("the scan must walk past a ready plugin") {
        Err(StartError::BindConflict { errno, .. }) => assert_eq!(errno, 98),
        other => panic!("expected the deeper BindConflict, got {other:?}"),
    }
}

/// Deliberately NOT an ordering test: both assertions are order-independent. It
/// exists to catch a rewrite that keys `plugin_listens` by position in the
/// pending set instead of by plugin index.
#[skuld::test]
async fn aggregator_keys_listens_and_transports_by_plugin_index() {
    let (tx0, rx0) = oneshot::channel();
    let (tx1, rx1) = oneshot::channel();
    let (tx2, rx2) = oneshot::channel();
    let (ready_tx, ready_rx) = oneshot::channel();
    let shutdown = CancellationToken::new();

    tx2.send(Ok(PluginReady {
        listen: "127.0.0.1:1082".parse().unwrap(),
        transports: Transports::TCP | Transports::UDP,
    }))
    .unwrap();
    tx0.send(Ok(PluginReady {
        listen: "127.0.0.1:1080".parse().unwrap(),
        transports: Transports::TCP | Transports::UDP,
    }))
    .unwrap();
    tx1.send(Ok(PluginReady {
        listen: "127.0.0.1:1081".parse().unwrap(),
        transports: Transports::TCP,
    }))
    .unwrap();

    run_readiness_aggregator(
        vec![(0, rx0), (1, rx1), (2, rx2)],
        3,
        crate::chain::Mode::Client,
        shutdown,
        ready_tx,
    )
    .await;

    let ready = ready_rx
        .await
        .expect("aggregator should send")
        .expect("every plugin readied");
    assert_eq!(
        ready.listen,
        "127.0.0.1:1080".parse::<std::net::SocketAddr>().unwrap(),
        "Client mode reports position 0's listen address"
    );
    assert_eq!(
        ready.transports,
        Transports::TCP,
        "the chain carries only what every hop serves"
    );
}

/// The no-rescue rule, extended to the multi-plugin sweep: a LATER plugin's
/// delivered readiness is no evidence the chain survived the cancel either.
#[skuld::test]
async fn aggregator_never_reports_ready_when_a_later_plugin_readied_before_shutdown() {
    let (_tx0, rx0) = oneshot::channel::<Result<PluginReady, StartError>>();
    let (tx1, rx1) = oneshot::channel();
    let (ready_tx, ready_rx) = oneshot::channel();
    let shutdown = CancellationToken::new();

    tx1.send(Ok(PluginReady {
        listen: "127.0.0.1:1081".parse().unwrap(),
        transports: Transports::TCP,
    }))
    .unwrap();
    shutdown.cancel();

    run_readiness_aggregator(
        vec![(0, rx0), (1, rx1)],
        2,
        crate::chain::Mode::Client,
        shutdown,
        ready_tx,
    )
    .await;

    assert!(
        ready_rx.await.is_err(),
        "a chain cancelled mid-start must never be reported ready"
    );
}

/// A deferred exit must survive the cancel that the very same exit triggers.
/// `record_exit` fires `shutdown` on every plugin exit, so the shutdown arm is
/// the normal way out of a deferral, not an edge case — returning empty-handed
/// there would report a dropped channel where plugin order reported a `Fatal`.
#[skuld::test]
async fn aggregator_reports_a_deferred_exit_when_shutdown_ends_the_wait() {
    let (_tx0, rx0) = oneshot::channel::<Result<PluginReady, StartError>>();
    let (tx1, rx1) = oneshot::channel::<Result<PluginReady, StartError>>();
    let (ready_tx, ready_rx) = oneshot::channel();
    let shutdown = CancellationToken::new();

    // Index 1 exits unsent; index 0 never answers, so the aggregator defers and
    // parks — which is what lets the canceller below run.
    drop(tx1);
    let canceller = {
        let shutdown = shutdown.clone();
        tokio::spawn(async move { shutdown.cancel() })
    };

    run_readiness_aggregator(
        vec![(0, rx0), (1, rx1)],
        2,
        crate::chain::Mode::Client,
        shutdown,
        ready_tx,
    )
    .await;
    canceller.await.expect("canceller joined");

    match ready_rx.await.expect("a deferred exit must not be lost to the cancel") {
        Err(StartError::Fatal { detail, .. }) => {
            assert_eq!(detail, "plugin exited before becoming ready");
        }
        other => panic!("expected the synthesized exit failure, got {other:?}"),
    }
}

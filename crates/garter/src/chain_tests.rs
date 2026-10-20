// `CancellationToken::new` is the cancel-test harness root; module-level
// allow per the hole workspace clippy.toml's "Bridge cancellation contract"
// sanctioned-test-file exception. Also covers this file's `allocate_ports`
// calls, the TCP-only chain-port allocator under test here.
#![allow(clippy::disallowed_methods)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use crate::chain::{allocate_ports, ChainReady, ChainRunner};
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

pub(crate) fn test_env() -> crate::sip003::PluginEnv {
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

use crate::chain::{run_readiness_aggregator, Mode, Readiness, ReadyGate};

/// `BindConflict` is the only retryable class, so discarding one that the
/// plugin already delivered turns a transient port collision into a hard
/// start failure.
#[skuld::test]
async fn aggregator_reports_a_start_error_delivered_before_shutdown_won_the_race() {
    let (tx0, rx0) = oneshot::channel();
    let shutdown = CancellationToken::new();

    tx0.send(Err(StartError::BindConflict {
        errno: 98,
        addr: "127.0.0.1:1080".parse().unwrap(),
    }))
    .unwrap();
    shutdown.cancel();

    match run_readiness_aggregator(vec![(0, rx0)], 1, Mode::Client, shutdown).await {
        Readiness::Failed(StartError::BindConflict { errno, .. }) => assert_eq!(errno, 98),
        other => panic!("a delivered StartError must be reported, not discarded; got {other:?}"),
    }
}

/// A start failure ends the chain: the aggregator cancels the other plugins.
#[skuld::test]
async fn aggregator_returns_a_start_failure_and_cancels_the_chain() {
    let (tx0, rx0) = oneshot::channel();
    let shutdown = CancellationToken::new();

    tx0.send(Err(StartError::Fatal {
        detail: "broke".into(),
        errno: None,
    }))
    .unwrap();

    let readiness = run_readiness_aggregator(vec![(0, rx0)], 1, Mode::Client, shutdown.clone()).await;

    assert!(
        matches!(readiness, Readiness::Failed(StartError::Fatal { .. })),
        "{readiness:?}"
    );
    assert!(shutdown.is_cancelled(), "a start failure must stop the other plugins");
}

/// A plugin that drops its sender unsent exited before ready.
#[skuld::test]
async fn aggregator_synthesizes_a_failure_for_a_sender_dropped_unsent() {
    let (tx0, rx0) = oneshot::channel::<Result<PluginReady, StartError>>();
    let shutdown = CancellationToken::new();

    drop(tx0);

    let readiness = run_readiness_aggregator(vec![(0, rx0)], 1, Mode::Client, shutdown.clone()).await;

    assert!(
        matches!(&readiness, Readiness::Failed(StartError::Fatal { detail, .. }) if detail.contains("exited before becoming ready")),
        "{readiness:?}"
    );
    assert!(shutdown.is_cancelled());
}

#[skuld::test]
async fn aggregator_returns_the_chain_ready_once_every_plugin_is() {
    let (tx0, rx0) = oneshot::channel();
    let (tx1, rx1) = oneshot::channel();
    let ready = |port: u16| {
        Ok(PluginReady {
            listen: SocketAddr::from(([127, 0, 0, 1], port)),
            transports: Transports::TCP,
        })
    };
    tx0.send(ready(1080)).unwrap();
    tx1.send(ready(1081)).unwrap();

    let readiness = run_readiness_aggregator(vec![(0, rx0), (1, rx1)], 2, Mode::Client, CancellationToken::new()).await;

    match readiness {
        Readiness::Ready(chain) => assert_eq!(chain.listen.port(), 1080),
        other => panic!("{other:?}"),
    }
}

/// A delivered `Ok(PluginReady)` must NOT be rescued (see the shutdown
/// arm's comment for why).
#[skuld::test]
async fn aggregator_never_reports_ready_once_shutdown_won_the_race() {
    let (tx0, rx0) = oneshot::channel();
    let shutdown = CancellationToken::new();

    tx0.send(Ok(PluginReady {
        listen: "127.0.0.1:1080".parse().unwrap(),
        transports: Transports::TCP,
    }))
    .unwrap();
    shutdown.cancel();

    let readiness = run_readiness_aggregator(vec![(0, rx0)], 1, Mode::Client, shutdown).await;

    assert!(
        matches!(readiness, Readiness::Preempted { .. }),
        "a chain whose plugin already exited must never be reported ready: {readiness:?}"
    );
}

/// Shutdown preempting a plugin that delivered nothing. Covers `TryRecvError::Empty` — the sender is alive but unused.
#[skuld::test]
async fn aggregator_is_preempted_by_shutdown_on_an_empty_receiver() {
    let (tx0, rx0) = oneshot::channel::<Result<PluginReady, StartError>>();
    let shutdown = CancellationToken::new();

    shutdown.cancel();

    let readiness = run_readiness_aggregator(vec![(0, rx0)], 1, Mode::Client, shutdown).await;

    assert!(matches!(readiness, Readiness::Preempted { .. }), "{readiness:?}");
    drop(tx0);
}

/// Covers `TryRecvError::Closed` — the sender was dropped unsent BEFORE the
/// arm runs. Distinct from the empty case above, and pinned so a later PR
/// that gives `Closed` its own meaning has to do so deliberately.
#[skuld::test]
async fn aggregator_is_preempted_by_shutdown_on_a_closed_receiver() {
    let (tx0, rx0) = oneshot::channel::<Result<PluginReady, StartError>>();
    let shutdown = CancellationToken::new();

    drop(tx0);
    shutdown.cancel();

    let readiness = run_readiness_aggregator(vec![(0, rx0)], 1, Mode::Client, shutdown).await;

    assert!(
        matches!(readiness, Readiness::Preempted { .. }),
        "a sender dropped unsent must not become a synthesized Fatal in this arm: {readiness:?}"
    );
}

// The gate on the caller's `ready` ------------------------------------------------------------------------------------

fn chain_ready() -> ChainReady {
    ChainReady {
        listen: "127.0.0.1:1080".parse().unwrap(),
        transports: Transports::TCP,
    }
}

fn fatal() -> StartError {
    StartError::Fatal {
        detail: "broke".into(),
        errno: None,
    }
}

/// A ready chain is reported at once: its members are running, so there is nothing to wait for.
#[skuld::test]
fn the_gate_sends_a_ready_chain_at_once() {
    let (tx, mut rx) = oneshot::channel();
    let mut gate = ReadyGate::new(Some(tx));

    gate.absorb(Readiness::Ready(chain_ready()));

    assert!(matches!(rx.try_recv(), Ok(Ok(_))));
}

/// A failure is held, not sent: the caller hears of it only when the gate is released.
#[skuld::test]
fn the_gate_holds_a_start_failure_until_released() {
    let (tx, mut rx) = oneshot::channel();
    let mut gate = ReadyGate::new(Some(tx));

    gate.absorb(Readiness::Failed(fatal()));
    assert!(matches!(rx.try_recv(), Err(oneshot::error::TryRecvError::Empty)));

    gate.release();
    assert!(matches!(rx.try_recv(), Ok(Err(StartError::Fatal { .. }))));
}

/// Nothing to report: the sender stays open until the release, so the caller's channel does not close early.
#[skuld::test]
fn the_gate_keeps_the_sender_open_when_there_is_nothing_to_report_until_released() {
    let (tx, mut rx) = oneshot::channel();
    let mut gate = ReadyGate::new(Some(tx));
    let (_member_tx, unread) = oneshot::channel();

    gate.absorb(Readiness::Preempted { unread: vec![unread] });
    assert!(matches!(rx.try_recv(), Err(oneshot::error::TryRecvError::Empty)));

    gate.release();
    assert!(matches!(rx.try_recv(), Err(oneshot::error::TryRecvError::Closed)));
}

/// What the preempted plugin delivers before the release is read at the release, and only a typed failure counts: a
/// `PluginReady` does not rescue a chain whose `shutdown` already fired.
#[skuld::test]
fn the_gate_reports_what_the_preempted_plugin_delivered_by_the_release() {
    let ready = || {
        Ok(PluginReady {
            listen: "127.0.0.1:1080".parse().unwrap(),
            transports: Transports::TCP,
        })
    };
    for (delivered, reported_fatal) in [
        (Some(Err(fatal())), true),
        (Some(ready()), false),
        // Nothing delivered, sender still open or dropped unsent.
        (None, false),
    ] {
        let (tx, mut rx) = oneshot::channel();
        let mut gate = ReadyGate::new(Some(tx));
        let (member_tx, unread) = oneshot::channel();
        gate.absorb(Readiness::Preempted { unread: vec![unread] });
        assert!(matches!(rx.try_recv(), Err(oneshot::error::TryRecvError::Empty)));

        if let Some(delivered) = &delivered {
            member_tx.send(delivered.clone()).unwrap();
        }
        gate.release();

        match rx.try_recv() {
            Ok(Err(StartError::Fatal { .. })) => assert!(reported_fatal, "{delivered:?}"),
            Err(oneshot::error::TryRecvError::Closed) => assert!(!reported_fatal, "{delivered:?}"),
            other => panic!("{delivered:?}: {other:?}"),
        }
    }
}

/// A chain that never started aggregating is released the same way.
#[skuld::test]
fn the_gate_keeps_the_sender_open_until_released_even_if_it_never_absorbed_anything() {
    let (tx, mut rx) = oneshot::channel::<Result<ChainReady, StartError>>();
    let gate = ReadyGate::new(Some(tx));
    assert!(matches!(rx.try_recv(), Err(oneshot::error::TryRecvError::Empty)));

    gate.release();
    assert!(matches!(rx.try_recv(), Err(oneshot::error::TryRecvError::Closed)));
}

// A start failure waits for the other members =========================================================================

/// How a [`FailsAtStart`] member fails.
#[derive(Clone, Copy)]
enum StartFailure {
    /// Reports a typed `Fatal` on `ready`, then exits with an error.
    Typed,
    /// Exits with an error without reporting, dropping `ready` unsent.
    Dropped,
}

/// A member whose start fails at once.
struct FailsAtStart {
    how: StartFailure,
    /// Keeps running after it reported, and exits cleanly once told to stop, as a plugin that reports a failure
    /// but does not end itself.
    lingers: bool,
}

#[async_trait::async_trait]
impl ChainPlugin for FailsAtStart {
    fn name(&self) -> &str {
        "fails-at-start"
    }

    async fn run(
        self: Box<Self>,
        _local: SocketAddr,
        _remote: SocketAddr,
        shutdown: CancellationToken,
        ready: oneshot::Sender<Result<PluginReady, StartError>>,
    ) -> crate::Result<()> {
        match self.how {
            StartFailure::Typed => {
                let _ = ready.send(Err(StartError::Fatal {
                    detail: "member broke".into(),
                    errno: None,
                }));
            }
            StartFailure::Dropped => drop(ready),
        }
        if self.lingers {
            shutdown.cancelled().await;
            return Ok(());
        }
        Err(crate::Error::PluginExit {
            name: "fails-at-start".into(),
            code: 3,
        })
    }
}

/// A healthy member. Once the chain stops it, it holds a last line back until `gate` opens, as a plugin whose reader
/// is still relaying stderr, and records that the line was relayed before it returns.
struct LastLineMember {
    /// Reports ready at once; otherwise it holds `ready` and reports nothing.
    ready_first: bool,
    /// Fires when the chain has told the member to stop.
    stopped: oneshot::Sender<()>,
    gate: oneshot::Receiver<()>,
    relayed: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl ChainPlugin for LastLineMember {
    fn name(&self) -> &str {
        "last-line-member"
    }

    async fn run(
        self: Box<Self>,
        local: SocketAddr,
        _remote: SocketAddr,
        shutdown: CancellationToken,
        ready: oneshot::Sender<Result<PluginReady, StartError>>,
    ) -> crate::Result<()> {
        let _held_ready = if self.ready_first {
            let _ = ready.send(Ok(PluginReady {
                listen: local,
                transports: Transports::TCP,
            }));
            None
        } else {
            Some(ready)
        };
        shutdown.cancelled().await;
        let _ = self.stopped.send(());
        let _ = self.gate.await;
        self.relayed.store(true, Ordering::SeqCst);
        Ok(())
    }
}

/// A started chain of a failing member and a [`LastLineMember`], and the gate that holds the latter's last line back.
struct FailingChain {
    ready_rx: oneshot::Receiver<Result<ChainReady, StartError>>,
    stopped_rx: oneshot::Receiver<()>,
    gate_tx: oneshot::Sender<()>,
    relayed: Arc<AtomicBool>,
    handle: tokio::task::JoinHandle<crate::Result<()>>,
}

/// What the caller's `ready` receiver got: a value, or `RecvError` for a dropped sender.
type Reported = Result<Result<ChainReady, StartError>, oneshot::error::RecvError>;

impl FailingChain {
    fn start(failing: Box<dyn ChainPlugin>, failing_position: usize, drain_timeout: std::time::Duration) -> Self {
        let (stopped_tx, stopped_rx) = oneshot::channel();
        let (gate_tx, gate_rx) = oneshot::channel();
        let relayed = Arc::new(AtomicBool::new(false));
        let healthy = Box::new(LastLineMember {
            // The aggregator awaits the members in order: a healthy member in front of the failing one must have readied.
            ready_first: failing_position == 1,
            stopped: stopped_tx,
            gate: gate_rx,
            relayed: relayed.clone(),
        });
        let (ready_tx, ready_rx) = oneshot::channel();
        let runner = if failing_position == 0 {
            ChainRunner::new().add(failing).add(healthy)
        } else {
            ChainRunner::new().add(healthy).add(failing)
        }
        .drain_timeout(drain_timeout)
        .on_ready(ready_tx);

        let mut env = test_env();
        env.local_port = allocate_ports(1).unwrap().pop().unwrap().port();
        let handle = tokio::spawn(runner.run(env));
        Self {
            ready_rx,
            stopped_rx,
            gate_tx,
            relayed,
            handle,
        }
    }

    /// Waits until the healthy member was stopped, failing if the caller heard of the failure first. The gate has not
    /// opened, so the member's last line is still unrelayed.
    async fn until_the_healthy_member_is_stopped(&mut self) {
        tokio::select! {
            biased;
            r = &mut self.ready_rx => panic!("the start failure was reported ({r:?}) before the other member was stopped and its last line relayed"),
            _ = &mut self.stopped_rx => {}
        }
    }

    /// Opens the gate and returns what the caller was told and the chain's result, asserting the last line was relayed
    /// before the caller heard anything.
    async fn open_the_gate(self) -> (Reported, crate::Result<()>) {
        self.gate_tx.send(()).unwrap();
        let reported = self.ready_rx.await;
        assert!(
            self.relayed.load(Ordering::SeqCst),
            "the start failure was reported before the other member relayed its last line: {reported:?}"
        );
        (reported, self.handle.await.expect("chain task panicked"))
    }
}

/// How long the chain may sit idle before it counts as quiescent. Shorter than the chain's `drain_timeout` below.
pub(crate) const IDLE: std::time::Duration = std::time::Duration::from_secs(60);
pub(crate) const DRAIN: std::time::Duration = std::time::Duration::from_secs(3600);

/// Runs a chain of `failing` at `failing_position` and a [`LastLineMember`] on a paused clock, and asserts the
/// caller is not told of the failure until the healthy member was stopped and relayed the line it held back.
///
/// On a paused current-thread runtime a timer fires only when no task can make progress, so `IDLE` elapsing means
/// every task the chain's end woke has run: a failure not reported by then is being held, whatever the poll order.
async fn assert_failure_waits_for_the_other_members_last_line(
    failing: Box<dyn ChainPlugin>,
    failing_position: usize,
) -> (Reported, crate::Result<()>) {
    tokio::time::pause();
    let mut chain = FailingChain::start(failing, failing_position, DRAIN);
    chain.until_the_healthy_member_is_stopped().await;
    tokio::select! {
        biased;
        r = &mut chain.ready_rx => panic!("the start failure was reported ({r:?}) while the other member still held its last line"),
        () = tokio::time::sleep(IDLE) => {}
    }
    chain.open_the_gate().await
}

#[skuld::test]
async fn a_typed_start_failure_waits_for_the_other_members_last_line() {
    let (outcome, result) = assert_failure_waits_for_the_other_members_last_line(
        Box::new(FailsAtStart {
            how: StartFailure::Typed,
            lingers: false,
        }),
        0,
    )
    .await;
    let outcome = outcome.expect("the chain dropped `ready_tx` unsent");

    assert!(
        matches!(&outcome, Err(StartError::Fatal { detail, .. }) if detail == "member broke"),
        "want the member's own Fatal, got {outcome:?}"
    );
    assert!(
        matches!(result, Err(crate::Error::PluginExit { code: 3, .. })),
        "run must return the failing member's error, got {result:?}"
    );
}

#[skuld::test]
async fn an_exit_before_ready_waits_for_the_other_members_last_line() {
    let (outcome, result) = assert_failure_waits_for_the_other_members_last_line(
        Box::new(FailsAtStart {
            how: StartFailure::Dropped,
            lingers: false,
        }),
        0,
    )
    .await;
    let outcome = outcome.expect("the chain dropped `ready_tx` unsent");

    assert!(
        matches!(&outcome, Err(StartError::Fatal { detail, .. }) if detail.contains("exited before becoming ready")),
        "want the synthesized exited-before-ready Fatal, got {outcome:?}"
    );
    assert!(
        matches!(result, Err(crate::Error::PluginExit { code: 3, .. })),
        "run must return the failing member's error, got {result:?}"
    );
}

#[skuld::test]
async fn a_start_failure_behind_a_ready_member_waits_for_the_other_members_last_line() {
    let (outcome, result) = assert_failure_waits_for_the_other_members_last_line(
        Box::new(FailsAtStart {
            how: StartFailure::Typed,
            lingers: false,
        }),
        1,
    )
    .await;
    let outcome = outcome.expect("the chain dropped `ready_tx` unsent");

    assert!(
        matches!(&outcome, Err(StartError::Fatal { detail, .. }) if detail == "member broke"),
        "want the member's own Fatal, got {outcome:?}"
    );
    assert!(
        matches!(result, Err(crate::Error::PluginExit { code: 3, .. })),
        "run must return the failing member's error, got {result:?}"
    );
}

/// A member that reports a failure and keeps running does not leave the chain up: the start failure ends it.
#[skuld::test]
async fn a_start_failure_from_a_member_that_keeps_running_ends_the_chain() {
    for how in [StartFailure::Typed, StartFailure::Dropped] {
        let (ready_tx, ready_rx) = oneshot::channel();
        let runner = ChainRunner::new()
            .add(Box::new(FailsAtStart { how, lingers: true }))
            .on_ready(ready_tx);

        let mut env = test_env();
        env.local_port = allocate_ports(1).unwrap().pop().unwrap().port();
        let handle = tokio::spawn(runner.run(env));

        let outcome = ready_rx.await.expect("the failure must be reported, not dropped");
        assert!(matches!(outcome, Err(StartError::Fatal { .. })), "got {outcome:?}");
        // Only the chain ending lets this return; it exits cleanly because the member did.
        handle.await.unwrap().expect("a member that exits cleanly when stopped");
    }
}

/// The held failure is still delivered when a member ignores the cancel: `drain_timeout` is the chain's documented
/// failure bound.
#[skuld::test]
async fn a_start_failure_is_delivered_once_the_drain_bound_expires_on_a_member_that_ignores_shutdown() {
    let (ready_tx, ready_rx) = oneshot::channel();
    let runner = ChainRunner::new()
        .add(Box::new(FailsAtStart {
            how: StartFailure::Typed,
            lingers: false,
        }))
        .add(Box::new(StubbornPlugin {
            name: "stubborn".into(),
        }))
        .drain_timeout(std::time::Duration::from_millis(100))
        .on_ready(ready_tx);

    let mut env = test_env();
    env.local_port = allocate_ports(1).unwrap().pop().unwrap().port();
    let handle = tokio::spawn(runner.run(env));

    let outcome = ready_rx.await.expect("the held failure must be delivered, not dropped");
    assert!(
        matches!(&outcome, Err(StartError::Fatal { detail, .. }) if detail == "member broke"),
        "want the member's own Fatal, got {outcome:?}"
    );
    assert!(
        matches!(handle.await.unwrap(), Err(crate::Error::PluginExit { code: 3, .. })),
        "the member's error outranks the drain-timeout error"
    );
}

// The caller is released only after every member returned -------------------------------------------------------------

/// Like a Probe-mode `BinaryPlugin`: a side task owns `ready` until the chain's shutdown while `run` itself exits with
/// an error, so the readiness channel stays open when the chain is cancelled.
struct ProbeLikeCrash;

#[async_trait::async_trait]
impl ChainPlugin for ProbeLikeCrash {
    fn name(&self) -> &str {
        "probe-like-crash"
    }

    async fn run(
        self: Box<Self>,
        _local: SocketAddr,
        _remote: SocketAddr,
        shutdown: CancellationToken,
        ready: oneshot::Sender<Result<PluginReady, StartError>>,
    ) -> crate::Result<()> {
        tokio::spawn(async move {
            shutdown.cancelled().await;
            drop(ready);
        });
        Err(crate::Error::PluginExit {
            name: "probe-like-crash".into(),
            code: 3,
        })
    }
}

/// A member that panics while it holds `ready`.
struct PanicsAtStart;

#[async_trait::async_trait]
impl ChainPlugin for PanicsAtStart {
    fn name(&self) -> &str {
        "panics-at-start"
    }

    async fn run(
        self: Box<Self>,
        _local: SocketAddr,
        _remote: SocketAddr,
        _shutdown: CancellationToken,
        _ready: oneshot::Sender<Result<PluginReady, StartError>>,
    ) -> crate::Result<()> {
        panic!("member panicked at start");
    }
}

/// A member whose exit leaves `ready` open when the chain is cancelled reaches the caller as a dropped sender, and
/// that too waits for the other members: the aggregator has nothing to report, but dropping the sender is a release.
#[skuld::test]
async fn an_exit_that_leaves_ready_open_waits_for_the_other_members_last_line() {
    let (reported, result) = assert_failure_waits_for_the_other_members_last_line(Box::new(ProbeLikeCrash), 0).await;

    assert!(reported.is_err(), "nothing was reported to the caller: {reported:?}");
    assert!(
        matches!(result, Err(crate::Error::PluginExit { code: 3, .. })),
        "run must return the failing member's error, got {result:?}"
    );
}

#[skuld::test]
async fn a_member_that_panics_at_start_waits_for_the_other_members_last_line() {
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let (reported, result) = assert_failure_waits_for_the_other_members_last_line(Box::new(PanicsAtStart), 0).await;
    std::panic::set_hook(prev_hook);

    assert!(
        !matches!(reported, Ok(Ok(_))),
        "a chain whose member panicked is not ready: {reported:?}"
    );
    assert!(
        matches!(result, Err(crate::Error::Chain(ref msg)) if msg.contains("panicked")),
        "run must return the panic, got {result:?}"
    );
}

/// An external cancel before the chain is ready is not a start failure, but the caller's `ready` is still released
/// only after every member returned.
#[skuld::test]
async fn an_external_cancel_before_ready_releases_the_caller_after_the_members_returned() {
    tokio::time::pause();
    let (stopped_tx, mut stopped_rx) = oneshot::channel();
    let (gate_tx, gate_rx) = oneshot::channel();
    let relayed = Arc::new(AtomicBool::new(false));
    let cancel = CancellationToken::new();
    let (ready_tx, mut ready_rx) = oneshot::channel();
    let runner = ChainRunner::new()
        .add(Box::new(LastLineMember {
            ready_first: false,
            stopped: stopped_tx,
            gate: gate_rx,
            relayed: relayed.clone(),
        }))
        .cancel_token(cancel.clone())
        .drain_timeout(DRAIN)
        .on_ready(ready_tx);
    let mut env = test_env();
    env.local_port = allocate_ports(1).unwrap().pop().unwrap().port();
    let handle = tokio::spawn(runner.run(env));

    cancel.cancel();
    tokio::select! {
        biased;
        r = &mut ready_rx => panic!("the caller was released ({r:?}) before the member was stopped"),
        _ = &mut stopped_rx => {}
    }
    tokio::select! {
        biased;
        r = &mut ready_rx => panic!("the caller was released ({r:?}) while the member still held its last line"),
        () = tokio::time::sleep(IDLE) => {}
    }
    gate_tx.send(()).unwrap();
    assert!(ready_rx.await.is_err(), "a cancelled chain was not ready");
    assert!(
        relayed.load(Ordering::SeqCst),
        "released before the member relayed its last line"
    );
    handle.await.unwrap().expect("a cancel is a clean end");
}

/// The same on a multi-thread runtime, where a member's exit and the aggregator run on different threads. The caller's
/// channel must not close until the member's last line was relayed, whichever thread gets there first. This does not
/// control the order, so it cannot prove the absence of an early release; the paused-clock tests above do.
#[skuld::test]
fn on_a_multi_thread_runtime_an_exit_before_ready_waits_for_the_other_members_last_line() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        for failing in [
            Box::new(ProbeLikeCrash) as Box<dyn ChainPlugin>,
            Box::new(FailsAtStart {
                how: StartFailure::Dropped,
                lingers: false,
            }),
        ] {
            let mut chain = FailingChain::start(failing, 0, DRAIN);
            chain.until_the_healthy_member_is_stopped().await;
            let (reported, result) = chain.open_the_gate().await;
            assert!(!matches!(reported, Ok(Ok(_))), "{reported:?}");
            assert!(
                matches!(result, Err(crate::Error::PluginExit { code: 3, .. })),
                "{result:?}"
            );
        }
    });
}

/// `drain_timeout` bounds the wait for a member that ignores the cancel; the caller's channel is released then too,
/// not left open for ever.
#[skuld::test]
async fn an_open_ready_is_released_once_the_drain_bound_expires_on_a_member_that_ignores_shutdown() {
    let (ready_tx, ready_rx) = oneshot::channel();
    let runner = ChainRunner::new()
        .add(Box::new(ProbeLikeCrash))
        .add(Box::new(StubbornPlugin {
            name: "stubborn".into(),
        }))
        .drain_timeout(std::time::Duration::from_millis(100))
        .on_ready(ready_tx);

    let mut env = test_env();
    env.local_port = allocate_ports(1).unwrap().pop().unwrap().port();
    let handle = tokio::spawn(runner.run(env));

    assert!(ready_rx.await.is_err(), "the caller must be released, not left waiting");
    assert!(
        matches!(handle.await.unwrap(), Err(crate::Error::PluginExit { code: 3, .. })),
        "the member's error outranks the drain-timeout error"
    );
}

// poll_ready ==========================================================================================================

#[skuld::test]
async fn poll_ready_returns_the_address_once_it_accepts() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let ready = crate::chain::poll_ready(addr, CancellationToken::new()).await;

    assert_eq!(ready, Some(addr));
}

#[skuld::test]
async fn poll_ready_gives_up_on_shutdown_while_the_address_refuses() {
    // A freed port refuses until something else takes it; shutdown must end the poll either way.
    let freed = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let shutdown = CancellationToken::new();
    shutdown.cancel();

    assert_eq!(crate::chain::poll_ready(freed, shutdown).await, None);
}

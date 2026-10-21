// `CancellationToken::new` is the cancel-test harness root; module-level
// allow per the hole workspace clippy.toml's "Bridge cancellation contract"
// sanctioned-test-file exception.
#![allow(clippy::disallowed_methods)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use crate::chain::{ChainReady, ChainRunner};
use crate::once::Once;
use crate::plugin::ChainPlugin;
use crate::port::free_loopback_port;
use crate::sitrep::{PluginReady, StartError, Transports};

// Test helpers ========================================================================================================

pub(crate) fn test_env() -> crate::sip003::PluginEnv {
    crate::sip003::PluginEnv {
        local_host: "127.0.0.1".parse().unwrap(),
        local_port: 0, // tests that bind it set a free port
        remote_host: "127.0.0.1".into(),
        remote_port: 20000,
        plugin_options: None,
    }
}

/// Plugin that readies and exits cleanly at once.
pub(crate) struct InstantPlugin {
    pub(crate) name: String,
}

#[async_trait::async_trait]
impl ChainPlugin for InstantPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    async fn run(
        &self,
        local: SocketAddr,
        _remote: SocketAddr,
        _shutdown: CancellationToken,
        ready: oneshot::Sender<Result<PluginReady, StartError>>,
    ) -> crate::Result<()> {
        // A plugin that exits without readying has failed to start, which ends `run` with an error.
        let _ = ready.send(Ok(PluginReady {
            listen: local,
            transports: Transports::TCP,
        }));
        Ok(())
    }
}

/// Plugin that binds a TCP listener and waits for shutdown.
struct ListeningPlugin {
    name: String,
    /// The address it bound and reported, for a test to compare against what the chain reports.
    bound: Arc<Mutex<Option<SocketAddr>>>,
}

impl ListeningPlugin {
    fn new(name: &str) -> (Self, Arc<Mutex<Option<SocketAddr>>>) {
        let bound = Arc::new(Mutex::new(None));
        let plugin = Self {
            name: name.into(),
            bound: bound.clone(),
        };
        (plugin, bound)
    }
}

#[async_trait::async_trait]
impl ChainPlugin for ListeningPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    async fn run(
        &self,
        local: SocketAddr,
        _remote: SocketAddr,
        shutdown: CancellationToken,
        ready: oneshot::Sender<Result<PluginReady, StartError>>,
    ) -> crate::Result<()> {
        let listener = tokio::net::TcpListener::bind(local).await?;
        let actual = listener.local_addr().unwrap_or(local);
        *self.bound.lock().unwrap() = Some(actual);
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
/// chain's transports-intersection across hops without a real
/// subprocess.
struct TransportsPlugin {
    name: String,
    transports: Transports,
    /// The address it bound and reported, for a test to compare against what the chain reports.
    bound: Arc<Mutex<Option<SocketAddr>>>,
}

#[async_trait::async_trait]
impl ChainPlugin for TransportsPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    async fn run(
        &self,
        local: SocketAddr,
        _remote: SocketAddr,
        shutdown: CancellationToken,
        ready: oneshot::Sender<Result<PluginReady, StartError>>,
    ) -> crate::Result<()> {
        let listener = tokio::net::TcpListener::bind(local).await?;
        let actual = listener.local_addr().unwrap_or(local);
        *self.bound.lock().unwrap() = Some(actual);
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
        &self,
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

/// Plugin that readies, then exits with an error.
struct FailsAfterReady;

#[async_trait::async_trait]
impl ChainPlugin for FailsAfterReady {
    fn name(&self) -> &str {
        "fails-after-ready"
    }

    async fn run(
        &self,
        local: SocketAddr,
        _remote: SocketAddr,
        _shutdown: CancellationToken,
        ready: oneshot::Sender<Result<PluginReady, StartError>>,
    ) -> crate::Result<()> {
        let _ = ready.send(Ok(PluginReady {
            listen: local,
            transports: Transports::TCP,
        }));
        Err(crate::Error::PluginExit {
            name: "fails-after-ready".into(),
            code: 1,
        })
    }
}

/// Plugin that reports ready, then never exits and deliberately ignores `shutdown`.
/// Models a long-running plugin (e.g. v2ray-plugin) for drain-timeout regression
/// tests. It readies so the hop behind it can start.
struct StubbornPlugin {
    name: String,
}

#[async_trait::async_trait]
impl ChainPlugin for StubbornPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    async fn run(
        &self,
        local: SocketAddr,
        _remote: SocketAddr,
        _shutdown: CancellationToken,
        ready: oneshot::Sender<Result<PluginReady, StartError>>,
    ) -> crate::Result<()> {
        let _ = ready.send(Ok(PluginReady {
            listen: local,
            transports: Transports::TCP,
        }));
        std::future::pending::<crate::Result<()>>().await
    }
}

/// Plugin that readies, then panics. Exercises the `JoinError` arm of
/// `record_exit`.
struct PanickingPlugin;

#[async_trait::async_trait]
impl ChainPlugin for PanickingPlugin {
    fn name(&self) -> &str {
        "panicking"
    }

    async fn run(
        &self,
        local: SocketAddr,
        _remote: SocketAddr,
        _shutdown: CancellationToken,
        ready: oneshot::Sender<Result<PluginReady, StartError>>,
    ) -> crate::Result<()> {
        let _ = ready.send(Ok(PluginReady {
            listen: local,
            transports: Transports::TCP,
        }));
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
async fn on_ready_fires_with_the_bound_address() {
    let (tx, rx) = oneshot::channel();
    let (listener, bound) = ListeningPlugin::new("listener");

    let runner = ChainRunner::new().add(Box::new(listener)).on_ready(tx);

    // Port 0: the plugin binds a port of its own and reports it.
    let env = test_env();

    let handle = tokio::spawn(runner.run(env));

    // rx fires with the chain-ready payload once every plugin is listening.
    let chain_ready = rx
        .await
        .expect("ready_tx was dropped without sending")
        .expect("chain should be ready, not a start error");

    assert_ne!(
        chain_ready.listen.port(),
        0,
        "the chain reports the bound port, not the requested 0"
    );
    assert_eq!(
        Some(chain_ready.listen),
        *bound.lock().unwrap(),
        "the chain reports the address the plugin bound"
    );
    tokio::net::TcpStream::connect(chain_ready.listen)
        .await
        .expect("the reported address is really listening");

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

    // The plugin exits before readying, so the chain synthesizes a
    // process-exit `StartError::Fatal` and sends it through ready_tx.
    let outcome = rx.await.expect("the chain should report a start error, not drop");
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

/// The chain reports the end-to-end transports as the intersection
/// across every hop: a transport is carried only if EVERY plugin serves
/// it. Here a TCP|UDP hop and a TCP-only hop must intersect to TCP. The
/// `listen` must be the position-0 plugin's (Client mode), not whichever
/// readied first.
#[skuld::test]
async fn on_ready_transports_are_intersection_across_hops() {
    let (tx, rx) = oneshot::channel();

    // Position 0 is the chain-public hop; it serves TCP+UDP. Position 1
    // (downstream) is TCP-only, so the end-to-end set narrows to TCP.
    let public_bound = Arc::new(Mutex::new(None));
    let downstream_bound = Arc::new(Mutex::new(None));

    let runner = ChainRunner::new()
        .add(Box::new(TransportsPlugin {
            name: "public".into(),
            transports: Transports::TCP | Transports::UDP,
            bound: public_bound.clone(),
        }))
        .add(Box::new(TransportsPlugin {
            name: "downstream".into(),
            transports: Transports::TCP,
            bound: downstream_bound.clone(),
        }))
        .on_ready(tx);

    // Port 0: the public hop binds a port of its own and reports it.
    let env = test_env();

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
    let public = public_bound.lock().unwrap().expect("the public hop bound");
    let downstream = downstream_bound.lock().unwrap().expect("the downstream hop bound");
    assert_ne!(public, downstream, "the hops bound different ports");
    assert_eq!(
        chain_ready.listen, public,
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
        .add(Box::new(ListeningPlugin::new("listener").0))
        .cancel_token(cancel.clone())
        .on_ready(ready_tx);

    // Port 0: the plugin binds a port of its own.
    let env = test_env();

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

/// Plugin that records its `(local, remote)` args, reports ready and exits cleanly. Used
/// to assert address wiring without doing real I/O. It readies because the chain starts a hop only
/// after the hop it forwards to is ready. Backing storage is
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
        &self,
        local: SocketAddr,
        remote: SocketAddr,
        _shutdown: CancellationToken,
        ready: oneshot::Sender<Result<PluginReady, StartError>>,
    ) -> crate::Result<()> {
        *self.record.lock().unwrap() = Some((local, remote));
        let _ = ready.send(Ok(PluginReady {
            listen: local,
            transports: Transports::TCP,
        }));
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
    let ss_remote_port = free_loopback_port().port();
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
    let (inner, inner_bound) = ListeningPlugin::new("inner-listener");
    let (outer, outer_bound) = ListeningPlugin::new("outer-listener");

    // `ListeningPlugin` binds whatever `local` it is given. In Server mode the OUTER (position 1) plugin gets
    // `local = SS_REMOTE`, so `on_ready` must report what THAT plugin bound, not what the inner did. Port 0 for
    // SS_REMOTE: each plugin binds a port of its own and records it.
    let runner = ChainRunner::new()
        .mode(crate::chain::Mode::Server)
        .add(Box::new(inner))
        .add(Box::new(outer))
        .on_ready(tx);

    let ss_local_port = free_loopback_port().port(); // the inner forwards here; nothing binds it
    let env = crate::sip003::PluginEnv {
        local_host: "127.0.0.1".parse().unwrap(),
        local_port: ss_local_port,
        remote_host: "127.0.0.1".into(),
        remote_port: 0,
        plugin_options: None,
    };

    let handle = tokio::spawn(runner.run(env));
    let chain_ready = rx.await.expect("ready_tx dropped").expect("chain should be ready");
    let outer = outer_bound.lock().unwrap().expect("the outer plugin bound");
    let inner = inner_bound.lock().unwrap().expect("the inner plugin bound");
    assert_ne!(outer.port(), 0);
    assert_ne!(outer, inner, "the plugins bound different ports");
    assert_eq!(
        chain_ready.listen, outer,
        "on_ready in Server mode must report SS_REMOTE (outer's local), not SS_LOCAL (inner's remote)"
    );
    handle.abort();
}

#[skuld::test]
async fn chain_runner_default_matches_explicit_client_mode() {
    let ss_local: SocketAddr = "127.0.0.1:22222".parse().unwrap();
    let ss_remote_port = free_loopback_port().port();
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
    env.local_port = free_loopback_port().port();

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
        .add(Box::new(FailsAfterReady))
        .add(Box::new(StubbornPlugin {
            name: "stubborn".into(),
        }))
        .drain_timeout(drain_timeout);

    let mut env = test_env();
    env.local_port = free_loopback_port().port();

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
    env.local_port = free_loopback_port().port();

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

/// A member that readies, signals it is running, then fails.
struct SignalsThenFails {
    running: Once<oneshot::Sender<()>>,
}

#[async_trait::async_trait]
impl ChainPlugin for SignalsThenFails {
    fn name(&self) -> &str {
        "signals-then-fails"
    }

    async fn run(
        &self,
        local: SocketAddr,
        _remote: SocketAddr,
        _shutdown: CancellationToken,
        ready: oneshot::Sender<Result<PluginReady, StartError>>,
    ) -> crate::Result<()> {
        let _ = ready.send(Ok(PluginReady {
            listen: local,
            transports: Transports::TCP,
        }));
        let _ = self.running.take().send(());
        Err(crate::Error::PluginExit {
            name: "signals-then-fails".into(),
            code: 1,
        })
    }
}

/// External cancel fires concurrently with a plugin error — the plugin's
/// error must still win over any drain-timeout wrapping, regardless of
/// which wins the Phase 1 `select!` race. The cancel is sent once the failing member is running: the chain starts
/// it only after the stubborn one behind it is ready.
#[skuld::test]
async fn external_cancel_concurrent_with_plugin_error_preserves_plugin_error() {
    let cancel = CancellationToken::new();
    let drain_timeout = std::time::Duration::from_millis(200);

    let (running_tx, running_rx) = oneshot::channel();
    let runner = ChainRunner::new()
        .add(Box::new(SignalsThenFails {
            running: Once::new(running_tx),
        }))
        .add(Box::new(StubbornPlugin {
            name: "stubborn".into(),
        }))
        .cancel_token(cancel.clone())
        .drain_timeout(drain_timeout);

    let mut env = test_env();
    env.local_port = free_loopback_port().port();

    // Fire the external cancel as close as we can to the plugin error. Whether
    // Phase 1 observes the plugin exit first, or `shutdown.cancelled()` first,
    // `record_exit` must still have captured `first_error` by the time the
    // chain returns.
    let handle = tokio::spawn(runner.run(env));
    running_rx.await.expect("the failing member ran");
    cancel.cancel();

    let result = handle.await.expect("no JoinError");

    match result {
        Err(crate::Error::PluginExit { code: 1, .. }) => {}
        other => panic!("expected FailingPlugin's PluginExit error to be preserved, got {other:?}"),
    }
}

/// How long a member's take-down takes once it is told to stop: a `BinaryPlugin`'s own two waits (5 s for the root
/// to exit, 5 s for its output), written out so a change to either fails here.
const TAKE_DOWN: std::time::Duration = std::time::Duration::from_secs(10);

/// A member that takes `TAKE_DOWN` to stop, then ends with an error, as a plugin that ignores terminate does.
struct SlowToStop;

#[async_trait::async_trait]
impl ChainPlugin for SlowToStop {
    fn name(&self) -> &str {
        "slow-to-stop"
    }

    async fn run(
        &self,
        _local: SocketAddr,
        _remote: SocketAddr,
        shutdown: CancellationToken,
        _ready: oneshot::Sender<Result<PluginReady, StartError>>,
    ) -> crate::Result<()> {
        shutdown.cancelled().await;
        tokio::time::sleep(TAKE_DOWN).await;
        Err(crate::Error::PluginExit {
            name: "slow-to-stop".into(),
            code: 3,
        })
    }
}

/// The bounds are derived from one another, each waiting on the one below it with headroom, and the default drain
/// budget sits on top of the stack. Both are written out here so a change to any of them fails here.
#[skuld::test]
fn the_drain_timeout_default_is_derived_from_the_bounds_it_waits_on() {
    use crate::binary::{TAKEDOWN_BOUND, TAKEDOWN_TAIL};
    use crate::chain::DEFAULT_DRAIN_TIMEOUT;
    use crate::tap::INNER_STOP_BOUND;

    assert_eq!(TAKEDOWN_BOUND, TAKE_DOWN);
    assert_eq!(TAKEDOWN_TAIL, std::time::Duration::from_secs(1));
    assert_eq!(INNER_STOP_BOUND, TAKE_DOWN + TAKEDOWN_TAIL);
    assert_eq!(DEFAULT_DRAIN_TIMEOUT, INNER_STOP_BOUND + TAKEDOWN_TAIL);
    assert_eq!(DEFAULT_DRAIN_TIMEOUT, std::time::Duration::from_secs(12));
}

/// The default drain budget outlasts a member's whole take-down, so a member that needs all of its own bounds to stop
/// is waited for, not aborted before it has relayed its last line.
#[skuld::test]
async fn the_default_drain_timeout_outlasts_a_members_take_down() {
    tokio::time::pause();
    let cancel = CancellationToken::new();
    let runner = ChainRunner::new()
        .add(Box::new(SlowToStop))
        .cancel_token(cancel.clone());
    let mut env = test_env();
    env.local_port = free_loopback_port().port();
    let handle = tokio::spawn(runner.run(env));

    cancel.cancel();
    let result = tokio::time::timeout(DRAIN, handle)
        .await
        .expect("the chain never ended")
        .unwrap();

    assert!(
        matches!(result, Err(crate::Error::PluginExit { code: 3, .. })),
        "the member must be waited for, not aborted at the default budget; got {result:?}"
    );
}

/// A member that panics while it is dropped, as the drain bound's abort drops it.
struct PanicsWhenAborted;

struct PanicsOnDrop;

impl Drop for PanicsOnDrop {
    fn drop(&mut self) {
        panic!("dropped");
    }
}

#[async_trait::async_trait]
impl ChainPlugin for PanicsWhenAborted {
    fn name(&self) -> &str {
        "panics-when-aborted"
    }

    async fn run(
        &self,
        _local: SocketAddr,
        _remote: SocketAddr,
        _shutdown: CancellationToken,
        _ready: oneshot::Sender<Result<PluginReady, StartError>>,
    ) -> crate::Result<()> {
        let _guard = PanicsOnDrop;
        std::future::pending().await
    }
}

/// What a member does in the abort window after the drain bound is not lost: a cancelled task is expected, anything
/// else (here a panic while the member is dropped) is recorded and outranks the drain-timeout error.
#[skuld::test]
async fn a_member_that_fails_in_the_abort_window_is_recorded() {
    tokio::time::pause();
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let cancel = CancellationToken::new();
    let runner = ChainRunner::new()
        .add(Box::new(PanicsWhenAborted))
        .cancel_token(cancel.clone())
        .drain_timeout(std::time::Duration::from_millis(100));
    let mut env = test_env();
    env.local_port = free_loopback_port().port();
    let handle = tokio::spawn(runner.run(env));

    cancel.cancel();
    let result = tokio::time::timeout(DRAIN, handle)
        .await
        .expect("the chain never ended")
        .unwrap();
    std::panic::set_hook(previous);

    assert!(
        matches!(&result, Err(crate::Error::Chain(msg)) if msg.contains("panicked")),
        "want the panic, got {result:?}"
    );
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
    env.local_port = free_loopback_port().port();

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

use crate::chain::{judge, HopFailure, Pending, Readiness, ReadyGate, Verdict};
use crate::hop::Decision;

fn ready_decision(port: u16) -> Decision {
    Decision::Ready {
        given: SocketAddr::from(([127, 0, 0, 1], port)),
        report: PluginReady {
            listen: SocketAddr::from(([127, 0, 0, 1], port)),
            transports: Transports::TCP,
        },
    }
}

/// `BindConflict` is the only retryable class, so discarding one that the
/// plugin already delivered turns a transient port collision into a hard
/// start failure.
#[skuld::test]
fn a_start_failure_delivered_before_shutdown_won_the_race_is_judged_a_failure() {
    let shutdown = CancellationToken::new();
    shutdown.cancel();

    let decision = Decision::Failed(StartError::BindConflict {
        errno: 98,
        addr: "127.0.0.1:1080".parse().unwrap(),
    });
    match judge(Ok(decision), &shutdown) {
        Verdict::Failed(StartError::BindConflict { errno, .. }) => assert_eq!(errno, 98),
        other => panic!("a delivered StartError must be reported, not discarded; got {other:?}"),
    }
}

/// A start failure ends the chain: judging it cancels the other plugins.
#[skuld::test]
fn judging_a_start_failure_cancels_the_chain() {
    let shutdown = CancellationToken::new();

    let verdict = judge(Ok(Decision::Failed(fatal())), &shutdown);

    assert!(
        matches!(verdict, Verdict::Failed(StartError::Fatal { .. })),
        "{verdict:?}"
    );
    assert!(shutdown.is_cancelled(), "a start failure must stop the other plugins");
}

/// A plugin that drops its sender unsent exited before ready.
#[skuld::test]
fn a_hop_that_dropped_its_sender_unsent_is_judged_a_failure() {
    let shutdown = CancellationToken::new();

    let verdict = judge(Ok(Decision::Dropped), &shutdown);

    assert!(
        matches!(&verdict, Verdict::Failed(StartError::Fatal { detail, .. }) if detail.contains("exited before becoming ready")),
        "{verdict:?}"
    );
    assert!(shutdown.is_cancelled());
}

#[skuld::test]
fn a_ready_hop_is_judged_ready() {
    let verdict = judge(Ok(ready_decision(1080)), &CancellationToken::new());

    match verdict {
        Verdict::Ready { given, report } => {
            assert_eq!(given.port(), 1080);
            assert_eq!(report.listen.port(), 1080);
        }
        other => panic!("{other:?}"),
    }
}

/// A delivered `Ok(PluginReady)` must NOT be rescued: `shutdown` is chain-wide and may have been cancelled by another
/// plugin exit or an external cancel, so nothing here shows the chain is still viable.
#[skuld::test]
fn a_ready_hop_is_preempted_once_shutdown_won_the_race() {
    let shutdown = CancellationToken::new();
    shutdown.cancel();

    let verdict = judge(Ok(ready_decision(1080)), &shutdown);

    assert!(
        matches!(verdict, Verdict::Preempted),
        "a chain whose plugin already exited must never be reported ready: {verdict:?}"
    );
}

/// A sender dropped unsent after the chain was cancelled is the cancel doing, not a synthesized `Fatal`.
#[skuld::test]
fn a_dropped_hop_is_preempted_once_shutdown_won_the_race() {
    let shutdown = CancellationToken::new();
    shutdown.cancel();

    let verdict = judge(Ok(Decision::Dropped), &shutdown);

    assert!(
        matches!(verdict, Verdict::Preempted),
        "a sender dropped unsent must not become a synthesized Fatal here: {verdict:?}"
    );
}

/// A hop task that ended without deciding after the chain was cancelled (it was cancelled while picking a port or
/// waiting to restart) has nothing to report.
#[skuld::test]
fn a_hop_that_ended_without_a_decision_is_preempted_once_shutdown_won_the_race() {
    let shutdown = CancellationToken::new();
    shutdown.cancel();
    let (tx, rx) = oneshot::channel::<Decision>();
    drop(tx);

    let verdict = judge(rx.blocking_recv(), &shutdown);

    assert!(matches!(verdict, Verdict::Preempted), "{verdict:?}");
}

/// A hop task that ended without deciding while the chain was not cancelled (its plugin handed `ready` to a task of
/// its own and returned) never started: it is the synthesized exited-before-ready failure, and it cancels the chain,
/// the same as a sender the plugin dropped itself.
#[skuld::test]
fn a_hop_that_ended_without_a_decision_fails_the_start_while_the_chain_runs() {
    let shutdown = CancellationToken::new();
    let (tx, rx) = oneshot::channel::<Decision>();
    drop(tx);

    let verdict = judge(rx.blocking_recv(), &shutdown);

    assert!(
        matches!(&verdict, Verdict::Failed(StartError::Fatal { detail, .. }) if detail.contains("exited before becoming ready")),
        "{verdict:?}"
    );
    assert!(shutdown.is_cancelled(), "a failed start must cancel the chain");
}

// The gate on the caller's `ready` ------------------------------------------------------------------------------------

fn chain_ready() -> ChainReady {
    ChainReady {
        listen: "127.0.0.1:1080".parse().unwrap(),
        transports: Transports::TCP,
    }
}

fn pending(decision: oneshot::Receiver<Decision>) -> Pending {
    Pending {
        plugin: "hop".into(),
        decision,
    }
}

/// Whether `result` is `run` ending on `plugin`'s failed start, with a cause `cause_is` accepts.
fn is_start_failed(result: &crate::Result<()>, plugin: &str, cause_is: impl Fn(&StartError) -> bool) -> bool {
    matches!(result, Err(crate::Error::StartFailed { plugin: p, cause }) if p == plugin && cause_is(cause))
}

fn exited_before_ready(cause: &StartError) -> bool {
    matches!(cause, StartError::Fatal { detail, .. } if detail.contains("exited before becoming ready"))
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

    gate.absorb(Readiness::Failed(HopFailure {
        plugin: "broken".into(),
        cause: fatal(),
    }));
    assert!(matches!(rx.try_recv(), Err(oneshot::error::TryRecvError::Empty)));

    let released = gate.release();
    assert!(matches!(rx.try_recv(), Ok(Err(StartError::Fatal { .. }))));
    assert!(matches!(released, Some(HopFailure { plugin, .. }) if plugin == "broken"));
}

/// What the gate hands back does not depend on a caller listening: a chain with no `on_ready` still learns of the
/// failure, the one it found and the one a preempted hop delivered since.
#[skuld::test]
fn the_gate_returns_the_failure_with_no_caller_registered() {
    let mut found = ReadyGate::new(None);
    found.absorb(Readiness::Failed(HopFailure {
        plugin: "found".into(),
        cause: fatal(),
    }));
    assert!(matches!(found.release(), Some(HopFailure { plugin, .. }) if plugin == "found"));

    let mut delivered = ReadyGate::new(None);
    let (hop_tx, unread) = oneshot::channel();
    delivered.absorb(Readiness::Preempted {
        unread: Some(pending(unread)),
    });
    hop_tx.send(Decision::Failed(fatal())).unwrap();
    assert!(matches!(delivered.release(), Some(HopFailure { plugin, .. }) if plugin == "hop"));

    assert!(ReadyGate::new(None).release().is_none());
}

/// Nothing to report: the sender stays open until the release, so the caller channel does not close early.
#[skuld::test]
fn the_gate_keeps_the_sender_open_when_there_is_nothing_to_report_until_released() {
    let (tx, mut rx) = oneshot::channel();
    let mut gate = ReadyGate::new(Some(tx));
    let (_hop_tx, unread) = oneshot::channel();

    gate.absorb(Readiness::Preempted {
        unread: Some(pending(unread)),
    });
    assert!(matches!(rx.try_recv(), Err(oneshot::error::TryRecvError::Empty)));

    gate.release();
    assert!(matches!(rx.try_recv(), Err(oneshot::error::TryRecvError::Closed)));
}

/// What the preempted hop delivers before the release is read at the release, and only a typed failure counts: a
/// `Ready` does not rescue a chain whose `shutdown` already fired.
#[skuld::test]
fn the_gate_reports_what_the_preempted_hop_delivered_by_the_release() {
    // `hop_drops_it`: the hop supervisor ended before the release without deciding, instead of staying open.
    for (delivered, hop_drops_it, reported_fatal) in [
        (Some(Decision::Failed(fatal())), false, true),
        (Some(ready_decision(1080)), false, false),
        (Some(Decision::Dropped), false, false),
        // Nothing delivered, sender still open.
        (None, false, false),
        // Nothing delivered, sender dropped: the receiver reads `Closed`, which is no failure to report.
        (None, true, false),
    ] {
        let (tx, mut rx) = oneshot::channel();
        let mut gate = ReadyGate::new(Some(tx));
        let (hop_tx, unread) = oneshot::channel();
        gate.absorb(Readiness::Preempted {
            unread: Some(pending(unread)),
        });
        assert!(matches!(rx.try_recv(), Err(oneshot::error::TryRecvError::Empty)));

        let case = format!("{delivered:?}, dropped={hop_drops_it}");
        if let Some(delivered) = delivered {
            hop_tx.send(delivered).unwrap();
        } else if hop_drops_it {
            drop(hop_tx);
        }
        gate.release();

        match rx.try_recv() {
            Ok(Err(StartError::Fatal { .. })) => assert!(reported_fatal, "{case}"),
            Err(oneshot::error::TryRecvError::Closed) => assert!(!reported_fatal, "{case}"),
            other => panic!("{case}: {other:?}"),
        }
    }
}

/// A preemption with nothing left to read (the decision was already consumed) releases the same way.
#[skuld::test]
fn the_gate_keeps_the_sender_open_until_released_even_if_nothing_is_left_to_read() {
    let (tx, mut rx) = oneshot::channel::<Result<ChainReady, StartError>>();
    let mut gate = ReadyGate::new(Some(tx));
    gate.absorb(Readiness::Preempted { unread: None });
    assert!(matches!(rx.try_recv(), Err(oneshot::error::TryRecvError::Empty)));

    gate.release();
    assert!(matches!(rx.try_recv(), Err(oneshot::error::TryRecvError::Closed)));
}

/// A gate that absorbed nothing is released the same way.
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
        &self,
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
    stopped: Once<oneshot::Sender<()>>,
    gate: Once<oneshot::Receiver<()>>,
    relayed: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl ChainPlugin for LastLineMember {
    fn name(&self) -> &str {
        "last-line-member"
    }

    async fn run(
        &self,
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
        let _ = self.stopped.take().send(());
        let _ = self.gate.take().await;
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
    /// The healthy member starts first and readies; `failing` starts behind it.
    fn start(failing: Box<dyn ChainPlugin>, drain_timeout: std::time::Duration) -> Self {
        let (stopped_tx, stopped_rx) = oneshot::channel();
        let (gate_tx, gate_rx) = oneshot::channel();
        let relayed = Arc::new(AtomicBool::new(false));
        let healthy = Box::new(LastLineMember {
            ready_first: true,
            stopped: Once::new(stopped_tx),
            gate: Once::new(gate_rx),
            relayed: relayed.clone(),
        });
        let (ready_tx, ready_rx) = oneshot::channel();
        let runner = ChainRunner::new()
            .add(failing)
            .add(healthy)
            .drain_timeout(drain_timeout)
            .on_ready(ready_tx);

        let mut env = test_env();
        env.local_port = free_loopback_port().port();
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

/// Runs a chain of a [`LastLineMember`] and, started behind it, `failing`, on a paused clock, and asserts the
/// caller is not told of the failure until the healthy member was stopped and relayed the line it held back.
///
/// On a paused current-thread runtime a timer fires only when no task can make progress, so `IDLE` elapsing means
/// every task the chain's end woke has run: a failure not reported by then is being held, whatever the poll order.
async fn assert_failure_waits_for_the_other_members_last_line(
    failing: Box<dyn ChainPlugin>,
) -> (Reported, crate::Result<()>) {
    tokio::time::pause();
    let mut chain = FailingChain::start(failing, DRAIN);
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
    let (outcome, result) = assert_failure_waits_for_the_other_members_last_line(Box::new(FailsAtStart {
        how: StartFailure::Typed,
        lingers: false,
    }))
    .await;
    let outcome = outcome.expect("the chain dropped `ready_tx` unsent");

    assert!(
        matches!(&outcome, Err(StartError::Fatal { detail, .. }) if detail == "member broke"),
        "want the member's own Fatal, got {outcome:?}"
    );
    assert!(
        is_start_failed(
            &result,
            "fails-at-start",
            |cause| matches!(cause, StartError::Fatal { detail, .. } if detail == "member broke")
        ),
        "run must return the failed start, got {result:?}"
    );
}

#[skuld::test]
async fn an_exit_before_ready_waits_for_the_other_members_last_line() {
    let (outcome, result) = assert_failure_waits_for_the_other_members_last_line(Box::new(FailsAtStart {
        how: StartFailure::Dropped,
        lingers: false,
    }))
    .await;
    let outcome = outcome.expect("the chain dropped `ready_tx` unsent");

    assert!(
        matches!(&outcome, Err(StartError::Fatal { detail, .. }) if detail.contains("exited before becoming ready")),
        "want the synthesized exited-before-ready Fatal, got {outcome:?}"
    );
    assert!(
        is_start_failed(&result, "fails-at-start", exited_before_ready),
        "run must return the failed start, got {result:?}"
    );
}

/// A member behind the failing one is never started: it starts only once the failing one is ready.
struct NeverStarted {
    entered: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl ChainPlugin for NeverStarted {
    fn name(&self) -> &str {
        "never-started"
    }

    async fn run(
        &self,
        _local: SocketAddr,
        _remote: SocketAddr,
        _shutdown: CancellationToken,
        _ready: oneshot::Sender<Result<PluginReady, StartError>>,
    ) -> crate::Result<()> {
        self.entered.store(true, Ordering::SeqCst);
        Ok(())
    }
}

/// A start failure in the first-started member ends the chain with the member behind it never started, and the caller
/// hears the typed failure.
#[skuld::test]
async fn a_start_failure_in_the_first_started_member_leaves_the_next_one_unstarted() {
    for how in [StartFailure::Typed, StartFailure::Dropped] {
        let entered = Arc::new(AtomicBool::new(false));
        let (ready_tx, ready_rx) = oneshot::channel();
        let runner = ChainRunner::new()
            .add(Box::new(NeverStarted {
                entered: entered.clone(),
            }))
            .add(Box::new(FailsAtStart { how, lingers: false }))
            .on_ready(ready_tx);
        let mut env = test_env();
        env.local_port = free_loopback_port().port();

        let result = runner.run(env).await;

        assert!(
            is_start_failed(&result, "fails-at-start", |cause| matches!(
                cause,
                StartError::Fatal { .. }
            )),
            "run must return the failed start, got {result:?}"
        );
        assert!(matches!(ready_rx.await, Ok(Err(StartError::Fatal { .. }))));
        assert!(
            !entered.load(Ordering::SeqCst),
            "a member behind a failed start was started"
        );
    }
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
        env.local_port = free_loopback_port().port();
        let handle = tokio::spawn(runner.run(env));

        let outcome = ready_rx.await.expect("the failure must be reported, not dropped");
        assert!(matches!(outcome, Err(StartError::Fatal { .. })), "got {outcome:?}");
        // Only the chain ending lets this return. The member exited cleanly when stopped, and the start failure
        // is still `run`'s result.
        let result = handle.await.unwrap();
        assert!(
            is_start_failed(&result, "fails-at-start", |cause| matches!(
                cause,
                StartError::Fatal { .. }
            )),
            "{result:?}"
        );
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
    env.local_port = free_loopback_port().port();
    let handle = tokio::spawn(runner.run(env));

    let outcome = ready_rx.await.expect("the held failure must be delivered, not dropped");
    assert!(
        matches!(&outcome, Err(StartError::Fatal { detail, .. }) if detail == "member broke"),
        "want the member's own Fatal, got {outcome:?}"
    );
    let result = handle.await.unwrap();
    assert!(
        is_start_failed(
            &result,
            "fails-at-start",
            |cause| matches!(cause, StartError::Fatal { detail, .. } if detail == "member broke")
        ),
        "the start failure outranks the drain-timeout error: {result:?}"
    );
}

// The caller is released only after every member returned -------------------------------------------------------------

/// Like a Probe-mode `BinaryPlugin`: a side task (the probe) owns `ready` while the plugin runs, and the plugin stops
/// and joins it before `run` returns an error, so the readiness sender is gone by the time the chain sees the exit.
struct ProbeLikeCrash;

#[async_trait::async_trait]
impl ChainPlugin for ProbeLikeCrash {
    fn name(&self) -> &str {
        "probe-like-crash"
    }

    async fn run(
        &self,
        _local: SocketAddr,
        _remote: SocketAddr,
        shutdown: CancellationToken,
        ready: oneshot::Sender<Result<PluginReady, StartError>>,
    ) -> crate::Result<()> {
        let stop = shutdown.child_token();
        let probe_stop = stop.clone();
        let probe = tokio::spawn(async move {
            probe_stop.cancelled().await;
            drop(ready);
        });
        stop.cancel();
        probe.await.expect("the probe ended");
        Err(crate::Error::PluginExit {
            name: "probe-like-crash".into(),
            code: 3,
        })
    }
}

/// A plugin that breaks the contract `ProbeLikeCrash` keeps: a side task owns `ready` until the chain's shutdown while
/// `run` itself exits with an error, so the readiness channel stays open when the chain is cancelled.
struct ReadyHolderCrash;

#[async_trait::async_trait]
impl ChainPlugin for ReadyHolderCrash {
    fn name(&self) -> &str {
        "ready-holder-crash"
    }

    async fn run(
        &self,
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
            name: "ready-holder-crash".into(),
            code: 3,
        })
    }
}

/// [`ReadyHolderCrash`], but `run` returns `Ok(())`.
struct ReadyHolderOk;

#[async_trait::async_trait]
impl ChainPlugin for ReadyHolderOk {
    fn name(&self) -> &str {
        "ready-holder-ok"
    }

    async fn run(
        &self,
        _local: SocketAddr,
        _remote: SocketAddr,
        shutdown: CancellationToken,
        ready: oneshot::Sender<Result<PluginReady, StartError>>,
    ) -> crate::Result<()> {
        tokio::spawn(async move {
            shutdown.cancelled().await;
            drop(ready);
        });
        Ok(())
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
        &self,
        _local: SocketAddr,
        _remote: SocketAddr,
        _shutdown: CancellationToken,
        _ready: oneshot::Sender<Result<PluginReady, StartError>>,
    ) -> crate::Result<()> {
        panic!("member panicked at start");
    }
}

/// A member that hands `ready` to a task of its own and returns without a decision, with the chain still running,
/// never started: the caller hears the synthesized exited-before-ready failure after the other members' last line, and
/// `run` returns it, whatever the member returned.
#[skuld::test]
async fn an_exit_that_leaves_ready_open_is_a_failed_start() {
    let (reported, result) = assert_failure_waits_for_the_other_members_last_line(Box::new(ReadyHolderCrash)).await;

    assert!(
        matches!(&reported, Ok(Err(StartError::Fatal { detail, .. })) if detail.contains("exited before becoming ready")),
        "want the synthesized exited-before-ready Fatal, got {reported:?}"
    );
    assert!(
        is_start_failed(&result, "ready-holder-crash", exited_before_ready),
        "run must return the failed start, got {result:?}"
    );
}

/// The same when the member returns `Ok(())`: `run` does not return `Ok` for a start that never happened.
#[skuld::test]
async fn an_ok_exit_that_leaves_ready_open_is_a_failed_start() {
    let (reported, result) = assert_failure_waits_for_the_other_members_last_line(Box::new(ReadyHolderOk)).await;

    assert!(
        matches!(&reported, Ok(Err(StartError::Fatal { detail, .. })) if detail.contains("exited before becoming ready")),
        "want the synthesized exited-before-ready Fatal, got {reported:?}"
    );
    assert!(
        is_start_failed(&result, "ready-holder-ok", exited_before_ready),
        "run must return the failed start, got {result:?}"
    );
}

/// A probe-owned member that stops its probe before it exits is read as exited before ready, and the caller hears the
/// typed `Fatal`, not a dropped sender, after the other members' last line.
#[skuld::test]
async fn a_probe_owned_member_that_exits_before_ready_reports_the_typed_fatal() {
    let (reported, result) = assert_failure_waits_for_the_other_members_last_line(Box::new(ProbeLikeCrash)).await;

    assert!(
        matches!(&reported, Ok(Err(StartError::Fatal { detail, .. })) if detail.contains("exited before becoming ready")),
        "want the synthesized exited-before-ready Fatal, got {reported:?}"
    );
    assert!(
        is_start_failed(&result, "probe-like-crash", exited_before_ready),
        "run must return the failed start, got {result:?}"
    );
}

/// The same for the first-started member, with nobody to wait for.
#[skuld::test]
async fn a_probe_owned_first_started_member_that_exits_before_ready_reports_the_typed_fatal() {
    let (ready_tx, ready_rx) = oneshot::channel();
    let runner = ChainRunner::new().add(Box::new(ProbeLikeCrash)).on_ready(ready_tx);
    let mut env = test_env();
    env.local_port = free_loopback_port().port();

    let result = runner.run(env).await;

    assert!(
        matches!(ready_rx.await, Ok(Err(StartError::Fatal { detail, .. })) if detail.contains("exited before becoming ready"))
    );
    assert!(
        is_start_failed(&result, "probe-like-crash", exited_before_ready),
        "{result:?}"
    );
}

#[skuld::test]
async fn a_member_that_panics_at_start_waits_for_the_other_members_last_line() {
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let (reported, result) = assert_failure_waits_for_the_other_members_last_line(Box::new(PanicsAtStart)).await;
    std::panic::set_hook(prev_hook);

    assert!(
        !matches!(reported, Ok(Ok(_))),
        "a chain whose member panicked is not ready: {reported:?}"
    );
    assert!(
        is_start_failed(&result, "panics-at-start", exited_before_ready),
        "a panic before ready is a failed start, got {result:?}"
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
            stopped: Once::new(stopped_tx),
            gate: Once::new(gate_rx),
            relayed: relayed.clone(),
        }))
        .cancel_token(cancel.clone())
        .drain_timeout(DRAIN)
        .on_ready(ready_tx);
    let mut env = test_env();
    env.local_port = free_loopback_port().port();
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

/// The same on a multi-thread runtime, where a member's exit and the chain's start run on different threads. The caller's
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
            let mut chain = FailingChain::start(failing, DRAIN);
            chain.until_the_healthy_member_is_stopped().await;
            let (reported, result) = chain.open_the_gate().await;
            assert!(
                matches!(&reported, Ok(Err(StartError::Fatal { detail, .. })) if detail.contains("exited before becoming ready")),
                "{reported:?}"
            );
            assert!(
                matches!(&result, Err(crate::Error::StartFailed { cause, .. }) if exited_before_ready(cause)),
                "{result:?}"
            );
        }
    });
}

/// `drain_timeout` bounds the wait for a member that ignores the cancel; the caller's channel is released then too,
/// not left open for ever.
#[skuld::test]
async fn the_caller_is_released_once_the_drain_bound_expires_on_a_member_that_ignores_shutdown() {
    let (ready_tx, ready_rx) = oneshot::channel();
    let runner = ChainRunner::new()
        .add(Box::new(ReadyHolderCrash))
        .add(Box::new(StubbornPlugin {
            name: "stubborn".into(),
        }))
        .drain_timeout(std::time::Duration::from_millis(100))
        .on_ready(ready_tx);

    let mut env = test_env();
    env.local_port = free_loopback_port().port();
    let handle = tokio::spawn(runner.run(env));

    let reported = ready_rx
        .await
        .expect("the caller must be released with the failure, not left waiting");
    assert!(
        matches!(&reported, Err(StartError::Fatal { detail, .. }) if detail.contains("exited before becoming ready")),
        "{reported:?}"
    );
    let result = handle.await.unwrap();
    assert!(
        is_start_failed(&result, "ready-holder-crash", exited_before_ready),
        "the start failure outranks the drain-timeout error: {result:?}"
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

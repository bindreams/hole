use std::net::SocketAddr;

use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use crate::chain::{allocate_ports, ChainRunner};
use crate::plugin::ChainPlugin;

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

/// A transient `WSAEACCES` at the rebind step inside `allocate_one_port` —
/// as happens when Windows' TCP dynamic excluded-port range shifts between
/// drop and rebind (Hyper-V / WSL2 / Docker Desktop reservations, visible via
/// `netsh int ipv4 show excludedportrange`) or when another socket holds
/// the port with `SO_EXCLUSIVEADDRUSE` on a wildcard interface — must be
/// absorbed: `allocate_one_port` should retry with a fresh ephemeral port
/// and return `Ok(addr)`, the same as it does for `WSAEADDRINUSE`.
///
/// The test drives this via the documented asymmetric Winsock rule: when
/// socket A holds the port with `SO_EXCLUSIVEADDRUSE` on a **wildcard
/// address** (`0.0.0.0:P`), a subsequent non-exclusive bind to the same
/// port on a **specific address** (`127.0.0.1:P`) returns `WSAEACCES`, not
/// `WSAEADDRINUSE`. This lets the test deterministically force the
/// `WSAEACCES` path on any Windows host without admin. See GitHub #20.
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
    ) -> crate::Result<()> {
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
    ) -> crate::Result<()> {
        let _listener = tokio::net::TcpListener::bind(local).await?;
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
    ) -> crate::Result<()> {
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

    // rx should fire with the local address once the plugin is listening.
    let ready_addr = tokio::time::timeout(std::time::Duration::from_secs(5), rx)
        .await
        .expect("timed out waiting for readiness")
        .expect("ready_tx was dropped without sending");

    assert_eq!(ready_addr.port(), addr.port());

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

    // The plugin fails immediately, so ready_tx is dropped → rx gets RecvError.
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), rx)
        .await
        .expect("timed out waiting for readiness result");

    assert!(
        result.is_err(),
        "rx should get RecvError when plugin fails before ready"
    );

    // The chain should have returned an error.
    let chain_result = handle.await.unwrap();
    assert!(chain_result.is_err());
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
    ready_rx.await.expect("plugin should become ready");

    // Cancel externally.
    cancel.cancel();

    // The chain should exit cleanly.
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), handle)
        .await
        .expect("timed out waiting for chain to exit")
        .unwrap();

    assert!(result.is_ok(), "chain should exit Ok on external cancellation");
}

// Drain-timeout semantics tests =======================================================================================

/// A long-running plugin (one that ignores `shutdown` and never exits on
/// its own) must not be killed before shutdown is requested. This is the
/// primary regression gate for the drain-timeout scope fix: pre-fix,
/// `drain_timeout` was applied to the whole chain lifetime, so
/// `StubbornPlugin` was aborted after ≈ drain_timeout.
#[skuld::test]
async fn long_running_plugin_survives_past_drain_timeout() {
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

    let mut handle = tokio::spawn(runner.run(env));

    // Wait past drain_timeout and confirm the plugin is still running.
    tokio::time::sleep(drain_timeout * 3).await;
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(10), &mut handle)
            .await
            .is_err(),
        "chain must still be running — drain_timeout must not bound the full lifetime"
    );

    // Cancel; chain should abort the stubborn plugin within drain_timeout
    // (+ scheduler slack) and return the drain-timeout error.
    cancel.cancel();
    let result = tokio::time::timeout(drain_timeout + std::time::Duration::from_millis(500), handle)
        .await
        .expect("chain should exit within drain_timeout after cancel")
        .expect("no JoinError");

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
    let result = tokio::time::timeout(drain_timeout + std::time::Duration::from_millis(500), handle)
        .await
        .expect("chain should exit within drain_timeout of plugin failure")
        .expect("no JoinError");

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

    let result = tokio::time::timeout(drain_timeout + std::time::Duration::from_millis(500), handle)
        .await
        .expect("chain should exit within drain_timeout")
        .expect("no JoinError");

    match result {
        Err(crate::Error::PluginExit { code: 1, .. }) => {}
        other => panic!("expected FailingPlugin's PluginExit error to be preserved, got {other:?}"),
    }
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

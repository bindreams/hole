# Cancellation and teardown

A connect is a sequence of slow phases (the plugin chain, the proxy, the DNS self-test, the TUN device, routes, DNS), and
the user can press Cancel in any of them. This page is the contract for code that runs inside a start: how a cancel
travels, what a failed or cancelled start leaves behind (nothing), and what is allowed to wait without a bound. Read it
before adding a phase or a long-lived resource to a {term}`bridge` start. The resources a start holds are listed in
[what one connect holds](overview.md#what-one-connect-holds).

## One cancel mechanism: tokens

Cancellation is **cooperative**. A `CancellationToken` is threaded into the start, and every phase checks it. Dropping a
future is not the way a cancel travels: a phase drops the future it is racing only when that future owns no cleanup (rule
1 below), and any other drop is the net for a panic or a future dropped for some other reason.

The token's root is the IPC `handle_start` handler in {src}`crates/bridge/src/ipc.rs`. A Cancel from the app names an
attempt id; the handler cancels the in-flight start only if it is that attempt, and a cancel that arrives before the
start registers is held for that attempt, so a stale cancel can never cancel a later, unrelated one.
`ProxyManager::start_cancellable` hands the token to every phase.

A fresh `CancellationToken::new()` inside `crates/bridge/src/` would be a scope nothing can cancel, so {src}`clippy.toml`
disallows it. The sanctioned sites each carry an `#[allow]` and are named in the lint's `reason`: the roots (the IPC
handler, the process and service entry points) and a few resources with a lifetime of their own, described below.
`reconcile_once`, which connects at boot, is not on the list: it takes the root token by reference and connects with a
child of it.

A phase follows three rules:

1. **Observe the token between steps.** A `biased` `tokio::select!` that returns `ProxyError::Cancelled` when the token wins, or a `cancel.is_cancelled()`
   check between loop iterations. A future may be dropped by the `select!` only when it owns no cleanup the drop would
   skip: `proxy.start` and the DNS forwarder's self-test are such futures (the self-test's only resource is a socket
   that closes on drop). The code that does this says so where it does.
1. **Async cleanup is explicit.** A type with cleanup that must be awaited exposes `async fn shutdown(&mut self)` and holds
   a `drop_bomb::DebugDropBomb`, defused by `shutdown`. A guard that was not shut down is a bug, and what a drop does is
   per type. `SystemDnsApplied` panics in a debug build and, in a release build, falls back to releasing the
   confinement or steering and flushing the resolver cache; it does not restore the adapters' resolvers.
   `Dispatcher::drop` blocks to drain the driver on a multi-thread runtime, where it defuses the bomb itself, and
   aborts the driver (leaving the bomb to panic in a debug build) on any other runtime.
1. **A `select!` arm must not drop work that is mid-cleanup.** Restructure so the cleanup is awaited after the `select!`
   returns.

Some phases cannot be interrupted from outside. The route commands (`route`, `netsh`, `pfctl`, the [system tools](system-tools.md) the bridge runs) are subprocesses, so a
cancel is seen at the phase boundary. Building the {term}`TUN` device is one: it waits for the operating system and runs on a blocking
thread raced against the token ([the TUN device](tun-device.md#the-build-is-cooperative)).

## A start's token does not outlive the start

The token stays registered in `handle_start` until the session has committed and been persisted, so a Cancel can still
reach it after the proxy is running. State that lives as long as the session therefore must not descend from it. The
plugin chain is the example: it owns its own shutdown token, created in `spawn_plugin_runner_at`, and honours the start
token explicitly (`await_ready`) only while the start is in progress.

The chain's task and its token live in one `ChainTask` ({src}`crates/bridge/src/proxy/plugin.rs`), whose `Drop` ends the
chain, so a start future that is dropped tears the plugin down. Every failure inside a start awaits `ChainTask::end`
before it is reported: the token is cancelled and the task aborted and awaited, so the runner starts no further plugin
before the teardown's reap, and a Cancel never waits for garter's own drain. Plugins get no graceful stop: aborting the
task drops the plugin's child handle, which is `kill_on_drop` and contained, so the plugin's whole process tree is
killed. The reap (below) is the backstop that kills by recorded identity.

Afterwards the chain ends only through `PluginChain::end`, or when a plugin exits on its own, which
`ProxyManager::check_health` reads as a death. A garter `ChainRunner` given a `cancel_token` installs no signal handler of
its own, so SIGTERM or Ctrl+C reaches the chain only through the bridge's own shutdown, never as an apparent plugin
death.

```{admonition} Known limit: a plugin being spawned as the chain ends
---
class: warning
---
`end` waits for garter's runner, not for the per-plugin tasks it spawned. A plugin that is being started at that instant
may still spawn and record itself after `end` returns. Its own drop kills the process tree, and its record stays in the
state file for the next reap to remove by identity. It happens only to a start that is cancelled, or fails its readiness
check, in the middle of a spawn.
```

## Every exit of a start ends in one teardown

`ProxyManager` builds a `Session` ({src}`crates/bridge/src/session.rs`) that owns each resource from the moment it is
acquired. A failed start, a stop and a health-check give-up all run `Session::teardown`, in the release order the
[overview](overview.md#what-one-connect-holds) lists. The standing [kill-switch cover](kill-switch.md) is the one
resource it does not release: it hands the cover back for the caller to settle.

- **The reap** runs whenever a plugin is configured, by the identities recorded in the {term}`state directory` ([crash recovery](crash-recovery.md)), so a chain that
  spawned and then failed to become ready is reaped too. It runs on a blocking thread, inline if the runtime cancelled
  that task before it ran.
- **No phase of the teardown observes a cancel token.** A cancel that arrives during a teardown cannot cut it short.

`Drop` is only the net for a panic or a dropped future, and it is not the teardown run implicitly. `Session` declares its
fields in the release order, so a drop releases them in that order, but it awaits nothing: a DNS guard or dispatcher
dropped without `shutdown()` is the case rule 2 above describes, the plugin chain is aborted without a join and no reap
runs (so a plugin it recorded may outlive it), and `proxy.stop()` is not awaited (the running proxy's own `Drop` closes
its sockets; see [the proxy shutdown contract](proxy-shutdown.md)). Route teardown has no awaited form: the routes guard
runs the route commands synchronously when it is dropped, on whichever thread drops it.

## The engine driver's join has no bound

Every await in `Driver::run` ({src}`crates/tun-engine/src/engine/driver.rs`, [the datapath](datapath.md)) is raced against the driver's cancellation
token, including the DNS interceptor call (`tun_engine::engine::dns::intercept`, [the DNS forwarder](dns-forwarder.md)) and the TUN write
(`tun_engine::engine::egress::flush`). The write is the loop's only await that a unix `AsyncFd` can hold `Pending` on
indefinitely, which is why it is raced too.

So `Dispatcher::shutdown` ({src}`crates/bridge/src/dispatcher.rs`) cancels the driver and joins its task **with no bound**.
It awaits through `&mut JoinHandle`, so a caller that is itself cancelled cannot detach the task, and it returns a
`DriverExit`. On Windows what the join really waits for is the synchronous `WintunCloseAdapter` call (and a registry
subtree delete), which runs in the future's `Drop` once `Driver::run` returns. That call is finite and uninterruptible,
and in tokio a task's future is dropped before its join waker fires, so a bound at the join would leak the adapter
rather than shorten anything.

The consequence reaches past this type. On the bridge's multi-thread runtime `Dispatcher::drop` blocks the same way, so
**dropping a future that owns a `Dispatcher` does not cancel the wait; it turns it into a synchronous block on the
dropping thread.** No caller may drop such a future to bound anything. The IPC router carries no timeout layer:
its expiry would drop the handler's future.

## Where to read next

- [The seams](test-isolation.md): the traits whose guards the teardown releases.
- [The proxy shutdown contract](proxy-shutdown.md): what `proxy.stop()` guarantees.

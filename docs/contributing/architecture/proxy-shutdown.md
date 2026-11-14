# The proxy shutdown contract

`ShadowsocksRunning::stop()` and its `Drop` ({src}`crates/bridge/src/proxy/shadowsocks.rs`) must close every socket the
{term}`Shadowsocks` local server bound **before returning**. Otherwise an immediate restart on the same fixed port fails with
`AddrInUse`. This page is for a developer changing how the proxy is started or stopped, or bumping `shadowsocks-service`:
it says why a plain `abort()` is not enough, what the code does instead, and which property rests on a pinned
dependency.

## Why a handle cannot be joined

The pinned upstream (`shadowsocks-service`, version in {src}`Cargo.lock`) runs `local::Server::run()` and tears it down
through three nested `abort()` calls that Hole cannot wait for, because the handles are private:

| Layer | Who aborts                                                | What the aborted task still owns                                                       |
| ----- | --------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| 1     | `ShadowsocksRunning::stop` aborts the `server.run()` task | nothing directly; its drop triggers layer 2                                            |
| 2     | `utils::ServerHandle::drop` aborts the sub-server tasks   | the `Socks` and `Http` accept loops: the TCP listener and the bound UDP socket         |
| 3     | `UdpAssociation::drop` aborts the association task        | a clone of the SOCKS5 UDP listener's socket, held by every live UDP association's task |

Holding the layer-2 handles ourselves would still leave layer 3: the association manager never surfaces its handles, so
a live UDP association keeps the port bound until its task is dropped. `Server::run(self)` consumes the server and
exposes no shutdown signal. The only way to know the sockets are closed is to wait for every task on the runtime to be
dropped.

## Each proxy owns a runtime, and `stop` joins it

`ShadowsocksProxy::start` builds a dedicated multi-thread tokio runtime (`SsRuntime`, threads named `hole-ss`) and runs
the server on it. `stop()` and `Drop` shut that runtime down and block until every task on it has been dropped; that
wait is what closes the descriptors. `Server::new` has to run on this runtime too, because tokio I/O resources belong to
the runtime that created them.

**Where dropping a `Runtime` is legal.** `Runtime::drop` panics unless the calling thread is not inside any runtime
(tokio's `try_enter_blocking_region` returns `None` when it is). The flavour of the surrounding runtime does not matter.
Three places satisfy it: outside any runtime, inside a `spawn_blocking` closure, and inside `block_in_place` on a
multi-thread worker.

`join_runtime` therefore always drops the runtime on a fresh `std::thread` and joins that thread, and uses
`block_in_place` only to release a multi-thread worker's core first. It does not use `spawn_blocking` as the hop: a
blocking pool that is shutting down drops the closure **inline on the calling thread**, which would drop the `Runtime` on
an entered worker and panic, leaving nothing to join it.

`std::thread::spawn` itself panics if the operating system refuses a new thread. There is deliberately no error arm
for that: a failed spawn has already dropped the closure, and with it the runtime, on the calling thread, so recovering
would need a channel handing the runtime to the thread only after it started, and the condition is a whole-process
resource failure. That is the one exception to the guarantee that `stop()` releases the port.

**`stop` classifies before it joins.** It awaits the aborted task to tell a panic from a cancellation, and only then
joins the runtime. Joining first would make every outcome look like a cancellation.

**`worker_threads(4)`.** `SsRuntime` runs on four workers, fewer than the ambient runtime's available parallelism that
the proxy ran on before. This is unmeasured: a sustained single-tunnel throughput test on a machine with more than four
cores that saturates all four workers, or a CPU profile showing the `hole-ss` threads pinned during a large transfer,
would show it to be too low. The local server is expected to be I/O-bound (loopback accept, SOCKS5 framing, a copy loop),
with the remote server and the plugin chain the practical ceiling.

## The no-hang property depends on the dependency version

Dropping a runtime waits for blocking-pool tasks that are *running*. Nothing reachable on the local-server path has one
today:

- `shadowsocks`: on Windows its `DnsResolver::System` branch calls a blocking `lookup_host`, but Hole's config never
  selects it (no ACL, every server address is a `ServerAddr::SocketAddr`).
- `hickory-resolver` and `hickory-proto`, pulled in by `shadowsocks-service`'s default `hickory-dns` feature, which
  `crates/bridge/Cargo.toml` does not disable. On unix `local::Server::new` always builds a hickory system resolver, so
  that code does run on `SsRuntime`, although Hole never asks it to resolve anything. Neither crate has a
  `spawn_blocking` call today.

A version bump could add one with no other test going red. `upstream_has_no_blocking_calls_on_the_shutdown_path`
({src}`crates/bridge/src/proxy/shadowsocks_tests.rs`) walks the source of all four dependencies and fails if it finds
`spawn_blocking` anywhere, or if `shadowsocks` has any `lookup_host(` call other than the one known site in
`dns_resolver/resolver.rs`. It is a textual scan, not call-graph reachability: a harmless
occurrence in a module Hole never reaches turns it red and needs a re-audit, and a rename or alias of either identifier
defeats it. It is a tripwire for an accidental reintroduction, not a proof.

```{dropdown} Test-only: carrying the tracing subscriber onto the runtime
The per-test subscriber helper asserts that the *ambient* runtime is current-thread, so it cannot see that the proxy's
tasks now run on `SsRuntime`'s own workers, and their events would be dropped in tests. Production installs a subscriber
globally and needs nothing. Under `#[cfg(test)]`, `SsRuntime::new` captures the constructing thread's dispatcher,
installs it on every worker in `on_thread_start`, and clears it in a matching `on_thread_stop`.

The clearing is the part to keep: the guard's `Drop` is the only place `tracing-core` decrements its process-global
count of scoped dispatchers. Forgetting the guard leaves that count non-zero for the rest of the test binary, which
pushes every thread in the process onto tracing's slower path and, past thread teardown, can lose events.
```

## Where to read next

- [Cancellation and teardown](cancellation.md): where `proxy.stop().await` sits in the teardown order.
- [The datapath](datapath.md#the-listener-the-datapath-dials): the listener the proxy binds.

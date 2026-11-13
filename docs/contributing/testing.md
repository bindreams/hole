# Testing

This page covers how to run Hole's tests, the rules a test follows, and what to check when a test fails only on Windows.
How CI runs them is on [Continuous integration](ci.md).

## Run the tests

Rust tests use [skuld](https://github.com/bindreams/skuld): write `#[skuld::test]`, not `#[test]` (a pre-commit hook
rejects a bare one). A module's tests live in a sibling file: `foo.rs` has `foo_tests.rs`.

```sh
cargo xtask run hole-tests         # the Hole crates, the way CI runs them
cargo xtask run garter-tests       # one crate outside that lane (`cargo xtask list` has the rest)
cargo xtask run plugin-e2e-tests   # real plugin binaries against a real Shadowsocks server
cargo xtask run ex-ray-tests       # ex-ray's Go tests, and the vendored TLS transports' tests
npm test                           # the front end's unit tests (Vitest)
```

Use `cargo xtask run`, or `cargo nextest` directly, rather than `cargo test`: {src}`.config/nextest.toml` serializes tests
that change global OS network state across test binaries, which `cargo test` does not.

The browser-level end-to-end specs in {src}`tests/webdriver/` run the app through WebDriver, on Windows. `npm run test:e2e` runs them against the app named by `HOLE_TEST_APP_PATH`, or `target/release/hole.exe`, which exists only after
a release build. It starts `tauri-driver` from `PATH` and needs `msedgedriver`; `npm install` provides neither. Only the
installer lane's `provision-e2e-tools` step downloads them, and puts them on `PATH` for that run's child processes alone
([The installers](installers.md)); CI runs the specs there.

### The elevated lane

Tests that create a TUN device, change routes or engage a firewall cover carry the skuld label `tun`, and need
administrator rights (an elevated shell on Windows, `sudo` on macOS). `SKULD_LABELS` selects by label:

- `SKULD_LABELS=tun` runs only those tests;
- `SKULD_LABELS='!tun'` runs everything else, and needs no elevation.

An unelevated run with no filter runs the `tun` tests too, and they fail. They do not skip.

## Rules every test follows

### Fail, do not skip

A test fails when it cannot run; it does not skip. A test that needs a tool, a binary, a privilege or a network, and
does not find it, fails with a message that says what is missing and how to get it. It is not marked `#[ignore]` and it
does not return early. To leave a lane out, say so with a filter such as `SKULD_LABELS='!tun'`. A test that skips on its
own lets a lane go quiet while it stays green. Nothing checks this mechanically; review does.

The rule has exceptions today: `get_default_gateway_info_returns_valid_result` in
{src}`crates/tun-engine/src/gateway_tests.rs` is `#[ignore]`d to be run by hand, one test in
{src}`crates/plugin-e2e/tests/interop.rs` is disabled with `#[ignore]`, and the installer projects' Python tests skip
on a host that is not the platform they test.

### Test observability

Every Rust crate with tests, apart from `xtask`, `xtask-lib` and `payload-archive`, has `hole-test-observability` as a
dev-dependency and calls `hole_test_observability::register!()` once per test binary. Before `main`, that installs a process-wide `tracing`
subscriber on stderr, sets `RUST_BACKTRACE=full` if it is unset, and chains Hole's panic hook. The default log filter
pins Hole's own crates to `debug`; `HOLE_TEST_LOG` adds directives on top of it. A test binary that does not use
`register!()` must call `hole_test_observability::install()` first in `main`.

### Per-test subscribers

`clippy.toml` disallows `tracing_subscriber::fmt().init()` and
`try_init()`, and the raw `tracing::subscriber::set_default`. A per-test subscriber goes through
`garter::tracing_test::set_default_in_current_thread` ({src}`crates/garter/src/tracing_test.rs`): the guard is
thread-local, so on a multi-thread runtime tasks started with `tokio::spawn` would lose it. The helper panics on such a
runtime, and `#[skuld::test] async fn` builds a current-thread runtime for you.

### No synchronization by elapsed time

`thread::sleep`, `tokio::time::sleep`, `browser.pause()` and a poll with a
timeout (`waitUntil({ timeout })`, `tokio::time::timeout(d, wait_for_x)`) are not allowed to make one thing wait for
another. Use what the codebase already has for in-process rendezvous: `oneshot` and `watch` channels, `WaitableWriter`,
`CancellationToken`, `JoinHandle::await`, and `tokio::time::pause` and `advance` for tests of time. Three cases are
allowed, and each carries a one-line comment naming its class:

1. **Test of timing.** The delay is the behaviour under test.
1. **External event with a failure bound.** An operation in another process or on another host may never succeed, and the
   framework's or the job's timeout is how a human learns of it. The bound reports a failure; it is never read as proof
   of a state.
1. **Paced re-check.** The state changes without any event announcing it, and there is no handle to block on. Every
   wake-up re-reads the real state, nothing is concluded from the interval, and there is no cap. The stop wait in
   `ServiceProcesses::wait_on_each` is the example.

Review enforces this; no tool does. A wait on a task the test itself spawned is not class 2, because the test controls
both sides. {src}`.config/nextest.toml` bounds such tests from outside instead, and its comments say which.

### A lost network is not a defect

A probe of real egress fails the same way for a broken cover and for a
runner that lost its network. A test that needs the host's primary IPv4 waits for the kernel to have a route
(`net_discovery::wait_for_primary_ipv4` and `HostNetwork::read_when_routed` in `crates/bridge/src/test_support`), with no
cap and a log line per change of state; the CI step's timeout is the bound. Only a lost network is waited out
(`PrimaryIpv4Error::NetworkLoss`); any other error, such as a refused socket, fails at once. How a test that probes
egress tells a lost network from a defect is on [Continuous integration](ci.md#a-test-that-needs-egress).

### Every crate runs in CI

The `every_workspace_crate_runs_in_ci` test ({src}`xtask/src/ci_coverage.rs`) fails when
a workspace crate's tests run in no CI job. A new crate joins a job's package filter, or, if it has no runnable tests,
gets an `UNTESTED_IN_CI` entry with a reason.

### No Cargo builds in tests

A hook rejects `Command::new("cargo")` in test code. A concurrent `cargo build`
replaces the binaries a sibling test is about to spawn. Tests find prebuilt binaries through `CARGO_BIN_EXE_*` or the
locators xtask provides.

### Tests that change global network state

The `global_net_state` group in
{src}`.config/nextest.toml` runs on one thread across binaries, because a real WFP filter or `pf` rule in one test would
corrupt another's. Membership is by test name, and `cargo xtask verify-global-net-state-labels` checks that the name
filter and the skuld label at each test select the same tests, and CI runs it on every `hole` runner.
`cargo xtask verify-global-net-state-executed --expected FILE --junit FILE` checks, from the two lanes' JUnit reports,
that every member that `verify-global-net-state-labels --record FILE` wrote down ran. CI runs it on the windows/amd64
runner only.

## Windows notes

### Firewall prompts

Bridge tests bind a TCP listener on all interfaces, so Windows Firewall prompts again after every rebuild: Cargo gives each
test binary a new content-hash name, and the consent attaches to the name. Stage the test binaries at a stable path and
approve the prompt once:

`stage` copies what `cargo xtask build hole` built, and then runs `cargo test --no-run --workspace` with default
features, which builds `hole` in production mode. So run `cargo xtask build hole` first, and have a real `ui/dist/`
(`cargo xtask build frontend-build`; [Building in detail](build.md#the-front-end-toggle)).

```sh
cargo xtask stage --with-tests \
    --out-dir target/debug/dist/bin --tests-out-dir target/debug/dist/tests
./target/debug/dist/tests/hole_bridge.test.exe   # approve the prompt once
```

Run the staging command again after each source change; the staged binary does not update itself. Where a package's
library and binary targets share a name, the staged files are named `<target>-lib.test.exe` and `<target>-bin.test.exe`.

### One galoshes runtime directory per worktree

{term}`galoshes` extracts its embedded ex-ray to one file per user, and every worktree builds different ex-ray bytes, so
two worktrees testing at once can make galoshes fail with "Access is denied". On Windows, `register!()` sets
`XDG_RUNTIME_DIR` to `target/galoshes-runtime` when it is unset or empty, so each worktree has its own. A value you export
wins. If `target/` cannot be written, one line on stderr names the path and the run continues without the isolation.

### A Windows CI timeout or hang

When Windows CI times out in `server_test_tests`, or loopback connects hang, work through these in order before you change
any timeout:

1. **A bind that fails with `PermissionDenied`, `WSAEACCES` or os error 10013.** `bind_ephemeral` retries it without a
   cap ({src}`crates/util/src/port_alloc.rs`). A loop that never ends means the machine's excluded port range covers most
   of the dynamic range: run `netsh int ipv4 show excludedportrange tcp` (and `udp`, `ipv6`). Hyper-V, WSL and Docker
   are the usual sources.
1. **`Access is denied (os error 5)` on a spawn.** Search the log for `file-lock holder`: `DistHarness::spawn` retries and
   lists the processes holding the file. Windows Defender (`MsMpEng.exe`) is the usual one, and as a protected process
   it may not be listable.
1. **Routing subprocesses.** `proxy_manager_tests_never_spawn_routing_subprocess` asserts that start/stop cycles spawn
   none. If it fails, a code path bypassed the `Routing` trait.
1. **A new `std::process::Command::new` in `crates/bridge/src/`.** Clippy rejects it, so a hit carries an `#[allow]`, and
   each is a possible subprocess leak during a test.
1. **A duration outlier** in skuld's per-test `pass (NN ms)` lines.
1. **A recent `main` run** on the same runner image, for comparison.
1. **Only then**, the runner image itself: open an issue and reconstruct a packet-capture job.

Do not raise a timeout in `server_test_tests.rs`, mark tests `#[cfg_attr(windows, ignore)]`, add `--test-threads=1`, or
serialize with a bare `#[skuld::test(serial)]`; use a label (see `skuld`'s serial labels). Every CI step has its own
literal `timeout-minutes`, and the per-leg job wall; those are the only global timeouts.

## Which lane proves what

The TUN datapath is tested in two lanes with different strengths.

The **unprivileged lane** (`SKULD_LABELS='!tun'`) drives the datapath from memory, through two seams:

- the router seam splits the drop path off the endpoint, so a test can assert what the routing cascade decided,
  including that a UDP flow for a plugin without UDP is dropped rather than bypassed (`hole_router_tests.rs` and
  `hole_router_dispatch_tests.rs` in `crates/bridge/src`);
- the datapath seam makes `Engine` generic over its packet I/O, so a test can run the whole packet loop over an in-memory
  TUN (`Engine::from_io` over `sim::SimWire`). The `driver_*_tests.rs` files in `crates/tun-engine/src/engine` cover UDP
  dispatch and reply framing, the DNS interceptor, TCP admission and relay, cancellation and the lifecycle;
  `dispatcher_tests.rs` in `crates/bridge/src` covers how the dispatcher joins and drains the driver.

The **elevated lane** (`SKULD_LABELS=tun`) is the only one that touches the operating system. The module doc of
{src}`crates/tun-engine/src/sim.rs` lists what only it proves: a real adapter with the requested name, MTU and address;
the OS routing packets into it and accepting packets written out of it; adapter-handle lifetime; and real egress from
the proxy and bypass paths. Those tests are the `*_privileged_tests.rs` files and `tests/*_privileged.rs`.

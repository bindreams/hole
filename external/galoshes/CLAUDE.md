# Project Instructions

## Architecture

This is a Cargo workspace with 5 crates:

- **garter** (lib) — core plugin chaining: `ChainPlugin` trait, `BinaryPlugin`, `ChainRunner`, SIP003u env parsing
- **garter-bin** (bin: `garter`) — YAML config-driven plugin chainer
- **galoshes** (bin) — bundled YAMUX + v2ray-plugin (embedded binary with SHA256 verification)
- **xtask** (bin) — build tooling (`cargo xtask v2ray-plugin`)
- **mock-plugin** (bin) — SIP003u-compliant TCP relay used only in tests

The core abstraction is `ChainPlugin`: each plugin receives `(local: SocketAddr, remote: SocketAddr, shutdown: CancellationToken)` and handles its own networking. `ChainRunner` allocates intermediate localhost ports and runs plugins concurrently.

## Key design decisions

- **Address-based plugin trait** — plugins bind on `local` and forward to `remote`, matching the SIP003 mental model. No stream-level composition.
- **yamux 0.13 has a poll-based API** — `Connection::poll_new_outbound` / `poll_next_inbound`. A single driver task owns the connection and communicates via channels. Do NOT use `.control()`, `.open_stream()`, or `into_stream()` — these do not exist.
- **`kill_on_drop(true)`** on spawned child processes — ensures cleanup during panic/shutdown. No custom ChildGuard needed.
- **Embedded v2ray-plugin** — `include_bytes!` at compile time, extracted at runtime with SHA256 verification and TOCTOU-safe fd-pinned launch.
- **Two `#[cfg]`-gated `main` functions in galoshes** — because `env!()` / `include_bytes!()` fail at compile time when the v2ray-plugin binary isn't built. The `v2ray_plugin_missing` cfg allows `cargo check` without the Go build.

## Building and testing

```bash
cargo check --workspace              # compiles without v2ray-plugin
cargo test --workspace               # unit tests
cargo test -p garter --test chain_integration  # integration test (builds mock-plugin automatically)
cargo xtask v2ray-plugin             # build v2ray-plugin (requires Go)
cargo build -p galoshes              # build galoshes (requires prior xtask step)
```

## Test conventions

- Unit tests live in separate files: `foo_tests.rs` for `foo.rs`
- Integration tests use the `skuld` test harness (`harness = false`) for reliable child process cleanup
- Async tests use `#[skuld::test]` directly on `async fn`; the `tokio` feature is enabled in the workspace's `skuld` dep
- Tests mutating env vars take the `env` fixture (`#[fixture] env: &skuld::EnvGuard`), which auto-serialises and reverts
- The `mock-plugin` crate is a minimal SIP003u TCP relay for integration tests

## Platform-specific code

- Unix: `libc` for SIGTERM, file permissions (`0o700`/`0o500`), `/proc/self/fd/N` for fd-pinned exec
- Windows: `windows` crate (safe Rust) for `GenerateConsoleCtrlEvent`, Job Objects (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`), `OpenProcess`/`TerminateProcess`, `share_mode(1)` for deny-write file handles
- Signal handling: Unix SIGTERM+SIGINT, Windows Ctrl+C
- Graceful shutdown: 5s drain timeout (configurable via `ChainRunner::drain_timeout`)

## SIP003 option format

`key1=value1;key2=value2` with backslash escaping (`\;`, `\\`, `\=`). Parsed by `garter::sip003::parse_plugin_options` using a two-pass approach: split on unescaped `;`, then on unescaped `=`, then unescape. Do NOT unescape during the splitting passes.

## Dependencies

- `yaml_serde` (not `serde_yaml`) — maintained by the YAML organization, successor to the deprecated `serde_yaml`
- `contracts` (not `debug_contract`) — provides `debug_requires`, `debug_ensures` macros
- `tracing::Instrument` for async span propagation — never use `Span::enter()` across `.await` points

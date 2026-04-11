# Contributing

## Getting started

```bash
git clone https://github.com/bindreams/galoshes
cd galoshes
cargo check --workspace
```

### Pre-commit hooks

This project uses [prek](https://github.com/bindreams/prek) for pre-commit hooks:

```bash
prek install
```

Hooks run `cargo fmt`, `cargo clippy`, editorconfig checks, and reject stray `#[test]` attributes (unit tests belong in `_tests.rs` files, not inline).

### Building galoshes

Galoshes embeds the v2ray-plugin binary. To build it:

```bash
# Requires Go toolchain
cargo xtask v2ray-plugin
cargo build -p galoshes
```

Without the Go build step, `cargo check -p galoshes` still works — galoshes compiles with a `v2ray_plugin_missing` cfg flag and panics at runtime with a helpful message.

## Project structure

```
garter/         Core library — ChainPlugin trait, BinaryPlugin, ChainRunner
garter-bin/     YAML config-driven chainer binary
galoshes/       Bundled YAMUX + v2ray-plugin binary
xtask/          Build tooling (cargo xtask v2ray-plugin)
mock-plugin/    Test fixture — SIP003u TCP relay
external/       Vendored v2ray-plugin Go source (git subrepo)
```

## Development workflow

### Writing code

Follow TDD: write tests in a separate `_tests.rs` file before implementing.

```
garter/src/sip003.rs        # implementation
garter/src/sip003_tests.rs  # tests
```

Use `foo.rs` + `foo/` module style (not `mod.rs`). Keep files focused — if you're adding section comments, consider splitting into a folder.

### Running tests

```bash
cargo test --workspace                                # all unit tests
cargo test -p garter --test chain_integration         # integration test (spawns mock-plugin)
```

Integration tests use the [skuld](https://github.com/bindreams/skuld) test harness for reliable child process cleanup. Since skuld has no async support, wrap async test bodies in `tokio::runtime::Runtime::new().block_on()`.

### Key conventions

- **Commit messages**: single line, no body (tool metadata goes after `\n`)
- **Error handling**: `thiserror` in `garter` (library boundary), `anyhow` in binaries
- **Debug contracts**: use `contracts::debug_requires` / `debug_ensures` for invariants
- **Async spans**: use `future.instrument(span)`, never `span.enter()` across `.await`
- **Child processes**: always set `cmd.kill_on_drop(true)` when spawning

### Platform-specific code

Use `#[cfg(unix)]` / `#[cfg(windows)]` on individual items, not on entire modules. Both platforms must compile on every commit — CI runs Linux, macOS, and Windows.

## CI

CI runs on every push and PR:

- **Lint**: `cargo fmt --check` + `cargo clippy -D warnings`
- **Test**: build + unit tests + integration tests on Linux (x64, arm64), macOS (x64, arm64), Windows (x64)

Build caching uses [sccache](https://github.com/mozilla/sccache).

## Adding a new in-process plugin

Implement `garter::ChainPlugin`:

```rust
use std::net::SocketAddr;
use tokio_util::sync::CancellationToken;

pub struct MyPlugin { /* config */ }

#[async_trait::async_trait]
impl garter::ChainPlugin for MyPlugin {
    fn name(&self) -> &str { "my-plugin" }

    async fn run(
        self: Box<Self>,
        local: SocketAddr,
        remote: SocketAddr,
        shutdown: CancellationToken,
    ) -> garter::Result<()> {
        // Bind on `local`, forward to `remote`
        // Watch `shutdown` for graceful termination
        todo!()
    }
}
```

Then add it to a chain:

```rust
let runner = ChainRunner::new()
    .add(Box::new(MyPlugin::new()))
    .add(Box::new(BinaryPlugin::new("v2ray-plugin", None)));
runner.run(env).await?;
```

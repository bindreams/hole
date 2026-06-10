use std::path::PathBuf;

/// Path to the `mock-plugin` fixture (a `[[bin]]` of this package, gated
/// behind `test-utils`; without that feature this `env!` is a compile
/// error — loud, never a silent skip). The runtime env var wins — nextest
/// (≥0.9.130, pinned in .config/nextest.toml) sets it remapped to the
/// extraction dir under `--archive-file`; the compile-time value covers
/// plain `cargo test`. The `CARGO_BIN_EXE_` spelling (not the
/// nextest-recommended `NEXTEST_BIN_EXE_`) is deliberate: it is the only
/// form with a compile-time counterpart. Same pattern as
/// `crates/handle-holders/tests/live_holders.rs`. Never invoke cargo here:
/// a concurrent build's uplift deletes+recreates `target/debug/<bin>`
/// (always, on macOS), racing sibling tests' spawns (bindreams/hole#496).
pub fn mock_plugin_path() -> PathBuf {
    std::env::var("CARGO_BIN_EXE_mock-plugin")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_mock-plugin").to_string())
        .into()
}

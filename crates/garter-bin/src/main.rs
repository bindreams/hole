use garter::{BinaryPlugin, ChainRunner, Mode, PluginEnv};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Sanctioned production caller of `fmt::SubscriberBuilder::init`;
    // banned in tests via clippy.toml `disallowed_methods`. See #301.
    #[allow(clippy::disallowed_methods)]
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let env = PluginEnv::from_env().map_err(|e| anyhow::anyhow!("failed to parse SIP003u environment: {e}"))?;

    let cfg = garter_bin::config::resolve_chain_config(env.plugin_options.as_deref())?;

    // Contract, not input validation: `resolve_chain_config` above already
    // ran the same string through the identical parser
    // (`config_path_from_plugin_options` → `split_plugin_options`) and
    // returned `Ok`, so this is provably unreachable on every real input.
    // `debug_assert!` makes a violation panic loudly in debug/test builds —
    // a genuine contract break, not routine input handling — while staying
    // truly zero-cost in release (compiled out entirely);
    // the `?` alongside it is release's own fallback, so a violation there
    // degrades to a normal, well-formed error instead of an uncontrolled
    // panic in a binary that ships.
    let mode_result = Mode::from_plugin_options(env.plugin_options.as_deref());
    debug_assert!(
        mode_result.is_ok(),
        "already validated by resolve_chain_config's config_path_from_plugin_options call above"
    );
    let mode = mode_result?;
    let mut runner = ChainRunner::new().mode(mode);
    for entry in cfg.chain {
        runner = runner.add(Box::new(BinaryPlugin::new(entry.plugin, entry.options.as_deref())));
    }

    runner.run(env).await.map_err(|e| anyhow::anyhow!(e))
}

use garter::{BinaryPlugin, ChainRunner, Mode, PluginEnv};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if let Some(text) = garter_bin::cli::info_output(std::env::args_os().skip(1)) {
        println!("{text}");
        return Ok(());
    }

    // Sanctioned production caller of `fmt::SubscriberBuilder::init`;
    // banned in tests via clippy.toml `disallowed_methods`.
    #[allow(clippy::disallowed_methods)]
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let env = PluginEnv::from_env().map_err(|e| anyhow::anyhow!("failed to parse SIP003u environment: {e}"))?;

    let cfg = garter_bin::config::resolve_chain_config(env.plugin_options.as_deref())?;

    // `resolve_chain_config` already parsed this string, so this cannot fail.
    let mode = Mode::from_plugin_options(env.plugin_options.as_deref())
        .expect("well-formed by construction: already validated by resolve_chain_config above");
    let mut runner = ChainRunner::new().mode(mode);
    for entry in cfg.chain {
        runner = runner.add(Box::new(BinaryPlugin::new(entry.plugin, entry.options.as_deref())));
    }

    runner.run(env).await.map_err(|e| anyhow::anyhow!(e))
}

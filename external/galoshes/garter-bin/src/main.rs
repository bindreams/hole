use garter::sip003::parse_plugin_options;
use garter::{BinaryPlugin, ChainRunner, PluginEnv};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let env = PluginEnv::from_env().map_err(|e| anyhow::anyhow!("failed to parse SIP003u environment: {e}"))?;

    let config_path = env
        .plugin_options
        .as_ref()
        .and_then(|opts| {
            parse_plugin_options(opts)
                .into_iter()
                .find(|(k, _)| k == "config")
                .map(|(_, v)| v)
        })
        .ok_or_else(|| anyhow::anyhow!("SS_PLUGIN_OPTIONS must contain config=/path/to/chain.yaml"))?;

    let cfg = garter_bin::config::load_config(std::path::Path::new(&config_path))?;
    anyhow::ensure!(!cfg.chain.is_empty(), "chain config must have at least one plugin");

    let mut runner = ChainRunner::new();
    for entry in cfg.chain {
        runner = runner.add(Box::new(BinaryPlugin::new(entry.plugin, entry.options.as_deref())));
    }

    runner.run(env).await.map_err(|e| anyhow::anyhow!(e))
}

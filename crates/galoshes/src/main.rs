#![cfg_attr(v2ray_plugin_missing, allow(dead_code, unused_imports))]

use garter::{BinaryPlugin, ChainRunner, Mode, PluginEnv};

#[cfg(not(v2ray_plugin_missing))]
const V2RAY_BYTES: &[u8] = include_bytes!(env!("V2RAY_PLUGIN_PATH"));
#[cfg(v2ray_plugin_missing)]
const V2RAY_BYTES: &[u8] = b"";

#[cfg(v2ray_plugin_missing)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    anyhow::bail!("galoshes was compiled without v2ray-plugin. Run `cargo xtask v2ray-plugin` and rebuild.");
}

#[cfg(not(v2ray_plugin_missing))]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Sanctioned production caller of `fmt::SubscriberBuilder::init`;
    // banned in tests via clippy.toml `disallowed_methods`. See #301.
    #[allow(clippy::disallowed_methods)]
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let env = PluginEnv::from_env().map_err(|e| anyhow::anyhow!("failed to parse SIP003u environment: {e}"))?;

    // Parse SHA256 from build-time env
    let sha256 = {
        let hex = env!("V2RAY_SHA256");
        let mut bytes = [0u8; 32];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            bytes[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
        }
        bytes
    };

    let v2ray_binary = galoshes::embedded::EmbeddedBinary {
        name: "v2ray-plugin",
        data: V2RAY_BYTES,
        sha256,
    };

    let verified = v2ray_binary.prepare()?;

    let mode = Mode::from_plugin_options(env.plugin_options.as_deref());
    // Parse the galoshes-specific client UDP NAT idle-eviction timeout from the
    // shared options string before any I/O so a misconfiguration fails loudly
    // at startup. v2ray-plugin ignores this key (it only reads keys it knows).
    let udp_timeout = galoshes::yamux::parse_udp_timeout(env.plugin_options.as_deref())?;
    let yamux_plugin = galoshes::yamux::YamuxPlugin::new(mode == Mode::Server, udp_timeout);
    let v2ray_plugin = BinaryPlugin::new(verified.exec_path(), env.plugin_options.as_deref());

    let runner = ChainRunner::new()
        .mode(mode)
        .add(Box::new(yamux_plugin))
        .add(Box::new(v2ray_plugin));

    // `verified` must remain alive here -- its open handle prevents TOCTOU
    // attacks on the extracted binary. It is dropped after `run()` returns.
    let result = runner.run(env).await.map_err(|e| anyhow::anyhow!(e));
    drop(verified);
    result
}

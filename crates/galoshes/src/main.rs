#![cfg_attr(ex_ray_missing, allow(dead_code, unused_imports))]

use galoshes::sitrep_out::{chain_result_to_event, emit};
use garter::{
    BinaryPlugin, ChainReady, ChainRunner, Mode, PluginEnv, ReadinessMode, SitrepEvent, StartError, SITREP_PROTOCOL,
};

#[cfg(not(ex_ray_missing))]
const EX_RAY_BYTES: &[u8] = include_bytes!(env!("EX_RAY_PATH"));
#[cfg(ex_ray_missing)]
const EX_RAY_BYTES: &[u8] = b"";

#[cfg(ex_ray_missing)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    anyhow::bail!("galoshes was compiled without ex-ray. Run `cargo xtask ex-ray` and rebuild.");
}

#[cfg(not(ex_ray_missing))]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Sanctioned production caller of `fmt::SubscriberBuilder::init`;
    // banned in tests via clippy.toml `disallowed_methods`. See #301.
    //
    // Logs go to STDERR: galoshes' process STDOUT is reserved for the
    // sitrep event stream (newline-delimited JSON) that the bridge reads.
    // The `tracing_subscriber::fmt` default writer is `io::stdout`, which
    // would interleave human logs into the JSON stream and corrupt it.
    #[allow(clippy::disallowed_methods)]
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with_writer(std::io::stderr)
        .init();

    // sitrep handshake: ALWAYS the first stdout line, emitted before we
    // parse the environment or build the chain so it lands as line 1 even
    // if a later step fails.
    emit(&SitrepEvent::Hello {
        protocol: SITREP_PROTOCOL.to_string(),
    });

    // Native-crash observability (bindreams/hole#438). galoshes does NOT
    // route through hole_common::logging (it owns its own subscriber above),
    // so it attaches + sweeps directly. Placed AFTER the Hello emit: Hello
    // must be stdout line 1 (the bridge reads it), and runtime_dir() is
    // fallible — it must not precede Hello. Markers are pid-keyed and sweep
    // reports the PREVIOUS run, so ordering after Hello is correct. The
    // marker/.dmp land in galoshes' per-user runtime dir
    // (%LOCALAPPDATA%/galoshes etc.) — the bridge sweeps its OWN log dir, so
    // galoshes markers are reported on the NEXT galoshes start, not by the
    // bridge. Best-effort: a dir-resolution failure here must not block
    // plugin startup, so attach/sweep are skipped on Err.
    if let Ok(crash_dir) = galoshes::embedded::runtime_dir() {
        tombstone::sweep(&crash_dir);
        tombstone::attach("galoshes", &crash_dir);
    }

    let env = PluginEnv::from_env().map_err(|e| anyhow::anyhow!("failed to parse SIP003u environment: {e}"))?;

    // Parse SHA256 from build-time env
    let sha256 = {
        let hex = env!("EX_RAY_SHA256");
        let mut bytes = [0u8; 32];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            bytes[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
        }
        bytes
    };

    let ex_ray_binary = galoshes::embedded::EmbeddedBinary {
        name: "ex-ray",
        data: EX_RAY_BYTES,
        sha256,
    };

    let verified = ex_ray_binary.prepare()?;

    let mode = Mode::from_plugin_options(env.plugin_options.as_deref());
    // Parse the galoshes-specific client UDP NAT idle-eviction timeout from the
    // shared options string before any I/O so a misconfiguration fails loudly
    // at startup. ex-ray ignores unrecognized keys (it only reads keys it knows).
    let udp_timeout = galoshes::yamux::parse_udp_timeout(env.plugin_options.as_deref())?;
    let yamux_plugin = galoshes::yamux::YamuxPlugin::new(mode == Mode::Server, udp_timeout);
    let ex_ray_plugin =
        BinaryPlugin::new(verified.exec_path(), env.plugin_options.as_deref()).readiness(ReadinessMode::ExpectSitrep);

    // Bridge-facing readiness: galoshes' OWN ChainRunner aggregates the
    // per-plugin readiness of [yamux, ex-ray] and fires this channel with
    // the chain-level outcome. We map that to a PROCESS-stdout sitrep event
    // (overriding the inner-chain transport intersection with galoshes'
    // true TCP|UDP capability — see `sitrep_out`) so the bridge sees a
    // structured `ready`/`bind_conflict`/`fatal` on galoshes' stdout.
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<Result<ChainReady, StartError>>();

    // The emitter must run concurrently with `runner.run`: the plugins
    // only start (and report ready) once `run` is driving them, so we
    // cannot await `ready_rx` before calling `run`. On channel drop
    // (RecvError) we emit nothing — galoshes will exit and the bridge sees
    // stdout EOF, which is the backstop.
    let emitter = tokio::spawn(async move {
        if let Ok(outcome) = ready_rx.await {
            emit(&chain_result_to_event(outcome));
        }
    });

    let runner = ChainRunner::new()
        .mode(mode)
        .on_ready(ready_tx)
        .add(Box::new(yamux_plugin))
        .add(Box::new(ex_ray_plugin));

    // `verified` must remain alive here -- its open handle prevents TOCTOU
    // attacks on the extracted binary. It is dropped after `run()` returns.
    let result = runner.run(env).await.map_err(|e| anyhow::anyhow!(e));
    // The aggregator drops `ready_tx` once the chain ends (or on shutdown),
    // so the emitter task either already emitted or sees RecvError; await
    // it to completion rather than fire-and-forget.
    let _ = emitter.await;
    drop(verified);
    result
}

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

    // Validates `env.plugin_options` first, so its malformed-options `Err` is
    // what a bad SS_PLUGIN_OPTIONS string surfaces as here — the same defect
    // would also fail `parse_udp_timeout`/`ex_ray_options` below, but they can
    // never reach that branch through this binary; both stay fallible for
    // their own callers and unit tests.
    let mode = Mode::from_plugin_options(env.plugin_options.as_deref())?;
    // Parse the galoshes-specific client UDP NAT idle-eviction timeout from the
    // shared options string before any I/O so a misconfiguration fails loudly
    // at startup. ex-ray ignores unrecognized keys (it only reads keys it knows).
    let udp_timeout = galoshes::yamux::parse_udp_timeout(env.plugin_options.as_deref())?;
    let yamux_plugin = galoshes::yamux::YamuxPlugin::new(mode == Mode::Server, udp_timeout);
    // The embedded ex-ray gets its own options; the yamux hop keeps the caller's,
    // since `mux` means nothing to it.
    let ex_ray_options = galoshes::exray_options::ex_ray_options(env.plugin_options.as_deref())?;
    let ex_ray_plugin =
        BinaryPlugin::new(verified.exec_path(), Some(&ex_ray_options)).readiness(ReadinessMode::ExpectSitrep);

    // Bridge-facing readiness: galoshes' OWN ChainRunner aggregates the
    // per-plugin readiness of [yamux, ex-ray] and fires this channel with
    // the chain-level outcome. We map that to a PROCESS-stdout sitrep event
    // (overriding the inner-chain transport intersection with galoshes'
    // true TCP|UDP capability — see `sitrep_out`) so the bridge sees a
    // structured `ready`/`bind_conflict`/`fatal` on galoshes' stdout.
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<Result<ChainReady, StartError>>();

    let runner = ChainRunner::new()
        .mode(mode)
        .on_ready(ready_tx)
        .add(Box::new(yamux_plugin))
        .add(Box::new(ex_ray_plugin));

    // `run()` is spawned rather than awaited inline: the plugins only start
    // (and report ready) once `run` is driving them, so we cannot await
    // `ready_rx` before calling `run`. Spawning also gives the
    // `ExitedBeforeReady` arm below a handle it can join early, to recover
    // a more specific reason from the chain's own terminal result — the
    // same recovery bridge's `recover_exit_detail` performs against the
    // plugin-driving task IT holds. `run_handle` is consumed by exactly one
    // of the two branches below (`Pending` tracks which), never twice.
    let run_handle = tokio::spawn(runner.run(env));

    enum Pending {
        NotJoined(tokio::task::JoinHandle<garter::Result<()>>),
        Joined(Result<garter::Result<()>, tokio::task::JoinError>),
    }

    let (event, pending) = match ready_rx.await {
        Ok(Ok(ready)) => (Some(chain_result_to_event(Ok(ready))), Pending::NotJoined(run_handle)),
        Ok(Err(StartError::ExitedBeforeReady)) => {
            let joined = run_handle.await;
            let detail = garter::recover_exit_detail_from_joined(&joined);
            (
                Some(chain_result_to_event(Err(StartError::Fatal { detail, errno: None }))),
                Pending::Joined(joined),
            )
        }
        Ok(Err(other)) => (Some(chain_result_to_event(Err(other))), Pending::NotJoined(run_handle)),
        // The ready channel itself dropped unsent (shutdown fired before the
        // aggregator sent anything) — emit nothing; galoshes will exit and
        // the bridge sees stdout EOF, the existing backstop.
        Err(_) => (None, Pending::NotJoined(run_handle)),
    };
    if let Some(event) = &event {
        emit(event);
    }

    // `verified` must remain alive here -- its open handle prevents TOCTOU
    // attacks on the extracted binary. It is dropped after the chain's own
    // task is fully joined (below), whichever branch above already did so.
    let joined = match pending {
        Pending::Joined(j) => j,
        Pending::NotJoined(h) => h.await,
    };
    drop(verified);
    joined
        .map_err(|je| anyhow::anyhow!("plugin-driving task ended abnormally: {je}"))
        .and_then(|r| r.map_err(|e| anyhow::anyhow!(e)))
}

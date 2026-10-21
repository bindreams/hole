//! SIP003 plugin stub for `tests/plugin_chain.rs`. Reports the environment it
//! was actually given, then behaves like a minimal plugin: bind the SIP003
//! local address and serve.
//!
//! ORDER IS THE CONTRACT — see `tests/plugin_chain.rs`'s module doc. `hello` is
//! the first stdout line (SITREP.md: it MUST be), then `SS_PLUGIN_OPTIONS`,
//! then `ready`. Keep the options line on stdout and before `ready`; stderr is a
//! second pipe with no ordering against readiness.

use std::io::Write;
use std::net::SocketAddr;

use garter::sitrep::{SitrepEvent, Transports, SITREP_PROTOCOL};
use tokio::net::TcpListener;

fn emit(ev: &SitrepEvent) {
    println!("{}", serde_json::to_string(ev).expect("serialize sitrep event"));
    let _ = std::io::stdout().flush();
}

/// Fault-injection knob, read out of `SS_PLUGIN_OPTIONS` because
/// `start_plugin_chain` has no environment seam: `fail-bind-once=<path>` makes
/// the FIRST invocation sharing that sentinel path report a bind conflict.
/// Atomic via `create_new`, so there is no TOCTOU between sibling attempts.
fn losing_bind_race(opts: &str) -> bool {
    let Some(path) = opts.split(';').find_map(|s| s.strip_prefix("fail-bind-once=")) else {
        return false;
    };
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .is_ok()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let local_host = std::env::var("SS_LOCAL_HOST")?;
    let local_port: u16 = std::env::var("SS_LOCAL_PORT")?.parse()?;
    let local_addr: SocketAddr = format!("{local_host}:{local_port}").parse()?;
    let opts = std::env::var("SS_PLUGIN_OPTIONS").unwrap_or_default();

    emit(&SitrepEvent::Hello {
        protocol: SITREP_PROTOCOL.to_string(),
    });

    println!("test-plugin: SS_PLUGIN_OPTIONS={opts}");
    let _ = std::io::stdout().flush();

    // Fault-injection knob: `fail-stderr-then-exit=<msg>` writes `<msg>` to
    // stderr and exits before ever binding — models a plugin that crashes
    // (e.g. a Go panic under `GOTRACEBACK=crash`) writing its last words to
    // stderr rather than stdout, before the chain ever becomes ready.
    if let Some(msg) = opts.split(';').find_map(|s| s.strip_prefix("fail-stderr-then-exit=")) {
        eprintln!("{msg}");
        let _ = std::io::stderr().flush();
        std::process::exit(1);
    }

    // Fault-injection knob: `connect-back=<addr>` dials `<addr>`, sends the local
    // port this attempt was told to bind (2 bytes, big-endian: a test tells a live
    // attempt's stream from a dead one's), and holds the stream until this process
    // dies, so the test's end of it reads EOF exactly when the plugin is gone.
    let _held = match opts.split(';').find_map(|s| s.strip_prefix("connect-back=")) {
        Some(addr) => {
            let mut stream = tokio::net::TcpStream::connect(addr).await?;
            tokio::io::AsyncWriteExt::write_all(&mut stream, &local_port.to_be_bytes()).await?;
            Some(stream)
        }
        None => None,
    };

    // Fault-injection knob: `never-ready` parks here, before the chain can
    // become ready — models a plugin still starting when the user cancels.
    if opts.split(';').any(|s| s == "never-ready") {
        std::future::pending::<()>().await;
    }

    // A lost port race must be reported as `bind_conflict`, the only class
    // `bind_ephemeral` retries on a fresh port — exiting with a bare error
    // instead would turn the residual probe-drop-to-bind TOCTOU into an
    // unconditional test failure. Mirrors mock-plugin's `bind_conflict` path.
    let bind = if losing_bind_race(&opts) {
        Err(std::io::Error::from(std::io::ErrorKind::AddrInUse))
    } else {
        TcpListener::bind(local_addr).await
    };
    let listener = match bind {
        Ok(l) => l,
        Err(e) => {
            emit(&SitrepEvent::BindConflict {
                errno: e.raw_os_error().unwrap_or(0),
                addr: local_addr,
            });
            std::process::exit(1);
        }
    };
    emit(&SitrepEvent::Ready {
        listen: local_addr,
        transports: Transports::TCP,
    });

    // Fault-injection knob: `exit-after-ready` exits as soon as `ready` is out
    // — models a plugin dying mid-session.
    if opts.split(';').any(|s| s == "exit-after-ready") {
        std::process::exit(0);
    }

    loop {
        let _ = listener.accept().await?;
    }
}

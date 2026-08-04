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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let local_host = std::env::var("SS_LOCAL_HOST")?;
    let local_port: u16 = std::env::var("SS_LOCAL_PORT")?.parse()?;
    let local_addr: SocketAddr = format!("{local_host}:{local_port}").parse()?;

    emit(&SitrepEvent::Hello {
        protocol: SITREP_PROTOCOL.to_string(),
    });

    println!(
        "test-plugin: SS_PLUGIN_OPTIONS={}",
        std::env::var("SS_PLUGIN_OPTIONS").unwrap_or_default()
    );
    let _ = std::io::stdout().flush();

    let listener = TcpListener::bind(local_addr).await?;
    emit(&SitrepEvent::Ready {
        listen: local_addr,
        transports: Transports::TCP,
    });

    loop {
        let _ = listener.accept().await?;
    }
}

use std::net::SocketAddr;

use garter::sitrep::{SitrepEvent, Transports, SITREP_PROTOCOL};
use tokio::io;
use tokio::net::{TcpListener, TcpStream};

/// Emit a sitrep event to STDOUT (one JSON object per line) unless
/// `sitrep_enabled` is false, in which case the plugin behaves like a
/// pre-sitrep plain forwarder (prints nothing to stdout). Gated by the
/// `MOCK_PLUGIN_NO_SITREP` knob — see `main`.
fn emit(ev: &SitrepEvent, sitrep_enabled: bool) {
    if !sitrep_enabled {
        return;
    }
    println!("{}", serde_json::to_string(ev).expect("serialize sitrep event"));
    use std::io::Write;
    let _ = std::io::stdout().flush();
}

/// True on the FIRST call across process invocations sharing the sentinel
/// path; false thereafter. Atomic via O_CREAT|O_EXCL semantics — no TOCTOU.
fn first_failure_for_sentinel() -> bool {
    let Some(path) = std::env::var_os("MOCK_PLUGIN_FAIL_SENTINEL") else {
        return true; // no sentinel configured → always "first" (plain bind_conflict)
    };
    match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(_) => true, // we created it → this is the first failure
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false, // retry → succeed
        Err(_) => true, // any other error → behave as first failure (fail loud)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let local_host = std::env::var("SS_LOCAL_HOST")?;
    let local_port: u16 = std::env::var("SS_LOCAL_PORT")?.parse()?;
    let remote_host = std::env::var("SS_REMOTE_HOST")?;
    let remote_port: u16 = std::env::var("SS_REMOTE_PORT")?.parse()?;

    let local_addr: SocketAddr = format!("{local_host}:{local_port}").parse()?;
    let remote_addr = format!("{remote_host}:{remote_port}");

    if std::env::var_os("MOCK_PLUGIN_ECHO_ENV").is_some() {
        if let Ok(opts) = std::env::var("SS_PLUGIN_OPTIONS") {
            eprintln!("mock-plugin: SS_PLUGIN_OPTIONS={opts}");
        }
    }

    // Knob: MOCK_PLUGIN_NO_SITREP — suppress ALL stdout sitrep emits so the
    // plugin behaves like a pre-sitrep plain forwarder (the tier-2 self-probe
    // path). It still binds + forwards; it just prints nothing to stdout.
    // Fault knobs that emit-then-exit still EXIT (the emit is just skipped).
    let sitrep_enabled = std::env::var_os("MOCK_PLUGIN_NO_SITREP").is_none();
    // Knob: MOCK_PLUGIN_BAD_PROTOCOL — emit a `hello` with an unknown major
    // (`sitrep-2.0.0`) so the consumer's protocol gate falls back to tier-2
    // probe; the plugin still binds + emits `ready` (which the consumer
    // ignores because handshake_ok stayed false).
    let bad_protocol = std::env::var_os("MOCK_PLUGIN_BAD_PROTOCOL").is_some();
    // Knob: MOCK_PLUGIN_EMPTY_TRANSPORTS — emit `ready` with an empty
    // transports set (a SITREP protocol violation) so the consumer rejects
    // it as Fatal. The `hello` handshake is still well-formed.
    let empty_transports = std::env::var_os("MOCK_PLUGIN_EMPTY_TRANSPORTS").is_some();

    // sitrep handshake: ALWAYS the first stdout line (when sitrep is enabled).
    let hello_protocol = if bad_protocol {
        "sitrep-2.0.0".to_string()
    } else {
        SITREP_PROTOCOL.to_string()
    };
    emit(
        &SitrepEvent::Hello {
            protocol: hello_protocol,
        },
        sitrep_enabled,
    );

    // Fault-injection knob: MOCK_PLUGIN_FAIL=fatal | bind_conflict | bind_conflict_once
    let fail = std::env::var("MOCK_PLUGIN_FAIL").unwrap_or_default();
    if fail == "fatal" {
        emit(
            &SitrepEvent::Fatal {
                detail: "injected fatal".into(),
                errno: None,
            },
            sitrep_enabled,
        );
        std::process::exit(1);
    }
    // Host-native errno: AddrInUse is 48 on macOS, 98 on Linux, 10048 (WSA)
    // on Windows. The bridge's BindRace mapping sets ErrorKind directly and
    // ignores this number for classification (see Task 9), so a representative
    // non-zero value is fine — but emit the real host value for diagnostic
    // honesty rather than a hardcoded foreign constant.
    let addr_in_use_errno: i32 = {
        #[cfg(target_os = "windows")]
        {
            10048
        }
        #[cfg(target_os = "linux")]
        {
            98
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            48
        }
    };
    if fail == "bind_conflict" || (fail == "bind_conflict_once" && first_failure_for_sentinel()) {
        emit(
            &SitrepEvent::BindConflict {
                errno: addr_in_use_errno,
                addr: local_addr,
            },
            sitrep_enabled,
        );
        std::process::exit(1);
    }

    eprintln!("mock-plugin: listening on {local_addr}, forwarding to {remote_addr}");
    let listener = TcpListener::bind(local_addr).await?;

    // sitrep ready: listener is bound & accepting. With
    // MOCK_PLUGIN_EMPTY_TRANSPORTS the transports set is empty (a protocol
    // violation the consumer rejects as Fatal). With MOCK_PLUGIN_BAD_PROTOCOL
    // the ready emits TCP|UDP so the tier-2 probe (which always reports TCP
    // only) is distinguishable from a wrongly-honored bad-major ready.
    let ready_transports = if empty_transports {
        Transports::empty()
    } else if bad_protocol {
        Transports::TCP | Transports::UDP
    } else {
        Transports::TCP
    };
    emit(
        &SitrepEvent::Ready {
            listen: local_addr,
            transports: ready_transports,
        },
        sitrep_enabled,
    );

    loop {
        let (inbound, peer) = listener.accept().await?;
        eprintln!("mock-plugin: accepted connection from {peer}");
        let remote = remote_addr.clone();
        tokio::spawn(async move {
            match TcpStream::connect(&remote).await {
                Ok(outbound) => {
                    let (mut ri, mut wi) = io::split(inbound);
                    let (mut ro, mut wo) = io::split(outbound);
                    let c2s = io::copy(&mut ri, &mut wo);
                    let s2c = io::copy(&mut ro, &mut wi);
                    let _ = tokio::try_join!(c2s, s2c);
                }
                Err(e) => eprintln!("mock-plugin: failed to connect to {remote}: {e}"),
            }
        });
    }
}

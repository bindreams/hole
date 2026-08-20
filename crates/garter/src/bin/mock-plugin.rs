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

/// Absorb the cooperative shutdown signal, so only a force-kill can end this process.
#[cfg(unix)]
fn ignore_cooperative_signal() {
    // SAFETY: setting SIG_IGN runs no handler code; it only changes a process-wide disposition.
    unsafe {
        libc::signal(libc::SIGTERM, libc::SIG_IGN);
    }
}

#[cfg(windows)]
fn ignore_cooperative_signal() {
    use windows::Win32::System::Console::SetConsoleCtrlHandler;

    // Returning TRUE claims the event as handled, so the default disposition
    // (STATUS_CONTROL_C_EXIT) never runs.
    unsafe extern "system" fn absorb(_ctrl_type: u32) -> windows::core::BOOL {
        windows::Win32::Foundation::TRUE
    }

    // SAFETY: `absorb` is a valid handler with the required ABI and no state of its own.
    unsafe { SetConsoleCtrlHandler(Some(absorb), true) }.expect("install a console control handler");
}

/// One readiness byte on stdout, flushed. The reader's `read_exact` of it is the
/// happens-before edge for "this process is executing its own code" — which the
/// Windows leg needs, because a child is not registered with any console at the
/// instant its spawn returns.
fn report_ready() {
    use std::io::Write;
    let mut out = std::io::stdout();
    out.write_all(b"R").expect("write the readiness byte");
    out.flush().expect("flush the readiness byte");
}

/// Middle level of the nesting probe: spawn a nested contained copy of ourselves,
/// then report two lines on stdout — the grandchild's achieved containment, and how
/// its cooperative shutdown ended.
async fn run_nest_probe(control_addr: std::ffi::OsString) -> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::AsyncReadExt;

    let mut cmd = cosca::tokio::Command::new();
    cmd.executable(std::env::current_exe()?)
        .env("MOCK_PLUGIN_NEST_GRANDCHILD", &control_addr)
        .env_remove("MOCK_PLUGIN_NEST_PROBE")
        .kill_on_drop(true)
        .contain();
    cmd.stdin(cosca::Stdio::null())?;
    cmd.stdout(cosca::Stdio::pipe())?;
    cmd.stderr(cosca::Stdio::null())?;
    let mut grandchild = cmd.spawn()?;

    let mut stdout = grandchild.stdout().expect("the grandchild's stdout was piped");
    let mut ready = [0u8; 1];
    stdout.read_exact(&mut ready).await?;

    println!("{}", grandchild.containment());
    println!("{}", describe_shutdown(&mut grandchild).await);
    use std::io::Write;
    std::io::stdout().flush()?;
    Ok(())
}

/// Shut the grandchild down cooperatively and render the outcome as one line:
/// `error=<e>`, or the exit status the escalation-capable call returned.
async fn describe_shutdown(grandchild: &mut cosca::tokio::Child) -> String {
    let status = match grandchild.graceful_shutdown(std::time::Duration::from_secs(5)).await {
        Ok(status) => status,
        Err(e) => return format!("error={e}"),
    };
    let code = status.code().map_or_else(|| "none".to_string(), |c| c.to_string());
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        let signal = status.signal().map_or_else(|| "none".to_string(), |s| s.to_string());
        format!("code={code} signal={signal}")
    }
    #[cfg(not(unix))]
    format!("code={code}")
}

/// Middle level of the std-handle hygiene probe (bindreams/hole#197): spawn a copy
/// of ourselves with every stdio slot redirected to null, handing it the numeric
/// value of OUR stdout handle, then exit at once — so the only process that can
/// still be holding the host's pipe is the grandchild.
///
/// `MOCK_PLUGIN_HYGIENE_NEST` picks the spawn route, which is the whole experiment:
/// `"std"` is the positive control, a `std::process::Command` that scopes nothing,
/// and `"contain"` is the real leg, a nested contained cosca spawn.
#[cfg(windows)]
async fn run_hygiene_probe(control_addr: std::ffi::OsString) -> Result<(), Box<dyn std::error::Error>> {
    use windows::Win32::System::Console::{GetStdHandle, STD_OUTPUT_HANDLE};

    // SAFETY: a plain query of this process's own standard-handle table.
    let stdout_handle = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) }?;
    let sentinel = (stdout_handle.0 as usize).to_string();
    let via_std = std::env::var_os("MOCK_PLUGIN_HYGIENE_NEST").is_some_and(|v| v == "std");

    // Positive control: `std::process::Command` passes `bInheritHandles = TRUE` with
    // no handle list, so the grandchild receives every handle this process has marked
    // inheritable — including the stdout pipe it was never given as stdio.
    if via_std {
        let mut cmd = std::process::Command::new(std::env::current_exe()?);
        cmd.env("MOCK_PLUGIN_HYGIENE_SENTINEL", &sentinel)
            .env("MOCK_PLUGIN_HYGIENE_PROBE", &control_addr)
            .env_remove("MOCK_PLUGIN_HYGIENE_NEST")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        // std's `Child` is not kill-on-drop, so the grandchild outlives this process.
        cmd.spawn()?;
        return Ok(());
    }

    let mut cmd = cosca::tokio::Command::new();
    cmd.executable(std::env::current_exe()?)
        .env("MOCK_PLUGIN_HYGIENE_SENTINEL", &sentinel)
        .env("MOCK_PLUGIN_HYGIENE_PROBE", &control_addr)
        .env_remove("MOCK_PLUGIN_HYGIENE_NEST")
        // The grandchild must outlive this process: it is the subject under test.
        .kill_on_drop(false)
        .contain();
    cmd.stdin(cosca::Stdio::null())?;
    cmd.stdout(cosca::Stdio::null())?;
    cmd.stderr(cosca::Stdio::null())?;
    cmd.spawn()?;
    Ok(())
}

/// Innermost level of the hygiene probe. Answer whether the handle value we were
/// handed is a pipe in THIS process — inherited handles keep their numeric value —
/// and report the verdict on the control channel.
#[cfg(windows)]
async fn run_hygiene_grandchild(
    sentinel: std::ffi::OsString,
    control_addr: std::ffi::OsString,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    use std::os::windows::io::FromRawHandle;
    use tokio::io::AsyncWriteExt;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{GetFileType, FILE_TYPE_PIPE};

    let raw: usize = sentinel
        .to_str()
        .expect("MOCK_PLUGIN_HYGIENE_SENTINEL is valid utf-8")
        .parse()?;
    let handle = HANDLE(raw as *mut std::ffi::c_void);

    // Probe BEFORE dialling: a Windows socket also answers FILE_TYPE_PIPE, so a
    // socket opened first would widen the numeric-collision window for no benefit.
    // The handle value is fixed at process start; opening a socket cannot change it.
    // SAFETY: `GetFileType` reads a handle value and answers FILE_TYPE_UNKNOWN for
    // one this process does not own — it never dereferences anything.
    let is_pipe = unsafe { GetFileType(handle) } == FILE_TYPE_PIPE;

    let addr = control_addr.to_str().expect("MOCK_PLUGIN_HYGIENE_PROBE is valid utf-8");
    let mut control = TcpStream::connect(addr).await?;

    let verdict = if is_pipe {
        // Exactly the #197 leak: a grandchild writing down the host's stdout pipe,
        // whose reader would never see EOF while this process lives. `ManuallyDrop`
        // keeps holding it, so the test's EOF assertion is about this process's death.
        let mut host_pipe = std::mem::ManuallyDrop::new(unsafe {
            std::fs::File::from_raw_handle(handle.0 as std::os::windows::raw::HANDLE)
        });
        host_pipe.write_all(b"HYGIENE\n")?;
        host_pipe.flush()?;
        "held"
    } else {
        "clear"
    };
    control.write_all(format!("{verdict}\n").as_bytes()).await?;
    control.flush().await?;
    std::future::pending::<()>().await;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Knob: MOCK_PLUGIN_SLEEP — "grandchild" mode (a garter process-tree-reaping
    // test seam). Live forever, inheriting whatever stdio the parent gave us; do
    // NOT read SIP003 env. Stands in for an inner plugin (e.g. galoshes's ex-ray)
    // that a force-killed parent would otherwise orphan.
    //
    // If MOCK_PLUGIN_GRANDCHILD_CALLBACK is set, first dial that loopback addr and
    // HOLD the connection open for the process lifetime. The test accepts it to
    // observe our liveness (deterministic readiness — no pidfile poll) and reads
    // it to observe our death: the socket EOFs/resets the instant this process is
    // reaped. That is reuse-immune (a recycled PID cannot resurrect this specific
    // TCP connection) and needs no sleep. We never write to the socket — closing
    // it is purely an exit signal.
    if std::env::var_os("MOCK_PLUGIN_SLEEP").is_some() {
        // Knob: MOCK_PLUGIN_IGNORE_SIGNALS — absorb the cooperative shutdown signal
        // (SIGTERM / CTRL_BREAK) so only a force-kill can end this process. Installed
        // before the callback dial, so a test that has observed readiness is past it.
        if std::env::var_os("MOCK_PLUGIN_IGNORE_SIGNALS").is_some() {
            ignore_cooperative_signal();
        }
        let _callback = match std::env::var_os("MOCK_PLUGIN_GRANDCHILD_CALLBACK") {
            Some(addr) => {
                let addr = addr.to_str().expect("MOCK_PLUGIN_GRANDCHILD_CALLBACK is valid utf-8");
                Some(
                    TcpStream::connect(addr)
                        .await
                        .expect("grandchild dials the test callback"),
                )
            }
            None => None,
        };
        std::future::pending::<()>().await;
    }

    // Knob: MOCK_PLUGIN_NEST_GRANDCHILD=<control addr> — the innermost level of the
    // nesting probe. Dial the control address and hold it (the test accepts it to
    // observe liveness, and reads it to observe death), report readiness on stdout,
    // then park. NO signal handler: the cooperative signal must end this process by
    // its default disposition, which is what distinguishes it from an escalation.
    if let Some(addr) = std::env::var_os("MOCK_PLUGIN_NEST_GRANDCHILD") {
        let addr = addr.to_str().expect("MOCK_PLUGIN_NEST_GRANDCHILD is valid utf-8");
        let _control = TcpStream::connect(addr)
            .await
            .expect("grandchild dials the control channel");
        report_ready();
        std::future::pending::<()>().await;
    }

    // Knob: MOCK_PLUGIN_NEST_PROBE=<control addr> — the middle level. Spawn a
    // contained copy of ourselves (nested, because our own environment carries the
    // containment marker) and report, on stdout, what containment it achieved and
    // how the cooperative signal ended it.
    if let Some(addr) = std::env::var_os("MOCK_PLUGIN_NEST_PROBE") {
        return run_nest_probe(addr).await;
    }

    // Knobs: MOCK_PLUGIN_HYGIENE_{PROBE,NEST,SENTINEL} — the Windows std-handle
    // hygiene probe. SENTINEL is checked first: it is what makes a process the
    // grandchild, and both levels carry PROBE.
    #[cfg(windows)]
    if let Some(addr) = std::env::var_os("MOCK_PLUGIN_HYGIENE_PROBE") {
        return match std::env::var_os("MOCK_PLUGIN_HYGIENE_SENTINEL") {
            Some(sentinel) => run_hygiene_grandchild(sentinel, addr).await,
            None => run_hygiene_probe(addr).await,
        };
    }

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
        // Echoed in this order (NO_COLOR then CLICOLOR) so a test waiting
        // on the LAST line is guaranteed both have already been written —
        // they land as two separate stderr lines / tracing events.
        eprintln!("mock-plugin: NO_COLOR={:?}", std::env::var("NO_COLOR"));
        eprintln!("mock-plugin: CLICOLOR={:?}", std::env::var("CLICOLOR"));
    }

    // Knob: MOCK_PLUGIN_FORCE_ANSI_STDERR — write one ANSI-colored stderr
    // line unconditionally, ignoring NO_COLOR/CLICOLOR entirely. Simulates
    // a plugin whose own logging library does NOT honor either convention,
    // so a consumer test can prove garter's own relay strips ANSI
    // regardless of the child's cooperation.
    if std::env::var_os("MOCK_PLUGIN_FORCE_ANSI_STDERR").is_some() {
        eprintln!("\x1b[31mmock-plugin: colored line\x1b[0m");
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

    // Knob: MOCK_PLUGIN_RAW_STDOUT_LINE — print this env var's value
    // verbatim as one extra stdout line, right after `hello`, then
    // continue normal startup (bind + `ready`). Lets a test hand-construct
    // an exact byte sequence (e.g. a sitrep-shaped line with a raw,
    // unescaped control byte inside a JSON string — illegal per RFC 8259)
    // without teaching mock-plugin a new fault mode for every shape.
    if let Ok(raw) = std::env::var("MOCK_PLUGIN_RAW_STDOUT_LINE") {
        println!("{raw}");
        use std::io::Write;
        let _ = std::io::stdout().flush();
    }

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
    // ignores this number for classification (see `ProxyError::BindRace`
    // handling in crates/bridge/src/proxy/plugin.rs), so a representative
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

    // Knob: MOCK_PLUGIN_SPAWN_GRANDCHILD=<callback_addr> — spawn a long-lived
    // grandchild that INHERITS our stdio (default `Command` stdio), mimicking an
    // inner plugin (galoshes→ex-ray) that, if orphaned, holds the host's
    // stdout/stderr pipe. The grandchild dials <callback_addr> on startup and
    // holds the connection, so a test can verify a force-kill of the chain reaps
    // the whole process tree via the connection's liveness/EOF (reuse-immune, no
    // PID poll). The grandchild gets MOCK_PLUGIN_SLEEP (so it short-circuits) plus
    // the callback addr, and NOT this knob (so it does not recurse). std `Child`
    // is not kill-on-drop, so letting it drop leaves the process running for the
    // test.
    if let Some(callback_addr) = std::env::var_os("MOCK_PLUGIN_SPAWN_GRANDCHILD") {
        let exe = std::env::current_exe()?;
        let mut cmd = std::process::Command::new(exe);
        cmd.env("MOCK_PLUGIN_SLEEP", "1")
            .env("MOCK_PLUGIN_GRANDCHILD_CALLBACK", &callback_addr)
            .env_remove("MOCK_PLUGIN_SPAWN_GRANDCHILD");
        // Mimic how garter spawns a NESTED plugin (galoshes→ex-ray) so this
        // grandchild is reaped only by the root's process-tree kill, never by the
        // parent's graceful stop:
        //  - Windows: give it its OWN console group (CREATE_NEW_PROCESS_GROUP,
        //    exactly as garter spawns every plugin) so graceful_stop's CTRL_BREAK
        //    to the parent's group can't reach it; it still joins the root's job
        //    object by handle inheritance and is reaped that way.
        //  - Unix: do NOT setpgid — inherit the parent's process group like a
        //    nested ex-ray, so the root's kill(-pgid) reaps it. graceful_stop's
        //    SIGTERM is PID-targeted, so it can't reach the grandchild anyway.
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
            cmd.creation_flags(CREATE_NEW_PROCESS_GROUP);
        }
        let _grandchild = cmd.spawn()?;
    }

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

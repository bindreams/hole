//! The `--scan-sid` mode: which processes carry a service's SID in their token,
//! and what this caller could not read on the way.
//!
//! The same `ServiceSid::is_in_token_of` check the uninstaller's hold runs, over
//! every process, so a test reads off what an elevated administrator and
//! LocalSystem can open and read. Every failure is printed with its Win32 code,
//! the kind the production code classifies it as, and what each `Basis` table
//! row does about it, so the per-failure table is read off a run (probe P5).

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::path::PathBuf;

use hole_bridge::cutover::scm_wait::call_error::{ScmCall, ScmCallError};
use hole_bridge::cutover::scm_wait::hold::{Basis, ProbeFailure};
use hole_bridge::cutover::scm_wait::ReportedPid;
use hole_bridge::platform::os::{scan_service_processes, ServiceSid};
use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL, WAIT_OBJECT_0};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SYNCHRONIZE,
};

/// `<service> <out-file> [done-event]`. Writes the measurement (or the panic
/// that ended it) to `<out-file>`, then signals `done-event`.
pub fn run(mut args: impl Iterator<Item = OsString>) {
    let service = args
        .next()
        .expect("--scan-sid takes a service name")
        .into_string()
        .expect("service name is UTF-8");
    let out = PathBuf::from(args.next().expect("--scan-sid takes an output file"));
    let done = args.next().map(|name| name.into_string().expect("event name is UTF-8"));

    let report = std::panic::catch_unwind(|| measure(&service)).unwrap_or_else(|panic| {
        let cause = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic.downcast_ref::<&str>().copied())
            .unwrap_or("not a string");
        format!("scan panicked: {cause}\n")
    });
    let written = std::fs::write(&out, report);
    if let Some(done) = done {
        super::signal(&done);
    }
    written.expect("write the scan report");
}

/// One `key: value` line per fact. `matches` is the line a test parses.
fn measure(service: &str) -> String {
    let mut report = String::new();
    writeln!(report, "caller: {}", caller_sid()).unwrap();
    let sid = ServiceSid::of(service);
    writeln!(report, "service SID: {sid}").unwrap();
    // The OS answers only while the service is registered and not marked for
    // deletion; printed to cross-check the derivation (P4), never used.
    match ServiceSid::os_lookup(service) {
        Ok(from_os) => writeln!(
            report,
            "OS lookup (P4 cross-check): {from_os}; equals the derived: {}",
            from_os == sid
        ),
        Err(e) => writeln!(report, "OS lookup (P4 cross-check): Err {e}"),
    }
    .unwrap();

    let (mut total, mut opened, mut absent) = (0usize, 0usize, 0usize);
    // Keyed by the call, the code and the kind and rows the production table gives it.
    let mut open_refused: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut token_unreadable: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut matches = Vec::new();
    for (pid, exe) in processes() {
        total += 1;
        let who = format!("{pid}:{exe}");
        // SAFETY: plain FFI call.
        let process = match unsafe { OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
        {
            // SAFETY: `OpenProcess` returned a new handle this value now owns.
            Ok(handle) => unsafe { OwnedHandle::from_raw_handle(handle.0) },
            Err(e) => {
                let code = (e.code().0 as u32) & 0xFFFF;
                let failed = ScmCallError {
                    call: ScmCall::OpenProcess,
                    code,
                }
                .into_io_unlogged();
                open_refused
                    .entry(format!("{e}; {}", classified(&failed)))
                    .or_default()
                    .push(who);
                continue;
            }
        };
        opened += 1;
        match sid.is_in_token_of(&process) {
            Ok(true) => matches.push(who),
            Ok(false) => absent += 1,
            Err(e) => {
                let gone = if exited(&process) {
                    "; the process has exited"
                } else {
                    ""
                };
                token_unreadable
                    .entry(format!("{e}; {}{gone}", classified(&e)))
                    .or_default()
                    .push(who);
            }
        }
    }

    writeln!(
        report,
        "processes: {total}; opened: {opened}; token read, SID absent: {absent}"
    )
    .unwrap();
    for (cause, who) in &open_refused {
        writeln!(report, "open refused ({cause}) x{}: {}", who.len(), who.join(", ")).unwrap();
    }
    for (cause, who) in &token_unreadable {
        writeln!(report, "token unreadable ({cause}) x{}: {}", who.len(), who.join(", ")).unwrap();
    }
    match scan_service_processes(&sid) {
        Ok(found) => {
            let alive: Vec<u32> = found.alive.iter().map(|(pid, _)| *pid).collect();
            writeln!(report, "production scan, alive: {alive:?}").unwrap();
            writeln!(report, "production scan, undetermined: {:?}", found.undetermined).unwrap();
        }
        Err(e) => writeln!(report, "production scan failed: {e}").unwrap(),
    }
    let ids: Vec<&str> = matches.iter().filter_map(|who| who.split(':').next()).collect();
    writeln!(
        report,
        "matches: {}",
        if ids.is_empty() { "none".into() } else { ids.join(",") }
    )
    .unwrap();
    writeln!(report, "matching processes: {}", matches.join(", ")).unwrap();
    report
}

/// How the production code classifies `failed` and what each table row does
/// with it: `kind=...; scanned=...; named-valid=...; named-may-be-invalid=...`.
fn classified(failed: &std::io::Error) -> String {
    let kind = ProbeFailure::of_error(failed);
    let code = failed
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<ScmCallError>())
        .map(|typed| format!("{} win32={}", typed.call.name(), typed.code))
        .unwrap_or_default();
    format!(
        "{code}; kind={kind:?}; scanned={:?}; named-valid={:?}; named-may-be-invalid={:?}",
        Basis::Scanned.verdict(kind),
        Basis::Named(ReportedPid::Valid).verdict(kind),
        Basis::Named(ReportedPid::MayBeInvalid).verdict(kind),
    )
}

/// Whether `process` has exited (a zero-timeout wait).
fn exited(process: &OwnedHandle) -> bool {
    // SAFETY: `process` is a live handle this function only reads the state of.
    let waited = unsafe { WaitForSingleObject(HANDLE(std::os::windows::io::AsRawHandle::as_raw_handle(process)), 0) };
    waited == WAIT_OBJECT_0
}

/// Every process the snapshot lists, as (id, image name).
fn processes() -> Vec<(u32, String)> {
    // SAFETY: plain FFI call.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.expect("snapshot the processes");
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut found = Vec::new();
    // SAFETY: `snapshot` is the live handle just returned, and `entry` is a
    // `PROCESSENTRY32W` with its size set, as both calls require.
    let mut more = unsafe { Process32FirstW(snapshot, &mut entry) }.is_ok();
    while more {
        let name = &entry.szExeFile;
        let len = name.iter().position(|unit| *unit == 0).unwrap_or(name.len());
        found.push((entry.th32ProcessID, String::from_utf16_lossy(&name[..len])));
        // SAFETY: as above.
        more = unsafe { Process32NextW(snapshot, &mut entry) }.is_ok();
    }
    // SAFETY: `snapshot` is the live handle returned above.
    let _ = unsafe { CloseHandle(snapshot) };
    found
}

/// The user SID of this process's token, as a string, or the step that failed.
fn caller_sid() -> String {
    let mut token = HANDLE::default();
    // SAFETY: plain FFI call on this process's own pseudo-handle.
    if let Err(e) = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } {
        return format!("OpenProcessToken failed: {e}");
    }
    // SAFETY: `OpenProcessToken` returned a new handle this value now owns.
    let token = unsafe { OwnedHandle::from_raw_handle(token.0) };
    let token = HANDLE(std::os::windows::io::AsRawHandle::as_raw_handle(&token));
    let mut len = 0u32;
    // SAFETY: the sizing call; its expected failure is ignored.
    let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut len) };
    // `u64`s: `TOKEN_USER` has pointer alignment.
    let mut buf = vec![0u64; (len as usize).div_ceil(8).max(1)];
    // SAFETY: `buf` holds at least `len` bytes, the size reported above.
    if let Err(e) = unsafe { GetTokenInformation(token, TokenUser, Some(buf.as_mut_ptr().cast()), len, &mut len) } {
        return format!("GetTokenInformation failed: {e}");
    }
    // SAFETY: on success `buf` holds a `TOKEN_USER`.
    let user = unsafe { &*buf.as_ptr().cast::<TOKEN_USER>() };
    let mut raw = PWSTR::null();
    // SAFETY: the user's SID is valid inside `buf`; `raw` is freed below.
    if let Err(e) = unsafe { ConvertSidToStringSidW(user.User.Sid, &mut raw) } {
        return format!("ConvertSidToStringSidW failed: {e}");
    }
    // SAFETY: `raw` is a NUL-terminated string owned until `LocalFree`.
    let text = unsafe { raw.to_string() }.unwrap_or_default();
    // SAFETY: `raw` came from `LocalAlloc` inside the conversion.
    let _ = unsafe { LocalFree(Some(HLOCAL(raw.0.cast()))) };
    text
}

//! The `--scan-sid` mode: which processes carry a service's SID in their token,
//! and what this caller could not read on the way.
//!
//! The same `ServiceSid::is_in_token_of` check the uninstaller's hold runs, over
//! every process, so a test reads off what an elevated administrator and
//! LocalSystem can open and read.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::path::PathBuf;

use hole_bridge::platform::os::ServiceSid;
use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
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
    let sid = match ServiceSid::of(service) {
        Ok(sid) => {
            writeln!(report, "service SID lookup: Ok").unwrap();
            Some(sid)
        }
        Err(e) => {
            writeln!(report, "service SID lookup: Err {e}").unwrap();
            None
        }
    };

    let (mut total, mut opened, mut absent) = (0usize, 0usize, 0usize);
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
                open_refused.entry(e.to_string()).or_default().push(who);
                continue;
            }
        };
        opened += 1;
        let Some(sid) = &sid else { continue };
        match sid.is_in_token_of(&process) {
            Ok(true) => matches.push(who),
            Ok(false) => absent += 1,
            Err(e) => token_unreadable.entry(e.to_string()).or_default().push(who),
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

//! Windows handle-holder enumeration via `NtQuerySystemInformation`.
//!
//! # Algorithm
//!
//! First, open the target file ourselves (`CreateFileW` with
//! `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE` so we
//! coexist with AV scanners) and resolve its kernel path via
//! `GetFinalPathNameByHandleW(VOLUME_NAME_NT)` — e.g.
//! `\Device\HarddiskVolume3\...\hole.exe`. This is the single canonical
//! namespace we compare against.
//!
//! Next, call `NtQuerySystemInformation(SystemExtendedHandleInformation)`
//! to dump every kernel handle. Find our own entry to discover the File
//! object type index (stable within a boot).
//!
//! Group candidate handles by owning PID. For each PID, try
//! `OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION)`,
//! then `DuplicateHandle`, then `NtQueryObject(ObjectNameInformation)`
//! on each of its File handles until we match the target or the per-PID
//! budget expires. `NtQueryObject` can block on certain handle types
//! (named pipes, remote files) — we wrap it in a worker thread with a
//! 100 ms timeout, the same pattern Process Explorer uses. A blocked
//! worker is orphaned rather than joined.
//!
//! When `OpenProcess(DUP_HANDLE)` is denied (non-admin session, PPL
//! processes like Defender's MsMpEng.exe, System PID 4) we don't list
//! the PID: without handle-level access we can't distinguish "holds
//! *our* file" from "holds *some* file". Instead, we log an aggregate
//! count of skipped PIDs at `info!`. Callers that specifically want
//! Defender coverage can elevate with `SeDebugPrivilege` and enumerate
//! in a follow-up call.
//!
//! # Dependency choice
//!
//! The structures `SYSTEM_HANDLE_INFORMATION_EX` /
//! `SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX` and the constant
//! `SystemExtendedHandleInformation = 64` are not exposed by the
//! `windows` crate. Rather than pull in `ntapi` + its transitive
//! `winapi` dep (which would force `HANDLE`-type conversions at every
//! call site), we define the structs locally — same approach
//! `plugin_recovery.rs` takes elsewhere in this crate.
//!
//! # Caveats (documented rather than mitigated)
//!
//! - **PID reuse race**: the handle table is a snapshot, but a PID
//!   could be recycled between snapshot and `OpenProcess`. Rare on
//!   x64 and this is a best-effort diagnostic.
//! - **Elevation**: on a non-admin runner,
//!   `PROCESS_QUERY_LIMITED_INFORMATION` against PPL processes like
//!   MsMpEng.exe fails → we report `{image: None, verified: false}`.
//!   Windows GitHub Actions runners run as Administrator, so this is
//!   fine in CI.

#![allow(clippy::missing_safety_doc)]

use super::FileHolder;
use std::collections::HashMap;
use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use windows::core::{PCWSTR, PWSTR};
use windows::Wdk::Foundation::{NtQueryObject, OBJECT_INFORMATION_CLASS};
use windows::Wdk::System::SystemInformation::{NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS};
use windows::Win32::Foundation::{CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE, NTSTATUS};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, GetFinalPathNameByHandleW, FILE_FLAGS_AND_ATTRIBUTES, FILE_GENERIC_READ, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, VOLUME_NAME_NT,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, QueryFullProcessImageNameW, PROCESS_DUP_HANDLE, PROCESS_NAME_FORMAT,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

// ===== Local struct + const definitions ==============================================================================
//
// These are not in the `windows` crate's public surface. Taken from
// System Informer's `phnt` headers (the canonical undocumented-API
// reference used by Sysinternals).

/// `SystemExtendedHandleInformation` information class for
/// `NtQuerySystemInformation`.
const SYSTEM_EXTENDED_HANDLE_INFORMATION: SYSTEM_INFORMATION_CLASS = SYSTEM_INFORMATION_CLASS(64);

/// `ObjectNameInformation` class for `NtQueryObject`.
const OBJECT_NAME_INFORMATION: OBJECT_INFORMATION_CLASS = OBJECT_INFORMATION_CLASS(1);

/// Return status "buffer too small — try again with a larger one."
const STATUS_INFO_LENGTH_MISMATCH: NTSTATUS = NTSTATUS(0xC0000004u32 as i32);

/// Total budget for one `find_holders` call.
const OVERALL_BUDGET: Duration = Duration::from_secs(3);
/// Budget per PID (across all its File handles).
const PER_PID_BUDGET: Duration = Duration::from_millis(100);
/// Timeout for a single `NtQueryObject(ObjectNameInformation)` call —
/// may block indefinitely on named pipes / remote files.
const NAME_QUERY_TIMEOUT: Duration = Duration::from_millis(100);

#[repr(C)]
#[derive(Clone, Copy)]
struct SystemHandleTableEntryInfoEx {
    object: *mut c_void,
    unique_process_id: usize,
    handle_value: usize,
    granted_access: u32,
    creator_back_trace_index: u16,
    object_type_index: u16,
    handle_attributes: u32,
    reserved: u32,
}

/// UNICODE_STRING mirror. `NtQueryObject(ObjectNameInformation)`
/// writes one at the start of its output buffer; the `buffer` pointer
/// points back into that same allocation.
#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

/// RAII wrapper that calls `CloseHandle` on drop.
struct Handle(HANDLE);

impl Handle {
    fn get(&self) -> HANDLE {
        self.0
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

fn encode_wide(p: &Path) -> Vec<u16> {
    p.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}

/// Open the target file for read-attributes with shared access. Must
/// coexist with AV scanners that have the file open for read.
fn open_target(path: &Path) -> io::Result<Handle> {
    let wide = encode_wide(path);
    let h = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_GENERIC_READ.0, // includes FILE_READ_ATTRIBUTES
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
    }
    .map_err(|e| io::Error::other(format!("CreateFileW failed: {e}")))?;
    Ok(Handle(h))
}

/// Resolve our own file handle to an NT-namespace kernel path via
/// `GetFinalPathNameByHandleW(VOLUME_NAME_NT)`.
fn nt_path_of_handle(h: HANDLE) -> io::Result<String> {
    let mut buf = vec![0u16; 1024];
    loop {
        let len = unsafe { GetFinalPathNameByHandleW(h, &mut buf, VOLUME_NAME_NT) };
        if len == 0 {
            return Err(io::Error::last_os_error());
        }
        if (len as usize) < buf.len() {
            let nt = String::from_utf16_lossy(&buf[..len as usize]);
            return Ok(nt);
        }
        buf.resize(len as usize + 1, 0);
    }
}

/// Call `NtQuerySystemInformation(SystemExtendedHandleInformation)`
/// with a growing buffer until it fits. Returns the raw bytes.
fn query_extended_handle_information() -> io::Result<Vec<u8>> {
    let mut cap = 1 << 20; // 1 MiB
    let cap_limit = 256usize << 20; // 256 MiB
    loop {
        let mut buf = vec![0u8; cap];
        let mut ret_len: u32 = 0;
        let status = unsafe {
            NtQuerySystemInformation(
                SYSTEM_EXTENDED_HANDLE_INFORMATION,
                buf.as_mut_ptr() as *mut _,
                cap as u32,
                &mut ret_len,
            )
        };
        if status.is_ok() {
            buf.truncate(ret_len as usize);
            return Ok(buf);
        }
        if status == STATUS_INFO_LENGTH_MISMATCH {
            let next = cap.saturating_mul(2);
            if next > cap_limit {
                tracing::warn!("handle table exceeds 256 MiB; returning partial results");
                buf.truncate(ret_len as usize);
                return Ok(buf);
            }
            cap = next;
            continue;
        }
        return Err(io::Error::other(format!(
            "NtQuerySystemInformation failed: status {:#x}",
            status.0 as u32,
        )));
    }
}

/// View the raw buffer returned by
/// `NtQuerySystemInformation(SystemExtendedHandleInformation)` as a
/// slice of `SystemHandleTableEntryInfoEx` entries. Layout is:
/// `[usize NumberOfHandles][usize Reserved][entries...]`.
fn parse_handle_entries(buf: &[u8]) -> &[SystemHandleTableEntryInfoEx] {
    if buf.len() < 2 * std::mem::size_of::<usize>() {
        return &[];
    }
    let num = unsafe { *(buf.as_ptr() as *const usize) };
    let entries_ptr = unsafe {
        buf.as_ptr()
            .add(2 * std::mem::size_of::<usize>())
            .cast::<SystemHandleTableEntryInfoEx>()
    };
    let entry_size = std::mem::size_of::<SystemHandleTableEntryInfoEx>();
    let available = (buf.len() - 2 * std::mem::size_of::<usize>()) / entry_size;
    let count = num.min(available);
    unsafe { std::slice::from_raw_parts(entries_ptr, count) }
}

/// Run `NtQueryObject(ObjectNameInformation)` on a worker thread with
/// a hard timeout. Returns `None` if the query fails, the handle is
/// unnamed, or the worker exceeds `NAME_QUERY_TIMEOUT`. A blocked
/// worker is abandoned (never joined); this is the standard Process
/// Explorer pattern.
fn query_name_with_timeout(h: HANDLE) -> Option<String> {
    let (tx, rx) = mpsc::channel::<Option<String>>();
    let handle_bits = h.0 as isize;
    std::thread::spawn(move || {
        // Reconstruct HANDLE inside the thread — raw pointers aren't Send.
        let h = HANDLE(handle_bits as *mut c_void);
        let _ = tx.send(nt_path_of_dup_handle(h));
    });
    // On recv timeout the worker is abandoned and returns None.
    rx.recv_timeout(NAME_QUERY_TIMEOUT).unwrap_or_default()
}

/// Synchronous (may block) inner name query. Callers should invoke
/// this only from a worker thread with a timeout.
fn nt_path_of_dup_handle(h: HANDLE) -> Option<String> {
    let mut buf = vec![0u8; 2048];
    loop {
        let mut ret_len: u32 = 0;
        let status = unsafe {
            NtQueryObject(
                Some(h),
                OBJECT_NAME_INFORMATION,
                Some(buf.as_mut_ptr() as *mut _),
                buf.len() as u32,
                Some(&mut ret_len),
            )
        };
        if status.is_ok() {
            if buf.len() < std::mem::size_of::<UnicodeString>() {
                return None;
            }
            let us = unsafe { &*(buf.as_ptr() as *const UnicodeString) };
            if us.length == 0 || us.buffer.is_null() {
                return None;
            }
            let count = (us.length as usize) / 2;
            let slice = unsafe { std::slice::from_raw_parts(us.buffer, count) };
            return Some(String::from_utf16_lossy(slice));
        }
        if status == STATUS_INFO_LENGTH_MISMATCH && (ret_len as usize) > buf.len() {
            buf.resize(ret_len as usize, 0);
            continue;
        }
        return None;
    }
}

/// Fetch the executable path for `pid` via
/// `QueryFullProcessImageNameW`. Requires only
/// `PROCESS_QUERY_LIMITED_INFORMATION`, which usually works even for
/// PPL processes as long as we're running elevated.
fn process_image(pid: u32) -> Option<PathBuf> {
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let h = Handle(h);
    let mut buf = vec![0u16; 1024];
    let mut size = buf.len() as u32;
    let ok = unsafe { QueryFullProcessImageNameW(h.get(), PROCESS_NAME_FORMAT(0), PWSTR(buf.as_mut_ptr()), &mut size) };
    if ok.is_err() {
        return None;
    }
    Some(PathBuf::from(String::from_utf16_lossy(&buf[..size as usize])))
}

pub(super) fn find_holders_impl(path: &Path) -> io::Result<Vec<FileHolder>> {
    let target = open_target(path)?;
    let target_nt = nt_path_of_handle(target.get())?;

    let buf = query_extended_handle_information()?;
    let entries = parse_handle_entries(&buf);
    let me = std::process::id() as usize;

    // Step 1: find our own handle entry to learn the File object type index.
    let file_type_index: Option<u16> = entries.iter().find_map(|e| {
        (e.unique_process_id == me && e.handle_value == target.get().0 as usize).then_some(e.object_type_index)
    });

    let Some(file_type_index) = file_type_index else {
        tracing::warn!("could not locate own target handle in system handle table");
        return Ok(Vec::new());
    };

    // Step 2: group candidate entries by PID (excluding self).
    let mut by_pid: HashMap<u32, Vec<&SystemHandleTableEntryInfoEx>> = HashMap::new();
    for entry in entries {
        if entry.object_type_index != file_type_index {
            continue;
        }
        let pid = entry.unique_process_id as u32;
        if pid == me as u32 {
            continue;
        }
        by_pid.entry(pid).or_default().push(entry);
    }

    let current_process = unsafe { GetCurrentProcess() };
    let target_nt_lc = target_nt.to_ascii_lowercase();
    let overall_deadline = Instant::now() + OVERALL_BUDGET;

    let mut holders: Vec<FileHolder> = Vec::new();
    let mut inaccessible_pids = 0u32;

    for (pid, pid_entries) in by_pid {
        if Instant::now() >= overall_deadline {
            tracing::warn!(
                holders_so_far = holders.len(),
                "file-lock holder enumeration hit {OVERALL_BUDGET:?} budget; returning partial results",
            );
            break;
        }

        // Verified path: DUP_HANDLE + NtQueryObject(Name) comparison.
        let Ok(src) = (unsafe { OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, false, pid) })
        else {
            // Protected process or privilege lacking. We deliberately
            // do NOT list this PID as a "suspect" holder: the handle
            // table says it holds *some* file, but we have no evidence
            // it holds *this* file, so reporting it would be noise
            // (dozens of false positives on non-admin sessions). Count
            // it so the caller knows coverage wasn't complete.
            inaccessible_pids += 1;
            continue;
        };
        let src = Handle(src);
        let pid_deadline = Instant::now() + PER_PID_BUDGET;
        let mut matched = false;
        for entry in &pid_entries {
            if Instant::now() >= pid_deadline {
                break;
            }
            let mut dup: HANDLE = HANDLE::default();
            let dup_ok = unsafe {
                DuplicateHandle(
                    src.get(),
                    HANDLE(entry.handle_value as *mut _),
                    current_process,
                    &mut dup,
                    0,
                    false,
                    DUPLICATE_SAME_ACCESS,
                )
            }
            .is_ok();
            if !dup_ok {
                continue;
            }
            let dup = Handle(dup);
            if let Some(name) = query_name_with_timeout(dup.get()) {
                if name.to_ascii_lowercase() == target_nt_lc {
                    holders.push(FileHolder {
                        pid,
                        image: process_image(pid),
                        verified: true,
                    });
                    matched = true;
                    break;
                }
            }
        }
        let _ = matched;
    }

    if inaccessible_pids > 0 {
        tracing::info!(
            count = inaccessible_pids,
            "file-lock holder enumeration skipped PIDs we couldn't open (likely PPL processes like MsMpEng.exe or processes in other sessions); rerun elevated with SeDebugPrivilege for wider coverage",
        );
    }

    Ok(holders)
}

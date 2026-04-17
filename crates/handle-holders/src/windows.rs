//! Windows handle-holder enumeration via `NtQuerySystemInformation`.
//!
//! # Algorithm
//!
//! First, open the target file ourselves (`CreateFileW` with
//! `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE` so we
//! coexist with AV scanners) and read its
//! `BY_HANDLE_FILE_INFORMATION` via `GetFileInformationByHandle` —
//! the `(VolumeSerialNumber, nFileIndexHigh:nFileIndexLow)` tuple
//! uniquely identifies the file and is stable across different
//! `CreateFile` calls to the same file. This dodges the path-form
//! hazards of `GetFinalPathNameByHandleW` (normalization) vs
//! `NtQueryObject(Name)` (as-opened form) disagreeing when short
//! `BINDRE~1`-style names are in play.
//!
//! Next, call `NtQuerySystemInformation(SystemExtendedHandleInformation)`
//! to dump every kernel handle. Find our own entry to discover the File
//! object type index (stable within a boot).
//!
//! Group candidate handles by owning PID. For each PID, try
//! `OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION)`,
//! then `DuplicateHandle`, then — before the potentially blocking
//! `GetFileInformationByHandle` — a non-blocking `GetFileType` check
//! to weed out pipes / consoles / char devices that share the `File`
//! object-type with real disk files. Only `FILE_TYPE_DISK` handles
//! reach the file-id comparison. An earlier iteration ran the
//! file-id query on a worker thread with a timeout (Process Explorer
//! pattern), but leaked worker threads trigger a Rust runtime abort
//! ("operation failed to complete synchronously, aborting") on
//! Windows CI. The `GetFileType` pre-filter makes the inline call
//! safe; the per-PID and overall deadlines below cap worst-case time
//! on legitimate-but-slow disk handles (e.g. remote SMB).
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
//! call site), we define the structs locally.
//!
//! # Caveats (documented rather than mitigated)
//!
//! - **PID reuse race**: the handle table is a snapshot, but a PID
//!   could be recycled between snapshot and `OpenProcess`. Rare on
//!   x64 and this is a best-effort diagnostic.
//! - **Elevation**: on a non-admin runner,
//!   `PROCESS_QUERY_LIMITED_INFORMATION` against PPL processes like
//!   MsMpEng.exe fails → we skip that PID. Windows GitHub Actions
//!   runners run as Administrator, so this is fine in CI.

#![allow(clippy::missing_safety_doc)]

use super::FileHolder;
use std::collections::HashMap;
use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use windows::core::{PCWSTR, PWSTR};
use windows::Wdk::System::SystemInformation::{NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS};
use windows::Win32::Foundation::{CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE, NTSTATUS};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, GetFileInformationByHandle, GetFileType, BY_HANDLE_FILE_INFORMATION, FILE_FLAGS_AND_ATTRIBUTES,
    FILE_GENERIC_READ, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_DISK, OPEN_EXISTING,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, QueryFullProcessImageNameW, PROCESS_DUP_HANDLE, PROCESS_NAME_FORMAT,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

// Local struct + const definitions ====================================================================================
//
// These are not in the `windows` crate's public surface. Taken from
// System Informer's `phnt` headers (the canonical undocumented-API
// reference used by Sysinternals).

/// `SystemExtendedHandleInformation` information class for
/// `NtQuerySystemInformation`.
const SYSTEM_EXTENDED_HANDLE_INFORMATION: SYSTEM_INFORMATION_CLASS = SYSTEM_INFORMATION_CLASS(64);

/// Return status "buffer too small — try again with a larger one."
const STATUS_INFO_LENGTH_MISMATCH: NTSTATUS = NTSTATUS(0xC0000004u32 as i32);

/// Total budget for one `find_holders` call.
const OVERALL_BUDGET: Duration = Duration::from_secs(3);
/// Budget per PID (across all its File handles).
const PER_PID_BUDGET: Duration = Duration::from_millis(100);

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

/// Stable identifier for a file: `(VolumeSerialNumber, FileIndex)`.
/// All handles to the same file return the same tuple regardless of
/// which path form they were opened with (long vs 8.3 short name).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileId {
    volume: u32,
    index: u64,
}

fn file_id_of_handle(h: HANDLE) -> Option<FileId> {
    // `GetFileInformationByHandle` can block indefinitely on non-disk
    // handles (named pipes, serial ports, console devices). The kernel
    // lumps all of those under the same `File` object-type as disk
    // files, so type-index filtering alone doesn't exclude them. `GetFileType`
    // is a pure kernel-attribute lookup and returns in O(1); skip
    // anything that isn't `FILE_TYPE_DISK`.
    if unsafe { GetFileType(h) } != FILE_TYPE_DISK {
        return None;
    }
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(h, &mut info) }.ok()?;
    Some(FileId {
        volume: info.dwVolumeSerialNumber,
        index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    })
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
                // `ret_len` on failure is advisory; the buffer contents
                // are undefined. Return empty rather than propagate
                // zeroed bytes as if they were a valid handle table.
                tracing::warn!("handle table exceeds 256 MiB; returning no holders (enumeration skipped)");
                return Ok(Vec::new());
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

/// Parse the raw buffer returned by
/// `NtQuerySystemInformation(SystemExtendedHandleInformation)` into
/// owned entries via `read_unaligned`.
///
/// Layout: `[usize NumberOfHandles][usize Reserved][entries...]`.
/// Windows' `HeapAlloc`-backed `Vec<u8>` is in practice 16-byte
/// aligned, but the Rust type system doesn't guarantee that — using
/// unaligned reads sidesteps any UB risk.
fn parse_handle_entries(buf: &[u8]) -> Vec<SystemHandleTableEntryInfoEx> {
    let header_size = 2 * std::mem::size_of::<usize>();
    if buf.len() < header_size {
        return Vec::new();
    }
    let num = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const usize) };
    let entry_size = std::mem::size_of::<SystemHandleTableEntryInfoEx>();
    let available = (buf.len() - header_size) / entry_size;
    let count = num.min(available);
    let mut out = Vec::with_capacity(count);
    let base = unsafe { buf.as_ptr().add(header_size) };
    for i in 0..count {
        let entry =
            unsafe { std::ptr::read_unaligned(base.add(i * entry_size) as *const SystemHandleTableEntryInfoEx) };
        out.push(entry);
    }
    out
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
    let target_id = file_id_of_handle(target.get())
        .ok_or_else(|| io::Error::other("GetFileInformationByHandle failed on target"))?;

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
    let mut by_pid: HashMap<u32, Vec<SystemHandleTableEntryInfoEx>> = HashMap::new();
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

        // Verified path: DUP_HANDLE + GetFileInformationByHandle comparison.
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
            if let Some(id) = file_id_of_handle(dup.get()) {
                if id == target_id {
                    holders.push(FileHolder {
                        pid,
                        image: process_image(pid),
                    });
                    break;
                }
            }
        }
    }

    if inaccessible_pids > 0 {
        tracing::info!(
            count = inaccessible_pids,
            "file-lock holder enumeration skipped PIDs we couldn't open (likely PPL processes like MsMpEng.exe or processes in other sessions); rerun elevated with SeDebugPrivilege for wider coverage",
        );
    }

    Ok(holders)
}

//! What the process list shows about a SYSTEM process that has just exited,
//! read as a standard user: the question behind `Stamp::is_running`'s fallback
//! for a process it may not open (`disable_record::stamp`).
//!
//! The list is read with `SystemExtendedProcessInformation`, which carries each
//! thread's state and wait reason beside the entry's thread count, and the
//! table is printed: the measurement is what decides whether the list can tell
//! an exited process from a running one.

use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use hole_bridge::cutover::os::windows::WindowsCutoverOs;
use hole_bridge::cutover::os::CutoverOs;
use hole_bridge::disable_record::Stamp;
use hole_bridge::platform::os::SERVICE_NAME;
use windows::Wdk::System::SystemInformation::{NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS};
use windows::Win32::Foundation::STATUS_INFO_LENGTH_MISMATCH;
use windows::Win32::System::WindowsProgramming::SYSTEM_PROCESS_INFORMATION;

use super::start_type_lock_proofs::as_a_standard_user;
use super::{scm_probe, ProvisionedService, GLOBAL_NET_STATE, TUN};

fn helper() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_test_service"))
}

fn os_actor() -> WindowsCutoverOs {
    WindowsCutoverOs {
        images: vec![],
        target_version: "test".into(),
    }
}

/// `SystemExtendedProcessInformation`.
const SYSTEM_EXTENDED_PROCESS_INFORMATION_CLASS: SYSTEM_INFORMATION_CLASS = SYSTEM_INFORMATION_CLASS(57);

/// `SYSTEM_PROCESS_INFORMATION` is `0x100` bytes on a 64-bit Windows and its
/// thread records follow it.
const PROCESS_HEADER_SIZE: usize = 0x100;
/// `SYSTEM_EXTENDED_THREAD_INFORMATION`: the 0x50-byte `SYSTEM_THREAD_INFORMATION`
/// and seven pointer-sized fields.
const THREAD_RECORD_SIZE: usize = 0x88;
/// Offsets into a thread record: `ClientId.UniqueProcess`, `ThreadState`, `WaitReason`.
const THREAD_PID_AT: usize = 40;
const THREAD_STATE_AT: usize = 68;
const THREAD_WAIT_REASON_AT: usize = 72;

/// One thread of a listed process.
struct ThreadRow {
    state: u32,
    wait_reason: u32,
}

/// One process-list entry, with its threads.
struct ListedProcess {
    threads: u32,
    handles: u32,
    rows: Vec<ThreadRow>,
}

/// `KTHREAD_STATE`.
fn state_name(state: u32) -> &'static str {
    match state {
        0 => "Initialized",
        1 => "Ready",
        2 => "Running",
        3 => "Standby",
        4 => "Terminated",
        5 => "Waiting",
        6 => "Transition",
        7 => "DeferredReady",
        8 => "GateWaitObsolete",
        9 => "WaitingForProcessInSwap",
        _ => "another state",
    }
}

impl ListedProcess {
    /// The threads as `count x state/wait-reason`, grouped: the System process has hundreds.
    fn describe(&self) -> String {
        let mut groups = BTreeMap::new();
        for row in &self.rows {
            *groups.entry((row.state, row.wait_reason)).or_insert(0usize) += 1;
        }
        let groups: Vec<String> = groups
            .iter()
            .map(|((state, wait_reason), count)| format!("{count} x {}/wait-reason {wait_reason}", state_name(*state)))
            .collect();
        format!(
            "NumberOfThreads {}, HandleCount {}, threads [{}]",
            self.threads,
            self.handles,
            groups.join(", ")
        )
    }
}

fn describe(entry: &Option<ListedProcess>) -> String {
    entry
        .as_ref()
        .map_or_else(|| "not listed".to_owned(), ListedProcess::describe)
}

fn read_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four bytes"))
}

fn read_u64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("eight bytes"))
}

/// The extended process list, read into a buffer grown until it fits.
fn extended_process_list() -> io::Result<Vec<u8>> {
    let mut capacity = 1usize << 21;
    loop {
        let mut buffer = vec![0u8; capacity];
        let mut returned = 0u32;
        // SAFETY: the buffer is `capacity` writable bytes.
        let status = unsafe {
            NtQuerySystemInformation(
                SYSTEM_EXTENDED_PROCESS_INFORMATION_CLASS,
                buffer.as_mut_ptr().cast(),
                capacity as u32,
                &mut returned,
            )
        };
        if status.is_ok() {
            buffer.truncate(returned as usize);
            return Ok(buffer);
        }
        if status == STATUS_INFO_LENGTH_MISMATCH {
            capacity = capacity.saturating_mul(2);
            continue;
        }
        return Err(io::Error::other(format!(
            "the extended process list could not be read: status {:#x}",
            status.0 as u32
        )));
    }
}

/// The list's entry for `pid`, if it has one. Panics if a thread record does
/// not name `pid` as its process: the layout above is then wrong.
fn listed(pid: u32) -> Option<ListedProcess> {
    assert_eq!(
        std::mem::size_of::<SYSTEM_PROCESS_INFORMATION>(),
        PROCESS_HEADER_SIZE,
        "the process entry's size"
    );
    let list = extended_process_list().expect("the extended process list");
    let mut offset = 0usize;
    loop {
        let bytes = &list[offset..];
        // SAFETY: a full header is in the buffer at `offset`; plain data, read unaligned.
        let info: SYSTEM_PROCESS_INFORMATION = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast()) };
        if info.UniqueProcessId.0 as usize as u32 == pid {
            let rows = (0..info.NumberOfThreads as usize)
                .map(|i| {
                    let thread = &bytes[PROCESS_HEADER_SIZE + i * THREAD_RECORD_SIZE..];
                    assert_eq!(
                        read_u64(thread, THREAD_PID_AT),
                        u64::from(pid),
                        "thread {i} of {pid} names another process: the thread record layout is wrong"
                    );
                    ThreadRow {
                        state: read_u32(thread, THREAD_STATE_AT),
                        wait_reason: read_u32(thread, THREAD_WAIT_REASON_AT),
                    }
                })
                .collect();
            return Some(ListedProcess {
                threads: info.NumberOfThreads,
                handles: info.HandleCount,
                rows,
            });
        }
        if info.NextEntryOffset == 0 {
            return None;
        }
        offset += info.NextEntryOffset as usize;
    }
}

/// Measures, as a standard user, the process list's entry for a SYSTEM process
/// (a) while it runs, (b) at the first read after it has exited, with an
/// administrator's handle on it still open, and (c) after that handle is
/// closed; the System process (pid 4) is a second live row. Asserts that the
/// first read after the exit says the stamped process is not running.
///
/// Proves: `Stamp::is_running`, which reads the process list for a process the
/// caller may not open, does not report a SYSTEM process that has just exited
/// as running. Red under: the list keeping the exited process's entry with
/// threads while a read can still see it.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_probe_a_standard_users_first_read_after_a_system_process_exits() {
    let _service = ProvisionedService::install(helper());
    CutoverOs::start_service_wait_running(&mut os_actor()).expect("bring the service up");
    let pid = scm_probe::service_process_id();
    let stamp = Stamp::of_listed_process(pid)
        .expect("the process list")
        .expect("the service process is listed");
    let watched = scm_probe::watch_process(pid);

    let (live, system) = as_a_standard_user(|| (listed(pid), listed(4)));

    CutoverOs::stop_service_wait_stopped(&mut os_actor()).expect("stop the service");
    scm_probe::wait_for_exit(&watched);

    let (running, first) = as_a_standard_user(|| (stamp.is_running(), listed(pid)));
    drop(watched);
    let (closed, second) = as_a_standard_user(|| (stamp.is_running(), listed(pid)));

    eprintln!(
        "PROCESS LIST ({SERVICE_NAME}'s process {pid}), read as a standard user:\n\
         live SYSTEM process:                      {}\n\
         System process (pid 4):                   {}\n\
         first read after the exit, handle held:   is_running {running:?}; {}\n\
         read after the handle is closed:          is_running {closed:?}; {}",
        describe(&live),
        describe(&system),
        describe(&first),
        describe(&second),
    );

    assert!(
        !running.expect("the first read"),
        "the first read by a standard user after a SYSTEM process exited reads it as running"
    );
}

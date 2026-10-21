//! The identity a change stamps its record with: the writer's process id and
//! creation time.
//!
//! The pid alone is reused by the OS; with the creation time it names one
//! process for good. The GUI reads whether that process is still running to
//! tell a change in progress from an interrupted one. The writer may be
//! SYSTEM (the cutover child, an installer's custom action), and the GUI is an
//! unprivileged user: `OpenProcess` is refused for every SYSTEM process there
//! (measured: `ERROR_ACCESS_DENIED` for `services.exe` and `svchost.exe`, even
//! for `PROCESS_QUERY_LIMITED_INFORMATION`), so liveness is read from the
//! system process list (`NtQuerySystemInformation`), which needs no access to
//! any process.

use std::io;

use windows::Wdk::System::SystemInformation::{NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS};
use windows::Win32::Foundation::{FILETIME, STATUS_INFO_LENGTH_MISMATCH};
use windows::Win32::System::Threading::{GetCurrentProcess, GetCurrentProcessId, GetProcessTimes};
use windows::Win32::System::WindowsProgramming::SYSTEM_PROCESS_INFORMATION;

/// `SystemProcessInformation`.
const SYSTEM_PROCESS_INFORMATION_CLASS: SYSTEM_INFORMATION_CLASS = SYSTEM_INFORMATION_CLASS(5);

/// Where the creation time sits in `SYSTEM_PROCESS_INFORMATION::Reserved1`
/// (which `winternl.h` declares as opaque): after the 8-byte working-set size,
/// the hard-fault count, the thread high-water mark and the 8-byte cycle time,
/// 24 bytes in, an 8-byte `FILETIME` value. A test compares it with
/// `GetProcessTimes`, so a layout that moved fails there.
const CREATE_TIME_AT: usize = 24;

/// A process, by id and creation time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stamp {
    pub(crate) pid: u32,
    /// The creation `FILETIME`, 100 ns ticks since 1601.
    pub(crate) created: u64,
}

impl Stamp {
    /// This process.
    pub fn current() -> Self {
        let (mut created, mut exited, mut kernel, mut user) = (
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
        );
        // SAFETY: the pseudo-handle needs no access check and no close; the
        // out-values are locals.
        unsafe { GetProcessTimes(GetCurrentProcess(), &mut created, &mut exited, &mut kernel, &mut user) }
            .expect("a process can read its own times");
        Self {
            // SAFETY: no arguments.
            pid: unsafe { GetCurrentProcessId() },
            created: (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime),
        }
    }

    /// `"<pid>:<created>"`, both decimal.
    pub fn encode(&self) -> String {
        format!("{}:{}", self.pid, self.created)
    }

    /// The stamp `text` spells, or `None` for anything else.
    pub fn decode(text: &str) -> Option<Self> {
        let (pid, created) = text.split_once(':')?;
        let digits = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
        if !digits(pid) || !digits(created) {
            return None;
        }
        Some(Self {
            pid: pid.parse().ok()?,
            created: created.parse().ok()?,
        })
    }

    /// Whether the stamped process is running: listed with this creation time
    /// and a thread left. A pid listed with another creation time is the OS's
    /// reuse of it.
    pub fn is_running(&self) -> io::Result<bool> {
        Ok(Self::of_listed_process(self.pid)?.is_some_and(|listed| listed.created == self.created))
    }

    /// Every live process in the list (one with a thread left; an exited one
    /// that a handle keeps is not), with the creation time it was listed with.
    /// One read, so each id and its time belong to one snapshot.
    pub fn listed_processes() -> io::Result<Vec<Self>> {
        let list = process_list()?;
        let mut stamps = Vec::new();
        let mut offset = 0usize;
        loop {
            let entry = list.entry_at(offset)?;
            if entry.threads > 0 {
                stamps.push(Self {
                    pid: entry.pid,
                    created: entry.created,
                });
            }
            if entry.next == 0 {
                return Ok(stamps);
            }
            offset += entry.next;
        }
    }

    /// The stamp of the live process `pid`, if the process list has it. The
    /// list needs no access to the process, so this works for any process.
    pub fn of_listed_process(pid: u32) -> io::Result<Option<Self>> {
        Ok(Self::listed_processes()?.into_iter().find(|stamp| stamp.pid == pid))
    }
}

/// One process-list entry.
struct Entry {
    /// Bytes from this entry to the next; 0 for the last.
    next: usize,
    threads: u32,
    pid: u32,
    created: u64,
}

/// The raw bytes of `SystemProcessInformation`.
struct ProcessList(Vec<u8>);

impl ProcessList {
    fn entry_at(&self, offset: usize) -> io::Result<Entry> {
        let size = std::mem::size_of::<SYSTEM_PROCESS_INFORMATION>();
        let bytes = self
            .0
            .get(offset..)
            .filter(|rest| rest.len() >= size)
            .ok_or_else(|| io::Error::other("the process list ends inside an entry"))?;
        // SAFETY: at least `size` bytes remain at `offset`, and the struct is
        // plain data that any bit pattern fills; the read is unaligned
        // because the buffer is a byte vector.
        let info: SYSTEM_PROCESS_INFORMATION = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast()) };
        let created = u64::from_le_bytes(
            info.Reserved1[CREATE_TIME_AT..CREATE_TIME_AT + 8]
                .try_into()
                .expect("eight bytes"),
        );
        Ok(Entry {
            next: info.NextEntryOffset as usize,
            threads: info.NumberOfThreads,
            pid: info.UniqueProcessId.0 as usize as u32,
            created,
        })
    }
}

/// The process list, read into a buffer grown until it fits.
fn process_list() -> io::Result<ProcessList> {
    let mut capacity = 1usize << 20;
    loop {
        let mut buffer = vec![0u8; capacity];
        let mut returned = 0u32;
        // SAFETY: the buffer is `capacity` writable bytes.
        let status = unsafe {
            NtQuerySystemInformation(
                SYSTEM_PROCESS_INFORMATION_CLASS,
                buffer.as_mut_ptr().cast(),
                capacity as u32,
                &mut returned,
            )
        };
        if status.is_ok() {
            buffer.truncate(returned as usize);
            return Ok(ProcessList(buffer));
        }
        if status == STATUS_INFO_LENGTH_MISMATCH {
            capacity = capacity.saturating_mul(2);
            continue;
        }
        return Err(io::Error::other(format!(
            "the process list could not be read: status {:#x}",
            status.0 as u32
        )));
    }
}

#[cfg(test)]
#[path = "stamp_tests.rs"]
mod stamp_tests;

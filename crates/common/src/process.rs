//! Cross-platform process probes for the cutover marker driver identity: the
//! privileged bridge stamps a child's start time into the marker and the GUI
//! verifies it, so both share one impl (byte-identical values). `process_start_time`
//! is the creation-time source; `process_matches_and_alive` adds the exit-state
//! check the GUI's liveness needs (a terminated-but-unreaped process stays
//! openable with its original creation time).

/// Start time of a process as Unix milliseconds; `None` if it does not exist.
pub fn process_start_time(pid: u32) -> Option<u64> {
    platform::process_start_time_impl(pid)
}

/// Whether `pid` is a RUNNING process (not exited or a handle-retained zombie)
/// whose creation time equals `expected_start_unix_ms`. Windows only; `false`
/// elsewhere (Part B liveness is Windows-scoped).
pub fn process_matches_and_alive(pid: u32, expected_start_unix_ms: u64) -> bool {
    platform::process_matches_and_alive_impl(pid, expected_start_unix_ms)
}

#[cfg(target_os = "windows")]
mod platform {
    use windows::Win32::Foundation::{CloseHandle, FILETIME};
    use windows::Win32::System::Threading::{GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    /// FILETIME (100-ns intervals since 1601) → Unix milliseconds.
    fn filetime_to_unix_ms(ft: FILETIME) -> Option<u64> {
        let raw = ((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64;
        const EPOCH_DIFF_100NS: u64 = 116_444_736_000_000_000;
        Some(raw.checked_sub(EPOCH_DIFF_100NS)? / 10_000)
    }

    fn zero(ft: FILETIME) -> bool {
        (ft.dwLowDateTime | ft.dwHighDateTime) == 0
    }

    /// Read a process's creation + exit FILETIMEs via `PROCESS_QUERY_LIMITED_INFORMATION`
    /// (grantable across privilege levels, so the unprivileged GUI can query the
    /// SYSTEM cutover child). `None` if the PID does not resolve.
    fn process_times(pid: u32) -> Option<(FILETIME, FILETIME)> {
        // SAFETY: the handle is checked and closed below.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
        let (mut creation, mut exit, mut kernel, mut user) = (
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
        );
        let ok = unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) };
        let _ = unsafe { CloseHandle(handle) };
        ok.ok()?;
        Some((creation, exit))
    }

    pub fn process_start_time_impl(pid: u32) -> Option<u64> {
        let (creation, _exit) = process_times(pid)?;
        filetime_to_unix_ms(creation)
    }

    pub fn process_matches_and_alive_impl(pid: u32, expected: u64) -> bool {
        let Some((creation, exit)) = process_times(pid) else {
            return false; // reaped/absent → dead
        };
        // A RUNNING process has a zero exit FILETIME; an exited process (even one
        // kept unreaped by an open handle) has a non-zero exit time. Unambiguous
        // (no GetExitCodeProcess/STILL_ACTIVE-259 collision). Identity: the
        // creation FILETIME must match the stamped value.
        zero(exit) && filetime_to_unix_ms(creation) == Some(expected)
    }
}

#[cfg(target_os = "macos")]
mod platform {
    pub fn process_start_time_impl(pid: u32) -> Option<u64> {
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
        let ret = unsafe {
            libc::proc_pidinfo(
                pid as i32,
                libc::PROC_PIDTBSDINFO,
                0,
                &mut info as *mut _ as *mut libc::c_void,
                size,
            )
        };
        if ret <= 0 {
            return None;
        }
        Some(info.pbi_start_tvsec * 1000 + info.pbi_start_tvusec / 1000)
    }

    pub fn process_matches_and_alive_impl(_pid: u32, _expected: u64) -> bool {
        false // Part B liveness is Windows-only
    }
}

#[cfg(target_os = "linux")]
mod platform {
    pub fn process_start_time_impl(pid: u32) -> Option<u64> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let after_comm = stat.rfind(')')?.checked_add(2)?;
        let fields: Vec<&str> = stat[after_comm..].split_whitespace().collect();
        let starttime_ticks: u64 = fields.get(19)?.parse().ok()?;
        let btime_secs: u64 = std::fs::read_to_string("/proc/stat")
            .ok()?
            .lines()
            .find(|l| l.starts_with("btime "))?
            .split_whitespace()
            .nth(1)?
            .parse()
            .ok()?;
        let ticks_per_sec = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u64;
        let start_secs = btime_secs + starttime_ticks / ticks_per_sec;
        Some(start_secs * 1000 + (starttime_ticks % ticks_per_sec) * 1000 / ticks_per_sec)
    }

    pub fn process_matches_and_alive_impl(_pid: u32, _expected: u64) -> bool {
        false
    }
}

#[cfg(test)]
#[path = "process_tests.rs"]
mod process_tests;

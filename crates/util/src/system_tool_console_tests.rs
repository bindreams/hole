//! `CREATE_NO_WINDOW` gives the child a windowless console of its own; without
//! it the child inherits this process's console. A child's own `conhost.exe`
//! therefore tells the flag from its absence, and `std` has no getter for the flag.

#![allow(clippy::disallowed_methods)] // the control builds a bare `Command`, to show the flag is the difference

use std::io::{BufRead, BufReader, Write};
use std::os::windows::io::AsRawHandle;
use std::process::{Child, Command, Stdio};

use windows::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, ERROR_NO_MORE_FILES, FILETIME, HANDLE,
};
use windows::Win32::System::Console::GetConsoleProcessList;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

use crate::system_tool::{SystemPowershell, SystemTool};

/// The creation time of the process behind `handle`, in 100 ns ticks.
///
/// # Safety
///
/// `handle` must be a valid process handle with query access.
unsafe fn creation_time(handle: HANDLE) -> u64 {
    let (mut created, mut exited, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: the caller guarantees the handle; the out-pointers are live locals.
    unsafe { GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user) }.expect("GetProcessTimes");
    (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime)
}

/// The creation time of process `pid`, or `None` when it cannot be a console
/// host of ours: it has exited, or it is not ours to open. A console host
/// created for a child runs as that child's user, so this process can open it.
fn creation_time_of_pid(pid: u32) -> Option<u64> {
    // SAFETY: the handle is closed below; `creation_time` gets a valid one.
    unsafe {
        match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(handle) => {
                let time = creation_time(handle);
                CloseHandle(handle).expect("close process handle");
                Some(time)
            }
            Err(e)
                if e.code() == ERROR_INVALID_PARAMETER.to_hresult() || e.code() == ERROR_ACCESS_DENIED.to_hresult() =>
            {
                None
            }
            Err(e) => panic!("OpenProcess({pid}): {e}"),
        }
    }
}

/// Whether `child` has a console host among its children. A host counts only if
/// it was created no earlier than `child`: the snapshot's parent pid is never
/// updated and Windows reuses pids, so an older host can name `child`'s pid.
fn owns_a_console_host(child: &Child) -> bool {
    let pid = child.id();
    // SAFETY: the raw handle belongs to `child`, which outlives this call.
    let child_created = unsafe { creation_time(HANDLE(child.as_raw_handle())) };
    // SAFETY: the snapshot handle is closed below; the entry is sized as the API requires.
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).expect("process snapshot");
        let mut entry = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut found = false;
        let mut step = Process32FirstW(snapshot, &mut entry);
        loop {
            match step {
                Ok(()) => {}
                Err(e) if e.code() == ERROR_NO_MORE_FILES.to_hresult() => break,
                Err(e) => panic!("process walk: {e}"),
            }
            let len = entry
                .szExeFile
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.szExeFile.len());
            let name = String::from_utf16_lossy(&entry.szExeFile[..len]).to_ascii_lowercase();
            if entry.th32ParentProcessID == pid
                && (name == "conhost.exe" || name == "openconsole.exe")
                && creation_time_of_pid(entry.th32ProcessID).is_some_and(|created| created >= child_created)
            {
                found = true;
                break;
            }
            step = Process32NextW(snapshot, &mut entry);
        }
        CloseHandle(snapshot).expect("close snapshot");
        found
    }
}

/// Whether the spawned `cmd` owns a console host. Waits for its first stdout
/// line so the child has attached to its console before the check, and sends
/// `release` only afterwards: a child that exits first takes its host with it.
fn child_owns_a_console_host(mut cmd: Command, input: &str, release: &str) -> bool {
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(input.as_bytes()).unwrap();
    let mut first = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut first)
        .unwrap();
    assert!(!first.is_empty(), "the child exited before writing anything");
    let owns = owns_a_console_host(&child);
    stdin.write_all(release.as_bytes()).unwrap();
    drop(stdin);
    child.wait().unwrap();
    owns
}

/// Control: if this fails, the observable in the tests below proves nothing.
#[skuld::test]
fn a_child_without_the_flag_inherits_the_console_and_owns_no_console_host() {
    // The unflagged child must inherit a console. Without one it would allocate
    // its own, visible, and the assertion below would fail for that reason.
    let mut pids = [0u32; 1];
    // SAFETY: `pids` is a live buffer of the length passed.
    let attached = unsafe { GetConsoleProcessList(&mut pids) };
    assert!(
        attached > 0,
        "this test process has no console; run the tests from a shell, not detached"
    );
    let cmd = Command::new(SystemTool::Netsh.path().unwrap());
    assert!(!child_owns_a_console_host(cmd, "help\r\n", ""));
}

#[skuld::test]
fn a_system_tool_command_owns_a_windowless_console() {
    let cmd = SystemTool::Netsh.command().unwrap();
    assert!(child_owns_a_console_host(cmd, "help\r\n", ""));
}

#[skuld::test]
fn a_system_powershell_command_owns_a_windowless_console() {
    let cmd = SystemPowershell::command("[Console]::Out.WriteLine('up'); [Console]::In.ReadLine() | Out-Null").unwrap();
    assert!(child_owns_a_console_host(cmd, "", "\r\n"));
}

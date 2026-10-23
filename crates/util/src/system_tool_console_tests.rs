//! A release GUI has no console, so a console tool it spawns would get a new
//! visible one. `CREATE_NO_WINDOW` gives the child a console of its own with no
//! window; a child that merely inherits this process's console has no console
//! host of its own. A child's own `conhost.exe` is therefore the observable
//! that tells the flag from its absence, and `std` offers no getter for the flag.

#![allow(clippy::disallowed_methods)] // the control builds a bare `Command`, to show the flag is the difference

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};

use crate::system_tool::{SystemPowershell, SystemTool};

/// Whether `pid` has a console host among its children.
fn owns_a_console_host(pid: u32) -> bool {
    // SAFETY: the snapshot handle is closed below; the entry is sized as the API requires.
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).expect("process snapshot");
        let mut entry = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut found = false;
        let mut more = Process32FirstW(snapshot, &mut entry).is_ok();
        while more {
            let len = entry
                .szExeFile
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.szExeFile.len());
            let name = String::from_utf16_lossy(&entry.szExeFile[..len]).to_ascii_lowercase();
            if entry.th32ParentProcessID == pid && (name == "conhost.exe" || name == "openconsole.exe") {
                found = true;
                break;
            }
            more = Process32NextW(snapshot, &mut entry).is_ok();
        }
        CloseHandle(snapshot).expect("close snapshot");
        found
    }
}

/// Spawns `cmd`, sends `input` on its stdin, waits for its first line of
/// stdout (so the child has started and attached to its console), reports
/// whether it owns a console host, then lets it exit.
fn child_owns_a_console_host(mut cmd: Command, input: &str) -> bool {
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
    let owns = owns_a_console_host(child.id());
    drop(stdin);
    child.wait().unwrap();
    owns
}

/// Control: with no flag, a child shares this process's console and has no
/// console host of its own. If this fails, the observable below proves nothing.
#[skuld::test]
fn a_child_without_the_flag_inherits_the_console_and_owns_no_console_host() {
    let cmd = Command::new(SystemTool::Netsh.path().unwrap());
    assert!(!child_owns_a_console_host(cmd, "help\r\n"));
}

#[skuld::test]
fn a_system_tool_command_owns_a_windowless_console() {
    let cmd = SystemTool::Netsh.command().unwrap();
    assert!(child_owns_a_console_host(cmd, "help\r\n"));
}

#[skuld::test]
fn a_system_powershell_command_owns_a_windowless_console() {
    let cmd = SystemPowershell::command("[Console]::Out.WriteLine('up'); [Console]::In.ReadLine() | Out-Null").unwrap();
    assert!(child_owns_a_console_host(cmd, "\r\n"));
}

#[cfg(windows)]
use crate::system_tool::SystemPowershell;
use crate::system_tool::SystemTool;

/// Where each variant must resolve to (the whole path on macOS, the tail under
/// the system directory on Windows); exhaustive, so a new variant fails to
/// compile until listed.
fn expected_path(tool: SystemTool) -> &'static str {
    #[cfg(target_os = "macos")]
    return match tool {
        SystemTool::Route => "/sbin/route",
        SystemTool::Ifconfig => "/sbin/ifconfig",
        SystemTool::Pfctl => "/sbin/pfctl",
        SystemTool::Networksetup => "/usr/sbin/networksetup",
        SystemTool::Dscacheutil => "/usr/bin/dscacheutil",
        SystemTool::Killall => "/usr/bin/killall",
        SystemTool::Launchctl => "/bin/launchctl",
        SystemTool::Dseditgroup => "/usr/sbin/dseditgroup",
        SystemTool::Stat => "/usr/bin/stat",
        SystemTool::Logname => "/usr/bin/logname",
    };
    #[cfg(windows)]
    return match tool {
        SystemTool::Route => "route.exe",
        SystemTool::Netsh => "netsh.exe",
        SystemTool::Net => "net.exe",
        SystemTool::Pnputil => "pnputil.exe",
    };
}

#[skuld::test]
fn every_system_tool_resolves_to_an_existing_absolute_path() {
    assert!(!SystemTool::ALL.is_empty());
    for &tool in SystemTool::ALL {
        let path = tool.path().expect("the OS reports its system directory");
        assert!(path.is_absolute(), "{tool:?} resolved to a non-absolute path {path:?}");
        assert!(path.exists(), "{tool:?} resolved to {path:?}, which does not exist");
    }
}

#[skuld::test]
fn every_system_tool_resolves_to_its_own_binary() {
    for &tool in SystemTool::ALL {
        let path = tool.path().unwrap();
        assert!(path.ends_with(expected_path(tool)), "{tool:?} resolved to {path:?}");
    }
}

#[skuld::test]
fn command_runs_the_resolved_absolute_path_and_nothing_else() {
    for &tool in SystemTool::ALL {
        let cmd = tool.command().unwrap();
        assert_eq!(cmd.get_program(), tool.path().unwrap().as_os_str(), "{tool:?}");
        assert_eq!(cmd.get_args().count(), 0, "{tool:?} must start with no arguments");
    }
}

#[skuld::test]
fn all_lists_each_tool_once() {
    let mut paths: Vec<_> = SystemTool::ALL.iter().map(|t| t.path().unwrap()).collect();
    let n = paths.len();
    paths.sort();
    paths.dedup();
    assert_eq!(
        paths.len(),
        n,
        "two variants resolve to the same binary, or one is listed twice"
    );
}

/// The Windows directory comes from the OS (`GetSystemDirectoryW`). The
/// `SystemRoot` environment variable is the independent oracle; the two agree
/// on every normal install.
#[cfg(windows)]
#[skuld::test]
fn windows_tools_live_under_the_system_directory() {
    let root = std::env::var_os("SystemRoot").expect("SystemRoot is set on every Windows session");
    let system32 = std::path::Path::new(&root).join("System32");
    for &tool in SystemTool::ALL {
        let path = tool.path().unwrap();
        assert!(
            path.to_string_lossy()
                .to_ascii_lowercase()
                .starts_with(&system32.to_string_lossy().to_ascii_lowercase()),
            "{tool:?} resolved to {path:?}, outside {system32:?}"
        );
    }
}

#[skuld::test]
fn display_with_is_the_absolute_path_then_the_arguments() {
    for &tool in SystemTool::ALL {
        let path = tool.path().unwrap().display().to_string();
        assert_eq!(tool.display_with::<&str>(&[]), path, "{tool:?}");
        assert_eq!(tool.display_with(&["-n", "add"]), format!("{path} -n add"), "{tool:?}");
    }
}

/// The text is only logged, never run, so an unavailable path names the tool.
#[skuld::test]
fn display_names_the_tool_when_its_path_is_unavailable() {
    for &tool in SystemTool::ALL {
        let unavailable = || Err(std::io::Error::other("no system directory"));
        assert_eq!(
            tool.display_from(unavailable(), &["-n", "add"]),
            format!("{} -n add", tool.name())
        );
        assert_eq!(tool.display_from::<&str>(unavailable(), &[]), tool.name());
    }
}

/// `name` is the program's bare name, the stem of its expected path.
#[skuld::test]
fn name_is_the_bare_program_name() {
    for &tool in SystemTool::ALL {
        let stem = std::path::Path::new(expected_path(tool))
            .file_stem()
            .unwrap()
            .to_owned();
        assert_eq!(tool.name(), stem, "{tool:?}");
    }
}

/// A failed `GetSystemDirectoryW` is an `Err` the caller carries as its spawn
/// error, never a panic: a `Drop`-driven teardown must keep going. The injected
/// closure stands in for the OS call.
#[cfg(windows)]
#[skuld::test]
fn a_failing_system_directory_call_is_an_error_not_a_panic() {
    // Fails at the length query.
    assert!(crate::system_tool::read_system_directory(|_| 0).is_err());
    // Reports a length, then fails to fill the buffer.
    assert!(crate::system_tool::read_system_directory(|buf| if buf.is_none() { 8 } else { 0 }).is_err());
    // The buffer filled is not shorter than the reported length (the directory
    // changed between the two calls): no valid slice to return. Both the
    // grown case and the equal boundary, where the length written would
    // include a NUL.
    assert!(crate::system_tool::read_system_directory(|buf| if buf.is_none() { 8 } else { 9 }).is_err());
    assert!(crate::system_tool::read_system_directory(|_| 8).is_err());
}

/// A failure is not cached: the next call asks the OS again, so one transient
/// failure does not turn every later spawn into an error.
#[cfg(windows)]
#[skuld::test]
fn a_failed_system_directory_read_is_not_cached() {
    use std::sync::OnceLock;
    static CELL: OnceLock<std::path::PathBuf> = OnceLock::new();
    let calls = std::cell::Cell::new(0u32);
    let read = |fail: bool| {
        crate::system_tool::cached_system_directory(&CELL, |buf| {
            calls.set(calls.get() + 1);
            match (fail, buf) {
                (true, _) => 0,
                (false, None) => 4,
                (false, Some(b)) => {
                    for (slot, c) in b.iter_mut().zip("C:\\".encode_utf16()) {
                        *slot = c;
                    }
                    3
                }
            }
        })
        .cloned()
    };
    assert!(read(true).is_err());
    assert_eq!(read(false).unwrap(), std::path::PathBuf::from("C:\\"));
    let after_success = calls.get();
    assert_eq!(
        read(true).unwrap(),
        std::path::PathBuf::from("C:\\"),
        "a cached success is not re-read"
    );
    assert_eq!(calls.get(), after_success);
}

#[cfg(windows)]
#[skuld::test]
fn the_system_directory_call_returns_what_the_os_wrote() {
    let dir = crate::system_tool::read_system_directory(|buf| match buf {
        None => 4, // "C:\\" is 3 UTF-16 units plus the NUL
        Some(b) => {
            for (slot, c) in b.iter_mut().zip("C:\\".encode_utf16()) {
                *slot = c;
            }
            3
        }
    })
    .unwrap();
    assert_eq!(dir, std::path::PathBuf::from("C:\\"));
}

/// PowerShell reads single quotes as a string delimiter in their ASCII and
/// typographic forms alike; each is doubled to stay inside the literal.
#[skuld::test]
fn a_powershell_literal_cannot_be_closed_early() {
    use crate::system_tool::powershell_literal;
    assert_eq!(powershell_literal("C:\\Win\\Modules"), "'C:\\Win\\Modules'");
    assert_eq!(powershell_literal("a'b"), "'a''b'");
    for quote in ['\u{2018}', '\u{2019}', '\u{201A}', '\u{201B}'] {
        assert_eq!(
            powershell_literal(&format!("a{quote}b")),
            format!("'a{quote}{quote}b'"),
            "U+{:04X}",
            quote as u32
        );
    }
}

#[skuld::test]
fn a_powershell_script_starts_by_setting_the_module_path() {
    use crate::system_tool::module_path_script;
    assert_eq!(
        module_path_script(
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules",
            "Get-NetAdapter"
        ),
        "$env:PSModulePath = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules'; Get-NetAdapter"
    );
}

/// `SystemPowershell` is not a `SystemTool`, so `SystemTool::command` cannot
/// build a PowerShell without a script; its path is still absolute, existing
/// and under the system directory.
#[cfg(windows)]
#[skuld::test]
fn powershell_resolves_to_its_binary_under_the_system_directory() {
    let path = SystemPowershell::path().expect("the OS reports its system directory");
    assert!(path.is_absolute(), "{path:?}");
    assert!(path.exists(), "{path:?}");
    assert!(path.ends_with("WindowsPowerShell/v1.0/powershell.exe"), "{path:?}");
    let system32 = SystemTool::Route.path().unwrap().parent().unwrap().to_path_buf();
    assert!(path.starts_with(&system32), "{path:?} is outside {system32:?}");
}

#[cfg(windows)]
#[skuld::test]
fn powershell_command_runs_its_script_without_a_profile_after_setting_the_module_path() {
    let cmd = SystemPowershell::command("Get-Date").unwrap();
    assert_eq!(cmd.get_program(), SystemPowershell::path().unwrap().as_os_str());
    let args: Vec<_> = cmd.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
    assert_eq!(&args[..2], ["-NoProfile", "-Command"]);
    assert_eq!(args.len(), 3);
    assert!(
        args[2].starts_with("$env:PSModulePath = '") && args[2].ends_with("; Get-Date"),
        "{:?}",
        args[2]
    );
}

#[cfg(windows)]
#[skuld::test]
fn powershell_command_pins_psmodulepath_to_the_system_module_directory() {
    let cmd = SystemPowershell::command("Get-Date").unwrap();
    let pinned = cmd
        .get_envs()
        .find(|(k, _)| k.eq_ignore_ascii_case("PSModulePath"))
        .and_then(|(_, v)| v)
        .expect("a root PowerShell must not inherit PSModulePath");
    assert_eq!(std::path::Path::new(pinned), system_module_directory());
}

#[cfg(windows)]
fn system_module_directory() -> std::path::PathBuf {
    let system32 = SystemTool::Route.path().unwrap().parent().unwrap().to_path_buf();
    system32.join("WindowsPowerShell").join("v1.0").join("Modules")
}

/// Runs `script` in a root PowerShell with stdout as UTF-8, and returns it.
#[cfg(windows)]
fn powershell_stdout(script: &str, process_module_path: Option<&str>) -> String {
    let script = format!("[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false; {script}");
    let mut cmd = SystemPowershell::command(&script).unwrap();
    if let Some(value) = process_module_path {
        cmd.env("PSModulePath", value); // after the pin: overrides it
    }
    let out = cmd.output().unwrap();
    assert!(out.status.success(), "{out:?}");
    String::from_utf8(out.stdout).unwrap()
}

/// PowerShell keeps a `PSModulePath` that differs from the machine's and
/// rebuilds one that equals it, putting the invoking user's writable
/// `Documents\WindowsPowerShell\Modules` first. With the process value forced
/// to the machine value, the modules PowerShell can resolve are the oracle:
/// every one must live under the system module directory.
#[cfg(windows)]
#[skuld::test]
fn powershell_resolves_modules_only_from_the_system_module_directory_when_the_process_value_is_the_machine_value() {
    let machine = powershell_stdout(
        "[Console]::Out.Write([Environment]::GetEnvironmentVariable('PSModulePath', 'Machine'))",
        None,
    );
    assert!(!machine.is_empty(), "the machine PSModulePath is unset");

    let bases = powershell_stdout(
        "[Console]::Out.Write(((Get-Module -ListAvailable | ForEach-Object { $_.ModuleBase }) -join '|'))",
        Some(&machine),
    );
    assert!(
        !bases.is_empty(),
        "no module is resolvable, so the check proves nothing"
    );
    let allowed = system_module_directory().to_string_lossy().to_ascii_lowercase();
    for base in bases.split('|') {
        assert!(
            base.to_ascii_lowercase().starts_with(&allowed),
            "module at {base:?} resolved from outside {allowed:?} (machine value {machine:?})"
        );
    }
}

/// None of the `SystemTool`s is a PowerShell, so none carries its module pin.
#[cfg(windows)]
#[skuld::test]
fn the_other_windows_tools_leave_psmodulepath_alone() {
    for &tool in SystemTool::ALL {
        let cmd = tool.command().unwrap();
        assert!(
            cmd.get_envs().all(|(k, _)| !k.eq_ignore_ascii_case("PSModulePath")),
            "{tool:?}"
        );
    }
}

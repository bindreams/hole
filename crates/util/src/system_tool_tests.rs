use crate::system_tool::SystemTool;

/// Independent oracle: where each variant must resolve to (the whole path on
/// macOS, the tail under the system directory on Windows). The exhaustive match
/// makes adding a variant a compile error here until its expectation is written
/// down.
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
        SystemTool::Powershell => "WindowsPowerShell/v1.0/powershell.exe",
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
    let tool = SystemTool::ALL[0];
    let path = tool.path().unwrap().display().to_string();
    assert_eq!(tool.display_with::<&str>(&[]), path);
    assert_eq!(tool.display_with(&["-n", "add"]), format!("{path} -n add"));
}

/// `name` is what a user-facing error says instead of a path: the program's
/// bare name, which `expected_path` already spells out for every variant.
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
    // changed between the two calls): no valid slice to return.
    assert!(crate::system_tool::read_system_directory(|buf| if buf.is_none() { 8 } else { 9 }).is_err());
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

/// Every root PowerShell resolves modules from machine-scoped directories
/// only: the default `PSModulePath` starts with the invoking user's
/// `Documents\WindowsPowerShell\Modules`, which that user can write. Asks a real
/// child what it sees.
#[cfg(windows)]
#[skuld::test]
fn powershell_sees_no_user_writable_module_directory() {
    let system32 = SystemTool::Route.path().unwrap().parent().unwrap().to_path_buf();
    let expected = system32.join("WindowsPowerShell").join("v1.0").join("Modules");
    let out = SystemTool::Powershell
        .command()
        .unwrap()
        .args(["-NoProfile", "-Command", "[Console]::Out.Write($env:PSModulePath)"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let seen = String::from_utf8_lossy(&out.stdout).into_owned();
    let entries: Vec<&str> = seen.split(';').filter(|e| !e.is_empty()).collect();
    assert!(
        entries
            .iter()
            .any(|e| e.eq_ignore_ascii_case(&expected.to_string_lossy())),
        "the system module directory is missing from {seen:?}"
    );
    let system_root = std::env::var("SystemRoot").unwrap().to_ascii_lowercase();
    let program_files = std::env::var("ProgramFiles").unwrap().to_ascii_lowercase();
    for e in entries {
        let e = e.to_ascii_lowercase();
        assert!(
            e.starts_with(&system_root) || e.starts_with(&program_files),
            "{e:?} is outside the machine-scoped directories, in {seen:?}"
        );
    }
}

#[cfg(windows)]
#[skuld::test]
fn powershell_command_pins_psmodulepath_to_the_system_module_directory() {
    let cmd = SystemTool::Powershell.command().unwrap();
    let pinned = cmd
        .get_envs()
        .find(|(k, _)| k.eq_ignore_ascii_case("PSModulePath"))
        .and_then(|(_, v)| v)
        .expect("a root PowerShell must not inherit PSModulePath");
    let system32 = SystemTool::Route.path().unwrap().parent().unwrap().to_path_buf();
    let expected = system32.join("WindowsPowerShell").join("v1.0").join("Modules");
    assert_eq!(std::path::Path::new(pinned), expected);
}

#[cfg(windows)]
#[skuld::test]
fn the_other_windows_tools_leave_psmodulepath_alone() {
    for &tool in SystemTool::ALL {
        if tool == SystemTool::Powershell {
            continue;
        }
        let cmd = tool.command().unwrap();
        assert!(
            cmd.get_envs().all(|(k, _)| !k.eq_ignore_ascii_case("PSModulePath")),
            "{tool:?}"
        );
    }
}

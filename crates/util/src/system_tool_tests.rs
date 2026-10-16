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
    };
}

#[skuld::test]
fn every_system_tool_resolves_to_an_existing_absolute_path() {
    assert!(!SystemTool::ALL.is_empty());
    for &tool in SystemTool::ALL {
        let path = tool.path();
        assert!(path.is_absolute(), "{tool:?} resolved to a non-absolute path {path:?}");
        assert!(path.exists(), "{tool:?} resolved to {path:?}, which does not exist");
    }
}

#[skuld::test]
fn every_system_tool_resolves_to_its_own_binary() {
    for &tool in SystemTool::ALL {
        let path = tool.path();
        assert!(path.ends_with(expected_path(tool)), "{tool:?} resolved to {path:?}");
    }
}

#[skuld::test]
fn command_runs_the_resolved_absolute_path_and_nothing_else() {
    for &tool in SystemTool::ALL {
        let cmd = tool.command();
        assert_eq!(cmd.get_program(), tool.path().as_os_str(), "{tool:?}");
        assert_eq!(cmd.get_args().count(), 0, "{tool:?} must start with no arguments");
    }
}

#[skuld::test]
fn all_lists_each_tool_once() {
    let mut paths: Vec<_> = SystemTool::ALL.iter().map(|t| t.path()).collect();
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
        let path = tool.path();
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
    let path = tool.path().display().to_string();
    assert_eq!(tool.display_with::<&str>(&[]), path);
    assert_eq!(tool.display_with(&["-n", "add"]), format!("{path} -n add"));
}

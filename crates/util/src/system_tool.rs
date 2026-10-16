//! Absolute paths for the OS tools Hole spawns.
//!
//! The bridge runs as root/SYSTEM, so a program named without a directory is
//! resolved by something an unprivileged user can influence: `PATH` on macOS;
//! on Windows `CreateProcess` searches the application's directory and the
//! *current directory* before System32 (see
//! <https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw>,
//! "lpApplicationName"). [`SystemTool::command`] is the only way to build a
//! `Command` for these tools, and its program is always an absolute path.
//!
//! The Windows directory is read from the OS (`GetSystemDirectoryW`), never
//! assumed to be `C:\Windows` and never replaced by a bare name when the read
//! fails.

use std::io;
use std::path::PathBuf;
use std::process::Command;

/// Declares `SystemTool` and its `ALL` from one variant list, so a variant
/// cannot be left out of `ALL`.
macro_rules! system_tools {
    ($doc:literal, $($variant:ident),+ $(,)?) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum SystemTool {
            $($variant),+
        }

        impl SystemTool {
            pub const ALL: &'static [SystemTool] = &[$(Self::$variant),+];
        }
    };
}

#[cfg(target_os = "macos")]
mod tools {
    use std::io;
    use std::path::PathBuf;
    use std::process::Command;

    system_tools! {
        "An OS tool the macOS bridge spawns, at its fixed absolute path.",
        Route,
        Ifconfig,
        Pfctl,
        Networksetup,
        Dscacheutil,
        Killall,
        Launchctl,
        Dseditgroup,
        Stat,
        Logname,
    }

    impl SystemTool {
        /// The tool's absolute path. These are SIP-protected locations that are
        /// stable across the macOS versions Hole supports, so this never fails.
        pub(super) fn resolve_path(self) -> io::Result<PathBuf> {
            Ok(PathBuf::from(match self {
                Self::Route => "/sbin/route",
                Self::Ifconfig => "/sbin/ifconfig",
                Self::Pfctl => "/sbin/pfctl",
                Self::Networksetup => "/usr/sbin/networksetup",
                Self::Dscacheutil => "/usr/bin/dscacheutil",
                Self::Killall => "/usr/bin/killall",
                Self::Launchctl => "/bin/launchctl",
                Self::Dseditgroup => "/usr/sbin/dseditgroup",
                Self::Stat => "/usr/bin/stat",
                Self::Logname => "/usr/bin/logname",
            }))
        }

        /// The program's bare name, for text that must stay free of paths.
        pub fn name(self) -> &'static str {
            match self {
                Self::Route => "route",
                Self::Ifconfig => "ifconfig",
                Self::Pfctl => "pfctl",
                Self::Networksetup => "networksetup",
                Self::Dscacheutil => "dscacheutil",
                Self::Killall => "killall",
                Self::Launchctl => "launchctl",
                Self::Dseditgroup => "dseditgroup",
                Self::Stat => "stat",
                Self::Logname => "logname",
            }
        }

        pub(super) fn pin_environment(self, _command: &mut Command) -> io::Result<()> {
            Ok(())
        }

        /// Every macOS tool is built by [`command`](SystemTool::command) alone.
        pub(super) fn ensure_scriptless(self) -> io::Result<()> {
            Ok(())
        }
    }
}

#[cfg(windows)]
mod tools {
    use std::io;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::OnceLock;

    system_tools! {
        "An OS tool the Windows bridge spawns, under the system directory.",
        Route,
        Netsh,
        Net,
        Powershell,
        Pnputil,
    }

    impl SystemTool {
        /// The tool's absolute path under the OS-reported system directory.
        pub(super) fn resolve_path(self) -> io::Result<PathBuf> {
            let system32 = system_directory()?;
            Ok(match self {
                Self::Route => system32.join("route.exe"),
                Self::Netsh => system32.join("netsh.exe"),
                Self::Net => system32.join("net.exe"),
                Self::Powershell => system32.join("WindowsPowerShell").join("v1.0").join("powershell.exe"),
                Self::Pnputil => system32.join("pnputil.exe"),
            })
        }

        /// The program's bare name, for text that must stay free of paths.
        pub fn name(self) -> &'static str {
            match self {
                Self::Route => "route",
                Self::Netsh => "netsh",
                Self::Net => "net",
                Self::Powershell => "powershell",
                Self::Pnputil => "pnputil",
            }
        }

        /// A root PowerShell autoloads cmdlets from `PSModulePath`, whose default
        /// begins with the invoking user's `Documents\WindowsPowerShell\Modules`
        /// (user-writable), so the child gets only the system module directory.
        /// This pin alone is not enough: PowerShell rebuilds a `PSModulePath`
        /// equal to the machine's, so [`SystemTool::powershell_command`] also
        /// sets it from inside the script.
        pub(super) fn pin_environment(self, command: &mut Command) -> io::Result<()> {
            match self {
                Self::Powershell => {
                    command.env("PSModulePath", powershell_module_directory()?);
                }
                Self::Route | Self::Netsh | Self::Net | Self::Pnputil => {}
            }
            Ok(())
        }

        /// Whether [`command`](SystemTool::command) may build this tool without
        /// more input. A root PowerShell may not: its module path is set by the
        /// script it runs, so it is built only by
        /// [`powershell_command`](SystemTool::powershell_command).
        pub(super) fn ensure_scriptless(self) -> io::Result<()> {
            match self {
                Self::Powershell => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "PowerShell is built with SystemTool::powershell_command, which sets its module path",
                )),
                Self::Route | Self::Netsh | Self::Net | Self::Pnputil => Ok(()),
            }
        }
    }

    pub(super) fn powershell_module_directory() -> io::Result<PathBuf> {
        Ok(system_directory()?
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("Modules"))
    }

    /// The system directory, read once. A failure is not cached: the next call
    /// asks the OS again.
    fn system_directory() -> io::Result<&'static PathBuf> {
        static DIR: OnceLock<PathBuf> = OnceLock::new();
        cached_system_directory(&DIR, |buf| {
            use windows::Win32::System::SystemInformation::GetSystemDirectoryW;
            // SAFETY: `GetSystemDirectoryW` writes only into the slice it is given.
            unsafe { GetSystemDirectoryW(buf) }
        })
    }

    /// [`read_system_directory`] behind `cell`: a success is kept, a failure
    /// leaves `cell` empty so the next call reads again.
    pub(crate) fn cached_system_directory(
        cell: &'static OnceLock<PathBuf>,
        get: impl FnMut(Option<&mut [u16]>) -> u32,
    ) -> io::Result<&'static PathBuf> {
        if let Some(dir) = cell.get() {
            return Ok(dir);
        }
        let dir = read_system_directory(get)?;
        Ok(cell.get_or_init(|| dir))
    }

    /// `GetSystemDirectoryW`'s two-call protocol over an injectable `get`: with
    /// `None` it returns the buffer length needed (NUL included), with a buffer
    /// it returns the length written (NUL excluded). 0 is failure in both.
    pub(crate) fn read_system_directory(mut get: impl FnMut(Option<&mut [u16]>) -> u32) -> io::Result<PathBuf> {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;

        let needed = get(None) as usize;
        if needed == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buf = vec![0u16; needed];
        let written = get(Some(&mut buf)) as usize;
        if written == 0 {
            return Err(io::Error::last_os_error());
        }
        if written >= needed {
            // The directory grew between the two calls; `written` is then the
            // size needed, not a length written.
            return Err(io::Error::other(
                "GetSystemDirectoryW: the system directory changed between the length query and the read",
            ));
        }
        Ok(PathBuf::from(OsString::from_wide(&buf[..written])))
    }
}

pub use tools::SystemTool;

#[cfg(windows)]
#[cfg(test)]
pub(crate) use tools::{cached_system_directory, read_system_directory};

impl SystemTool {
    /// The tool's absolute path.
    ///
    /// # Errors
    ///
    /// On Windows, when `GetSystemDirectoryW` fails. There is then no directory
    /// to trust, and the caller reports it as its spawn error.
    pub fn path(self) -> io::Result<PathBuf> {
        self.resolve_path()
    }

    /// The only sanctioned constructor of a `Command` for a system tool. Its
    /// program is [`path`](Self::path), never a bare name, and its environment is
    /// pinned where the tool would otherwise search a user-writable place.
    ///
    /// # Errors
    ///
    /// As [`path`](Self::path).
    #[allow(clippy::disallowed_methods)] // this IS the sanctioned constructor; clippy.toml routes every other site here
    pub fn command(self) -> io::Result<Command> {
        self.ensure_scriptless()?;
        self.build()
    }

    #[allow(clippy::disallowed_methods)] // as `command`
    fn build(self) -> io::Result<Command> {
        let mut command = Command::new(self.path()?);
        self.pin_environment(&mut command)?;
        Ok(command)
    }

    /// The only constructor of a root PowerShell `Command`: `-NoProfile
    /// -Command <script>`, where the script first sets `$env:PSModulePath` to
    /// the system module directory. Autoload reads `$env:PSModulePath`, so
    /// setting it from inside the script holds on a host where PowerShell would
    /// rebuild the inherited value with the invoking user's writable module
    /// directory in front.
    ///
    /// # Errors
    ///
    /// As [`path`](Self::path).
    #[cfg(windows)]
    pub fn powershell_command(script: &str) -> io::Result<Command> {
        let modules = tools::powershell_module_directory()?;
        let mut command = Self::Powershell.build()?;
        command
            .args(["-NoProfile", "-Command"])
            .arg(module_path_script(&modules.to_string_lossy(), script));
        Ok(command)
    }

    /// The argv text for logging: the absolute path followed by `args`. When the
    /// path is unavailable (see [`path`](Self::path)) it names the tool instead,
    /// since the text is only ever logged, never run.
    pub fn display_with<S: AsRef<str>>(self, args: &[S]) -> String {
        self.display_from(self.path(), args)
    }

    fn display_from<S: AsRef<str>>(self, path: io::Result<PathBuf>, args: &[S]) -> String {
        let mut out = match path {
            Ok(path) => path.display().to_string(),
            Err(_) => self.name().to_string(),
        };
        for a in args {
            out.push(' ');
            out.push_str(a.as_ref());
        }
        out
    }
}

/// `script` preceded by an assignment of `$env:PSModulePath`.
#[cfg(any(windows, test))]
fn module_path_script(modules: &str, script: &str) -> String {
    format!("$env:PSModulePath = {}; {script}", powershell_literal(modules))
}

/// `text` as a PowerShell single-quoted string. PowerShell treats U+2018..U+201B
/// as single quotes too, so each is doubled along with the ASCII one.
#[cfg(any(windows, test))]
fn powershell_literal(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('\'');
    for c in text.chars() {
        out.push(c);
        if matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}') {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

#[cfg(test)]
#[path = "system_tool_tests.rs"]
mod system_tool_tests;

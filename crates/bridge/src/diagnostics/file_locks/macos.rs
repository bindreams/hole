//! macOS handle-holder enumeration.
//!
//! We shell out to `lsof` (BSD tool, always available on macOS) rather
//! than calling `proc_listpidspath` via the `libproc` crate.
//!
//! # Why not libproc
//!
//! `libproc 0.14`'s `pids_by_path` reports a spurious `io::Error`
//! whenever `proc_listpidspath` returns 0 bytes (the "no matches"
//! case): it reads the thread's `errno` without first clearing it,
//! so leftover `errno` from an unrelated prior syscall masquerades
//! as a fresh error. Observed on GitHub Actions macOS 14/15 runners
//! as `EINVAL` / `ESRCH` even for valid empty enumerations. The
//! race is in libproc's `list_pids_ret`; we can't fix it from the
//! outside. Shelling out to `lsof` dodges the quirk and is what
//! `DistHarness` already implicitly relies on (the `lsof` helper is
//! present on every macOS runner in the matrix).
//!
//! # `lsof` output format (we use `-F`)
//!
//! `-F pcn` emits one field per line, each prefixed with a type
//! character: `p<pid>`, `c<command>`, `n<path>`. Records are
//! grouped per process. We only consume `p` (pid) and `c` (command)
//! — the filename argument scopes the query so every matched
//! process holds our file.

use super::FileHolder;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub(super) fn find_holders_impl(path: &Path) -> io::Result<Vec<FileHolder>> {
    // Canonicalize so macOS's `/var -> /private/var` tempdir alias
    // doesn't cause lsof to miss kernel-resolved vnode paths.
    let path = std::fs::canonicalize(path)?;

    // lsof: list processes holding `path`, one field per line.
    //   -F pc : emit only pid (p) and command (c) fields
    //   --    : end of options, next arg is a filename
    // Exit codes: 0 = matches found, 1 = no matches (NOT an error here).
    let out = Command::new("lsof")
        .args(["-F", "pc", "--"])
        .arg(&path)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()?;

    // lsof returns 1 when no processes have the file open; that's
    // not an error for us. Non-zero AND stderr-like failure would
    // return empty here too — diagnostics are best-effort.
    let stdout = String::from_utf8_lossy(&out.stdout);
    let holders = parse_lsof_fn_output(&stdout);

    let me = std::process::id();
    Ok(holders.into_iter().filter(|h| h.pid != me).collect())
}

/// Parse `lsof -F pc` output. Records are groups of lines prefixed by
/// field characters; `p<pid>` starts a new record, `c<command>` carries
/// the command name. We preserve the last-seen pid/command pair per
/// record.
fn parse_lsof_fn_output(s: &str) -> Vec<FileHolder> {
    let mut out = Vec::new();
    let mut current_pid: Option<u32> = None;
    let mut current_cmd: Option<String> = None;
    for line in s.lines() {
        if let Some(pid_str) = line.strip_prefix('p') {
            // Starting a new record: flush the previous one.
            if let Some(pid) = current_pid.take() {
                out.push(FileHolder {
                    pid,
                    image: current_cmd.take().map(PathBuf::from),
                });
            }
            current_pid = pid_str.parse::<u32>().ok();
            current_cmd = None;
        } else if let Some(cmd) = line.strip_prefix('c') {
            current_cmd = Some(cmd.to_owned());
        }
    }
    if let Some(pid) = current_pid {
        out.push(FileHolder {
            pid,
            image: current_cmd.map(PathBuf::from),
        });
    }
    out
}

#[cfg(test)]
mod macos_parse_tests {
    use super::parse_lsof_fn_output;

    #[skuld::test]
    fn parse_two_records() {
        let input = "p42\ncsleep\np17\nctail\n";
        let got = parse_lsof_fn_output(input);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].pid, 42);
        assert_eq!(got[0].image.as_ref().unwrap().to_str().unwrap(), "sleep");
        assert_eq!(got[1].pid, 17);
        assert_eq!(got[1].image.as_ref().unwrap().to_str().unwrap(), "tail");
    }

    #[skuld::test]
    fn parse_empty() {
        assert!(parse_lsof_fn_output("").is_empty());
    }

    #[skuld::test]
    fn parse_pid_without_command() {
        let got = parse_lsof_fn_output("p99\n");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].pid, 99);
        assert!(got[0].image.is_none());
    }
}

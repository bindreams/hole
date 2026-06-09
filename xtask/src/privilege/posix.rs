//! POSIX privilege effect layer. See `privilege.rs` for the public API.
use std::ffi::CString;
use std::io;
use std::os::unix::process::CommandExt as _;
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use nix::unistd::User;

use crate::privilege::{ElevateStrategy, Groups, Host, InvokingUser, Transition};

pub(super) fn detect(is_ci: bool) -> Host {
    // SAFETY: geteuid/isatty have no preconditions and never fail.
    let elevated = unsafe { libc::geteuid() } == 0;
    let has_tty = unsafe { libc::isatty(libc::STDIN_FILENO) } == 1;
    Host {
        elevated,
        invoking_user: resolve_invoking_user(),
        is_ci,
        has_tty,
        strategy: ElevateStrategy::Posix,
    }
}

/// The drop target: HOLE_BUILD_USER (explicit override) else SUDO_USER. A value
/// of `"root"` or one that does not resolve (a `getpwnam` miss, warned) yields
/// None — no drop. Note `HOLE_BUILD_USER=root` resolves to None (no drop) —
/// intended: it's the documented way to assert "no unprivileged user to honor."
fn resolve_invoking_user() -> Option<InvokingUser> {
    let name = std::env::var("HOLE_BUILD_USER")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("SUDO_USER").ok())?;
    if name == "root" {
        return None;
    }
    match User::from_name(&name) {
        Ok(Some(u)) => Some(InvokingUser::Posix {
            name: u.name,
            uid: u.uid.as_raw(),
            gid: u.gid.as_raw(),
            // `nix::User::dir` is already a `PathBuf`; bind it through `home: PathBuf`.
            home: u.dir,
        }),
        Ok(None) | Err(_) => {
            eprintln!("xtask: warning: invoking user {name:?} could not be resolved (getpwnam); running as-is");
            None
        }
    }
}

/// Prime sudo so per-step `sudo -n` succeeds. Probe `sudo -n true` (passwordless
/// CI or cached cred); else interactive `sudo -v` if a TTY; else hard fail.
/// NEVER a blind `sudo -v` (it fails on macOS with no TTY).
///
/// `sudo -v` and the later per-step `sudo -n` share sudo's credential timestamp.
/// xtask runs both from the same process tree / controlling tty, so the cache
/// applies regardless of sudoers `timestamp_type` (tty/ppid/global). If a site
/// runs sudoers with an exotic per-tty scope AND xtask's children somehow ran on
/// a different tty, the per-step `sudo -n` would re-fail loudly (not silently
/// elevate) — acceptable per the contract.
pub(super) fn prime_sudo(host: &Host) -> Result<()> {
    if Command::new("sudo")
        .args(["-n", "true"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        return Ok(());
    }
    if host.has_tty
        && Command::new("sudo")
            .arg("-v")
            .status()
            .context("running `sudo -v`")?
            .success()
    {
        return Ok(());
    }
    bail!(
        "a step needs root but sudo credentials are unavailable and there is no TTY to prompt. \
         Re-run the whole command elevated (e.g. under `sudo`)."
    )
}

pub(super) fn run_command(transition: Transition, cmd: Command, groups: &Groups, label: &str) -> Result<()> {
    match transition {
        Transition::RunAsIs => crate::privilege::run_inherit(cmd, label),
        Transition::WarnVacuous(why) => {
            eprintln!("xtask: warning: {why}");
            crate::privilege::run_inherit(cmd, label)
        }
        Transition::HardFail(why) => Err(anyhow!("{label}: {why}")),
        Transition::DropTo(user) => crate::privilege::run_inherit(drop_to(cmd, &user, groups)?, label),
        Transition::ElevateChild => crate::privilege::run_inherit(sudo_wrap(cmd), label),
        Transition::SelfElevateProcess => Err(anyhow!(
            "{label}: internal: SelfElevateProcess is not a POSIX transition"
        )),
    }
}

/// Configure `cmd` to drop to `user` in the forked child. Groups precomputed in
/// the parent; the closure does only async-signal-safe libc syscalls.
fn drop_to(mut cmd: Command, user: &InvokingUser, groups: &Groups) -> Result<Command> {
    let InvokingUser::Posix { name, uid, gid, home } = user else {
        bail!("internal: non-POSIX InvokingUser");
    };
    let (uid, gid) = (*uid, *gid);
    let group_gids: Vec<libc::gid_t> = match groups {
        Groups::Full => getgrouplist(name, gid)?,
        Groups::Only(names) => names
            .iter()
            .map(|g| group_gid(g).ok_or_else(|| anyhow!("group {g:?} not found (getgrnam)")))
            .collect::<Result<_>>()?,
    };
    cmd.env("HOME", home).env("USER", name).env("LOGNAME", name);
    // SAFETY: runs in the forked child pre-exec; no allocation (group_gids moved
    // in, read-only), only async-signal-safe syscalls in setgroups→setgid→setuid order.
    unsafe {
        cmd.pre_exec(move || {
            if libc::setgroups(group_gids.len() as _, group_gids.as_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::setgid(gid as libc::gid_t) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::setuid(uid as libc::uid_t) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(cmd)
}

/// libc::getgrouplist with NGROUPS-aware growth (nix omits it on apple_targets).
fn getgrouplist(name: &str, gid: u32) -> Result<Vec<libc::gid_t>> {
    let c = CString::new(name).context("username has interior NUL")?;
    let mut ngroups: libc::c_int = 32;
    loop {
        let mut buf = vec![0 as libc::gid_t; ngroups as usize];
        let mut n = ngroups;
        // SAFETY: buf has `n` slots; getgrouplist writes ≤ n and updates n to the needed count.
        let rc = unsafe { libc::getgrouplist(c.as_ptr(), gid as _, buf.as_mut_ptr() as *mut _, &mut n) };
        if rc >= 0 {
            buf.truncate(n as usize);
            return Ok(buf);
        }
        // rc < 0: buffer too small. The `+1` makes growth UNCONDITIONALLY
        // monotone — that, not the assert, is what guarantees termination
        // (no arbitrary cap, no infinite spin) even if a broken libc fails to
        // update `n`. The debug_assert just documents/checks the normal
        // contract ("n holds the needed size") in dev builds.
        debug_assert!(n > ngroups, "getgrouplist should report the needed size on overflow");
        ngroups = n.max(ngroups + 1);
    }
}

pub(crate) fn group_gid(name: &str) -> Option<libc::gid_t> {
    let c = CString::new(name).ok()?;
    // SAFETY: getgrnam returns a pointer into static storage or null.
    let p = unsafe { libc::getgrnam(c.as_ptr()) };
    if p.is_null() {
        None
    } else {
        Some(unsafe { (*p).gr_gid })
    }
}

/// Wrap `cmd` to run elevated via sudo, non-interactively, preserving PATH/HOME
/// past secure_path. ALL `KEY=VALUE` assignments precede the program (env treats
/// trailing assignments as program args). No `--` (macOS BSD env rejects it).
fn sudo_wrap(cmd: Command) -> Command {
    let mut sudo = Command::new("sudo");
    sudo.arg("-n")
        .arg("--preserve-env=PATH,HOME,SKULD_LABELS,CI")
        .arg("env");
    // Assignments first: PATH/HOME (defeat secure_path) + the step's own env overrides.
    let kv = |k: &std::ffi::OsStr, v: &std::ffi::OsStr| {
        let mut s = k.to_os_string();
        s.push("=");
        s.push(v);
        s
    };
    sudo.arg(kv(
        std::ffi::OsStr::new("PATH"),
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    sudo.arg(kv(
        std::ffi::OsStr::new("HOME"),
        &std::env::var_os("HOME").unwrap_or_default(),
    ));
    for (k, v) in cmd.get_envs() {
        if let Some(v) = v {
            sudo.arg(kv(k, v));
        }
    }
    // Then program + args (program is resolved by PATH; never an option token).
    sudo.arg(cmd.get_program()).args(cmd.get_args());
    if let Some(d) = cmd.get_current_dir() {
        sudo.current_dir(d);
    }
    sudo
}

//! Windows privilege effect layer. See `privilege.rs` for the public API.
//!
//! All Windows handles use the inline RAII [`OwnedHandle`] guard.
//! `WaitForSingleObject(.., INFINITE)` awaits an external child exit (the
//! sanctioned exception to the no-timeout rule), never a self-sync timer.

use std::ffi::{c_void, OsStr};
use std::io::Read as _;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::FromRawHandle as _;
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, HANDLE, WAIT_OBJECT_0};
use windows::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TokenElevation, TokenIntegrityLevel,
    TokenLinkedToken, SECURITY_ATTRIBUTES, TOKEN_DUPLICATE, TOKEN_ELEVATION, TOKEN_LINKED_TOKEN, TOKEN_MANDATORY_LABEL,
    TOKEN_QUERY,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows::Win32::System::Pipes::CreatePipe;
use windows::Win32::System::SystemServices::SECURITY_MANDATORY_HIGH_RID;
use windows::Win32::System::Threading::{
    CreateProcessWithTokenW, GetCurrentProcess, GetExitCodeProcess, OpenProcessToken, ResumeThread, TerminateProcess,
    WaitForSingleObject, CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, INFINITE,
    LOGON_WITH_PROFILE, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
};
use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

use crate::privilege::{ElevateStrategy, Host, InvokingUser, Readiness, Transition};

/// `ERROR_CANCELLED` (1223) as an `HRESULT` (`0x800704C7`) — the code
/// `ShellExecuteExW` surfaces when the user declines the UAC prompt.
/// `WIN32_ERROR` has no `to_hresult()` in windows-rs 0.62, so we compare against
/// the literal (matching `crates/hole/src/setup.rs`).
const ERROR_CANCELLED_HRESULT: windows::core::HRESULT = windows::core::HRESULT(0x800704C7_u32 as i32);

/// UTF-16, NUL-terminated, for a `PCWSTR`/`PWSTR` arg.
fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

/// RAII close-on-drop for a HANDLE.
pub(super) struct OwnedHandle(pub HANDLE);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: the handle was returned by a successful Win32 call and is
            // owned by this guard; closing it exactly once on drop is sound.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

pub(super) fn detect(is_ci: bool) -> Host {
    let elevated = is_elevated().unwrap_or(false);
    let invoking_user = if elevated && linked_token().is_ok() {
        Some(InvokingUser::WindowsLinkedToken)
    } else {
        None
    };
    Host {
        elevated,
        invoking_user,
        is_ci,
        has_tty: false,
        strategy: ElevateStrategy::Windows,
    }
}

fn is_elevated() -> Result<bool> {
    // SAFETY: standard token-query; handle closed by guard.
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)?;
        let _g = OwnedHandle(token);
        let mut e = TOKEN_ELEVATION::default();
        let mut ret = 0u32;
        GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut e as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret,
        )?;
        Ok(e.TokenIsElevated != 0)
    }
}

/// The user's limited (medium-IL) linked primary-ready token. Caller owns it.
pub(super) fn linked_token() -> Result<OwnedHandle> {
    // SAFETY: query our token, then its linked token (elevated→limited needs no SeTcb).
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &mut token)?;
        let _g = OwnedHandle(token);
        let mut linked = TOKEN_LINKED_TOKEN::default();
        let mut ret = 0u32;
        GetTokenInformation(
            token,
            TokenLinkedToken,
            Some(&mut linked as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_LINKED_TOKEN>() as u32,
            &mut ret,
        )?;
        Ok(OwnedHandle(linked.LinkedToken))
    }
}

/// Re-launch this whole xtask process elevated via UAC (`ShellExecuteEx`
/// `runas`), wait for it, and report its exit code. `SW_SHOWNORMAL` (not
/// `SW_HIDE`) so the elevated console is visible — xtask is interactive build
/// tooling, unlike the hidden bridge installer. A declined prompt
/// (`ERROR_CANCELLED`) is a clear, non-generic error.
pub(super) fn self_elevate() -> Result<Readiness> {
    let exe = std::env::current_exe()?;
    let exe_w = wide(exe.as_os_str());
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let params = super::win_quote::join_command_line(&argv);
    let params_w = wide(std::ffi::OsStr::new(&params));
    let verb_w = wide(std::ffi::OsStr::new("runas"));
    // SAFETY: `info` is fully initialized with the correct `cbSize`; the `wide`
    // buffers outlive the call, keeping the PCWSTR pointers valid.
    // SEE_MASK_NOCLOSEPROCESS asks for a process handle in `info.hProcess`,
    // which the guard closes below.
    unsafe {
        let mut info = SHELLEXECUTEINFOW {
            cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
            lpVerb: PCWSTR(verb_w.as_ptr()),
            lpFile: PCWSTR(exe_w.as_ptr()),
            lpParameters: PCWSTR(params_w.as_ptr()),
            nShow: SW_SHOWNORMAL.0,
            ..Default::default()
        };
        ShellExecuteExW(&mut info).map_err(|e| {
            if e.code() == ERROR_CANCELLED_HRESULT {
                anyhow!("UAC elevation was declined")
            } else {
                anyhow!("UAC elevation (ShellExecuteEx runas) failed: {e}")
            }
        })?;
        let child = OwnedHandle(info.hProcess);
        if child.0.is_invalid() {
            bail!("ShellExecuteEx did not return a process handle for the elevated xtask child");
        }
        if WaitForSingleObject(child.0, INFINITE) != WAIT_OBJECT_0 {
            bail!("waiting on the elevated xtask child failed");
        }
        let mut code = 0u32;
        GetExitCodeProcess(child.0, &mut code)?;
        Ok(Readiness::ElevatedChildExited(code as i32))
    }
}

pub(super) fn run_command(transition: Transition, mut cmd: Command, label: &str) -> Result<()> {
    match transition {
        Transition::RunAsIs => crate::privilege::run_inherit(cmd, label),
        Transition::WarnVacuous(why) => {
            eprintln!("xtask: warning: {why}");
            crate::privilege::run_inherit(cmd, label)
        }
        Transition::HardFail(why) => Err(anyhow!("{label}: {why}")),
        Transition::DropTo(_) => de_elevate(&mut cmd, label)
            .map(|_| ())
            .with_context(|| format!("de-elevating {label}")),
        Transition::ElevateChild => Err(anyhow!("{label}: internal: ElevateChild is not a Windows transition")),
        Transition::SelfElevateProcess => Err(anyhow!(
            "{label}: internal: SelfElevateProcess must be handled up front"
        )),
    }
}

/// One anonymous pipe whose child-facing WRITE end is inheritable (the child's
/// stdout/stderr) and whose parent-facing READ end is not.
struct InheritablePipe {
    /// Parent's read end (the relay reads from here). Not inheritable.
    parent: OwnedHandle,
    /// Child's write end. Inheritable; closed by the parent once relays start.
    child: OwnedHandle,
}

/// A `SECURITY_ATTRIBUTES` requesting an inheritable handle.
fn inheritable_sa() -> SECURITY_ATTRIBUTES {
    SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: true.into(),
    }
}

/// Create an anonymous pipe whose WRITE end (the child's stdout/stderr) is
/// inheritable and whose READ end (the parent's relay) is not.
///
/// `CreatePipe` marks BOTH ends inheritable (the `SECURITY_ATTRIBUTES` applies
/// to both), so we clear the inherit flag on the parent read end — otherwise the
/// child would inherit a copy and the relay's read would never EOF.
fn make_pipe() -> Result<InheritablePipe> {
    let sa = inheritable_sa();
    let mut read = HANDLE::default();
    let mut write = HANDLE::default();
    // SAFETY: out-params are valid; both handles are wrapped in guards below.
    unsafe { CreatePipe(&mut read, &mut write, Some(&sa), 0).context("CreatePipe")? };
    let (parent, child) = (OwnedHandle(read), OwnedHandle(write));
    clear_inherit(&parent).context("clearing inherit flag on the parent pipe read end")?;
    Ok(InheritablePipe { parent, child })
}

/// Clear `HANDLE_FLAG_INHERIT` so the child does not inherit this handle.
fn clear_inherit(h: &OwnedHandle) -> Result<()> {
    use windows::Win32::Foundation::{SetHandleInformation, HANDLE_FLAGS, HANDLE_FLAG_INHERIT};
    // SAFETY: `h` is a live handle owned by the guard.
    unsafe { SetHandleInformation(h.0, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0))? };
    Ok(())
}

/// An inheritable handle to the `NUL` device opened for reading — the child's
/// stdin. `CreateProcessWithTokenW` requires a real handle when
/// `STARTF_USESTDHANDLES` is set; a null stdin would otherwise be inherited.
fn nul_stdin() -> Result<OwnedHandle> {
    let sa = inheritable_sa();
    let name = wide(OsStr::new("NUL"));
    // SAFETY: `name` outlives the call; the returned handle is owned by the guard.
    let h = unsafe {
        CreateFileW(
            PCWSTR(name.as_ptr()),
            GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            Some(&sa),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .context("opening NUL for the de-elevated child's stdin")?
    };
    Ok(OwnedHandle(h))
}

/// Read the PE `Machine` field of `exe` and assert it is a 64-bit machine.
///
/// `CreateProcessWithTokenW` has a documented WOW64 bug: launching a 32-bit
/// child silently drops the inherited std handles, so the relay pipes would
/// never receive output. We check the exe FILE's PE header before launch (the
/// running-process `IsWow64Process2` API cannot be used pre-creation). The repo
/// is amd64-only, but an arm64 child is equally valid; both are accepted, only
/// `i386`/`THUMB`/etc. are rejected.
fn assert_child_is_64bit(exe: &std::path::Path) -> Result<()> {
    use std::io::{Read, Seek, SeekFrom};
    const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
    const IMAGE_FILE_MACHINE_ARM64: u16 = 0xAA64;

    // Read a too-short file as a hard error rather than reading garbage: a
    // truncated/non-PE file would otherwise yield an arbitrary `Machine` value.
    let short = |what: &str| format!("child exe {} is too short to be a PE image ({what})", exe.display());

    let mut f = std::fs::File::open(exe).with_context(|| format!("opening child exe {}", exe.display()))?;
    // DOS header: "MZ" magic at offset 0, then e_lfanew (PE header offset) at 0x3C.
    let mut dos = [0u8; 2];
    f.read_exact(&mut dos).map_err(|_| anyhow!(short("no DOS header")))?;
    if &dos != b"MZ" {
        bail!(
            "child exe {} is not a PE image (missing \"MZ\" DOS signature)",
            exe.display()
        );
    }
    f.seek(SeekFrom::Start(0x3C)).context("seeking to e_lfanew")?;
    let mut lfanew = [0u8; 4];
    f.read_exact(&mut lfanew).map_err(|_| anyhow!(short("no e_lfanew")))?;
    let pe_off = u32::from_le_bytes(lfanew) as u64;
    // PE header: 4-byte "PE\0\0" signature, then the COFF header whose first
    // field (2 bytes) is Machine.
    f.seek(SeekFrom::Start(pe_off)).context("seeking to the PE signature")?;
    let mut sig = [0u8; 4];
    f.read_exact(&mut sig).map_err(|_| anyhow!(short("no PE signature")))?;
    if &sig != b"PE\0\0" {
        bail!(
            "child exe {} is not a PE image (missing \"PE\\0\\0\" signature at e_lfanew)",
            exe.display()
        );
    }
    let mut machine = [0u8; 2];
    f.read_exact(&mut machine)
        .map_err(|_| anyhow!(short("no COFF Machine field")))?;
    let machine = u16::from_le_bytes(machine);
    match machine {
        IMAGE_FILE_MACHINE_AMD64 | IMAGE_FILE_MACHINE_ARM64 => Ok(()),
        other => bail!(
            "child exe {} is not 64-bit (PE Machine = {other:#06x}); CreateProcessWithTokenW \
             silently drops a 32-bit child's std handles (WOW64 bug)",
            exe.display()
        ),
    }
}

/// Build a UTF-16, double-NUL-terminated environment block = the current
/// process env merged with `cmd`'s overrides (`None` value = removal).
///
/// `CreateProcessWithTokenW` with `lpEnvironment = NULL` would inherit the
/// *elevated* xtask env, dropping per-step `environment:` overrides. We pass an
/// explicit block built from our env (the elevated process's env, which is what
/// the dropped child should see) overlaid with the step's overrides.
fn build_env_block(cmd: &Command) -> Vec<u16> {
    use std::collections::BTreeMap;
    use std::ffi::OsString;

    let mut env: BTreeMap<OsString, OsString> = std::env::vars_os().collect();
    for (k, v) in cmd.get_envs() {
        match v {
            Some(v) => {
                env.insert(k.to_os_string(), v.to_os_string());
            }
            None => {
                env.remove(k);
            }
        }
    }

    let mut block: Vec<u16> = Vec::new();
    for (k, v) in &env {
        block.extend(k.encode_wide());
        block.push(b'=' as u16);
        block.extend(v.encode_wide());
        block.push(0);
    }
    // A trailing NUL terminates the block (double-NUL after the last entry).
    block.push(0);
    block
}

/// `true` iff `token`'s integrity level is at or above High (i.e. NOT dropped).
/// Used to assert the de-elevated child really lost its elevation before resume.
fn token_is_high_or_above(token: HANDLE) -> Result<bool> {
    // SAFETY: two-call GetTokenInformation pattern; the buffer is sized by the
    // first call's `ret`, and the SID pointer is read only while the buffer lives.
    unsafe {
        let mut ret = 0u32;
        // First call sizes the buffer (expected to fail with insufficient buffer).
        let _ = GetTokenInformation(token, TokenIntegrityLevel, None, 0, &mut ret);
        if ret == 0 {
            bail!("GetTokenInformation(TokenIntegrityLevel) returned a zero size");
        }
        let mut buf = vec![0u8; ret as usize];
        GetTokenInformation(
            token,
            TokenIntegrityLevel,
            Some(buf.as_mut_ptr() as *mut c_void),
            ret,
            &mut ret,
        )
        .context("GetTokenInformation(TokenIntegrityLevel)")?;
        let label = &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
        let sid = label.Label.Sid;
        let count_ptr = GetSidSubAuthorityCount(sid);
        if count_ptr.is_null() || *count_ptr == 0 {
            bail!("integrity-level SID has no sub-authorities");
        }
        let last = (*count_ptr as u32) - 1;
        let rid = *GetSidSubAuthority(sid, last);
        Ok(rid >= SECURITY_MANDATORY_HIGH_RID as u32)
    }
}

/// Reaping job, mirroring `crates/garter/src/proc_group.rs`: a
/// `KILL_ON_JOB_CLOSE` Job Object whose membership is reaped when the handle
/// closes. Closing it before joining the relays reaps a pipe-holding grandchild
/// so the relays can EOF (the #197 lesson).
fn create_kill_on_close_job() -> Result<OwnedHandle> {
    // SAFETY: standard job creation; the handle is owned by the guard.
    unsafe {
        let job = CreateJobObjectW(None, PCWSTR::null()).context("CreateJobObjectW")?;
        let job = OwnedHandle(job);
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(
            job.0,
            JobObjectExtendedLimitInformation,
            std::ptr::addr_of!(info).cast(),
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
        .context("SetInformationJobObject")?;
        Ok(job)
    }
}

/// De-elevate `cmd` onto the invoking user's linked token. Returns the
/// `ResumeThread` previous suspend count (`1` proves `CREATE_SUSPENDED` was
/// honored) so the suspend-rendezvous test can assert it.
///
/// Loud-fails EVERY branch: there is no path that resumes or runs an elevated
/// child. See the module docs and the 9-step sequence in the implementation.
fn de_elevate(cmd: &mut Command, label: &str) -> Result<u32> {
    // 1. Resolve program + args and assert the child is 64-bit (WOW64 stdio bug).
    let program = std::path::PathBuf::from(cmd.get_program());
    let exe = which_exe(&program).with_context(|| format!("resolving child program {program:?}"))?;
    assert_child_is_64bit(&exe)?;

    let mut argv: Vec<String> = vec![exe.to_string_lossy().into_owned()];
    for a in cmd.get_args() {
        argv.push(a.to_string_lossy().into_owned());
    }
    let cmdline = super::win_quote::join_command_line(&argv);
    let mut cmdline_w = wide(OsStr::new(&cmdline));

    let cwd = cmd.get_current_dir().map(|p| wide(p.as_os_str()));

    // 2. Three dedicated inheritable pipes + an inheritable NUL stdin.
    let stdin = nul_stdin()?;
    let out = make_pipe()?;
    let err = make_pipe()?;

    // 3. Env block: our env overlaid with the step's overrides.
    let mut env_block = build_env_block(cmd);

    // 4. CreateProcessWithTokenW(CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP | CREATE_UNICODE_ENVIRONMENT).
    let linked = linked_token().context("obtaining the invoking user's linked token")?;
    let si = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        dwFlags: STARTF_USESTDHANDLES,
        hStdInput: stdin.0,
        hStdOutput: out.child.0,
        hStdError: err.child.0,
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();
    let cwd_ptr = cwd.as_ref().map(|c| PCWSTR(c.as_ptr())).unwrap_or_else(PCWSTR::null);
    // SAFETY: all pointers (cmdline, env, cwd, si, pi) outlive the call; the
    // returned process/thread handles are wrapped in guards immediately.
    unsafe {
        CreateProcessWithTokenW(
            linked.0,
            LOGON_WITH_PROFILE,
            PCWSTR::null(),
            Some(PWSTR(cmdline_w.as_mut_ptr())),
            CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP | CREATE_UNICODE_ENVIRONMENT,
            Some(env_block.as_mut_ptr() as *const c_void),
            cwd_ptr,
            &si,
            &mut pi,
        )
        .context("CreateProcessWithTokenW")?;
    }
    let proc = OwnedHandle(pi.hProcess);
    let thread = OwnedHandle(pi.hThread);

    // The child holds its own inheritable copies of the std handles now; the
    // job + IL checks happen in the suspended window before any code runs.
    let resume_count = run_suspended_child(&proc, &thread, label, out, err)?;
    Ok(resume_count)
}

/// Test-only entry point: de-elevate `cmd` and return the `ResumeThread`
/// previous suspend count (`1` proves `CREATE_SUSPENDED` was honored). The
/// suspend-rendezvous effect test asserts this is `1`.
#[cfg(test)]
pub(crate) fn de_elevate_for_test(cmd: &mut Command, label: &str) -> Result<u32> {
    de_elevate(cmd, label)
}

/// The suspended-window sequence (steps 5-9). Split out so `de_elevate`'s
/// pipe/handle guards drop in the right order and every early return reaps the
/// suspended child.
fn run_suspended_child(
    proc: &OwnedHandle,
    thread: &OwnedHandle,
    label: &str,
    out: InheritablePipe,
    err: InheritablePipe,
) -> Result<u32> {
    // 5. Assert the child's integrity level dropped below High. If not, this is
    //    NOT a de-elevated child — terminate and hard-fail (never resume it).
    let child_high = {
        let mut ctoken = HANDLE::default();
        // SAFETY: query the suspended child's token; guard closes it.
        let r = unsafe { OpenProcessToken(proc.0, TOKEN_QUERY, &mut ctoken) };
        match r {
            Ok(()) => {
                let _g = OwnedHandle(ctoken);
                token_is_high_or_above(ctoken)
            }
            Err(e) => Err(anyhow!("OpenProcessToken on the suspended child failed: {e}")),
        }
    };
    let child_high = match child_high {
        Ok(v) => v,
        Err(e) => {
            terminate(proc);
            return Err(e.context("checking the suspended child's integrity level"));
        }
    };
    if child_high {
        terminate(proc);
        bail!("{label}: de-elevated child is still at High integrity (token did not drop); refusing to resume");
    }

    // 6. Reaping job; assign the suspended child. Failure → terminate + hard-fail
    //    (a child outside the job could escape reaping — never run it elevated-adjacent).
    let job = match create_kill_on_close_job() {
        Ok(j) => j,
        Err(e) => {
            terminate(proc);
            return Err(e);
        }
    };
    // SAFETY: both handles are live; assigning a suspended child to an empty job
    // succeeds under the nested-job rules.
    if let Err(e) = unsafe { AssignProcessToJobObject(job.0, proc.0) } {
        terminate(proc);
        return Err(anyhow!(
            "AssignProcessToJobObject failed: {e}; refusing to run the child outside its reaping job"
        ));
    }

    // 7. Spawn relay threads reading the parent ends; hand the child-side write
    //    ends to be closed so EOF can propagate once the child (and any
    //    grandchild) releases them.
    let out_relay = spawn_relay(out.parent, RelayTarget::Stdout);
    let err_relay = spawn_relay(err.parent, RelayTarget::Stderr);
    drop(out.child); // close our copy of the child-side write ends
    drop(err.child);

    // 8. Resume. The previous suspend count MUST be 1 — proof CREATE_SUSPENDED
    //    was honored through seclogon (0 = ignored → the child already ran). The
    //    last mutation before waiting.
    // SAFETY: `thread` is the live primary thread handle from CreateProcess.
    let prev = unsafe { ResumeThread(thread.0) };
    if prev != 1 {
        // The child may already be running (CREATE_SUSPENDED ignored). Reap via
        // the job and hard-fail — we cannot prove it de-elevated correctly.
        drop(job);
        let _ = out_relay.join();
        let _ = err_relay.join();
        bail!(
            "{label}: ResumeThread returned previous suspend count {prev}, expected 1; \
             CREATE_SUSPENDED was not honored — refusing to trust this child"
        );
    }

    // 9. Wait for exit, read the code, THEN close the job BEFORE joining relays
    //    (a pipe-holding grandchild would otherwise hang the relay join — the
    //    proc_group.rs #197 lesson), then join.
    // SAFETY: `proc` is the live child process handle; INFINITE awaits its exit.
    let code = unsafe {
        if WaitForSingleObject(proc.0, INFINITE) != WAIT_OBJECT_0 {
            // Reap and join before surfacing the error so no relay/grandchild lingers.
            drop(job);
            let _ = out_relay.join();
            let _ = err_relay.join();
            bail!("{label}: waiting on the de-elevated child failed");
        }
        let mut code = 0u32;
        GetExitCodeProcess(proc.0, &mut code).context("GetExitCodeProcess")?;
        code
    };

    drop(job); // reap stragglers + release their write ends → relays EOF
    let _ = out_relay.join();
    let _ = err_relay.join();

    if code != 0 {
        bail!("{label} failed: exit code {code}");
    }
    Ok(prev)
}

/// Force-terminate a suspended/misbehaving child. Best-effort; used only on
/// hard-fail paths where the child must never run.
fn terminate(proc: &OwnedHandle) {
    // SAFETY: `proc` is a live process handle; terminating it is sound.
    unsafe {
        let _ = TerminateProcess(proc.0, 1);
    }
}

/// Which parent stream a relay copies its pipe into.
enum RelayTarget {
    Stdout,
    Stderr,
}

/// Spawn a thread that copies the pipe `read_end` byte-for-byte into the
/// parent's real stdout/stderr until EOF, then returns. Takes ownership of the
/// handle (closed when the wrapping `File` drops).
fn spawn_relay(read_end: OwnedHandle, target: RelayTarget) -> std::thread::JoinHandle<()> {
    // Take the raw handle out of the guard so the File owns it (no double-close).
    // Send it as an integer — a raw `*mut c_void` is `!Send`, but a pipe HANDLE
    // is a process-wide kernel handle that is sound to use from another thread.
    let raw = read_end.0 .0 as isize;
    std::mem::forget(read_end);
    std::thread::spawn(move || {
        // SAFETY: `raw` is a valid pipe read handle whose ownership we took above.
        let mut file = unsafe { std::fs::File::from_raw_handle(raw as *mut c_void) };
        let mut buf = [0u8; 8192];
        loop {
            match file.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    use std::io::Write as _;
                    let written = match target {
                        RelayTarget::Stdout => std::io::stdout().write_all(&buf[..n]),
                        RelayTarget::Stderr => std::io::stderr().write_all(&buf[..n]),
                    };
                    if written.is_err() {
                        break;
                    }
                }
            }
        }
    })
}

/// Resolve a program name to an absolute executable path. An absolute/relative
/// path with a separator is used as-is (with a `.exe` fallback); a bare name is
/// searched on `PATH`.
fn which_exe(program: &std::path::Path) -> Result<std::path::PathBuf> {
    if program.components().count() > 1 || program.is_absolute() {
        if program.is_file() {
            return Ok(program.to_path_buf());
        }
        let with_exe = program.with_extension("exe");
        if with_exe.is_file() {
            return Ok(with_exe);
        }
        bail!("program path {program:?} does not exist (tried {with_exe:?})");
    }
    // Bare name: search PATH, honoring PATHEXT for the .exe extension.
    let path = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path) {
        for ext in ["", "exe", "EXE"] {
            let cand = if ext.is_empty() {
                dir.join(program)
            } else {
                dir.join(program).with_extension(ext)
            };
            if cand.is_file() {
                return Ok(cand);
            }
        }
    }
    bail!("could not find {program:?} on PATH")
}

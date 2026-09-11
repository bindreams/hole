# Runs msiexec (install or uninstall) with a bounded wait instead of an
# unbounded `Start-Process -Wait`. `Process.WaitForExit(ms)` returns false on
# timeout without touching the process, so a wedged msiexec fails this step
# with diagnostics -- log tail, HoleBridge service state, surviving hole.exe
# processes, msiexec's own process tree, and every thread's native call stack
# -- instead of hanging until the JOB timeout kills the whole job and every
# step after this one (including any artifact upload) never runs.
#
# Shared by both the Install and Uninstall CI steps: they carry the same
# unbounded-wait exposure, so the fix lives once here rather than twice in
# ci.yaml.
#
# `-ExePath`/`-ExeArgs` are a test seam: they substitute the process actually
# started, so the bound + diagnostic-capture path can be exercised against a
# stand-in that never exits, without a real MSI transaction. Every ci.yaml
# call site leaves them at their defaults.
param(
    [Parameter(Mandatory)]
    [ValidateSet('/i', '/x')]
    [string]$Verb,

    [Parameter(Mandatory)]
    [string]$MsiPath,

    [Parameter(Mandatory)]
    [string]$LogPath,

    # No direct cold-run measurement exists for this job -- CI here runs
    # often enough that sccache has never been observed to go fully cold --
    # so this is derived, not measured: the sibling `test-dmg-signing` job
    # (same `timeout-minutes: 60`, held equal by
    # `ci_installer_assembly_jobs_share_a_timeout_budget`) recorded its
    # darwin/amd64 leg at 1.83x slower cold than warm (45m45s vs ~25min).
    # Applied to this job's observed ~17-27min warm range, a cold run could
    # reach ~49min, leaving ~11min of the 60min wall if both Install and
    # Uninstall wedge in the same run -- and a wedge on Install skips the
    # E2E/tauri-driver steps that make up part of that warm baseline, so this
    # is already a pessimistic estimate. 3 minutes each leaves comfortable
    # margin; the steps themselves normally complete in 2-4 seconds, so a
    # much smaller bound loses nothing.
    [ValidateRange(0.0, 60.0)]
    [double]$BoundMinutes = 3,

    # Total wall-clock budget for the thread-stack capture at expiry, shared
    # across every target process rather than granted per target, so the wedge
    # branch's cost stays bounded however many hole.exe/msiexec.exe processes
    # survive. Spent in evidentiary order (bridge first), so an exhausted
    # budget costs the least-informative capture, not the decisive one.
    #
    # Sized against what is actually spare in the 60min job budget, which is
    # NOT the ~11min above: 6 of those minutes are already committed to the
    # two 3-minute bounds when both steps wedge, leaving ~5min.
    #
    # This budget covers the capture loop only, so the wedge branch's real
    # worst case is the sum of every bound in it: two 15s CIM probes before
    # the loop, this 60s, and a 5s reap per process killed (one cdb, at most
    # one per target, at most one per msiexec-tree member) -- about 2min 10s
    # for a plausible four targets. Both steps wedging spends that twice,
    # ~4.5min of the ~5min spare, and the artifact upload -- the whole reason
    # the bound exists -- still runs.
    #
    # Measured cost is far under the cap: 33s for one process against a cold
    # symbol cache and 0.3s against a warm one (Windows 11 26100, SDK
    # 10.0.26100 cdb), with the two steps sharing one cache under RUNNER_TEMP.
    # Every one of these is a failure bound, not an expected duration.
    [ValidateRange(0.0, 3600.0)]
    [double]$StackCaptureSeconds = 60,

    # Install failure is fatal; Uninstall is best-effort cleanup -- callers set
    # this switch to match their own error-handling policy. A wedge is fatal
    # either way regardless of this switch (see the `throw` below).
    [switch]$FailOnNonZeroExit,

    [string]$ExePath = "msiexec",
    [string[]]$ExeArgs,

    # Second test seam, same shape as -ExePath: substitutes the debugger the
    # capture shells out to, so a stand-in that never exits drives the
    # capture's own bound. Empty means "find the real cdb" -- every ci.yaml
    # call site leaves it that way.
    [string]$CdbPath
)

if (-not $ExeArgs) {
    $ExeArgs = @($Verb, $MsiPath, "/quiet", "/norestart", "/l*vx", $LogPath)
}

# The wedge branch's helpers: the process-tree walk and the native thread-stack
# capture. Dot-sourced rather than inlined so this file keeps the shape of what
# it does -- run bounded, probe, capture, kill, throw -- at one level.
. (Join-Path $PSScriptRoot 'wedge-diagnostics.ps1')

# `Start-Process -ArgumentList` joins array elements with a single space and
# does not quote them (documented behavior) -- an element containing
# whitespace, e.g. a python `-c` payload from the -ExeArgs test seam, is
# otherwise split into multiple argv entries by the child process.
$quotedExeArgs = $ExeArgs | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }
$proc = Start-Process $ExePath -ArgumentList $quotedExeArgs -PassThru

if (-not $proc.WaitForExit([int]($BoundMinutes * 60000))) {
    Write-Host "::error::msiexec $Verb did not exit within $BoundMinutes minute(s) -- capturing diagnostics before failing the step"

    # Each probe below is isolated in its own try/catch: pwsh's default
    # `$ErrorActionPreference = 'Stop'` turns any unhandled error -- e.g. the
    # log read below, which races a msiexec that is still alive and still
    # holding the file open under `/l*vx` -- into a terminating one that would
    # otherwise abort this whole block, including the `throw` at the end, and
    # fail the step with no diagnostics at all.

    Write-Host "--- MSI log tail: $LogPath ---"
    try {
        if (Test-Path $LogPath) {
            Get-Content $LogPath -Tail 50 -ErrorAction Stop
        } else {
            Write-Host "(log not found at $LogPath)"
        }
    } catch {
        Write-Host "(failed to read ${LogPath}: $($_.Exception.Message))"
    }

    Write-Host "--- HoleBridge service state ---"
    try {
        $svc = Get-Service -Name HoleBridge -ErrorAction SilentlyContinue
        # Named properties rather than `*`: ServiceController's
        # DependentServices/ServicesDependedOn/RequiredServices each make a
        # fresh, unbounded SCM RPC on access -- on the very SCM that is failing
        # to answer SERVICE_CONTROL_STOP -- and HoleBridge declares no
        # dependencies either way. Everything else `*` printed is still here.
        if ($svc) {
            $svc | Format-List Name, DisplayName, Status, StartType, ServiceType, CanStop, CanShutdown, CanPauseAndContinue, MachineName
        } else { Write-Host "(HoleBridge service not registered)" }
    } catch {
        Write-Host "(failed to query HoleBridge service: $($_.Exception.Message))"
    }

    Write-Host "--- hole.exe processes ---"
    try {
        $holeProcs = Get-Process hole -ErrorAction SilentlyContinue
        if ($holeProcs) { $holeProcs | Format-List Id, ProcessName, Path, StartTime, Responding, SessionId } else { Write-Host "(no hole.exe process running)" }
    } catch {
        Write-Host "(failed to query hole.exe processes: $($_.Exception.Message))"
    }

    # `Get-Process` above has no ParentProcessId/CommandLine -- same gap the
    # msiexec probe below works around via CIM. A second, unexpected hole.exe
    # (e.g. a distinct session/parent from the service's) is otherwise
    # unattributable to whatever launched it.
    Write-Host "--- hole.exe process tree (parent pid + command line) ---"
    try {
        $holeCimProcs = Get-CimInstance Win32_Process -Filter "Name = 'hole.exe'" -OperationTimeoutSec $cimProbeTimeoutSeconds -ErrorAction Stop
        if ($holeCimProcs) { $holeCimProcs | Select-Object ProcessId, ParentProcessId, SessionId, CreationDate, CommandLine | Format-Table -AutoSize | Out-String -Width 4096 } else { Write-Host "(no hole.exe process running)" }
    } catch {
        Write-Host "(CIM query for hole.exe failed: $($_.Exception.Message))"
    }

    # Unlike Get-Service/Get-Process above, Get-CimInstance returns an empty
    # result silently on a genuinely empty query -- it does not raise the
    # non-terminating error `-ErrorAction SilentlyContinue` is meant to
    # swallow. Suppressing errors here would print "no msiexec.exe process
    # running" for a failed WMI query too, exactly when the host is unhealthy
    # enough for that to be false.
    Write-Host "--- msiexec process tree ---"
    $msiProcs = $null
    try {
        $msiProcs = Get-CimInstance Win32_Process -Filter "Name = 'msiexec.exe'" -OperationTimeoutSec $cimProbeTimeoutSeconds -ErrorAction Stop
        if ($msiProcs) { $msiProcs | Select-Object ProcessId, ParentProcessId, CreationDate, CommandLine | Format-Table -AutoSize | Out-String -Width 4096 } else { Write-Host "(no msiexec.exe process running)" }
    } catch {
        Write-Host "(CIM query for msiexec.exe failed: $($_.Exception.Message))"
    }

    # Shared by the stack capture and the kill below: both act on exactly the
    # process tree this script started, and computing it once keeps them from
    # disagreeing about what "the wedged tree" is.
    $wedgedTreeIds = @($proc.Id)
    try {
        if ($msiProcs) { $wedgedTreeIds = Get-DescendantProcessIds -RootId $proc.Id -AllProcs $msiProcs }
    } catch {
        Write-Host "::warning::failed to walk the wedged process tree, falling back to pid $($proc.Id) alone: $($_.Exception.Message)"
    }

    # Pin each tree member against pid reuse for as long as this block holds the
    # object. The capture below runs for up to a minute between reading these
    # pids and acting on them, and a descendant that exits in that window
    # releases its number to whatever the kernel hands it to next -- including
    # the bridge SCM restarts after a suspended target is terminated. `$proc` is
    # already pinned: this script started it and holds its handle.
    $wedgedTreePins = @{}
    foreach ($treeId in $wedgedTreeIds) {
        $pinned = Get-PinnedProcess ([int]$treeId)
        if ($pinned) { $wedgedTreePins[[int]$treeId] = $pinned }
        else { Write-Host "::warning::could not pin pid ${treeId} against reuse; it will be killed by pid alone" }
    }

    Write-Host "--- native thread stacks ---"
    $suspendedTargetIds = @(Invoke-ThreadStackCapture -LogPath $LogPath -WedgedTreeIds $wedgedTreeIds `
            -BudgetSeconds $StackCaptureSeconds -DebuggerPathOverride $CdbPath)

    # Nothing else in this job releases a target the capture left suspended:
    # the tree kill below covers the msiexec tree only, and ci.yaml's
    # "Kill hole.exe after E2E" runs BEFORE Uninstall, not after it. A
    # suspended HoleBridge would therefore survive this step unable to answer
    # the very SERVICE_CONTROL_STOP whose absence is under investigation --
    # the instrument manufacturing the hang it exists to diagnose.
    #
    # Terminating it is not the end of the story, and the log says so: the
    # service carries SCM restart-on-failure with a 1s delay
    # (`restart_failure_actions` in crates/bridge/src/platform/windows.rs), and
    # a force-kill counts as a failure, so a FRESH bridge appears about a
    # second later. That is still strictly better than a frozen one -- a live
    # bridge can be stopped, a suspended one can not -- but whatever reads the
    # next steps needs to know the process it sees is not the wedged one.
    if ($suspendedTargetIds) {
        Write-Host "--- terminating targets the capture left suspended ---"
        foreach ($suspendedId in $suspendedTargetIds) {
            try {
                Stop-Process -Id $suspendedId -Force -ErrorAction Stop
                Wait-ProcessReaped -ProcessId $suspendedId -What 'suspended capture target'
                Write-Host "terminated suspended pid $suspendedId (if this was HoleBridge, SCM restarts it ~1s later as a fresh process)"
            } catch {
                Write-Host "::warning::failed to terminate suspended pid ${suspendedId}: $($_.Exception.Message)"
            }
        }
    }

    # Kill the tree so a wedged msiexec doesn't outlive this step: on Install
    # it would hold the `_MSIExecute` mutex against the Uninstall step that
    # runs next (`if: always()`), and on Uninstall it would keep appending to
    # the log while "Upload MSI logs" reads it. Best-effort and isolated like
    # the probes above -- a failure here must not swallow the wedge `throw`.
    # Deferred by the whole capture above -- its budget plus the reaps -- so
    # the stacks are taken from a live tree; the msiexec log keeps growing for
    # that long, which the tail printed earlier is already past.
    Write-Host "--- killing wedged process tree ---"
    try {
        # A tree member already terminated for being left suspended would
        # otherwise be reported here as a kill failure.
        $targetIds = @($wedgedTreeIds | Where-Object { $_ -notin $suspendedTargetIds })
        $killed = @()
        $failed = @()
        foreach ($targetId in $targetIds) {
            try {
                # By handle where one was pinned, so the kill cannot land on an
                # unrelated process that inherited the number in the meantime.
                $pin = $wedgedTreePins[[int]$targetId]
                if ($pin) { Stop-Process -InputObject $pin -Force -ErrorAction Stop }
                else { Stop-Process -Id $targetId -Force -ErrorAction Stop }
                # `-Force` calls TerminateProcess, which returns synchronously
                # without waiting for the process to actually be reaped --
                # same reasoning as the `Wait-Process` after `Stop-Process` in
                # the "Kill any running hole.exe" step.
                Wait-ProcessReaped -ProcessId $targetId -What 'wedged tree member'
                $killed += $targetId
            } catch {
                $failed += "$targetId ($($_.Exception.Message))"
            }
        }
        if ($killed) { Write-Host "killed process id(s): $($killed -join ', ')" }
        if ($failed) { Write-Host "::warning::failed to kill process id(s): $($failed -join '; ')" }
    } catch {
        Write-Host "::warning::failed to kill the wedged process tree: $($_.Exception.Message)"
    }

    throw "msiexec $Verb wedged: did not exit within $BoundMinutes minute(s)"
}

if ($proc.ExitCode -ne 0) {
    # Same isolation as the wedge branch above: a log read that races a
    # not-yet-released handle must not swallow the exit-code message below.
    try {
        if (Test-Path $LogPath) { Get-Content $LogPath -Tail 50 -ErrorAction Stop }
    } catch {
        Write-Host "(failed to read ${LogPath}: $($_.Exception.Message))"
    }
    $message = "msiexec $Verb failed with exit code $($proc.ExitCode)"
    if ($FailOnNonZeroExit) { throw $message } else { Write-Warning $message }
}

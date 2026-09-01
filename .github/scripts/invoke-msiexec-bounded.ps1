# Runs msiexec (install or uninstall) with a bounded wait instead of an
# unbounded `Start-Process -Wait`. `Process.WaitForExit(ms)` returns false on
# timeout without touching the process, so a wedged msiexec fails this step
# with diagnostics -- log tail, HoleBridge service state, surviving hole.exe
# processes, msiexec's own process tree -- instead of hanging until the JOB
# timeout kills the whole job and every step after this one (including any
# artifact upload) never runs.
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
    [double]$BoundMinutes = 3,

    # Install failure is fatal; Uninstall is best-effort cleanup -- callers set
    # this switch to match their own error-handling policy. A wedge is fatal
    # either way regardless of this switch (see the `throw` below).
    [switch]$FailOnNonZeroExit,

    [string]$ExePath = "msiexec",
    [string[]]$ExeArgs
)

if (-not $ExeArgs) {
    $ExeArgs = @($Verb, $MsiPath, "/quiet", "/norestart", "/l*vx", $LogPath)
}

# Walks the Win32_Process table from $RootId through ParentProcessId links,
# returning every pid in the tree. msiexec commonly re-launches itself as an
# elevated child to run the actual transaction, so killing only the root
# leaves that child -- and the global `_MSIExecute` mutex it holds -- running.
function Get-DescendantProcessIds([int]$RootId, $AllProcs) {
    $ids = @($RootId)
    $frontier = @($RootId)
    while ($frontier) {
        $frontier = @($AllProcs | Where-Object { $_.ParentProcessId -in $frontier -and $_.ProcessId -notin $ids } | Select-Object -ExpandProperty ProcessId)
        $ids += $frontier
    }
    return $ids
}

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
        if ($svc) { $svc | Format-List * } else { Write-Host "(HoleBridge service not registered)" }
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

    # Unlike Get-Service/Get-Process above, Get-CimInstance returns an empty
    # result silently on a genuinely empty query -- it does not raise the
    # non-terminating error `-ErrorAction SilentlyContinue` is meant to
    # swallow. Suppressing errors here would print "no msiexec.exe process
    # running" for a failed WMI query too, exactly when the host is unhealthy
    # enough for that to be false.
    Write-Host "--- msiexec process tree ---"
    $msiProcs = $null
    try {
        $msiProcs = Get-CimInstance Win32_Process -Filter "Name = 'msiexec.exe'" -ErrorAction Stop
        if ($msiProcs) { $msiProcs | Select-Object ProcessId, ParentProcessId, CreationDate, CommandLine | Format-Table -AutoSize | Out-String -Width 4096 } else { Write-Host "(no msiexec.exe process running)" }
    } catch {
        Write-Host "(CIM query for msiexec.exe failed: $($_.Exception.Message))"
    }

    # Kill the tree so a wedged msiexec doesn't outlive this step: on Install
    # it would hold the `_MSIExecute` mutex against the Uninstall step that
    # runs next (`if: always()`), and on Uninstall it would keep appending to
    # the log while "Upload MSI logs" reads it. Best-effort and isolated like
    # the probes above -- a failure here must not swallow the wedge `throw`.
    Write-Host "--- killing wedged process tree ---"
    try {
        $targetIds = if ($msiProcs) { Get-DescendantProcessIds -RootId $proc.Id -AllProcs $msiProcs } else { @($proc.Id) }
        $killed = @()
        $failed = @()
        foreach ($targetId in $targetIds) {
            try {
                Stop-Process -Id $targetId -Force -ErrorAction Stop
                # `-Force` calls TerminateProcess, which returns synchronously
                # without waiting for the process to actually be reaped --
                # same reasoning as the `Wait-Process` after `Stop-Process` in
                # the "Kill any running hole.exe" step.
                Wait-Process -Id $targetId -ErrorAction SilentlyContinue
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

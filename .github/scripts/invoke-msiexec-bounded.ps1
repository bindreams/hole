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

    # Comfortably under the job's `timeout-minutes: 60`: this step normally
    # completes in a few seconds (msiexec itself), and the job's `Build MSI`
    # step is what consumes the bulk of a healthy ~24-27 minute total, so a
    # 10-minute bound leaves ample room for the diagnostics below and the log
    # upload after this step to still run inside the job's own budget.
    [Parameter(Mandatory)]
    [double]$BoundMinutes,

    # Install failure is fatal (matches the pre-existing `throw` there);
    # Uninstall failure is best-effort cleanup (matches the pre-existing
    # `Write-Warning` there). A wedge is fatal either way -- see the `throw`
    # below -- this switch only covers the ordinary nonzero-exit-code path.
    [switch]$FailOnNonZeroExit,

    [string]$ExePath = "msiexec",
    [string[]]$ExeArgs
)

if (-not $ExeArgs) {
    $ExeArgs = @($Verb, $MsiPath, "/quiet", "/norestart", "/l*vx", $LogPath)
}

$proc = Start-Process $ExePath -ArgumentList $ExeArgs -PassThru

if (-not $proc.WaitForExit([int]($BoundMinutes * 60000))) {
    Write-Host "::error::msiexec $Verb did not exit within $BoundMinutes minute(s) -- capturing diagnostics before failing the step"

    Write-Host "--- MSI log tail: $LogPath ---"
    if (Test-Path $LogPath) { Get-Content $LogPath -Tail 50 } else { Write-Host "(log not found at $LogPath)" }

    Write-Host "--- HoleBridge service state ---"
    $svc = Get-Service -Name HoleBridge -ErrorAction SilentlyContinue
    if ($svc) { $svc | Format-List * } else { Write-Host "(HoleBridge service not registered)" }

    Write-Host "--- hole.exe processes ---"
    $holeProcs = Get-Process hole -ErrorAction SilentlyContinue
    if ($holeProcs) { $holeProcs | Format-List Id, ProcessName, Path, StartTime, Responding, SessionId } else { Write-Host "(no hole.exe process running)" }

    Write-Host "--- msiexec process tree ---"
    $msiProcs = Get-CimInstance Win32_Process -Filter "Name = 'msiexec.exe'" -ErrorAction SilentlyContinue
    if ($msiProcs) { $msiProcs | Select-Object ProcessId, ParentProcessId, CreationDate, CommandLine | Format-Table -AutoSize | Out-String -Width 4096 } else { Write-Host "(no msiexec.exe process running)" }

    throw "msiexec $Verb wedged: did not exit within $BoundMinutes minute(s)"
}

if ($proc.ExitCode -ne 0) {
    if (Test-Path $LogPath) { Get-Content $LogPath -Tail 50 }
    $message = "msiexec $Verb failed with exit code $($proc.ExitCode)"
    if ($FailOnNonZeroExit) { throw $message } else { Write-Warning $message }
}

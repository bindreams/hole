# Kills every running hole.exe except the HoleBridge service process, and waits
# for the kernel to reap them.
#
# Shared by the two ci.yaml steps that need a clean slate -- before tauri-driver
# launches, and after the E2E run so the Uninstall step's msiexec finds no held
# handles -- because they carry the same exposure, and a fix applied to one and
# not the other is how this went wrong in the first place.
#
# The service process is spared. What both steps need is the GUI gone (a free
# single-instance slot for tauri-driver, no held handles for msiexec); neither
# needs the bridge dead. Killing it starts the SCM's 1s restart-on-failure
# clock, and msiexec's uninstall then reaches the bridge about when the restart
# lands. Left alone, the bridge is stopped by the
# uninstall the way a user's uninstall stops it.
#
# Resolving BEFORE the kill is the point. `Wait-Process -Name hole` resolves its
# targets once, at the moment it runs; HoleBridge carries SCM restart-on-failure
# with a 1s delay (`restart_failure_actions`, crates/bridge/src/platform/
# windows.rs), so a name resolved *after* the kill lands on the freshly
# restarted bridge and blocks forever on a live process. Waiting on the objects
# captured before the kill cannot.
param(
    # A kill that has not been reaped by now is not going to be. The bound is
    # the failure report, surfaced below, not a delay anything depends on.
    [ValidateRange(1, 600)]
    [int]$ReapTimeoutSeconds = 30
)

# 0 when the service is not running (or not registered), which no process has.
$servicePid = [int](Get-CimInstance Win32_Service -Filter "Name = 'HoleBridge'" -ErrorAction Stop).ProcessId
$holeProcs = @(Get-Process hole -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne $servicePid })
if (-not $holeProcs) { return }

# `-ErrorAction SilentlyContinue` because a process that exited on its own
# between the query and here is a benign race -- under Actions' injected
# `$ErrorActionPreference = 'Stop'` it would otherwise take the whole step down
# before the wait and the warning below ever run.
$holeProcs | Stop-Process -Force -ErrorAction SilentlyContinue
$holeProcs | Wait-Process -Timeout $ReapTimeoutSeconds -ErrorAction SilentlyContinue

$alive = @($holeProcs | Where-Object { -not $_.HasExited })
if ($alive) {
    Write-Host "::warning::hole.exe pid(s) $($alive.Id -join ', ') had not exited ${ReapTimeoutSeconds}s after being killed"
}

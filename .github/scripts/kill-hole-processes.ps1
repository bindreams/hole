# Kills every running hole.exe except the HoleBridge service process, and waits
# for the kernel to reap them. With -InstallDir, only hole.exe processes running
# from under that directory: a developer's own build elsewhere is left alone. A
# process whose image path cannot be read is not provably elsewhere, so it is killed.
#
# Shared by the installer harness's two kill points (msi-installer/tests/installed/support.py):
# before tauri-driver launches, and before the uninstall so its msiexec finds no held handles.
#
# The service process is spared. What both kill points need is the GUI gone (a free
# single-instance slot for tauri-driver, no held handles for msiexec); neither
# needs the bridge dead. Killing it starts the SCM's restart-on-failure clock,
# and msiexec's uninstall then reaches the bridge about when the restart lands.
# Left alone, the bridge is stopped by the uninstall the way a user's uninstall
# stops it.
#
# Resolving BEFORE the kill is the point. `Wait-Process -Name hole` resolves its
# targets once, at the moment it runs; HoleBridge carries SCM restart-on-failure
# (`restart_failure_actions`, crates/bridge/src/platform/windows.rs), so a name
# resolved *after* the kill lands on the freshly restarted bridge and blocks
# forever on a live process. Waiting on the objects captured before the kill
# cannot.
param(
    [string]$InstallDir,

    # A kill that has not been reaped by now is not going to be. The bound is
    # the failure, thrown below, not a delay anything depends on.
    [ValidateRange(1, 600)]
    [int]$ReapTimeoutSeconds = 30
)

# 0 when the service is not running (or not registered), which no process has.
$servicePid = [int](Get-CimInstance Win32_Service -Filter "Name = 'HoleBridge'" -ErrorAction Stop).ProcessId
$holeProcs = @(Get-Process hole -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne $servicePid })
if ($InstallDir) {
    . (Join-Path $PSScriptRoot 'get-process-image-path.ps1')
    $prefix = $InstallDir.TrimEnd('\') + '\'
    $holeProcs = @($holeProcs | Where-Object {
            $path = Get-ProcessImagePath $_
            if (-not $path) { Write-Host "hole.exe pid $($_.Id): image path unreadable, killing it"; return $true }
            $path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
        })
}
if (-not $holeProcs) { return }

# `-ErrorAction SilentlyContinue` because a process that exited on its own
# between the query and here is a benign race -- under Actions' injected
# `$ErrorActionPreference = 'Stop'` it would otherwise take the whole step down
# before the wait and the failure below ever run.
$holeProcs | Stop-Process -Force -ErrorAction SilentlyContinue
$holeProcs | Wait-Process -Timeout $ReapTimeoutSeconds -ErrorAction SilentlyContinue

$alive = @($holeProcs | Where-Object { -not $_.HasExited })
if ($alive) {
    throw "hole.exe pid(s) $($alive.Id -join ', ') had not exited ${ReapTimeoutSeconds}s after being killed"
}

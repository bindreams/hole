# BR-probe (investigation, never merged): induce one condition under which the MSI's BridgeRelease custom action
# (`hole bridge release-covers`, Return="check") can fail, run the uninstall, and record what happened.
#
# Runs on a throwaway Windows machine (a CI runner or a VM), never on a developer's desktop: it installs Hole, stops
# BFE, renames hole.exe and edits ACLs under C:\ProgramData\hole.
#
# Evidence goes to -OutDir: results.txt (one line per uninstall), the MSI log and its tail, C:\ProgramData\hole\{logs,state},
# service state, and `netsh wfp show filters` / `show boottimepolicy` with a count of Hole's provider GUID in each.
param(
    [Parameter(Mandatory)]
    [ValidateSet('baseline', 'bfe-stopped', 'exe-missing', 'exe-acl-denied', 'stray-bridge-peer', 'stray-bridge-service-dir', 'state-dir-write-denied', 'target-file-is-dir')]
    [string]$Condition,
    [Parameter(Mandatory)]
    [string]$MsiPath,
    [Parameter(Mandatory)]
    [string]$OutDir,
    # Engage the standing kill-switch cover (kill switch on + a start that fails) before inducing the condition.
    [switch]$Cover,
    # The repo's .github\scripts directory (for invoke-msiexec-bounded.ps1 and kill-hole-processes.ps1).
    [string]$ScriptsDir = $PSScriptRoot
)

$ErrorActionPreference = 'Continue'
$exe = 'C:\Program Files\hole\bin\hole.exe'
$state = Join-Path $env:ProgramData 'hole\state'
$providerGuid = 'a3f1c2d4-5b6e-47a8-9c0d-1e2f3a4b5c6d'
$tmp = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { $env:TEMP }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$results = Join-Path $OutDir 'results.txt'
function Note([string]$line) { Write-Host $line; Add-Content -Path $results -Value $line }

function Capture([string]$tag) {
    Note "--- capture: $tag ---"
    $d = Join-Path $OutDir $tag
    New-Item -ItemType Directory -Force -Path $d | Out-Null
    & sc.exe query BFE *> (Join-Path $d 'sc-bfe.txt')
    & sc.exe queryex HoleBridge *> (Join-Path $d 'sc-holebridge.txt')
    Get-ChildItem -Recurse -Force 'C:\Program Files\hole' -ErrorAction SilentlyContinue | Select-Object FullName, Length | Out-String -Width 400 | Set-Content (Join-Path $d 'install-dir.txt')
    Get-ChildItem -Recurse -Force (Join-Path $env:ProgramData 'hole') -ErrorAction SilentlyContinue | Select-Object FullName, Length | Out-String -Width 400 | Set-Content (Join-Path $d 'programdata-hole.txt')
    foreach ($sub in 'logs', 'state') {
        $src = Join-Path $env:ProgramData "hole\$sub"
        if (Test-Path $src) { Copy-Item $src (Join-Path $d "programdata-$sub") -Recurse -Force -ErrorAction SilentlyContinue }
    }
    foreach ($view in 'filters', 'boottimepolicy') {
        $file = Join-Path $d "wfp-$view.xml"
        & netsh wfp show $view file="$file" *> (Join-Path $d "netsh-$view.out.txt")
        $count = if (Test-Path $file) { @(Select-String -Path $file -Pattern $providerGuid -AllMatches -ErrorAction SilentlyContinue | ForEach-Object { $_.Matches }).Count } else { 'no file written (netsh failed)' }
        Note "  wfp $view : mentions of Hole's provider GUID = $count"
    }
}

function Uninstall([string]$tag) {
    $log = Join-Path $OutDir "msi-uninstall-$tag.log"
    $outcome = 'msiexec exit 0'
    try {
        & (Join-Path $ScriptsDir 'invoke-msiexec-bounded.ps1') -Verb /x -MsiPath $MsiPath -LogPath $log -FailOnNonZeroExit
    } catch {
        $outcome = $_.Exception.Message
    }
    Note "UNINSTALL [$Condition cover=$($Cover.IsPresent)] $tag : $outcome"
    if (Test-Path $log) { Get-Content $log -Tail 80 | Set-Content (Join-Path $OutDir "msi-uninstall-$tag.tail.txt") }
    $cli = Join-Path $env:ProgramData 'hole\logs\gui-cli.log'
    if (Test-Path $cli) { Get-Content $cli -Tail 20 | ForEach-Object { Note "  gui-cli.log: $_" } }
    Capture "after-uninstall-$tag"
}

function Send-Ipc([string]$json) {
    $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
    & $exe bridge ipc-send --base64 $b64
    Note "  ipc-send $json -> exit $LASTEXITCODE"
}

# A foreground bridge, started like a developer or a second bridge would. Returns once it holds its liveness lock
# (it connects to the rendezvous listener only after taking it), or once it has exited.
function Start-StrayBridge([string[]]$Extra) {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $port = $listener.LocalEndpoint.Port
    $token = [guid]::NewGuid().ToString('N')
    $bridgeArgs = @('bridge', 'run', '--socket-path', (Join-Path $tmp 'stray.sock'), '--log-dir', (Join-Path $OutDir 'stray-logs'), '--ready-notify', "127.0.0.1:$port/$token") + $Extra
    $p = Start-Process $exe -ArgumentList $bridgeArgs -PassThru -WindowStyle Hidden
    $accepted = $listener.AcceptTcpClientAsync()
    $exited = $p.WaitForExitAsync()
    [void][Threading.Tasks.Task]::WaitAny(@($accepted, $exited))
    $listener.Stop()
    Note "  stray bridge pid $($p.Id): $(if ($p.HasExited) { "EXITED early, code $($p.ExitCode)" } else { 'running, lock held' })"
    return $p
}

function Deny([string]$path, [string]$perm) { & icacls $path /deny "*S-1-5-18:$perm" | Out-Null; Note "  icacls deny SYSTEM $perm on $path -> exit $LASTEXITCODE" }
function Undeny([string]$path) { & icacls $path /remove:d "*S-1-5-18" | Out-Null }

# --- install ---------------------------------------------------------------------------------------------------------
Note "=== condition=$Condition cover=$($Cover.IsPresent) ==="
& (Join-Path $ScriptsDir 'invoke-msiexec-bounded.ps1') -Verb /i -MsiPath $MsiPath -LogPath (Join-Path $OutDir 'msi-install.log') -FailOnNonZeroExit
& (Join-Path $ScriptsDir 'kill-hole-processes.ps1')
Capture 'after-install'

# --- kill switch -----------------------------------------------------------------------------------------------------
# The only CLI verb for the kill switch is `bridge ipc-send` with SetLockdown; it records the intent and installs
# nothing. A standing cover appears on the next start.
Send-Ipc '{"SetLockdown":{"enabled":true}}'
if ($Cover) {
    $cfg = Join-Path $tmp 'probe-server.json'
    '{"id":"probe","name":"probe","server":"127.0.0.1","server_port":1,"method":"aes-256-gcm","password":"probe-password"}' | Set-Content $cfg
    $p = Start-Process $exe -ArgumentList @('proxy', 'start', '--config-file', $cfg, '--tunnel-mode', 'full') -PassThru -NoNewWindow
    # Child-process exit: the bound is a failure surfaced to a human, not a sync.
    if (-not $p.WaitForExit(180000)) { Note '  proxy start did not exit in 180s; killing it'; $p.Kill() } else { Note "  proxy start exit code $($p.ExitCode)" }
}
Capture 'before-induce'

# --- induce ----------------------------------------------------------------------------------------------------------
$remedy = { }
$stray = $null
switch ($Condition) {
    'baseline' { }
    'bfe-stopped' {
        Stop-Service BFE -Force
        Note "  BFE status: $((Get-Service BFE).Status)"
        $remedy = { Start-Service BFE; Start-Service MpsSvc -ErrorAction Continue }
    }
    'exe-missing' {
        # What an AV quarantine does: the service's image is released, then the file is gone.
        Stop-Service HoleBridge -Force
        Rename-Item $exe "$exe.quarantined"
        $remedy = { Rename-Item "$exe.quarantined" $exe }
    }
    'exe-acl-denied' {
        Stop-Service HoleBridge -Force
        Deny $exe '(RX)'
        $remedy = { Undeny $exe }
    }
    'stray-bridge-peer' {
        # An elevated foreground bridge of an interactive account: its state dir is that account's profile.
        $stray = Start-StrayBridge @()
        $remedy = { if ($stray -and -not $stray.HasExited) { $stray.Kill(); $stray.WaitForExit() } }
    }
    'stray-bridge-service-dir' {
        # A bridge outliving its service: it holds the service state dir's lock when the uninstall's stop finds the service stopped.
        Stop-Service HoleBridge -Force
        $stray = Start-StrayBridge @('--state-dir', $state)
        $remedy = { if ($stray -and -not $stray.HasExited) { $stray.Kill(); $stray.WaitForExit() } }
    }
    'state-dir-write-denied' {
        Stop-Service HoleBridge -Force
        Deny $state '(OI)(CI)(WD,AD)'
        $remedy = { Undeny $state }
    }
    'target-file-is-dir' {
        Stop-Service HoleBridge -Force
        $target = Join-Path $state 'bridge-target.json'
        Remove-Item $target -Force -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Path $target | Out-Null
        $remedy = { Remove-Item (Join-Path $state 'bridge-target.json') -Recurse -Force }
    }
}
Capture 'after-induce'

# --- uninstall, then the documented remedy and a retry -----------------------------------------------------------------
Uninstall 'first'
if (Test-Path $exe -ErrorAction SilentlyContinue) {
    Note '  hole.exe still present after the first uninstall: running the remedy, then retrying'
    & $remedy
    Uninstall 'retry'
}

# --- leave the machine open so the artifact can be uploaded ------------------------------------------------------------
if (Test-Path $exe) {
    Send-Ipc '"Unblock"'
    & $exe bridge unlock
    Note "  final bridge unlock -> exit $LASTEXITCODE"
}
Capture 'final'

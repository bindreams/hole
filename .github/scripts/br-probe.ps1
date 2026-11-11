# BR-probe (investigation, never merged): induce one condition under which the MSI's BridgeRelease custom action
# (`hole bridge release-covers`, Return="check") can fail, run the uninstall, and record what happened.
#
# Runs on a throwaway Windows machine (a CI runner or a VM), never on a developer's desktop: it installs Hole, stops
# BFE, replaces hole.exe and edits ACLs under C:\ProgramData\hole. With -Cover it engages Hole's standing kill-switch
# cover, which blocks the machine's own egress until the script (or Hole) releases it.
#
# Every leg proves its condition was induced and aborts (nonzero exit, "LEG ABORTED" in results.txt) when it was not.
# A cover leg proves a standing cover is engaged (Hole's provider GUID in `netsh wfp show filters`) before inducing.
#
# Evidence goes to -OutDir: results.txt (one line per step), the MSI log and its tail, C:\ProgramData\hole\{logs,state},
# service state, and `netsh wfp show filters` / `show boottimepolicy` with the counts that matter in each.
param(
    [Parameter(Mandatory)]
    [ValidateSet('baseline', 'bfe-stopped', 'exe-missing', 'exe-blocked', 'stray-bridge-peer', 'stray-bridge-service-dir', 'state-dir-write-denied', 'target-file-is-dir')]
    [string]$Condition,
    [Parameter(Mandatory)]
    [string]$MsiPath,
    [Parameter(Mandatory)]
    [string]$OutDir,
    # Engage the standing kill-switch cover (kill switch on + a successful full-tunnel start) before inducing the condition.
    [switch]$Cover,
    # The repo's .github\scripts directory (for invoke-msiexec-bounded.ps1 and kill-hole-processes.ps1).
    [string]$ScriptsDir = $PSScriptRoot
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$exe = 'C:\Program Files\hole\bin\hole.exe'
$binDir = 'C:\Program Files\hole\bin'
$state = Join-Path $env:ProgramData 'hole\state'
$providerGuid = 'a3f1c2d4-5b6e-47a8-9c0d-1e2f3a4b5c6d'
# `LOCKDOWN_BOOTTIME_BLOCK_ALL_GUIDS` (crates/tun-engine/src/routing/failclosed/windows.rs). `show boottimepolicy` names an
# item by its filter key, not by provider, so the twins are counted by key.
$twinKeys = 'ba322087-a133-481c-86cc-0692ad222e2d|227bca1d-5415-4421-a5da-bf5babe1c556'
$tmp = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { $env:TEMP }
$backupBin = Join-Path $tmp 'hole-bin-backup'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$results = Join-Path $OutDir 'results.txt'
function Note([string]$line) { Write-Host $line; Add-Content -Path $results -Value $line }

$script:LastCapture = @{ Filters = 'n/a'; BootTwins = 'n/a' }
$script:remedy = { }
$script:remedyDone = $false
$script:stray = $null
$script:aborted = $false

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
    $counts = @{}
    foreach ($view in 'filters', 'boottimepolicy') {
        $file = Join-Path $d "wfp-$view.xml"
        & netsh wfp show $view file="$file" *> (Join-Path $d "netsh-$view.out.txt")
        $pattern = if ($view -eq 'filters') { $providerGuid } else { $twinKeys }
        $counts[$view] = if (Test-Path $file) { @(Select-String -Path $file -Pattern $pattern -AllMatches -ErrorAction SilentlyContinue | ForEach-Object { $_.Matches }).Count } else { 'no file written (netsh failed)' }
    }
    $script:LastCapture = @{ Filters = $counts['filters']; BootTwins = $counts['boottimepolicy'] }
    Note "  wfp filters : mentions of Hole's provider GUID = $($counts['filters'])"
    Note "  wfp boottimepolicy : mentions of the two boot-time twin keys = $($counts['boottimepolicy'])"
}

# Whether a connection leaves the machine. A block is observed as a refusal or as no answer; the bound is the failure
# bound for an answer that may never come, not a synchronization.
function Test-Egress([string]$label) {
    $c = [Net.Sockets.TcpClient]::new()
    try {
        $t = $c.ConnectAsync('1.1.1.1', 443)
        $r = if ($t.Wait(5000)) { 'CONNECTED' } else { 'NO ANSWER within 5s (blocked or black-holed)' }
    } catch {
        $r = "FAILED: $($_.Exception.GetBaseException().Message)"
    } finally {
        $c.Dispose()
    }
    Note "  egress [$label] 1.1.1.1:443 -> $r"
}

function Test-HoleInstalled {
    $keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    return [bool](Get-ItemProperty $keys -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq 'Hole' })
}

function Uninstall([string]$tag) {
    $log = Join-Path $OutDir "msi-uninstall-$tag.log"
    $outcome = 'msiexec exit 0'
    try {
        & (Join-Path $ScriptsDir 'invoke-msiexec-bounded.ps1') -Verb /x -MsiPath $MsiPath -LogPath $log -FailOnNonZeroExit | Out-Null
    } catch {
        $outcome = $_.Exception.Message
    }
    Note "UNINSTALL [$Condition cover=$($Cover.IsPresent)] $tag : $outcome"
    Note "  product still installed after $tag : $(Test-HoleInstalled)"
    if (Test-Path $log) { Get-Content $log -Tail 80 | Set-Content (Join-Path $OutDir "msi-uninstall-$tag.tail.txt") }
    $cli = Join-Path $env:ProgramData 'hole\logs\gui-cli.log'
    if (Test-Path $cli) { Get-Content $cli -Tail 20 | ForEach-Object { Note "  gui-cli.log: $_" } }
    Capture "after-uninstall-$tag"
    Test-Egress "after-uninstall-$tag"
}

# hole.exe is a GUI-subsystem binary: a bare `& hole.exe` does not wait for it and leaves `$LASTEXITCODE` stale.
function Invoke-Hole([string]$exePath, [string[]]$HoleArgs) {
    $p = Start-Process $exePath -ArgumentList $HoleArgs -PassThru -Wait -NoNewWindow
    return $p.ExitCode
}

function Send-Ipc([string]$json) {
    $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
    $code = Invoke-Hole $exe @('bridge', 'ipc-send', '--base64', $b64)
    Note "  ipc-send $(if ($json.Length -gt 60) { $json.Substring(0, 60) + '...' } else { $json }) -> exit $code"
    return $code
}

# Run commands as SYSTEM through a one-shot scheduled task; returns their combined output. The task writes a marker file
# last, so the wait is on the real condition (the marker), not on time. Throws if the task ended without writing it.
function Invoke-AsSystem([string]$name, [string[]]$lines) {
    $task = "brprobe-$name"
    $cmdFile = Join-Path $tmp "$task.cmd"
    $outFile = Join-Path $tmp "$task.out.txt"
    $doneFile = Join-Path $tmp "$task.done"
    Remove-Item $outFile, $doneFile -Force -ErrorAction SilentlyContinue
    Set-Content -Path $cmdFile -Encoding ascii -Value (@('@echo off', '(') + $lines + @(") > `"$outFile`" 2>&1", "echo done > `"$doneFile`""))
    & schtasks.exe /create /tn $task /tr "`"$cmdFile`"" /sc once /st 00:00 /ru SYSTEM /rl HIGHEST /f | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "schtasks /create $task failed ($LASTEXITCODE)" }
    & schtasks.exe /run /tn $task | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "schtasks /run $task failed ($LASTEXITCODE)" }
    while (-not (Test-Path $doneFile)) {
        $info = Get-ScheduledTaskInfo -TaskName $task
        $st = (Get-ScheduledTask -TaskName $task).State
        if ($st -ne 'Running' -and $info.LastTaskResult -notin 267009, 267011 -and -not (Test-Path $doneFile)) {
            throw "SYSTEM task $task ended without its marker (result $($info.LastTaskResult))"
        }
        Start-Sleep -Milliseconds 200
    }
    $out = if (Test-Path $outFile) { Get-Content $outFile -Raw } else { '' }
    & schtasks.exe /delete /tn $task /f | Out-Null
    $sysDir = Join-Path $OutDir 'system-tasks'
    New-Item -ItemType Directory -Force -Path $sysDir | Out-Null
    Copy-Item $cmdFile, $outFile $sysDir -Force -ErrorAction SilentlyContinue
    return $out
}

# A foreground bridge, started like a developer or a second bridge would. Returns once it holds its liveness lock
# (it connects to the rendezvous listener only after taking it); throws if it exited first.
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
    $holds = $accepted.IsCompleted -and -not $accepted.IsFaulted -and -not $p.HasExited
    Note "  stray bridge pid $($p.Id): $(if ($holds) { 'running, lock held' } else { 'DID NOT take its lock' })"
    $script:stray = $p
    if (-not $holds) { throw "stray bridge did not take its liveness lock (exited=$($p.HasExited))" }
}

function Deny([string]$path, [string]$perm) {
    & icacls $path /deny "*S-1-5-18:$perm" | Out-Null
    Note "  icacls deny SYSTEM $perm on $path -> exit $LASTEXITCODE"
    if ($LASTEXITCODE -ne 0) { throw "icacls deny failed on $path" }
}
function Undeny([string]$path) { & icacls $path /remove:d "*S-1-5-18" | Out-Null }

# Throws unless starting this file fails: the proof that hole.exe cannot be run as it stands.
function Assert-CannotRun([string]$path) {
    $ran = $false
    try {
        $p = Start-Process $path -ArgumentList 'version' -PassThru -Wait -NoNewWindow -ErrorAction Stop
        $ran = $true
    } catch {
        Note "  verified: hole.exe cannot be started: $($_.Exception.Message)"
    }
    if ($ran) { throw "hole.exe still runs (exit $($p.ExitCode)); condition not induced" }
}

function Get-StoppedServicesDelta([string[]]$before) {
    $now = @(Get-Service | Where-Object Status -eq 'Running' | ForEach-Object Name)
    return @($before | Where-Object { $_ -notin $now })
}

function Recover {
    Note '--- recovery ---'
    if (-not $script:remedyDone) {
        $script:remedyDone = $true
        try { & $script:remedy } catch { Note "  remedy failed: $($_.Exception.Message)" }
    }
    if ($script:stray -and -not $script:stray.HasExited) { try { $script:stray.Kill(); $script:stray.WaitForExit() } catch { } }
    $holeExe = $null
    if ((Test-Path $exe) -and (Get-Item $exe).Length -gt 1MB) { $holeExe = $exe }
    elseif ((Test-Path (Join-Path $backupBin 'hole.exe')) -and (Get-Item (Join-Path $backupBin 'hole.exe')).Length -gt 1MB) { $holeExe = Join-Path $backupBin 'hole.exe' }
    if (-not $holeExe) { Note '  RECOVERY: no usable hole.exe (installed or backup) to unlock with'; return }
    Note "  recovery uses $holeExe"
    $svc = Get-Service HoleBridge -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -eq 'Running' -and $holeExe -eq $exe) { Note "  recovery Unblock via IPC -> exit $(Invoke-Hole $exe @('bridge', 'ipc-send', '--base64', [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('"Unblock"'))))" }
        try { Stop-Service HoleBridge -Force -ErrorAction Stop } catch { Note "  recovery: Stop-Service HoleBridge failed: $($_.Exception.Message)" }
    }
    Note "  recovery bridge unlock -> exit $(Invoke-Hole $holeExe @('bridge', 'unlock'))"
}

# --- install ---------------------------------------------------------------------------------------------------------
Note "=== condition=$Condition cover=$($Cover.IsPresent) ==="
try {
    try {
        & (Join-Path $ScriptsDir 'invoke-msiexec-bounded.ps1') -Verb /i -MsiPath $MsiPath -LogPath (Join-Path $OutDir 'msi-install.log') -FailOnNonZeroExit | Out-Null
    } catch {
        throw "MSI install failed: $($_.Exception.Message)"
    }
    if (-not (Test-Path $exe)) { throw "install produced no $exe" }
    if (-not (Test-HoleInstalled)) { throw 'install left no Uninstall registry entry named Hole' }
    if (-not (Get-Service HoleBridge -ErrorAction SilentlyContinue)) { throw 'install registered no HoleBridge service' }
    & (Join-Path $ScriptsDir 'kill-hole-processes.ps1')
    # A copy of the product, so the machine can be unlocked even when the uninstall removed hole.exe.
    Copy-Item $binDir $backupBin -Recurse -Force
    Capture 'after-install'
    Test-Egress 'after-install (no cover)'

    # --- kill switch -------------------------------------------------------------------------------------------------
    # `SetLockdown` records the intent and installs nothing. A standing cover is engaged by a START under that intent
    # (proxy_manager.rs: `install_standing_cover`, after routing.install). The Start is sent with the DNS forwarder off,
    # because its start-time self-test needs a working server and a failed start engages nothing; the server address is
    # a TEST-NET-1 address nobody answers on, so the tunnel comes up and carries nothing.
    if ((Send-Ipc '{"SetLockdown":{"enabled":true}}') -ne 0) { throw 'SetLockdown failed' }
    $lockdownFile = Join-Path $state 'bridge-lockdown.json'
    if (-not (Test-Path $lockdownFile) -or (Get-Content $lockdownFile -Raw | ConvertFrom-Json).enabled -ne $true) { throw "kill-switch intent not recorded: $lockdownFile" }
    Note '  kill-switch intent recorded: bridge-lockdown.json enabled=true'
    if ($Cover) {
        $start = @{ Start = @{
                config = @{
                    server = @{ id = 'probe'; name = 'probe'; server = '192.0.2.1'; server_port = 8388; method = 'aes-256-gcm'; password = 'probe-password' }
                    local_port = 4073; tunnel_mode = 'full'
                    dns = @{ enabled = $false; servers = @(); protocol = 'https' }
                }
                attempt_id = [guid]::NewGuid().ToString(); on_startup = $null
            }
        } | ConvertTo-Json -Depth 8 -Compress
        $code = Send-Ipc $start
        Capture 'cover-engaged'
        if ($code -ne 0) { throw "full-tunnel Start failed (exit $code); no standing cover to measure" }
        if ($script:LastCapture.Filters -isnot [int] -or $script:LastCapture.Filters -le 0) { throw "standing cover NOT engaged: Hole provider-GUID filters = $($script:LastCapture.Filters)" }
        if ($script:LastCapture.BootTwins -isnot [int] -or $script:LastCapture.BootTwins -lt 2) { Note "  WARNING: boot-time twins NOT seen in show boottimepolicy (count $($script:LastCapture.BootTwins), expected 2); the standing cover is engaged but its twins are not proven" }
        Note "  COVER ENGAGED: $($script:LastCapture.Filters) Hole filters, boot-time twin keys seen: $($script:LastCapture.BootTwins)"
        Test-Egress 'cover engaged, before induce'
    }
    Capture 'before-induce'

    # --- induce (each branch proves the condition before returning) --------------------------------------------------
    switch ($Condition) {
        'baseline' { }
        'bfe-stopped' {
            $before = @(Get-Service | Where-Object Status -eq 'Running' | ForEach-Object Name)
            Note "  BFE dependents: $((Get-Service BFE).DependentServices | ForEach-Object { "$($_.Name)=$($_.Status)" })"
            $out = Invoke-AsSystem 'bfe-stop' @('sc query bfe', 'net stop bfe /y', 'sc query bfe')
            Note "  SYSTEM net stop bfe /y output: $(($out -split "`r?`n" | Where-Object { $_ }) -join ' | ')"
            $script:stoppedWithBfe = Get-StoppedServicesDelta $before
            Note "  services stopped along with BFE: $($script:stoppedWithBfe -join ', ')"
            $status = (Get-Service BFE).Status
            Note "  BFE status: $status"
            if ($status -ne 'Stopped') { throw "BFE is $status, not Stopped; condition not induced" }
            $script:remedy = {
                $lines = @('net start bfe') + @($script:stoppedWithBfe | Where-Object { $_ -ne 'BFE' } | ForEach-Object { "net start `"$_`"" })
                $o = Invoke-AsSystem 'bfe-start' $lines
                Note "  SYSTEM restart of BFE and dependents: BFE is $((Get-Service BFE).Status)"
            }
        }
        'exe-missing' {
            # What an AV quarantine does: the service's image is released, then the file is gone.
            Stop-Service HoleBridge -Force
            Move-Item $exe "$exe.quarantined"
            Assert-CannotRun $exe
            $script:remedy = { if (Test-Path "$exe.quarantined") { Move-Item "$exe.quarantined" $exe -Force } }
        }
        'exe-blocked' {
            # A hole.exe that exists but cannot be run: what an execution block (AppLocker, WDAC, an AV) amounts to for the
            # MSI's CreateProcess. A text file takes the place of the real binary, which waits outside the install dir.
            Stop-Service HoleBridge -Force
            $script:realExe = Join-Path $tmp 'hole.exe.real'
            Move-Item $exe $script:realExe -Force
            Set-Content -Path $exe -Value 'not an executable'
            Assert-CannotRun $exe
            $script:remedy = { if (Test-Path $script:realExe) { Move-Item $script:realExe $exe -Force } }
        }
        'stray-bridge-peer' {
            # An elevated foreground bridge of an interactive account: its state dir is that account's profile.
            Start-StrayBridge @()
            $script:remedy = { if ($script:stray -and -not $script:stray.HasExited) { $script:stray.Kill(); $script:stray.WaitForExit() } }
        }
        'stray-bridge-service-dir' {
            # A bridge outliving its service: it holds the service state dir's lock when the uninstall's stop finds the service stopped.
            Stop-Service HoleBridge -Force
            if ((Get-Service HoleBridge).Status -ne 'Stopped') { throw 'HoleBridge is not Stopped; condition not induced' }
            Start-StrayBridge @('--state-dir', $state)
            $script:remedy = { if ($script:stray -and -not $script:stray.HasExited) { $script:stray.Kill(); $script:stray.WaitForExit() } }
        }
        'state-dir-write-denied' {
            Stop-Service HoleBridge -Force
            Deny $state '(OI)(CI)(WD,AD)'
            $out = Invoke-AsSystem 'state-write-probe' @("echo x > `"$state\br-probe-write.txt`"")
            Note "  SYSTEM write probe into the state dir: $(($out -split "`r?`n" | Where-Object { $_ }) -join ' | ')"
            if ($out -notmatch 'denied') { throw 'SYSTEM can still write into the state dir; condition not induced' }
            $script:remedy = { Undeny $state }
        }
        'target-file-is-dir' {
            Stop-Service HoleBridge -Force
            $target = Join-Path $state 'bridge-target.json'
            Remove-Item $target -Force -ErrorAction SilentlyContinue
            New-Item -ItemType Directory -Path $target | Out-Null
            if (-not (Test-Path $target -PathType Container)) { throw 'bridge-target.json is not a directory; condition not induced' }
            $script:remedy = { Remove-Item (Join-Path $state 'bridge-target.json') -Recurse -Force }
        }
    }
    Capture 'after-induce'
    if ($Cover) {
        if ($script:LastCapture.Filters -isnot [int] -or $script:LastCapture.Filters -le 0) { Note "  WARNING: after the condition was induced the standing cover reads $($script:LastCapture.Filters) Hole filters; the uninstall below runs WITHOUT a cover" }
        else { Note "  cover still held after the condition: $($script:LastCapture.Filters) Hole filters" }
        Test-Egress 'cover held, condition induced, before uninstall'
    }

    # --- uninstall, then the documented remedy and a retry -----------------------------------------------------------
    Uninstall 'first'
    if (Test-HoleInstalled) {
        Note '  product still installed after the first uninstall: running the remedy, then retrying'
        $script:remedyDone = $true
        & $script:remedy
        Uninstall 'retry'
    }
} catch {
    $script:aborted = $true
    Note "LEG ABORTED: $($_.Exception.Message)"
} finally {
    # Leave the machine open so the artifact can be uploaded.
    Recover
    Capture 'final'
    Test-Egress 'final, after recovery'
    if ($Cover -and ($script:LastCapture.Filters -isnot [int] -or $script:LastCapture.Filters -gt 0)) { Note "  RECOVERY INCOMPLETE: Hole filters left = $($script:LastCapture.Filters)" }
}
if ($script:aborted) { exit 1 }

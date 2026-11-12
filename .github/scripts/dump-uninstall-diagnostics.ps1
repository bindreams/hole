# Prints what the MSI's SYSTEM-run `hole bridge ...` actions and the SCM recorded
# about HoleBridge, for a failed uninstall. The actions have
# no console, so the CLI log in the MSI's log directory and the System log's Service
# Control Manager events are the only record of why `bridge uninstall` exited 1.
param(
    # Opens the event window: everything the service did since the install is
    # relevant, and nothing before it is.
    [datetime]$Since = (Get-Date).AddHours(-1)
)

# The MSI's actions pass `--log-dir "[CommonAppDataFolder]hole\logs"`; the SYSTEM
# profile is where an action that did not (an older package) logs by default.
$cliLogDirs = @(
    (Join-Path $env:ProgramData 'hole\logs'),
    (Join-Path $env:SystemRoot 'System32\config\systemprofile\AppData\Local\hole\logs')
)
foreach ($cliLogDir in $cliLogDirs) {
    Write-Host "--- CLI logs: $cliLogDir ---"
    try {
        if (Test-Path $cliLogDir) {
            foreach ($file in Get-ChildItem $cliLogDir -File -ErrorAction Stop) {
                Write-Host "== $($file.FullName)"
                try {
                    Get-Content $file.FullName -Tail 200 -ErrorAction Stop
                } catch {
                    Write-Host "(failed to read $($file.FullName): $($_.Exception.Message))"
                }
            }
        } else {
            Write-Host "(directory not found)"
        }
    } catch {
        Write-Host "(failed to list ${cliLogDir}: $($_.Exception.Message))"
    }
}

Write-Host "--- Service Control Manager events for HoleBridge ---"
try {
    # 7031/7034: the service terminated unexpectedly (a kill) and the recovery
    # action taken; 7036: a state change.
    Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; StartTime = $Since } -ErrorAction Stop |
        Where-Object { $_.Message -match 'Hole' } |
        Sort-Object TimeCreated |
        ForEach-Object { "{0:HH:mm:ss.fff}  {1}  {2}" -f $_.TimeCreated, $_.Id, $_.Message }
} catch {
    Write-Host "(failed to read the System log: $($_.Exception.Message))"
}

Write-Host "--- HoleBridge SCM status ---"
try {
    sc.exe queryex HoleBridge
} catch {
    Write-Host "(failed to run sc.exe queryex HoleBridge: $($_.Exception.Message))"
}

# A diagnostics dump is not a verdict: `sc.exe` exits 1060 for an unregistered
# service, which is the usual state after a failed uninstall.
exit 0

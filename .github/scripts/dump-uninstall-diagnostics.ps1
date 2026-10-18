# Prints what the MSI's SYSTEM-run `hole bridge ...` actions and the SCM recorded
# about HoleBridge, for a failed uninstall (bindreams/hole#1099). The actions have
# no console, so the CLI log under the SYSTEM profile and the System log's Service
# Control Manager events are the only record of why `bridge uninstall` exited 1.
param(
    # The install log's creation time opens the event window: everything the
    # service did since the install is relevant, and nothing before it is.
    [Parameter(Mandatory)]
    [string]$MsiInstallLog
)

$cliLogDir = Join-Path $env:SystemRoot 'System32\config\systemprofile\AppData\Local\hole\logs'
Write-Host "--- CLI logs under the SYSTEM profile: $cliLogDir ---"
if (Test-Path $cliLogDir) {
    foreach ($file in Get-ChildItem $cliLogDir -File) {
        Write-Host "== $($file.FullName)"
        Get-Content $file.FullName -Tail 200
    }
} else {
    Write-Host "(directory not found)"
}

Write-Host "--- Service Control Manager events for HoleBridge ---"
try {
    $since = if (Test-Path $MsiInstallLog) { (Get-Item $MsiInstallLog).CreationTime } else { (Get-Date).AddHours(-1) }
    # 7031/7034: the service terminated unexpectedly (a kill) and the recovery
    # action taken; 7036: a state change.
    Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; StartTime = $since } -ErrorAction Stop |
        Where-Object { $_.Message -match 'Hole' } |
        Sort-Object TimeCreated |
        ForEach-Object { "{0:HH:mm:ss.fff}  {1}  {2}" -f $_.TimeCreated, $_.Id, $_.Message }
} catch {
    Write-Host "(failed to read the System log: $($_.Exception.Message))"
}

Write-Host "--- HoleBridge SCM status ---"
sc.exe queryex HoleBridge

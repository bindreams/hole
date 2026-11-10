# Measures, on the real Windows Installer, the two premises the MSI's bridge start rests on (#1109):
#
#   M1  A failing BridgeStart (a commit custom action, Return="check") rolls the whole major upgrade back:
#       msiexec exits 1603, the old product is installed again, HoleBridge is registered and running, and what
#       the new product wrote (a registry marker, see New-Variant) is gone.
#   M2  With rollback disabled (DISABLEROLLBACK=1), which start runs. M2a is the shipped MSI: the in-script
#       BridgeStartNoRollback must start the service (asserted), and the marker proves the new product was laid.
#       M2b (only with -RecordM2b) is a variant that sequences the commit BridgeStart regardless of
#       RollbackDisabled: does a commit action run when rollback is disabled? Read from a log folder only its start writes,
#       recorded, never asserted; if it does, the in-script row is dropped.
#
# The upgrades are real major upgrades of the installed product, made by editing COPIES of the built MSI
# (a new ProductCode, package code and version, and a marker; M1 and M2b also edit custom-action or sequence
# rows), so nothing in the shipped MSI or the product carries a test hook. Everything it installs, it
# uninstalls.
param(
    [Parameter(Mandatory)]
    [string]$MsiPath,

    [Parameter(Mandatory)]
    [string]$WorkDir,

    [switch]$RecordM2b
)

$ErrorActionPreference = 'Stop'

# Windows Installer ProductState values (MsiQueryProductState).
$INSTALLSTATE_DEFAULT = 5

$installer = New-Object -ComObject WindowsInstaller.Installer
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null

# MSI database editing ================================================================================================

# An MSI database file stays open (and msiexec cannot read it) until every COM object on it is released.
function Release-Com($object) {
    if ($null -ne $object) { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($object) | Out-Null }
}

function Invoke-Sql($db, [string]$sql) {
    $view = $db.OpenView($sql)
    $view.Execute() | Out-Null
    $view.Close() | Out-Null
    Release-Com $view
}

function Get-MsiProperty($db, [string]$name) {
    $view = $db.OpenView('SELECT `Value` FROM `Property` WHERE `Property`=''' + $name + '''')
    $view.Execute() | Out-Null
    $record = $view.Fetch()
    $value = $record.StringData(1)
    $view.Close() | Out-Null
    Release-Com $record
    Release-Com $view
    return $value
}

# The Upgrade table's version bounds are part of its key, so they are replaced, not updated: every bound
# that is `$from` becomes `$to`.
function Move-UpgradeVersions($db, [string]$from, [string]$to) {
    $view = $db.OpenView('SELECT * FROM `Upgrade`')
    $view.Execute() | Out-Null
    $rows = @()
    while ($record = $view.Fetch()) {
        $rows += , @(1..7 | ForEach-Object { $record.StringData($_) })
        Release-Com $record
    }
    $view.Close() | Out-Null
    Release-Com $view

    Invoke-Sql $db 'DELETE FROM `Upgrade`'
    foreach ($row in $rows) {
        # Columns: UpgradeCode, VersionMin, VersionMax, Language, Attributes (integer), Remove, ActionProperty.
        $literals = for ($i = 0; $i -lt 7; $i++) {
            $value = $row[$i]
            if ($i -in 1, 2 -and $value -eq $from) { $value = $to }
            if ($value -eq '') { 'NULL' } elseif ($i -eq 4) { $value } else { "'" + $value + "'" }
        }
        Invoke-Sql $db ('INSERT INTO `Upgrade` (`UpgradeCode`, `VersionMin`, `VersionMax`, `Language`, `Attributes`, `Remove`, `ActionProperty`) VALUES (' + ($literals -join ', ') + ')')
    }
}

# A registry value the variants write and the shipped MSI does not, in the HoleExe component (the one that
# carries hole.exe): present means the new product was laid, absent after a rollback means it was undone. The
# variants' hole.exe is byte-identical to the original's (the cabinet is not rebuilt), so the file cannot tell
# the two products apart.
$MarkerKey = 'SOFTWARE\hole-msi-measure'
$MarkerName = 'ProductVersion'

# The marker's value, or $null. Both registry views are read, as the component's bitness decides which one
# the value lands in.
function Get-Marker {
    foreach ($view in 'Registry64', 'Registry32') {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', $view)
        try {
            $key = $base.OpenSubKey($MarkerKey)
            if ($key) {
                try { return $key.GetValue($MarkerName) } finally { $key.Dispose() }
            }
        } finally { $base.Dispose() }
    }
    return $null
}

# A copy of the MSI that is a different, newer product of the same upgrade family: its own ProductCode and
# package code, a version `$Bump` patch levels above the original's (the Upgrade table's version bounds
# move with it, so it detects the original as an older product), and the marker. `$Edits` are further SQL
# over the copy.
function New-Variant([string]$Name, [int]$Bump, [string[]]$Edits = @()) {
    $path = Join-Path $WorkDir "$Name.msi"
    Copy-Item -LiteralPath $MsiPath -Destination $path -Force
    Set-ItemProperty -LiteralPath $path -Name IsReadOnly -Value $false

    $db = $installer.OpenDatabase($path, 1)   # msiOpenDatabaseModeTransact
    $productCode = '{' + [guid]::NewGuid().ToString().ToUpper() + '}'
    $oldVersion = Get-MsiProperty $db 'ProductVersion'
    $parts = $oldVersion.Split('.')
    $parts[2] = [string]([int]$parts[2] + $Bump)
    $newVersion = $parts -join '.'

    Invoke-Sql $db ('UPDATE `Property` SET `Value`=''{0}'' WHERE `Property`=''ProductCode''' -f $productCode)
    Invoke-Sql $db ('UPDATE `Property` SET `Value`=''{0}'' WHERE `Property`=''ProductVersion''' -f $newVersion)
    Move-UpgradeVersions $db $oldVersion $newVersion
    # Root 2 is HKEY_LOCAL_MACHINE.
    Invoke-Sql $db ('INSERT INTO `Registry` (`Registry`, `Root`, `Key`, `Name`, `Value`, `Component_`) VALUES (''MeasureMarker'', 2, ''{0}'', ''{1}'', ''{2}'', ''HoleExe'')' -f $MarkerKey, $MarkerName, $newVersion)
    foreach ($edit in $Edits) { Invoke-Sql $db $edit }
    $db.Commit() | Out-Null

    # A different package needs a different package code (summary property 9, the Revision Number).
    $summary = $db.GetType().InvokeMember('SummaryInformation', 'GetProperty', $null, $db, @(5))
    $packageCode = '{' + [guid]::NewGuid().ToString().ToUpper() + '}'
    $summary.GetType().InvokeMember('Property', 'SetProperty', $null, $summary, @(9, $packageCode)) | Out-Null
    $summary.Persist() | Out-Null
    $db.Commit() | Out-Null
    Release-Com $summary
    Release-Com $db
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()

    return [pscustomobject]@{ Name = $Name; Path = $path; ProductCode = $productCode; Version = $newVersion }
}

function Get-OriginalProductCode {
    $db = $installer.OpenDatabase($MsiPath, 0)   # msiOpenDatabaseModeReadOnly
    $code = Get-MsiProperty $db 'ProductCode'
    Release-Com $db
    return $code
}

function Test-Installed([string]$productCode) {
    return ([int]$installer.ProductState($productCode)) -eq $INSTALLSTATE_DEFAULT
}

# Running msiexec =====================================================================================================

function Invoke-Msiexec([string]$Verb, [string]$Path, [string]$Name, [string[]]$Properties = @(), [switch]$MustSucceed) {
    $log = Join-Path $env:RUNNER_TEMP "msi-measure-$Name.log"
    $bounded = Join-Path $PSScriptRoot 'invoke-msiexec-bounded.ps1'
    if ($MustSucceed) {
        & $bounded -Verb $Verb -MsiPath $Path -LogPath $log -Properties $Properties -FailOnNonZeroExit | Out-Host
    } else {
        & $bounded -Verb $Verb -MsiPath $Path -LogPath $log -Properties $Properties | Out-Host
    }
    return $log
}

# The exit status msiexec ended with, from its own verbose log; the bounded runner reports a nonzero one
# only as a warning. A log without one is "could not measure".
function Get-MsiStatus([string]$log) {
    $match = Select-String -LiteralPath $log -Pattern 'Installation success or error status: (\d+)' |
        Select-Object -Last 1
    if (-not $match) { throw "could not measure: no exit status in $log" }
    return [int]$match.Matches[0].Groups[1].Value
}

# The bridge custom actions the installer scheduled into its script, from the log's script operations. A
# scheduled action may not have run (a commit action is skipped when rollback is disabled, and a failure
# cancels the rest); the bridge's own log says what ran.
function Get-ScriptedActions([string]$log) {
    return @(Select-String -LiteralPath $log -Pattern 'CustomActionSchedule\(Action=(Bridge\w+),' |
        ForEach-Object { $_.Matches[0].Groups[1].Value } | Select-Object -Unique)
}

# The service's state after msiexec has exited. One status read answers; the only wait is for a start still in
# flight to end, which the SCM bounds itself (a start that fails ends as Stopped).
function Get-ServiceState {
    $svc = Get-Service -Name HoleBridge -ErrorAction SilentlyContinue
    if (-not $svc) { return 'not registered' }
    while ($svc.Status -eq 'StartPending') {
        Start-Sleep -Milliseconds 200
        $svc.Refresh()
    }
    if ($svc.Status -eq 'Running') { return 'running' }
    return "registered, $($svc.Status)"
}

# The folder the M2b variant's BridgeStart writes its CLI log to (`--log-dir`), and no other action does: a
# `gui-cli.log` in it is the record that this commit action ran.
$M2bLogDir = Join-Path $env:ProgramData 'hole\logs-m2b'

function Write-Measurement([string]$Line) {
    Write-Host "MEASURE $Line"
    if ($env:GITHUB_STEP_SUMMARY) { Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Value "- $Line" }
}

# Dot-sourcing defines the functions above and runs nothing.
if ($MyInvocation.InvocationName -eq '.') { return }

# The measurements ====================================================================================================

$originalCode = Get-OriginalProductCode
$variants = @()
$failure = $null
try {
    Invoke-Msiexec '/i' $MsiPath 'original' -Properties 'SUPPRESS_LAUNCH=1' -MustSucceed | Out-Null
    $state = Get-ServiceState
    if ($state -ne 'running') { throw "setup: the freshly installed bridge is $state" }
    if ($null -ne (Get-Marker)) { throw 'setup: the shipped MSI wrote the marker' }

    # M1 ----------------------------------------------------------------------------------------------------------
    $failing = New-Variant 'upgrade-start-fails' 1 @(
        'UPDATE `CustomAction` SET `Target`=''bridge start --no-such-flag'' WHERE `Action`=''BridgeStart'''
    )
    $variants += $failing
    $log = Invoke-Msiexec '/i' $failing.Path 'm1' -Properties 'SUPPRESS_LAUNCH=1'
    $status = Get-MsiStatus $log
    $oldBack = Test-Installed $originalCode
    $newGone = -not (Test-Installed $failing.ProductCode)
    $service = Get-ServiceState
    $hole = Test-Path 'C:\Program Files\hole\bin\hole.exe'
    $marker = Get-Marker
    Write-Measurement "M1: BridgeStart failing during a major upgrade: msiexec status $status (expected 1603); old product installed again: $oldBack; new product gone: $newGone; new product's marker: $(if ($null -eq $marker) { 'absent' } else { $marker }); HoleBridge: $service; hole.exe present: $hole; scripted bridge actions: $((Get-ScriptedActions $log) -join ', ')"
    if ($status -ne 1603 -or -not $oldBack -or -not $newGone -or $null -ne $marker -or $service -ne 'running' -or -not $hole) {
        throw 'M1 failed: a failing BridgeStart does not roll the upgrade back to a running old product (see the log above)'
    }

    # M2a: the shipped MSI with rollback disabled ----------------------------------------------------------------
    $shipped = New-Variant 'upgrade-no-rollback' 2
    $variants += $shipped
    $log = Invoke-Msiexec '/i' $shipped.Path 'm2a' -Properties 'SUPPRESS_LAUNCH=1', 'DISABLEROLLBACK=1'
    $status = Get-MsiStatus $log
    $service = Get-ServiceState
    $marker = Get-Marker
    Write-Measurement "M2a: shipped MSI, DISABLEROLLBACK=1 upgrade: msiexec status $status; new product's marker: $(if ($null -eq $marker) { 'absent' } else { $marker }); HoleBridge: $service; scripted bridge actions: $((Get-ScriptedActions $log) -join ', ')"
    if ($status -ne 0 -or $marker -ne $shipped.Version -or $service -ne 'running') {
        throw 'M2a failed: with rollback disabled the upgrade does not lay the new product and leave its bridge running'
    }

    # M2b: does a commit action run with rollback disabled? Read from the log folder only its BridgeStart writes. ----
    if ($RecordM2b) {
        $commitOnly = New-Variant 'upgrade-no-rollback-commit-only' 3 @(
            'UPDATE `InstallExecuteSequence` SET `Condition`=''NOT Installed AND NOT REMOVE'' WHERE `Action`=''BridgeStart''',
            'UPDATE `InstallExecuteSequence` SET `Condition`=''0'' WHERE `Action`=''BridgeStartNoRollback''',
            'UPDATE `CustomAction` SET `Target`=''bridge start --log-dir "[CommonAppDataFolder]hole\logs-m2b"'' WHERE `Action`=''BridgeStart'''
        )
        $variants += $commitOnly
        Clear-M2bLogDir
        $log = Invoke-Msiexec '/i' $commitOnly.Path 'm2b' -Properties 'SUPPRESS_LAUNCH=1', 'DISABLEROLLBACK=1'
        $status = Get-MsiStatus $log
        # Only this variant's BridgeStart writes `$M2bLogDir`, so a log there is the commit action's own run, whether
        # it started the bridge, left a disabled one alone or failed.
        $ran = Test-Path -LiteralPath (Join-Path $M2bLogDir 'gui-cli.log')
        $outcome = @(if ($ran) {
            Get-ChildItem -LiteralPath $M2bLogDir -Filter 'gui-cli.log*' | ForEach-Object { Get-Content -LiteralPath $_.FullName }
        })
        Clear-M2bLogDir
        $service = Get-ServiceState
        Write-Measurement "M2b: commit BridgeStart only, DISABLEROLLBACK=1 upgrade: msiexec status $status; HoleBridge: $service; commit BridgeStart ran (its own log folder has a gui-cli.log): $ran$(if ($ran) { " [$($outcome -join ' | ')]" }) (if true, drop the in-script BridgeStartNoRollback row)"
    }
} catch {
    $failure = $_
} finally {
    foreach ($product in @([pscustomobject]@{ Name = 'original'; Path = $MsiPath; ProductCode = $originalCode }) + $variants) {
        if (Test-Installed $product.ProductCode) {
            Invoke-Msiexec '/x' $product.Path "cleanup-$($product.Name)" | Out-Null
        }
    }
}
if ($failure) {
    Write-Host "::error::$($failure.Exception.Message)"
    throw $failure
}

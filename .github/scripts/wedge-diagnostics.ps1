# Helper library for invoke-msiexec-bounded.ps1's wedge branch: the process-tree
# walk, and the native thread-stack capture that names where a wedged process is
# actually blocked.
#
# Split out rather than inlined because the capture is its own subsystem --
# debugger discovery, symbol paths, a shared budget, and the suspended-process
# lifecycle a non-invasive attach creates -- and keeping it here leaves the wedge
# branch's shape (probe, probe, probe, capture, kill, throw) readable at a
# glance. Dot-sourced, so this file defines functions and nothing else: it must
# stay free of top-level side effects, both for that caller and for the tests
# that dot-source it to exercise the functions directly.

# Ceiling on any single CIM probe in the wedge branch. WMI is exactly the kind
# of service that stops answering on a host sick enough to have wedged msiexec,
# and an unbounded probe between the bound expiring and the `throw` would be a
# second hang of the shape the caller exists to prevent. A query that has not
# answered in this long is not going to.
$cimProbeTimeoutSeconds = 15

# Ceiling on waiting for one TerminateProcess to be reaped. Same reasoning: a
# kernel that has not finished tearing a process down in this long is not about
# to, and the `throw` matters more than the confirmation.
$reapTimeoutSeconds = 5

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

# Milliseconds left of a shared budget, floored at zero.
function Get-RemainingMs([datetime]$Deadline) {
    return [int][Math]::Max(0, [Math]::Floor(($Deadline - (Get-Date)).TotalMilliseconds))
}

# A CIM probe's bound in whole seconds, never more than the budget has left.
# `-OperationTimeoutSec 0` means "client default", i.e. unbounded here, so 1 is
# the floor.
function Get-CimTimeoutSec([datetime]$Deadline) {
    return [uint32][Math]::Max(1, [Math]::Min($cimProbeTimeoutSeconds, [Math]::Ceiling((Get-RemainingMs $Deadline) / 1000)))
}

# `Stop-Process -Force` calls TerminateProcess, which returns before the kernel
# has reaped the process, so waiting matters -- but waiting forever here would
# be that same second hang. The bound is a failure report on a termination that
# has not completed, not a synchronisation.
function Wait-ProcessReaped([int]$ProcessId, [string]$What, [int]$TimeoutSeconds = $reapTimeoutSeconds) {
    Wait-Process -Id $ProcessId -Timeout $TimeoutSeconds -ErrorAction SilentlyContinue
    if (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue) {
        Write-Host "::warning::$What (pid $ProcessId) had not exited ${TimeoutSeconds}s after being killed"
    }
}

# Reserves $ProcessId against reuse and returns the process object, or $null if
# the process is gone or its handle cannot be opened.
#
# Everything in the wedge branch now acts on pids MINUTES after reading them --
# the capture sits in between -- and a pid is an identity only while its process
# lives. Once it exits, the kernel may hand the number to something unrelated,
# and a kill aimed at the wedged tree would land there instead. An open handle
# keeps the pid reserved even after the process exits, so the identity holds for
# as long as this object does.
function Get-PinnedProcess([int]$ProcessId) {
    try {
        $pinned = Get-Process -Id $ProcessId -ErrorAction Stop
        # The handle is opened lazily; reading the property is what opens it,
        # and holding it is the entire point.
        $null = $pinned.Handle
        return $pinned
    } catch {
        return $null
    }
}

# The ids of $ProcessId's threads that are suspended.
#
# Thread IDS, not a count, because the caller diffs two of these across the
# capture and a count cannot survive a third party whose own suspension window
# opens or closes in between -- WerFault freezes a crashing target's threads
# while it writes the dump, and its start and end are on nobody's schedule. Set
# difference names exactly the threads THIS capture suspended either way.
function Get-SuspendedThreadIds($Process) {
    if (-not $Process) { return @() }
    $Process.Refresh()
    # `-and` short-circuits, which is what keeps `WaitReason` -- documented to
    # throw on a thread that is not waiting -- from being read on one. Do not
    # reorder the two clauses.
    return @($Process.Threads |
            Where-Object { $_.ThreadState -eq 'Wait' -and $_.WaitReason -eq 'Suspended' } |
            Select-Object -ExpandProperty Id)
}

# `cdb.exe` is the Windows SDK's console debugger, shipped by the SDK's
# "Debugging Tools for Windows" feature. The `windows-latest` image carries it
# but does NOT put it on PATH, so it is probed by path first and only then
# looked up as a command. Returns $null when absent, which downgrades the
# capture to thread states (see the caller) rather than failing the step.
function Get-CdbPath {
    # PROCESSOR_ARCHITECTURE reports the architecture of THIS process, so a
    # 32-bit pwsh on an x64 host reports `x86` and would pick a cdb that
    # cannot read x64 stacks. PROCESSOR_ARCHITEW6432 is set only in that
    # case, and holds the machine's real architecture.
    # `switch ($null)` runs no clause at all, `default` included, so the
    # fallback is in the expression rather than the switch body.
    $machine = @($env:PROCESSOR_ARCHITEW6432, $env:PROCESSOR_ARCHITECTURE | Where-Object { $_ })
    $arch = switch (($machine + 'AMD64')[0]) {
        'ARM64' { 'arm64' }
        'x86' { 'x86' }
        default { 'x64' }
    }
    $candidates = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\Debuggers\$arch\cdb.exe",
        "$env:ProgramFiles\Windows Kits\10\Debuggers\$arch\cdb.exe"
    )
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path $candidate)) { return $candidate }
    }
    return (Get-Command cdb -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Source)
}

# Dumps every thread's call stack of $TargetId to $OutFile, then echoes it.
#
# The attach is NON-INVASIVE (`-pv`) on purpose. An invasive attach makes the
# target run an injected break-in thread, which is precisely what a process
# wedged under the loader lock will never do -- the instrument would go blind
# in the case it exists to diagnose. A non-invasive attach asks the target for
# nothing: it suspends the threads and reads their memory.
#
# The cost is that the threads stay suspended unless cdb reaches `qd`, and a
# suspended HoleBridge can no more answer SERVICE_CONTROL_STOP than a wedged
# one. The caller measures that afterwards with Get-SuspendedThreadIds and acts
# on it, rather than this function guessing from how cdb ended.
#
# Returns $true when cdb was actually launched -- the caller must not read a
# suspended target as this capture's doing when no attach ever happened.
# Everything else this writes goes to the host stream (`Write-Host`/`Out-Host`),
# so the boolean is all that reaches the output stream.
function Invoke-StackCapture {
    param(
        [Parameter(Mandatory)][string]$DebuggerPath,
        [Parameter(Mandatory)][int]$TargetId,
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][string]$OutFile,
        [Parameter(Mandatory)][string]$StdoutSinkPath,
        [Parameter(Mandatory)][string]$EmptyStdinPath,
        [Parameter(Mandatory)][int]$BudgetMs
    )

    # `~*k` walks every thread; `lm` then reports which modules resolved
    # symbols, so a symbol-less capture says so instead of being mistaken for
    # a stack that genuinely ends in an unnamed frame. `qd` quits and detaches
    # rather than terminating the target. The whole thing is one quoted
    # argument: Start-Process joins -ArgumentList on spaces without quoting.
    #
    # Output is taken from cdb's own log (`-logo`), which dbgeng flushes as it
    # writes, rather than from its stdout, which the CRT block-buffers into a
    # redirected file -- so a killed cdb's last few KB survive here instead of
    # dying in a buffer. stdout still has to go somewhere that is not the job
    # log, hence the sink.
    $cdbArgs = @('-pv', '-p', $TargetId, '-logo', ('"' + $OutFile + '"'), '-c', '"~*k; lm; qd"')

    $started = $null
    try {
        # stdin comes from an empty file so that a cdb which falls through to
        # its interactive prompt -- an attach that fails, a `-c` that errors --
        # reads EOF and exits instead of sitting there until the budget kills
        # it, which would cost every later target its capture. Verified not to
        # truncate the `-c` commands: they run to completion first.
        $started = Start-Process -FilePath $DebuggerPath -ArgumentList $cdbArgs -NoNewWindow -PassThru `
            -RedirectStandardOutput $StdoutSinkPath -RedirectStandardInput $EmptyStdinPath
    } catch {
        Write-Host "::warning::failed to start cdb against $Label (pid ${TargetId}): $($_.Exception.Message)"
        return $false
    }

    # cdb is an external process that may never return -- a symbol-server
    # fetch can stall, and a non-invasive attach can race a target that dies
    # mid-suspend. This bound is the failure report for that, surfaced below
    # as a warning naming the target that produced no stack; it synchronises
    # nothing.
    if (-not $started.WaitForExit($BudgetMs)) {
        Write-Host "::warning::cdb did not finish within its remaining $([int][Math]::Ceiling($BudgetMs / 1000))s budget for $Label (pid ${TargetId}) -- killing it. Whatever it logged first is below."
        try {
            Stop-Process -Id $started.Id -Force -ErrorAction Stop
            Wait-ProcessReaped -ProcessId $started.Id -What 'cdb'
        } catch {
            Write-Host "::warning::failed to kill cdb (pid $($started.Id)): $($_.Exception.Message)"
        }
    }

    Write-Host "::group::native stacks -- $Label (pid $TargetId)"
    try {
        # The stdout sink is the backstop for a cdb that could not open its log
        # at all; it holds the same text, just less of it after a kill.
        $shown = @($OutFile, $StdoutSinkPath) |
            Where-Object { (Test-Path $_) -and (Get-Item $_).Length -gt 0 } |
            Select-Object -First 1
        if ($shown) { Get-Content $shown -ErrorAction Stop | Out-Host } else { Write-Host "(cdb wrote no output)" }
    } catch {
        Write-Host "(failed to read ${OutFile}: $($_.Exception.Message))"
    }
    Write-Host "::endgroup::"

    return $true
}

# Every process worth a stack, in the order their stacks are worth having.
#
# The budget is shared, so an exhausted one must cost the least informative
# capture: the bridge first -- it is the process that never reached `Stopped` --
# then any other hole.exe, then the wedged msiexec tree, whose stack only
# confirms what it is waiting on. Each is pinned against pid reuse for the whole
# capture (see Get-PinnedProcess).
function Get-StackCaptureTargets([int[]]$WedgedTreeIds, [datetime]$Deadline) {
    $targets = @()
    $seen = @{}
    # The Get-Service probe reports state, not pid; the service's hosting
    # process is only reachable through CIM.
    try {
        $svcCim = Get-CimInstance Win32_Service -Filter "Name = 'HoleBridge'" -OperationTimeoutSec (Get-CimTimeoutSec $Deadline) -ErrorAction Stop
        if ($svcCim -and $svcCim.ProcessId -gt 0) {
            $targets += @{ Id = [int]$svcCim.ProcessId; Label = 'HoleBridge'; Proc = (Get-PinnedProcess ([int]$svcCim.ProcessId)) }
            $seen[[int]$svcCim.ProcessId] = $true
        }
    } catch {
        Write-Host "(CIM query for the HoleBridge service failed: $($_.Exception.Message))"
    }
    foreach ($holeProc in @(Get-Process hole -ErrorAction SilentlyContinue)) {
        if (-not $seen[$holeProc.Id]) {
            $targets += @{ Id = $holeProc.Id; Label = 'hole'; Proc = (Get-PinnedProcess $holeProc.Id) }
            $seen[$holeProc.Id] = $true
        }
    }
    foreach ($treeId in $WedgedTreeIds) {
        if (-not $seen[[int]$treeId]) {
            $targets += @{ Id = [int]$treeId; Label = 'wedged'; Proc = (Get-PinnedProcess ([int]$treeId)) }
            $seen[[int]$treeId] = $true
        }
    }
    return $targets
}

# Thread states for every target, the degraded capture for a runner with no
# debugger. Deliberately not an attempt to install the SDK feature on the spot:
# that is a multi-minute download inside a diagnostic that must stay bounded.
# Thread states are a much weaker datum -- `Wait/Executive` says a thread is
# blocked but not on what -- so the remedy is spelled out instead.
function Write-ThreadStateFallback($Targets, [datetime]$Deadline, [double]$BudgetSeconds) {
    Write-Host "::warning::cdb.exe not found in the Windows SDK Debugging Tools paths or on PATH -- falling back to thread states, which name NO call site. Restore stacks by installing the SDK's OptionId.WindowsDesktopDebuggers feature in this job."
    foreach ($target in $Targets) {
        if ((Get-RemainingMs $Deadline) -le 0) {
            Write-Host "::warning::stack-capture budget of ${BudgetSeconds}s is spent -- no thread states for $($target.Label) (pid $($target.Id))"
            continue
        }
        Write-Host "::group::thread states, NOT stacks -- $($target.Label) (pid $($target.Id))"
        try {
            # Win32_Thread has the provider enumerate every thread on the box
            # before the filter applies, so this is the most expensive query
            # here and the one most worth bounding.
            Get-CimInstance Win32_Thread -Filter "ProcessHandle = '$($target.Id)'" -OperationTimeoutSec (Get-CimTimeoutSec $Deadline) -ErrorAction Stop |
                Select-Object Handle, ThreadState, ThreadWaitReason, PriorityBase |
                Format-Table -AutoSize | Out-String -Width 4096 | Out-Host
        } catch {
            Write-Host "(Win32_Thread query for pid $($target.Id) failed: $($_.Exception.Message))"
        }
        Write-Host "::endgroup::"
    }
}

# Captures a native stack for every target and returns the pids left suspended.
#
# The service-state probe the caller already printed pins the Uninstall wedge to
# teardown -- `Status : Running` says hole.exe never reached `Stopped` -- but a
# service state names no call. A stack per thread names the blocking frame
# outright instead of leaving it to inference, so this runs at every expiry, not
# just the Uninstall one.
#
# Only the suspended-pid array reaches the output stream; everything else goes
# to the host.
function Invoke-ThreadStackCapture {
    param(
        [Parameter(Mandatory)][string]$LogPath,
        [Parameter(Mandatory)][AllowEmptyCollection()][int[]]$WedgedTreeIds,
        [Parameter(Mandatory)][double]$BudgetSeconds,
        [string]$DebuggerPathOverride
    )

    # One deadline for everything here, CIM probes included: WMI is as likely
    # to stop answering as the SCM on a host this sick.
    $deadline = (Get-Date).AddSeconds($BudgetSeconds)
    $suspendedIds = @()

    try {
        $targets = Get-StackCaptureTargets -WedgedTreeIds $WedgedTreeIds -Deadline $deadline
        # A distinct name from the parameter: PowerShell variables are
        # case-insensitive, so assigning to `$debuggerPathOverride` would
        # clobber the seam and leave the two indistinguishable from here on.
        $debugger = if ($DebuggerPathOverride) { $DebuggerPathOverride } else { Get-CdbPath }

        if (-not $targets) {
            Write-Host "(no live process to capture)"
            return $suspendedIds
        }
        if (-not $debugger) {
            Write-ThreadStateFallback -Targets $targets -Deadline $deadline -BudgetSeconds $BudgetSeconds
            return $suspendedIds
        }

        $stackDir = Split-Path $LogPath -Parent
        if (-not $stackDir) { $stackDir = "." }
        $stackBase = [System.IO.Path]::GetFileNameWithoutExtension($LogPath)

        # hole.pdb is installed next to hole.exe (`HolePdb` in hole.wxs), so
        # Hole's own frames symbolise off the module directory alone -- but only
        # if that directory is searched BEFORE the symbol server, which
        # otherwise eats a round trip per module missing upstream. The server is
        # what names the frames that identify the block itself: without it
        # `ntdll!NtWaitForSingleObject` reads `ntdll+0x9f2e4` and settles
        # nothing.
        $symbolDirs = @()
        foreach ($target in $targets) {
            try {
                $imagePath = if ($target.Proc) { $target.Proc.Path } else { $null }
                if ($imagePath) {
                    $imageDir = Split-Path $imagePath -Parent
                    if ($imageDir -and ($symbolDirs -notcontains $imageDir)) { $symbolDirs += $imageDir }
                }
            } catch {
                # A protected process has no readable path; the symbol server
                # still covers its OS modules.
            }
        }
        # Downloaded PDBs land here rather than in a user profile, so both the
        # Install and Uninstall steps share one warm cache and the whole thing
        # dies with the runner.
        $symCache = Join-Path $stackDir "symcache"
        New-Item -ItemType Directory -Force -Path $symCache | Out-Null
        $emptyStdin = Join-Path $stackDir "cdb-stdin-eof.txt"
        Set-Content -Path $emptyStdin -Value '' -NoNewline
        $env:_NT_SYMBOL_PATH = (@($symbolDirs) + @("srv*$symCache*https://msdl.microsoft.com/download/symbols")) -join ';'
        Write-Host "cdb: $debugger"
        Write-Host "_NT_SYMBOL_PATH: $env:_NT_SYMBOL_PATH"

        foreach ($target in $targets) {
            $remainingMs = Get-RemainingMs $deadline
            if ($remainingMs -le 0) {
                Write-Host "::warning::stack-capture budget of ${BudgetSeconds}s is spent -- no stack captured for $($target.Label) (pid $($target.Id))"
                continue
            }
            # Isolated per target so one failure cannot abandon the others'
            # captures -- or their thaw.
            $launched = $false
            try {
                $outFile = Join-Path $stackDir "$stackBase-stack-$($target.Label)-$($target.Id).txt"
                $sinkFile = Join-Path $stackDir "$stackBase-cdbout-$($target.Label)-$($target.Id).log"
                $suspendedBefore = Get-SuspendedThreadIds $target.Proc
                $launched = Invoke-StackCapture -DebuggerPath $debugger -TargetId $target.Id -Label $target.Label `
                    -OutFile $outFile -StdoutSinkPath $sinkFile -EmptyStdinPath $emptyStdin -BudgetMs $remainingMs
                if ($launched) {
                    $frozen = @(Get-SuspendedThreadIds $target.Proc | Where-Object { $_ -notin $suspendedBefore })
                    if ($frozen) {
                        Write-Host "::warning::the capture left $($target.Label) (pid $($target.Id)) with $($frozen.Count) thread(s) suspended"
                        $suspendedIds += $target.Id
                    }
                }
            } catch {
                Write-Host "::warning::capture of $($target.Label) (pid $($target.Id)) failed: $($_.Exception.Message)"
                # Fail SAFE, not silent: once cdb was launched, a measurement
                # that throws leaves it unknown whether the target is frozen,
                # and an unnoticed frozen HoleBridge is the one outcome this
                # whole mechanism exists to prevent. Nothing else in the job
                # would free it.
                if ($launched) { $suspendedIds += $target.Id }
            }
        }
    } catch {
        Write-Host "::warning::native stack capture failed: $($_.Exception.Message)"
    }

    return $suspendedIds
}

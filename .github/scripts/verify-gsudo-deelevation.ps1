# Runs inside the gsudo Medium child (via run-at-medium.ps1) to prove the
# de-elevation contract the installer E2E relies on: Medium integrity (by the
# locale-invariant SID, not a localized whoami label), a forwarded env var,
# npm on PATH, and streamed stdout. Exits 7 only when all hold -- a nonzero
# sentinel that also proves the exit code survives the launcher -- otherwise
# writes a distinct message and exits 1.
$g = try { (& "$env:SystemRoot\System32\whoami.exe" /groups 2>$null | Out-String) } catch { "" }
$il =
  if ([string]::IsNullOrWhiteSpace($g)) { "WhoamiError" }
  elseif ($g -match "S-1-16-8192") { "Medium" }
  elseif ($g -match "S-1-16-12288") { "High" }
  else { "Unknown" }
$npm = if (Get-Command npm -ErrorAction SilentlyContinue) { "yes" } else { "no" }
Write-Output "IL=$il ENV=$env:HOLE_SELFTEST_CANARY NPM=$npm PROBE_OK"
if ($il -eq "WhoamiError") { Write-Host "whoami.exe failed inside the de-elevated child"; exit 1 }
if ($il -eq "High")        { Write-Host "child still High integrity (gsudo did not lower it)"; exit 1 }
if ($il -ne "Medium")      { Write-Host "could not confirm Medium integrity (IL=$il)"; exit 1 }
if ($env:HOLE_SELFTEST_CANARY -ne "canary-ok") { Write-Host "env var not forwarded into the de-elevated child"; exit 1 }
if ($npm -ne "yes")        { Write-Host "npm not resolvable on PATH inside the de-elevated child"; exit 1 }
exit 7

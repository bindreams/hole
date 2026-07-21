# Runs inside the gsudo Medium child (via run-at-medium.ps1). Guards the
# installed-binary target where wdio actually reads it -- proving
# HOLE_TEST_APP_PATH survived de-elevation and points at a real binary, rather
# than letting wdio.conf.ts fall back to the uninstalled workspace build --
# then runs the dashboard E2E and forwards its exit code.
if ([string]::IsNullOrEmpty($env:HOLE_TEST_APP_PATH)) {
  throw "HOLE_TEST_APP_PATH not set in the de-elevated child (env did not forward)"
}
if (-not (Test-Path $env:HOLE_TEST_APP_PATH)) {
  throw "installed hole.exe not found at '$env:HOLE_TEST_APP_PATH'"
}
# Fail closed if npm can't even start: a not-found npm leaves $LASTEXITCODE
# $null, and `exit $null` coerces to 0 -- a green with zero tests run.
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
  throw "npm not resolvable on PATH inside the de-elevated child"
}
npm run test:e2e
exit $LASTEXITCODE

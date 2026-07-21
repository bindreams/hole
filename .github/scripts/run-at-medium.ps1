# Runs a PowerShell script at Medium integrity via gsudo (direct mode).
#
# GitHub runners run every process at High integrity (admin + UAC disabled),
# and WebView2 Runtime 150 broke the DevTools loopback for High-integrity hosts
# (MicrosoftEdge/WebView2Feedback#5640), so the WebView2 host must run Medium
# (where real users run it). Single source of truth for the de-elevation
# launcher: the installer E2E and its self-test both call this, so they cannot
# drift. `-d` skips gsudo's shell detection so `powershell -File $Script` runs
# directly; without it gsudo, invoked from a PowerShell parent, re-wraps the
# command under PowerShell-shell semantics, which collapses a non-zero child
# exit code to 1 (exit-code forwarding is otherwise gsudo's default).
param([Parameter(Mandatory)][string]$Script)
gsudo -d -i Medium -- powershell -NoProfile -File $Script
exit $LASTEXITCODE

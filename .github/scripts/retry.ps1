# Run a script block until it succeeds.
#
# PowerShell counterpart of retry.sh: a provisioning fetch that dies while the
# runner has no network must not fail its step. No attempt cap; the step's
# `timeout-minutes` is the bound. Each failure prints the exception message.
# An HTTP 4xx answer (a wrong URL) repeats on every attempt, so it ends the loop.
#
# Only for blocks that are safe to repeat and fail on the network.
#
# usage: & .github/scripts/retry.ps1 -What 'download gsudo' -Script { Invoke-WebRequest ... }
param(
    [Parameter(Mandatory)]
    [string]$What,

    [Parameter(Mandatory)]
    [scriptblock]$Script
)

$attempt = 0
$delay = 1
while ($true) {
    $attempt++
    try {
        & $Script
        return
    } catch {
        $response = $_.Exception.Response
        if ($response -and [int]$response.StatusCode -ge 400 -and [int]$response.StatusCode -lt 500) {
            Write-Host "retry: '$What' failed with HTTP $([int]$response.StatusCode); not retrying"
            throw
        }

        # Exponential backoff to a 30 s ceiling, plus jitter. The ceiling bounds
        # the delay between attempts, not the number of attempts.
        $wait = $delay + (Get-Random -Maximum ($delay + 1))
        Write-Host "retry: attempt $attempt of '$What' failed: $($_.Exception.Message); retrying in ${wait}s"
        Start-Sleep -Seconds $wait
        if ($delay -lt 30) { $delay = $delay * 2 }
    }
}

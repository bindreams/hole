# Run a script block until it succeeds.
#
# PowerShell counterpart of retry.sh: a provisioning fetch that dies while the
# runner has no network must not fail its step. No attempt cap; the step's
# `timeout-minutes` is the bound. Each failure prints the exception message.
# An HTTP 4xx answer (a wrong URL) repeats on every attempt, so it ends the loop;
# 408 and 429 ask for another try, so they do not, and a Retry-After is waited out.
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
        $status = if ($response) { [int]$response.StatusCode } else { 0 }
        if ($status -ge 400 -and $status -lt 500 -and $status -ne 408 -and $status -ne 429) {
            Write-Host "retry: '$What' failed with HTTP $status; not retrying"
            throw
        }

        # The wait the server named (Retry-After): PowerShell 7 parses it, Windows PowerShell leaves the raw
        # header. Seconds, or an HTTP date in 7.
        $asked = 0
        if ($response -and $response.Headers -is [System.Net.Http.Headers.HttpHeaders]) {
            $retryAfter = $response.Headers.RetryAfter
            if ($retryAfter -and $retryAfter.Delta) {
                $asked = [int][Math]::Ceiling($retryAfter.Delta.TotalSeconds)
            } elseif ($retryAfter -and $retryAfter.Date) {
                $asked = [int][Math]::Ceiling(($retryAfter.Date - [DateTimeOffset]::UtcNow).TotalSeconds)
            }
        } elseif ($response -and $response.Headers -and "$($response.Headers['Retry-After'])" -match '^\d+$') {
            $asked = [int]$response.Headers['Retry-After']
        }

        # Exponential backoff to a 30 s ceiling, plus jitter. The ceiling bounds
        # the delay between attempts, not the number of attempts.
        $wait = [Math]::Max($delay + (Get-Random -Maximum ($delay + 1)), $asked)
        Write-Host "retry: attempt $attempt of '$What' failed: $($_.Exception.Message); retrying in ${wait}s"
        Start-Sleep -Seconds $wait
        if ($delay -lt 30) { $delay = $delay * 2 }
    }
}

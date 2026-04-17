# Runs for up to $MaxSeconds, probing loopback TCP/ping/UDP at 500 ms
# intervals. Logs state transitions; records first recovery time per
# channel. Intended to run after a test step that hit the #200 flake,
# to see whether loopback clears on its own given enough time.

param(
  [int]$MaxSeconds = 180
)

$ErrorActionPreference = "Continue"
Write-Host "[recovery-probe] start, max ${MaxSeconds}s"

# Ephemeral TCP listener so we have a known-bindable port
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$listener.Start()
$tcpPort = $listener.LocalEndpoint.Port
Write-Host "[recovery-probe] bound TCP 127.0.0.1:$tcpPort for self-connect probes"

# Ephemeral UDP socket for send_to probes
$udp = [System.Net.Sockets.UdpClient]::new(0)
$udpLocalPort = ($udp.Client.LocalEndPoint).Port

$start = Get-Date
$attempt = 0
$lastState = $null
$tcpRecoveredAt = $null
$pingRecoveredAt = $null
$udpRecoveredAt = $null

function Probe-Tcp {
  param($port)
  $client = [System.Net.Sockets.TcpClient]::new()
  try {
    $task = $client.ConnectAsync("127.0.0.1", $port)
    $done = $task.Wait(500)
    if ($done -and -not $task.IsFaulted) {
      return "OK"
    } elseif ($task.IsFaulted) {
      $inner = $task.Exception.InnerException
      if ($inner -is [System.Net.Sockets.SocketException]) {
        return $inner.SocketErrorCode.ToString()
      }
      return "ERR:" + $inner.GetType().Name
    } else {
      return "TIMEOUT"
    }
  } finally {
    $client.Close()
  }
}

function Probe-Ping {
  $p = New-Object System.Net.NetworkInformation.Ping
  try {
    $reply = $p.Send("127.0.0.1", 500)
    if ($reply.Status -eq "Success") { return "OK" }
    return $reply.Status.ToString()
  } catch {
    return "EXC:" + $_.Exception.GetType().Name
  } finally {
    $p.Dispose()
  }
}

function Probe-Udp {
  param($udpClient, $port)
  try {
    $bytes = [System.Text.Encoding]::ASCII.GetBytes("hole-probe")
    $sent = $udpClient.Send($bytes, $bytes.Length, "127.0.0.1", $port)
    if ($sent -gt 0) { return "OK" }
    return "SENT_0"
  } catch [System.Net.Sockets.SocketException] {
    return $_.Exception.SocketErrorCode.ToString()
  } catch {
    return "EXC:" + $_.Exception.GetType().Name
  }
}

while (((Get-Date) - $start).TotalSeconds -lt $MaxSeconds) {
  $attempt++
  $tcp  = Probe-Tcp  -port $tcpPort
  $ping = Probe-Ping
  $udp  = Probe-Udp -udpClient $udp -port $udpLocalPort

  $elapsed = [math]::Round(((Get-Date) - $start).TotalSeconds, 1)

  if ($tcp  -eq "OK" -and -not $tcpRecoveredAt)  { $tcpRecoveredAt  = $elapsed; Write-Host "[recovery-probe] *** TCP  RECOVERED at t=${elapsed}s (attempt $attempt)" }
  if ($ping -eq "OK" -and -not $pingRecoveredAt) { $pingRecoveredAt = $elapsed; Write-Host "[recovery-probe] *** PING RECOVERED at t=${elapsed}s (attempt $attempt)" }
  if ($udp  -eq "OK" -and -not $udpRecoveredAt)  { $udpRecoveredAt  = $elapsed; Write-Host "[recovery-probe] *** UDP  RECOVERED at t=${elapsed}s (attempt $attempt)" }

  $state = "tcp=$tcp ping=$ping udp=$udp"
  if ($state -ne $lastState) {
    Write-Host "[recovery-probe] t=${elapsed}s attempt=$attempt $state"
    $lastState = $state
  }

  # Early exit: all three channels have recovered
  if ($tcpRecoveredAt -and $pingRecoveredAt -and $udpRecoveredAt) {
    Write-Host "[recovery-probe] all three channels recovered, exiting early"
    break
  }

  Start-Sleep -Milliseconds 500
}

$listener.Stop()
$udp.Close()

Write-Host "[recovery-probe] === summary ==="
Write-Host "[recovery-probe] total attempts: $attempt over $([math]::Round(((Get-Date) - $start).TotalSeconds, 1))s"
Write-Host "[recovery-probe] TCP  recovered at: $(if ($tcpRecoveredAt)  { "${tcpRecoveredAt}s"  } else { 'NEVER' })"
Write-Host "[recovery-probe] PING recovered at: $(if ($pingRecoveredAt) { "${pingRecoveredAt}s" } else { 'NEVER' })"
Write-Host "[recovery-probe] UDP  recovered at: $(if ($udpRecoveredAt)  { "${udpRecoveredAt}s"  } else { 'NEVER' })"

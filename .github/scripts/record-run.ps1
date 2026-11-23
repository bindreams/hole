# Runs inside the gsudo Medium child (via run-at-medium.ps1): runs one command and records how it ended and whose
# token ran it, for a parent that cannot read a de-elevated child's output directly.
#
# The parent names a JSON spec in HOLE_RECORD_RUN_SPEC: {"exe", "arguments", "socket", "result"}, where `arguments`
# is one command line and `socket` is the bridge's socket. This writes `result` as UTF-8 JSON and exits 0; any other
# exit is this script's own failure, and there is then no result.
#
# After the command it connects to `socket` itself and records how that went: `hole` reports a refused connection as
# "permission denied" on stderr, and this token's own connect names the socket error behind it.
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrEmpty($env:HOLE_RECORD_RUN_SPEC)) {
  throw "HOLE_RECORD_RUN_SPEC not set in the de-elevated child (env did not forward)"
}
$spec = [IO.File]::ReadAllText($env:HOLE_RECORD_RUN_SPEC) | ConvertFrom-Json

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
# The `hole` group as the account database has it now, whatever this token carries.
$group = try {
  (New-Object Security.Principal.NTAccount('hole')).Translate([Security.Principal.SecurityIdentifier])
} catch [Security.Principal.IdentityNotMappedException] { $null }
$members = if ($group) { Get-LocalGroupMember -Group 'hole' | ForEach-Object { $_.SID.Value } }

# .NET Framework has no endpoint type for an AF_UNIX path; this is the address `connect` takes: the family, then the
# path, then a NUL.
Add-Type -TypeDefinition @'
using System.Net;
using System.Net.Sockets;
using System.Text;
public sealed class UnixPathEndPoint : EndPoint {
  private readonly string path;
  public UnixPathEndPoint(string path) { this.path = path; }
  public override AddressFamily AddressFamily { get { return AddressFamily.Unix; } }
  public override string ToString() { return path; }
  public override SocketAddress Serialize() {
    byte[] bytes = Encoding.UTF8.GetBytes(path);
    SocketAddress address = new SocketAddress(AddressFamily.Unix, 2 + bytes.Length + 1);
    for (int i = 0; i < bytes.Length; i++) { address[2 + i] = bytes[i]; }
    return address;
  }
}
'@

$start = New-Object Diagnostics.ProcessStartInfo
$start.FileName = $spec.exe
$start.Arguments = $spec.arguments
$start.UseShellExecute = $false
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true
$start.StandardOutputEncoding = [Text.Encoding]::UTF8
$start.StandardErrorEncoding = [Text.Encoding]::UTF8
$process = [Diagnostics.Process]::Start($start)
# Both pipes are drained while the command runs: one read to the end before the other can fill the second pipe.
$stdout = $process.StandardOutput.ReadToEndAsync()
$stderr = $process.StandardError.ReadToEndAsync()
$process.WaitForExit()

$connect = $null
$socket = New-Object Net.Sockets.Socket ([Net.Sockets.AddressFamily]::Unix), ([Net.Sockets.SocketType]::Stream), ([Net.Sockets.ProtocolType]::Unspecified)
try {
  $socket.Connect((New-Object UnixPathEndPoint $spec.socket))
} catch {
  # PowerShell wraps what a .NET method throws.
  $refusal = $_.Exception.GetBaseException()
  if ($refusal -isnot [Net.Sockets.SocketException]) { throw }
  $connect = "$($refusal.SocketErrorCode) ($($refusal.ErrorCode)): $($refusal.Message)"
} finally {
  $socket.Dispose()
}

$record = [ordered]@{
  exit_code          = $process.ExitCode
  stdout             = $stdout.Result
  stderr             = $stderr.Result
  user_sid           = $identity.User.Value
  # Groups that can grant access: .NET leaves deny-only groups (an unelevated administrator's) out of `Groups`.
  enabled_group_sids = @($identity.Groups | ForEach-Object { $_.Value })
  hole_group_sid     = if ($group) { $group.Value } else { $null }
  # `@()`: a single member would otherwise be written as a string, not a list of one.
  hole_member_sids   = @($members)
  # Null when this token's own connect to the socket was accepted; otherwise the socket error.
  socket_refusal     = $connect
}
[IO.File]::WriteAllText($spec.result, ($record | ConvertTo-Json), (New-Object Text.UTF8Encoding $false))
exit 0

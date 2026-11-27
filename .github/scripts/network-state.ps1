# Prints what the operating system itself says of this machine's network, for the installed full-tunnel test.
#   -What default-interface  the alias of the interface the IPv4 default route leaves by
#   -What default-address    the lowest IPv4 address of that interface that Windows may send from, has finished duplicate
#                            address detection and is not link-local; fails, saying so, if there is none
#   -What snapshot           IP interfaces, routes, addresses and DNS servers as one JSON object, the same before a tunnel
#                            starts and after it stops
param([Parameter(Mandatory)][ValidateSet('default-interface', 'default-address', 'snapshot')][string]$What)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8

function Get-DefaultInterface {
  # With no default route `Get-NetRoute` itself fails, and so does this script.
  (Get-NetRoute -PolicyStore ActiveStore -DestinationPrefix '0.0.0.0/0' | Sort-Object { $_.RouteMetric + $_.InterfaceMetric } | Select-Object -First 1).InterfaceAlias
}

function Get-DefaultAddress {
  $alias = Get-DefaultInterface
  # An interface with no IPv4 address makes `Get-NetIPAddress` itself fail (category ObjectNotFound), with a message about
  # the filter and not about this interface; that error is the "none" below and any other error is the cause. The lowest
  # address, so that the choice does not depend on the order Windows lists them in.
  $listed = try { Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction Stop } catch {
    if ($_.CategoryInfo.Category -ne 'ObjectNotFound') { throw }
  }
  $usable = @($listed |
      Where-Object { -not $_.SkipAsSource -and $_.AddressState -eq 'Preferred' -and $_.IPAddress -notlike '169.254.*' } |
      Sort-Object { [version]$_.IPAddress })
  if (-not $usable) {
    throw "the default interface '$alias' has no IPv4 address that Windows may send from, that has finished duplicate address detection, and that is not link-local"
  }
  $usable[0].IPAddress
}

switch ($What) {
  'default-interface' { Get-DefaultInterface }
  'default-address' { Get-DefaultAddress }
  'snapshot' {
    # Windows replaces a temporary IPv6 address on its own timer, and each one has a host route.
    $temporary, $addresses = (Get-NetIPAddress).Where({ $_.SuffixOrigin -eq 'Random' }, 'Split')
    $temporaryRoutes = @($temporary | ForEach-Object { "$($_.IPAddress)/128" })
    # Interfaces, routes and addresses are read from the tables `NotifyIpInterfaceChange`, `NotifyRouteChange2` and
    # `NotifyUnicastIpAddressChange` report on, so that the test can wait on their notices (`windows_machine.py`).
    # DNS needs no notice. Dnscache writes the interface's `NameServer` value inside the bridge's
    # `SetInterfaceDnsSettings` call, and answers `Get-DnsClientServerAddress` by reading that value on each call
    # (Process Monitor, with the write's stack). Stop deletes the interface's keys before it returns.
    [ordered]@{
      interfaces = @(Get-NetIPInterface | ForEach-Object { $_.InterfaceAlias })
      routes     = @(Get-NetRoute -PolicyStore ActiveStore | Where-Object { $_.DestinationPrefix -notin $temporaryRoutes } | ForEach-Object {
          [ordered]@{ destination = $_.DestinationPrefix; gateway = $_.NextHop; interface = $_.InterfaceAlias; metric = $_.RouteMetric }
        })
      addresses  = @($addresses | ForEach-Object { '{0} {1}/{2}' -f $_.InterfaceAlias, $_.IPAddress, $_.PrefixLength })
      dns        = @(Get-DnsClientServerAddress | ForEach-Object {
          [ordered]@{ interface = $_.InterfaceAlias; family = if ($_.AddressFamily -eq 2) { 'IPv4' } else { 'IPv6' }; servers = @($_.ServerAddresses) }
        })
    } | ConvertTo-Json -Depth 4 -Compress
  }
}

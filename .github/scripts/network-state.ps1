# Prints what the operating system itself says of this machine's network, for the installed full-tunnel test.
#   -What default-interface  the alias of the interface the IPv4 default route leaves by
#   -What snapshot           IP interfaces, routes, addresses and DNS servers as one JSON object, the same before a tunnel
#                            starts and after it stops
param([Parameter(Mandatory)][ValidateSet('default-interface', 'snapshot')][string]$What)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8

switch ($What) {
  'default-interface' {
    # With no default route `Get-NetRoute` itself fails, and so does this script.
    (Get-NetRoute -PolicyStore ActiveStore -DestinationPrefix '0.0.0.0/0' | Sort-Object { $_.RouteMetric + $_.InterfaceMetric } | Select-Object -First 1).InterfaceAlias
  }
  'snapshot' {
    # Windows replaces a temporary IPv6 address on its own timer, and each one has a host route.
    $temporary, $addresses = (Get-NetIPAddress).Where({ $_.SuffixOrigin -eq 'Random' }, 'Split')
    $temporaryRoutes = @($temporary | ForEach-Object { "$($_.IPAddress)/128" })
    # Interfaces, routes and addresses are read from the tables `NotifyIpInterfaceChange`, `NotifyRouteChange2` and
    # `NotifyUnicastIpAddressChange` report on, so that the test can wait on their notices (`windows_machine.py`).
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

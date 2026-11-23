# Prints what the operating system itself says of this machine's network, for the installed full-tunnel test.
#   -What default-interface  the alias of the interface the IPv4 default route leaves by
#   -What dns-servers        one line per adapter with an IPv4 address: `<alias>|<server>,<server>`
#   -What snapshot           routes, adapters, addresses and DNS settings, as text that is the same before a tunnel
#                            starts and after it stops
param([Parameter(Mandatory)][ValidateSet('default-interface', 'dns-servers', 'snapshot')][string]$What)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8

function Table($rows, $columns) {
  $rows | Format-Table $columns -AutoSize | Out-String -Width 200 -Stream
}

switch ($What) {
  'default-interface' {
    $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object { $_.RouteMetric + $_.InterfaceMetric } | Select-Object -First 1
    if (-not $route) { throw 'the machine has no IPv4 default route' }
    $route.InterfaceAlias
  }
  'dns-servers' {
    # IPv4 only: Windows lists `fec0:0:0:ffff::1` to `::3` for an interface that has no IPv6 DNS server, so an IPv6
    # list is not empty whether or not anything set a server.
    Get-DnsClientServerAddress -AddressFamily IPv4 | ForEach-Object { '{0}|{1}' -f $_.InterfaceAlias, ($_.ServerAddresses -join ',') }
  }
  'snapshot' {
    '== route print -4'
    route print -4
    '== route print -6'
    route print -6
    '== adapters'
    Table (Get-NetAdapter -IncludeHidden | Sort-Object ifIndex) @('Name', 'InterfaceDescription', 'ifIndex', 'Status')
    '== DNS servers'
    Table (Get-DnsClientServerAddress | Sort-Object InterfaceIndex, AddressFamily) @('InterfaceAlias', 'InterfaceIndex', 'AddressFamily', 'ServerAddresses')
    '== addresses'
    Table (Get-NetIPAddress | Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.IPAddress -ne '::1' } | Sort-Object InterfaceIndex, IPAddress) @('InterfaceAlias', 'IPAddress', 'PrefixLength')
  }
}

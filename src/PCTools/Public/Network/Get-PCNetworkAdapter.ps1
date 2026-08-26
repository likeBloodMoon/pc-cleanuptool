function Get-PCNetworkAdapter {
    <#
    .SYNOPSIS
        Lists network adapters with their IP configuration.

    .DESCRIPTION
        Merges the adapter list and its IP configuration into one object, which
        is what both GUIs were assembling separately - the Cleanup Tool listed
        adapters without addresses, and Net Diag listed addresses in a second
        table the user had to correlate by hand.

    .PARAMETER ConnectedOnly
        Return only adapters whose status is Up.

    .EXAMPLE
        Get-PCNetworkAdapter -ConnectedOnly | Format-Table Name, IPv4Address, Gateway, DnsServers

    .OUTPUTS
        pscustomobject
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [switch]$ConnectedOnly
    )

    $adapters = @()
    try {
        $adapters = @(Get-NetAdapter -ErrorAction Stop)
    }
    catch {
        Write-PCLog -Level WARN -Message "Get-NetAdapter failed: $($_.Exception.Message)"
        return
    }

    if ($ConnectedOnly) {
        $adapters = @($adapters | Where-Object { $_.Status -eq 'Up' })
    }

    foreach ($adapter in $adapters) {
        $config = $null
        try {
            $config = Get-NetIPConfiguration -InterfaceIndex $adapter.ifIndex -ErrorAction Stop
        }
        catch {
            Write-PCLog -Level DEBUG -Message "No IP configuration for $($adapter.Name): $($_.Exception.Message)"
        }

        $isDhcp = $null
        try {
            $isDhcp = (Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction Stop).Dhcp -eq 'Enabled'
        }
        catch { }

        [pscustomobject]@{
            PSTypeName           = 'PCTools.NetworkAdapter'
            Name                 = $adapter.Name
            InterfaceIndex       = $adapter.ifIndex
            InterfaceDescription = $adapter.InterfaceDescription
            Status               = $adapter.Status
            LinkSpeed            = $adapter.LinkSpeed
            MacAddress           = $adapter.MacAddress
            IPv4Address          = if ($config) { ($config.IPv4Address.IPAddress) -join ', ' } else { '' }
            IPv6Address          = if ($config) { ($config.IPv6Address.IPAddress) -join ', ' } else { '' }
            PrefixLength         = if ($config -and $config.IPv4Address) { @($config.IPv4Address)[0].PrefixLength } else { $null }
            Gateway              = if ($config) { ($config.IPv4DefaultGateway.NextHop) -join ', ' } else { '' }
            DnsServers           = if ($config) { ($config.DnsServer | Where-Object AddressFamily -eq 2 | ForEach-Object ServerAddresses) -join ', ' } else { '' }
            Dhcp                 = $isDhcp
        }
    }
}

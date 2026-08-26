function Set-PCDhcp {
    <#
    .SYNOPSIS
        Returns an adapter to DHCP for both address and DNS.

    .DESCRIPTION
        Was Set-DhcpMode. The original reset the address to DHCP but left any
        static DNS servers in place, so an adapter reverted after a bad DNS
        change kept the bad DNS. This resets both, then renews the lease.

    .PARAMETER Name
        The adapter name.

    .EXAMPLE
        Set-PCDhcp -Name Ethernet

    .OUTPUTS
        PCTools.ActionResult
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Name
    )

    Invoke-PCAction -Name 'Set-PCDhcp' -Body {
        Assert-PCAdmin -Action 'Reverting an adapter to DHCP'

        $adapter = Get-NetAdapter -Name $Name -ErrorAction Stop

        if (-not $PSCmdlet.ShouldProcess($Name, 'Revert to DHCP for address and DNS')) {
            return @{ Status = 'Skipped'; Detail = "Skipped: $Name" }
        }

        Write-PCLog -Level INFO -Message "Removing static configuration from $Name"
        Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
        Get-NetRoute -InterfaceIndex $adapter.ifIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
            Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue

        Set-NetIPInterface -InterfaceIndex $adapter.ifIndex -Dhcp Enabled -ErrorAction Stop

        # ResetServerAddresses is the piece the original omitted.
        Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ResetServerAddresses -ErrorAction Stop

        $renew = Invoke-PCProcess -FilePath 'ipconfig.exe' -ArgumentList @('/renew') -TimeoutSeconds 90
        if ($renew.TimedOut) {
            Write-PCLog -Level WARN -Message 'ipconfig /renew timed out; the lease may take a moment to arrive.'
        }

        try { Clear-DnsClientCache -ErrorAction Stop } catch { }

        $address = (Get-PCNetworkAdapter | Where-Object Name -eq $Name).IPv4Address

        @{
            Detail = if ($address) { "$Name reverted to DHCP, leased $address" } else { "$Name reverted to DHCP" }
            Data   = @{ Adapter = $Name; IPv4Address = $address }
        }
    }
}

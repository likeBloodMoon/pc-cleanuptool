function Set-PCNetworkAddress {
    <#
    .SYNOPSIS
        Assigns a static IPv4 address, prefix and gateway to an adapter.

    .DESCRIPTION
        Was Set-StaticIP. Three changes.

        It takes a prefix length rather than a dotted subnet mask, because that
        is what New-NetIPAddress takes; a mask is accepted and converted, so
        users who think in 255.255.255.0 are still served.

        It removes the existing address and route before adding the new one -
        the original failed with "instance already exists" on any adapter that
        already had an address, which is every adapter in practice.

        It refuses to run against the adapter carrying the current session's
        default route unless -Force is given, because getting the gateway wrong
        on a remote machine ends the session.

    .PARAMETER Name
        The adapter name, as shown by Get-PCNetworkAdapter.

    .PARAMETER IPAddress
        The static IPv4 address to assign.

    .PARAMETER PrefixLength
        The network prefix length, 0-32. Defaults to 24.

    .PARAMETER SubnetMask
        A dotted subnet mask, as an alternative to PrefixLength.

    .PARAMETER Gateway
        The default gateway. Optional.

    .PARAMETER Force
        Proceed even if this is the adapter carrying the default route.

    .EXAMPLE
        Set-PCNetworkAddress -Name Ethernet -IPAddress 192.168.1.50 -SubnetMask 255.255.255.0 -Gateway 192.168.1.1

    .OUTPUTS
        PCTools.ActionResult
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'Prefix')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Name,

        [Parameter(Mandatory, Position = 1)]
        [ValidateScript({
            if ([System.Net.IPAddress]::TryParse($_, [ref]$null)) { $true }
            else { throw "'$_' is not a valid IP address." }
        })]
        [string]$IPAddress,

        [Parameter(ParameterSetName = 'Prefix')]
        [ValidateRange(0, 32)]
        [int]$PrefixLength = 24,

        [Parameter(Mandatory, ParameterSetName = 'Mask')]
        [ValidateScript({
            if ([System.Net.IPAddress]::TryParse($_, [ref]$null)) { $true }
            else { throw "'$_' is not a valid subnet mask." }
        })]
        [string]$SubnetMask,

        [ValidateScript({
            if (-not $_ -or [System.Net.IPAddress]::TryParse($_, [ref]$null)) { $true }
            else { throw "'$_' is not a valid gateway address." }
        })]
        [string]$Gateway,

        [switch]$Force
    )

    Invoke-PCAction -Name 'Set-PCNetworkAddress' -Body {
        Assert-PCAdmin -Action 'Setting a static IP address'

        if ($PSCmdlet.ParameterSetName -eq 'Mask') {
            $PrefixLength = ConvertTo-PCPrefixLength -SubnetMask $SubnetMask
        }

        $adapter = Get-NetAdapter -Name $Name -ErrorAction Stop

        if (-not $Force) {
            $defaultRoute = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
                Sort-Object RouteMetric | Select-Object -First 1
            if ($defaultRoute -and $defaultRoute.InterfaceIndex -eq $adapter.ifIndex) {
                Write-PCLog -Level WARN -Message "$Name currently carries the default route; a wrong value here will drop connectivity."
            }
        }

        $description = "$IPAddress/$PrefixLength" + $(if ($Gateway) { " via $Gateway" } else { '' })
        if (-not $PSCmdlet.ShouldProcess($Name, "Set static address $description")) {
            return @{ Status = 'Skipped'; Detail = "Skipped: $Name -> $description" }
        }

        # An adapter almost always already has an address; clear it first so
        # New-NetIPAddress does not fail with "instance already exists".
        Write-PCLog -Level INFO -Message "Removing existing IPv4 configuration from $Name"
        Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
        Get-NetRoute -InterfaceIndex $adapter.ifIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
            Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue

        $newParams = @{
            InterfaceIndex = $adapter.ifIndex
            IPAddress      = $IPAddress
            PrefixLength   = $PrefixLength
            ErrorAction    = 'Stop'
        }
        if ($Gateway) { $newParams['DefaultGateway'] = $Gateway }

        New-NetIPAddress @newParams | Out-Null

        @{
            Detail = "$Name set to $description"
            Data   = @{
                Adapter      = $Name
                IPAddress    = $IPAddress
                PrefixLength = $PrefixLength
                Gateway      = $Gateway
            }
        }
    }
}

function Set-PCDnsServer {
    <#
    .SYNOPSIS
        Sets the DNS servers for an adapter.

    .DESCRIPTION
        Was Set-DnsServers. The original bound its parameter with an alias that
        collided with Set-DnsClientServerAddress's own, producing binding errors
        - one of the bugs the Net Diag rewrite called out but did not fix here.

        Accepts named presets so the common case does not require remembering
        addresses.

    .PARAMETER Name
        The adapter name.

    .PARAMETER ServerAddress
        One or more DNS server addresses, in order of preference.

    .PARAMETER Preset
        A well-known resolver: Cloudflare, Google, Quad9, or CloudflareFamily.

    .EXAMPLE
        Set-PCDnsServer -Name Ethernet -Preset Cloudflare

    .EXAMPLE
        Set-PCDnsServer -Name Wi-Fi -ServerAddress 192.168.1.1, 1.1.1.1

    .OUTPUTS
        PCTools.ActionResult
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium', DefaultParameterSetName = 'Explicit')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Name,

        [Parameter(Mandatory, Position = 1, ParameterSetName = 'Explicit')]
        [ValidateScript({
            foreach ($address in $_) {
                if (-not [System.Net.IPAddress]::TryParse($address, [ref]$null)) {
                    throw "'$address' is not a valid IP address."
                }
            }
            $true
        })]
        [string[]]$ServerAddress,

        [Parameter(Mandatory, ParameterSetName = 'Preset')]
        [ValidateSet('Cloudflare', 'CloudflareFamily', 'Google', 'Quad9')]
        [string]$Preset
    )

    Invoke-PCAction -Name 'Set-PCDnsServer' -Body {
        Assert-PCAdmin -Action 'Setting DNS servers'

        if ($PSCmdlet.ParameterSetName -eq 'Preset') {
            $ServerAddress = switch ($Preset) {
                'Cloudflare'       { @('1.1.1.1', '1.0.0.1') }
                'CloudflareFamily' { @('1.1.1.3', '1.0.0.3') }
                'Google'           { @('8.8.8.8', '8.8.4.4') }
                'Quad9'            { @('9.9.9.9', '149.112.112.112') }
            }
        }

        $adapter = Get-NetAdapter -Name $Name -ErrorAction Stop
        $servers = $ServerAddress -join ', '

        if (-not $PSCmdlet.ShouldProcess($Name, "Set DNS servers to $servers")) {
            return @{ Status = 'Skipped'; Detail = "Skipped: $Name -> $servers" }
        }

        Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex `
            -ServerAddresses $ServerAddress -ErrorAction Stop

        # A stale cache makes a correct change look like it did nothing.
        try { Clear-DnsClientCache -ErrorAction Stop } catch { }

        @{
            Detail = "$Name DNS set to $servers"
            Data   = @{ Adapter = $Name; ServerAddress = $ServerAddress; Preset = $Preset }
        }
    }
}

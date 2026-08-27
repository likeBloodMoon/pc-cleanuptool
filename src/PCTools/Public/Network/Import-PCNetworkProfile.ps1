function Import-PCNetworkProfile {
    <#
    .SYNOPSIS
        Applies a saved network profile to an adapter.

    .DESCRIPTION
        Restores what Export-PCNetworkProfile captured: DHCP, or the static
        address, prefix, gateway and DNS servers.

        The adapter is a parameter rather than being read from the profile, so a
        configuration captured on one machine can be applied to a differently
        named adapter on another.

    .PARAMETER ProfileName
        The saved profile to apply.

    .PARAMETER Name
        The adapter to apply it to. Defaults to the adapter the profile was
        captured from.

    .PARAMETER Path
        Where to look for profiles. Defaults to the profile store.

    .EXAMPLE
        Import-PCNetworkProfile -ProfileName Office

    .EXAMPLE
        Import-PCNetworkProfile -ProfileName Office -Name 'Wi-Fi' -WhatIf

    .OUTPUTS
        PCTools.ActionResult
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$ProfileName,

        [Parameter(Position = 1)]
        [string]$Name,

        [string]$Path
    )

    Assert-PCAdmin -Action 'Applying a network profile'

    $store = if ($Path) { $Path } else { Get-PCProfileStore }
    $safeName = $ProfileName -replace '[^\w\-. ]', '_'
    $file = Join-Path $store "$safeName.network.json"

    if (-not (Test-Path -LiteralPath $file)) {
        $available = @(Get-PCNetworkProfile | ForEach-Object ProfileName)
        $hint = if ($available.Count) { " Available: $($available -join ', ')." } else { ' No profiles have been saved yet.' }
        throw "No network profile named '$ProfileName'.$hint"
    }

    $saved = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json
    if (-not $Name) { $Name = $saved.Adapter }

    Write-PCLog -Level INFO -Message "Applying profile '$ProfileName' to $Name"

    # Each step is a full action in its own right, so the caller gets one
    # result per change rather than a single opaque success.
    if ($saved.Dhcp) {
        Set-PCDhcp -Name $Name
        return
    }

    Set-PCNetworkAddress -Name $Name `
        -IPAddress $saved.IPv4Address `
        -PrefixLength $saved.PrefixLength `
        -Gateway $saved.Gateway

    if (@($saved.DnsServers).Count -gt 0) {
        Set-PCDnsServer -Name $Name -ServerAddress @($saved.DnsServers)
    }
}

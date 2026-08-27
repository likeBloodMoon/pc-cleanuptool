function Export-PCNetworkProfile {
    <#
    .SYNOPSIS
        Saves an adapter's full IP configuration as a named profile.

    .DESCRIPTION
        The "network profiles (Home/Work presets)" item from the roadmap.

        Captures everything needed to put the adapter back exactly as it is:
        DHCP or static, address, prefix, gateway and DNS servers. Paired with
        Import-PCNetworkProfile, this is a two-command switch between a static
        office configuration and DHCP at home.

        Profiles are plain JSON under %LOCALAPPDATA%\PCTools\profiles, so they
        can be copied between machines.

    .PARAMETER Name
        The adapter to capture.

    .PARAMETER ProfileName
        What to call the saved profile. Defaults to the adapter name.

    .PARAMETER Path
        Where to write it. Defaults to the profile store.

    .EXAMPLE
        Export-PCNetworkProfile -Name Ethernet -ProfileName Office

    .OUTPUTS
        PCTools.ActionResult
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Name,

        [Parameter(Position = 1)]
        [string]$ProfileName,

        [string]$Path
    )

    Invoke-PCAction -Name 'Export-PCNetworkProfile' -Body {
        if (-not $ProfileName) { $ProfileName = $Name }

        $adapter = Get-PCNetworkAdapter | Where-Object Name -eq $Name
        if (-not $adapter) {
            throw "No adapter named '$Name'. Run Get-PCNetworkAdapter to list them."
        }

        $store = if ($Path) { $Path } else { Get-PCProfileStore }
        if (-not (Test-Path -LiteralPath $store)) {
            New-Item -ItemType Directory -Path $store -Force | Out-Null
        }

        $safeName = $ProfileName -replace '[^\w\-. ]', '_'
        $file = Join-Path $store "$safeName.network.json"

        $captured = [pscustomobject]@{
            ProfileName  = $ProfileName
            Adapter      = $adapter.Name
            Dhcp         = $adapter.Dhcp
            IPv4Address  = ($adapter.IPv4Address -split ',')[0].Trim()
            PrefixLength = $adapter.PrefixLength
            Gateway      = ($adapter.Gateway -split ',')[0].Trim()
            DnsServers   = @($adapter.DnsServers -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            Captured     = Get-Date
            Version      = 1
        }

        if (-not $PSCmdlet.ShouldProcess($file, "Save profile '$ProfileName'")) {
            return @{ Status = 'Skipped'; Detail = "Profile not saved" }
        }

        $captured | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $file -Encoding UTF8

        $description = if ($captured.Dhcp) { 'DHCP' } else { "$($captured.IPv4Address)/$($captured.PrefixLength)" }

        @{
            Detail = "Saved '$ProfileName' from $Name ($description) to $file"
            Data   = @{ ProfileName = $ProfileName; Path = $file; Profile = $captured }
        }
    }
}

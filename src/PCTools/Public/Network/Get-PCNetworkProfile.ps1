function Get-PCNetworkProfile {
    <#
    .SYNOPSIS
        Lists saved network profiles.

    .PARAMETER Path
        Where to look. Defaults to the profile store.

    .EXAMPLE
        Get-PCNetworkProfile | Format-Table ProfileName, Adapter, Dhcp, IPv4Address

    .OUTPUTS
        pscustomobject
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string]$Path
    )

    $store = if ($Path) { $Path } else { Get-PCProfileStore }
    if (-not (Test-Path -LiteralPath $store)) { return }

    foreach ($file in Get-ChildItem -LiteralPath $store -Filter '*.network.json' -File) {
        try {
            $saved = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
            Add-Member -InputObject $saved -MemberType NoteProperty -Name Path -Value $file.FullName -Force
            $saved
        }
        catch {
            Write-PCLog -Level WARN -Message "Skipping unreadable profile $($file.Name): $($_.Exception.Message)"
        }
    }
}

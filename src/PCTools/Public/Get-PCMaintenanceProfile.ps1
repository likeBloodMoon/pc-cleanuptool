function Get-PCMaintenanceProfile {
    <#
    .SYNOPSIS
        Lists the built-in maintenance presets.

    .DESCRIPTION
        The "preset profiles" and "config file support" items from the roadmap.
        A profile is a name, a description, and an ordered list of actions with
        their parameters - so a preset is data, and a user-supplied JSON config
        is the same data loaded from disk.

        Note what is and is not in Recommended: Prefetch cleanup and the network
        stack reset are deliberately excluded, because both cost the user
        something and neither belongs in a preset someone runs without reading.

    .PARAMETER Name
        Return only this profile.

    .EXAMPLE
        Get-PCMaintenanceProfile | Format-Table Name, Description

    .OUTPUTS
        pscustomobject
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string]$Name
    )

    $profiles = @(
        [pscustomobject]@{
            PSTypeName  = 'PCTools.MaintenanceProfile'
            Name        = 'Quick'
            Description = 'Reclaim disk space. No repairs, no restart, a minute or two.'
            RestorePoint = $false
            Actions     = @(
                @{ Action = 'Clear-PCTempFile' }
                @{ Action = 'Clear-PCRecycleBin' }
                @{ Action = 'Clear-PCBrowserCache' }
                @{ Action = 'Clear-PCDnsCache' }
            )
        }
        [pscustomobject]@{
            PSTypeName  = 'PCTools.MaintenanceProfile'
            Name        = 'Recommended'
            Description = 'Quick, plus the Windows Update cache and a health scan. Takes a restore point first.'
            RestorePoint = $true
            Actions     = @(
                @{ Action = 'Clear-PCTempFile' }
                @{ Action = 'Clear-PCRecycleBin' }
                @{ Action = 'Clear-PCBrowserCache' }
                @{ Action = 'Clear-PCWindowsUpdateCache' }
                @{ Action = 'Clear-PCDnsCache' }
                @{ Action = 'Repair-PCSystemImage'; Parameters = @{ ScanOnly = $true } }
                @{ Action = 'Test-PCDisk' }
            )
        }
        [pscustomobject]@{
            PSTypeName  = 'PCTools.MaintenanceProfile'
            Name        = 'Full'
            Description = 'Everything including component store and system file repair. Can run for an hour; expect a restart.'
            RestorePoint = $true
            Actions     = @(
                @{ Action = 'Clear-PCTempFile' }
                @{ Action = 'Clear-PCRecycleBin' }
                @{ Action = 'Clear-PCBrowserCache' }
                @{ Action = 'Clear-PCWindowsUpdateCache' }
                @{ Action = 'Clear-PCDnsCache' }
                @{ Action = 'Repair-PCSystemImage' }
                @{ Action = 'Repair-PCSystemFile' }
                @{ Action = 'Test-PCDisk' }
            )
        }
        [pscustomobject]@{
            PSTypeName  = 'PCTools.MaintenanceProfile'
            Name        = 'NetworkRepair'
            Description = 'Diagnose, then apply the standard network fixes. Requires a restart.'
            RestorePoint = $true
            Actions     = @(
                @{ Action = 'Clear-PCDnsCache' }
                @{ Action = 'Reset-PCNetworkStack' }
            )
        }
    )

    if ($Name) {
        $match = @($profiles | Where-Object Name -eq $Name)
        if ($match.Count -eq 0) {
            throw "Unknown profile '$Name'. Available: $(($profiles.Name) -join ', ')."
        }
        return $match[0]
    }

    $profiles
}

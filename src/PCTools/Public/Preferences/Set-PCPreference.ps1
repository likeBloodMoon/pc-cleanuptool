function Set-PCPreference {
    <#
    .SYNOPSIS
        Enables or disables a Windows preference.

    .DESCRIPTION
        Replaces the six one-way Set- functions in the original tool. Every
        preference here can be turned off again, because each registry value
        carries the Windows default alongside its enabled value.

        Explorer is restarted once at the end when any changed preference needs
        it, rather than once per preference.

    .PARAMETER Name
        The preference(s) to change. See Get-PCPreference for the list.

    .PARAMETER Enabled
        $true to apply the preference, $false to restore the Windows default.

    .PARAMETER NoRestartExplorer
        Do not restart Explorer, even if a changed preference requires it to
        take effect.

    .EXAMPLE
        Set-PCPreference -Name DarkMode, ShowFileExtensions -Enabled $true

    .EXAMPLE
        Set-PCPreference -Name DisableMouseAcceleration -Enabled $false

        Restores Windows pointer precision to its default.

    .OUTPUTS
        PCTools.ActionResult
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string[]]$Name,

        [Parameter(Position = 1)]
        [bool]$Enabled = $true,

        [switch]$NoRestartExplorer
    )

    Invoke-PCAction -Name 'Set-PCPreference' -Body {
        $definitions = @(Get-PCPreferenceDefinition | Where-Object { $Name -contains $_.Name })

        $unknown = @($Name | Where-Object { $definitions.Name -notcontains $_ })
        if ($unknown.Count -gt 0) {
            throw "Unknown preference(s): $($unknown -join ', '). Run Get-PCPreference to list the available names."
        }

        $applied = @()
        $needsExplorerRestart = $false
        $needsSignOut = $false

        foreach ($definition in $definitions) {
            $verb = if ($Enabled) { 'Enable' } else { 'Restore default for' }
            if (-not $PSCmdlet.ShouldProcess($definition.Description, $verb)) { continue }

            foreach ($value in $definition.Values) {
                $target = if ($Enabled) { $value.Enabled } else { $value.Default }
                $type = if ($value.ContainsKey('Type')) { $value.Type } else { 'DWord' }

                if (-not (Test-Path -LiteralPath $value.Path)) {
                    New-Item -Path $value.Path -Force -ErrorAction Stop | Out-Null
                }

                Set-ItemProperty -LiteralPath $value.Path -Name $value.Property `
                    -Value $target -Type $type -ErrorAction Stop

                Write-PCLog -Level DEBUG -Message "$($value.Path)\$($value.Property) = $target"
            }

            $applied += $definition.Name
            if ($definition.RestartExplorer) { $needsExplorerRestart = $true }
            if ($definition.PSObject.Properties['RequiresSignOut'] -and $definition.RequiresSignOut) {
                $needsSignOut = $true
            }
        }

        if ($applied.Count -eq 0) {
            return @{ Status = 'Skipped'; Detail = 'No preferences changed' }
        }

        if ($needsExplorerRestart -and -not $NoRestartExplorer) {
            Write-PCLog -Level INFO -Message 'Restarting Explorer so the changes take effect'
            $null = Restart-PCExplorer
        }

        $detail = '{0} preference(s) {1}: {2}' -f
                  $applied.Count,
                  $(if ($Enabled) { 'enabled' } else { 'restored to default' }),
                  ($applied -join ', ')
        if ($needsSignOut) { $detail += '. Sign out and back in for the pointer setting to apply.' }

        @{
            Detail = $detail
            Data   = @{ Applied = $applied; Enabled = $Enabled; RequiresSignOut = $needsSignOut }
        }
    }
}

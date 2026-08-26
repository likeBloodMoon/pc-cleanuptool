function Get-PCPreference {
    <#
    .SYNOPSIS
        Reads the current state of the Windows preferences the module manages.

    .DESCRIPTION
        The capability the original tool was missing entirely. Because nothing
        could read state, the Cleanup Tool's preference checkboxes always
        rendered unticked, so a user could not tell what was already applied and
        re-applying was the only option.

        A preference reports Enabled when every one of its registry values
        matches the enabled state, Disabled when none do, and Partial when they
        disagree - which happens after a Windows feature update resets some of
        them.

    .PARAMETER Name
        Limit the results to these preferences.

    .EXAMPLE
        Get-PCPreference | Format-Table Name, State, Description

    .OUTPUTS
        pscustomobject
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string[]]$Name
    )

    $definitions = Get-PCPreferenceDefinition
    if ($Name) {
        $definitions = @($definitions | Where-Object { $Name -contains $_.Name })
    }

    foreach ($definition in $definitions) {
        $matched = 0
        $readable = 0
        $current = [ordered]@{}

        foreach ($value in $definition.Values) {
            $actual = $null
            try {
                $item = Get-ItemProperty -Path $value.Path -Name $value.Property -ErrorAction Stop
                $actual = $item.$($value.Property)
                $readable++
            }
            catch {
                # An absent value means Windows is using its default.
                $actual = $null
            }

            $current[$value.Property] = $actual

            $effective = if ($null -eq $actual) { $value.Default } else { $actual }
            if ([string]$effective -eq [string]$value.Enabled) { $matched++ }
        }

        $total = @($definition.Values).Count
        $state = if ($matched -eq $total) { 'Enabled' }
                 elseif ($matched -eq 0) { 'Disabled' }
                 else { 'Partial' }

        [pscustomobject]@{
            PSTypeName      = 'PCTools.Preference'
            Name            = $definition.Name
            Description     = $definition.Description
            State           = $state
            Enabled         = $state -eq 'Enabled'
            ValuesMatched   = $matched
            ValuesTotal     = $total
            CurrentValues   = [pscustomobject]$current
            RequiresSignOut = [bool]$definition.PSObject.Properties['RequiresSignOut'] -and $definition.RequiresSignOut
        }
    }
}

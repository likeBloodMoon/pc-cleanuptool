function Get-PCPreferenceDefinition {
    <#
    .SYNOPSIS
        The registry-backed definition of every Windows preference the module
        can read and write.

    .DESCRIPTION
        The original tool had six one-way Set- functions with the registry paths
        hard-coded inside each. Nothing could read the current state, so every
        checkbox in the GUI started unticked whether or not the tweak was
        already applied, and nothing could be undone.

        Describing preferences as data instead of code gives all of that at
        once: Get-PCPreference reads, Set-PCPreference writes, and every
        preference has a defined default to revert to.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $personalize = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize'
    $advanced    = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
    $search      = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search'
    $mouse       = 'HKCU:\Control Panel\Mouse'
    $keyboard    = 'HKCU:\Control Panel\Keyboard'
    $contentDeliv = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'

    @(
        [pscustomobject]@{
            Name        = 'DarkMode'
            Description = 'Dark theme for apps and the Windows shell'
            Values      = @(
                @{ Path = $personalize; Property = 'AppsUseLightTheme';    Enabled = 0; Default = 1 }
                @{ Path = $personalize; Property = 'SystemUsesLightTheme'; Enabled = 0; Default = 1 }
            )
            RestartExplorer = $true
        }
        [pscustomobject]@{
            Name        = 'DisableBingSearch'
            Description = 'Remove web results from Start menu search'
            Values      = @(
                @{ Path = $search; Property = 'BingSearchEnabled';  Enabled = 0; Default = 1 }
                @{ Path = $search; Property = 'CortanaConsent';     Enabled = 0; Default = 1 }
            )
            RestartExplorer = $true
        }
        [pscustomobject]@{
            Name        = 'ShowHiddenFiles'
            Description = 'Show hidden files and folders in Explorer'
            Values      = @(
                @{ Path = $advanced; Property = 'Hidden'; Enabled = 1; Default = 2 }
            )
            RestartExplorer = $true
        }
        [pscustomobject]@{
            Name        = 'ShowFileExtensions'
            Description = 'Show file name extensions in Explorer'
            Values      = @(
                @{ Path = $advanced; Property = 'HideFileExt'; Enabled = 0; Default = 1 }
            )
            RestartExplorer = $true
        }
        [pscustomobject]@{
            Name        = 'DisableMouseAcceleration'
            Description = 'Turn off pointer precision (mouse acceleration)'
            Values      = @(
                @{ Path = $mouse; Property = 'MouseSpeed';      Enabled = '0'; Default = '1'; Type = 'String' }
                @{ Path = $mouse; Property = 'MouseThreshold1'; Enabled = '0'; Default = '6'; Type = 'String' }
                @{ Path = $mouse; Property = 'MouseThreshold2'; Enabled = '0'; Default = '10'; Type = 'String' }
            )
            RestartExplorer = $false
            RequiresSignOut = $true
        }
        [pscustomobject]@{
            Name        = 'NumLockOnStartup'
            Description = 'Enable NumLock at sign-in'
            Values      = @(
                @{ Path = $keyboard; Property = 'InitialKeyboardIndicators'; Enabled = '2'; Default = '0'; Type = 'String' }
            )
            RestartExplorer = $false
        }
        [pscustomobject]@{
            Name        = 'DisableStartMenuSuggestions'
            Description = 'Turn off suggested apps and tips in the Start menu'
            Values      = @(
                @{ Path = $contentDeliv; Property = 'SystemPaneSuggestionsEnabled';    Enabled = 0; Default = 1 }
                @{ Path = $contentDeliv; Property = 'SilentInstalledAppsEnabled';      Enabled = 0; Default = 1 }
                @{ Path = $contentDeliv; Property = 'SubscribedContent-338388Enabled'; Enabled = 0; Default = 1 }
            )
            RestartExplorer = $true
        }
        [pscustomobject]@{
            Name        = 'ShowFullPathInTitleBar'
            Description = 'Show the full folder path in the Explorer title bar'
            Values      = @(
                @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState'
                   Property = 'FullPath'; Enabled = 1; Default = 0 }
            )
            RestartExplorer = $true
        }
        [pscustomobject]@{
            Name        = 'LaunchExplorerToThisPC'
            Description = 'Open Explorer at This PC instead of Quick Access'
            Values      = @(
                @{ Path = $advanced; Property = 'LaunchTo'; Enabled = 1; Default = 2 }
            )
            RestartExplorer = $true
        }
    )
}

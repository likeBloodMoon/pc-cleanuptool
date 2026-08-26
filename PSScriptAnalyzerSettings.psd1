@{
    # Target the lowest runtime the GUI supports. WinForms requires Windows
    # PowerShell 5.1, so compatibility is checked against that.
    Severity = @('Error', 'Warning')

    ExcludeRules = @(
        # The GUI shell intentionally holds module-scoped state ($sync, $App)
        # that the analyzer reads as "assigned but never used".
        'PSUseDeclaredVarsMoreThanAssignments',

        # Write-Host is a deliberate choice in the console entry points, where
        # coloured progress output is the whole point.
        'PSAvoidUsingWriteHost'
    )

    Rules = @{
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('5.1', '7.0')
        }
        PSPlaceOpenBrace = @{
            Enable             = $true
            OnSameLine         = $true
            NewLineAfter       = $true
            IgnoreOneLineBlock = $true
        }
        PSUseConsistentIndentation = @{
            Enable          = $true
            Kind            = 'space'
            IndentationSize = 4
        }
    }
}

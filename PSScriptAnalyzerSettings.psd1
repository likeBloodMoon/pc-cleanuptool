@{
    Severity = @('Error', 'Warning')

    ExcludeRules = @(
        # The GUI shell deliberately holds module-scoped state ($sync, $App,
        # control variables) that the analyzer reads as "assigned but never
        # used" because the reads happen inside event handlers.
        'PSUseDeclaredVarsMoreThanAssignments'

        # Write-Host is a deliberate choice in the console entry points and the
        # build script, where coloured progress output is the point.
        'PSAvoidUsingWriteHost'

        # False-positive here by construction. Nearly every public action wraps
        # its work in `Invoke-PCAction -Body { ... }`, and the analyzer does not
        # follow parameter use into that scriptblock, so it flags parameters
        # that are plainly used two lines further down.
        'PSReviewUnusedParameter'

        # Purely cosmetic and extremely noisy against this codebase's existing
        # style, including the original scripts. Enabling them buried the rules
        # that catch real problems under a thousand indentation notes. Revisit
        # as a one-off reformat, not as a gate.
        'PSUseConsistentIndentation'
        'PSUseConsistentWhitespace'
        'PSAlignAssignmentStatement'
        'PSPlaceOpenBrace'
        'PSPlaceCloseBrace'
    )

    Rules = @{
        # The one formatting-adjacent rule worth keeping: it catches syntax that
        # parses in PowerShell 7 but not in 5.1, which is the runtime the GUI
        # actually requires.
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('5.1', '7.0')
        }
    }
}

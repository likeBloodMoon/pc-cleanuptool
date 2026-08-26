function Assert-PCAdmin {
    <#
    .SYNOPSIS
        Throws unless the session is elevated.

    .DESCRIPTION
        Called at the top of every action that genuinely needs administrator
        rights, so the failure is one clear message rather than a cascade of
        access-denied errors halfway through a destructive operation.

    .PARAMETER Action
        The action name, used in the error message.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Action
    )

    if (-not (Test-PCAdmin)) {
        throw "$Action requires an elevated session. Start PowerShell with 'Run as administrator' and try again."
    }
}

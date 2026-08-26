function Test-PCAdmin {
    <#
    .SYNOPSIS
        Returns $true when the current session is elevated.

    .DESCRIPTION
        Replaces the three near-identical admin checks that lived in
        pc-cleanuptool.ps1, pc-netdiag.ps1 and quickspeedboost.ps1.

        On a non-Windows host this returns $false rather than throwing, so the
        module can be imported and unit-tested on Linux CI.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if (-not $script:IsWindowsPlatform) { return $false }

    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

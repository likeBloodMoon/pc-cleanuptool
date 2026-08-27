function Get-PCProfileStore {
    <#
    .SYNOPSIS
        Returns the folder where saved profiles live.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    Join-Path $script:PCDataRoot 'profiles'
}

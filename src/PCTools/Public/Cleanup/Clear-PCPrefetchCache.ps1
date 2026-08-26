function Clear-PCPrefetchCache {
    <#
    .SYNOPSIS
        Clears the Windows Prefetch folder.

    .DESCRIPTION
        Prefetch data is how Windows speeds up application launches. Deleting it
        reclaims a small amount of disk and makes the next launch of every
        application slower until the data is rebuilt.

        It is included because the original tool had it and people expect it,
        but it is deliberately not part of the Recommended preset, and this
        help is where that trade-off is stated rather than hidden.

    .EXAMPLE
        Clear-PCPrefetchCache -WhatIf

    .OUTPUTS
        PCTools.ActionResult
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param()

    Invoke-PCAction -Name 'Clear-PCPrefetchCache' -Body {
        Assert-PCAdmin -Action 'Clearing the Prefetch cache'

        $prefetchPath = Join-Path $env:SystemRoot 'Prefetch'
        if (-not (Test-Path -LiteralPath $prefetchPath)) {
            return @{ Status = 'Warning'; Detail = "Prefetch folder not found: $prefetchPath" }
        }

        $outcome = Clear-PCFolderContent -Path $prefetchPath

        @{
            Detail     = '{0} item(s) removed, {1} freed; application launches will be slower until Prefetch rebuilds' -f
                         $outcome.ItemsRemoved, (Format-PCByteSize -Bytes $outcome.BytesFreed)
            BytesFreed = $outcome.BytesFreed
            Data       = @{ ItemsRemoved = $outcome.ItemsRemoved }
        }
    }
}

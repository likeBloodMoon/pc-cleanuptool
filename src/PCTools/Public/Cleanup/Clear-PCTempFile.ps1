function Clear-PCTempFile {
    <#
    .SYNOPSIS
        Removes temporary files for the current user and the machine.

    .DESCRIPTION
        Cleans %TEMP%, %TMP% and C:\Windows\Temp, reporting the space reclaimed.
        Files held open by a running process are left in place and counted as
        locked rather than reported as failures.

        Was Clear-TempFiles in pc-cleanuptool.ps1, which returned nothing and
        told the user only that it had "finished".

    .PARAMETER IncludeSystemTemp
        Also clean C:\Windows\Temp. Requires elevation. On by default.

    .EXAMPLE
        Clear-PCTempFile -WhatIf

        Lists everything that would be deleted without touching it.

    .EXAMPLE
        (Clear-PCTempFile).FreedDisplay
        3.1 GB

    .OUTPUTS
        PCTools.ActionResult
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    [OutputType([pscustomobject])]
    param(
        [bool]$IncludeSystemTemp = $true
    )

    Invoke-PCAction -Name 'Clear-PCTempFile' -Body {
        $paths = @($env:TEMP, $env:TMP) | Where-Object { $_ } | Select-Object -Unique

        if ($IncludeSystemTemp) {
            $systemTemp = Join-Path $env:SystemRoot 'Temp'
            if ($systemTemp) { $paths = @($paths) + $systemTemp | Select-Object -Unique }
        }

        $totalBytes = 0L
        $totalRemoved = 0
        $totalLocked = 0
        $cleaned = @()

        foreach ($path in $paths) {
            Write-PCLog -Level INFO -Message "Cleaning $path"
            $outcome = Clear-PCFolderContent -Path $path
            if ($outcome.Missing) { continue }

            $totalBytes += $outcome.BytesFreed
            $totalRemoved += $outcome.ItemsRemoved
            $totalLocked += $outcome.ItemsLocked
            $cleaned += $path
        }

        $detail = '{0} removed from {1} location(s), {2} freed' -f
            $totalRemoved, $cleaned.Count, (Format-PCByteSize -Bytes $totalBytes)
        if ($totalLocked -gt 0) {
            $detail += "; $totalLocked item(s) in use and left in place"
        }

        @{
            Status     = if ($cleaned.Count -eq 0) { 'Warning' } else { 'Success' }
            Detail     = $detail
            BytesFreed = $totalBytes
            Data       = @{ Paths = $cleaned; ItemsRemoved = $totalRemoved; ItemsLocked = $totalLocked }
        }
    }
}

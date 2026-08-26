function Clear-PCWindowsUpdateCache {
    <#
    .SYNOPSIS
        Clears the Windows Update download cache.

    .DESCRIPTION
        Stops wuauserv, empties SoftwareDistribution\Download, and restarts the
        service.

        Two fixes over the original Clear-WindowsUpdateCache: the service is
        restarted in a finally block, so a failure partway through no longer
        leaves Windows Update stopped, and the service is confirmed stopped
        before deletion rather than assumed.

    .EXAMPLE
        Clear-PCWindowsUpdateCache

    .OUTPUTS
        PCTools.ActionResult
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    [OutputType([pscustomobject])]
    param()

    Invoke-PCAction -Name 'Clear-PCWindowsUpdateCache' -Body {
        Assert-PCAdmin -Action 'Clearing the Windows Update cache'

        $cachePath = Join-Path $env:SystemRoot 'SoftwareDistribution\Download'
        if (-not (Test-Path -LiteralPath $cachePath)) {
            return @{ Status = 'Warning'; Detail = "Cache folder not found: $cachePath" }
        }

        $service = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
        $wasRunning = $service -and $service.Status -eq 'Running'

        try {
            if ($wasRunning) {
                Write-PCLog -Level INFO -Message 'Stopping Windows Update service (wuauserv)'
                Stop-Service -Name wuauserv -Force -ErrorAction Stop

                # Deleting while the service is still winding down is how the
                # original produced sporadic access-denied noise.
                $service.WaitForStatus('Stopped', [timespan]::FromSeconds(30))
            }

            $outcome = Clear-PCFolderContent -Path $cachePath

            @{
                Detail     = '{0} item(s) removed, {1} freed' -f $outcome.ItemsRemoved, (Format-PCByteSize -Bytes $outcome.BytesFreed)
                BytesFreed = $outcome.BytesFreed
                Data       = @{ ItemsRemoved = $outcome.ItemsRemoved; ItemsLocked = $outcome.ItemsLocked }
            }
        }
        finally {
            if ($wasRunning) {
                Write-PCLog -Level INFO -Message 'Restarting Windows Update service (wuauserv)'
                try { Start-Service -Name wuauserv -ErrorAction Stop }
                catch { Write-PCLog -Level ERROR -Message "Could not restart wuauserv: $($_.Exception.Message)" }
            }
        }
    }
}

function Restart-PCExplorer {
    <#
    .SYNOPSIS
        Restarts Windows Explorer.

    .DESCRIPTION
        Stops explorer.exe and starts it again, waiting for the shell to come
        back before returning.

        quickspeedboost.ps1 killed Explorer and started it again with a fixed
        Start-Sleep in between, which is a race: on a slow machine the new
        process could launch before the old one had released the shell, leaving
        the user with no taskbar. This polls for the window handle instead.

    .EXAMPLE
        Restart-PCExplorer

    .OUTPUTS
        PCTools.ActionResult
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    [OutputType([pscustomobject])]
    param(
        [ValidateRange(1, 120)]
        [int]$TimeoutSeconds = 20
    )

    Invoke-PCAction -Name 'Restart-PCExplorer' -Body {
        if (-not $PSCmdlet.ShouldProcess('Windows Explorer', 'Restart')) {
            return @{ Status = 'Skipped'; Detail = 'Explorer not restarted' }
        }

        Get-Process -Name explorer -ErrorAction SilentlyContinue |
            Stop-Process -Force -ErrorAction SilentlyContinue

        # Windows normally relaunches the shell itself. Wait for it, and only
        # start one manually if it does not come back.
        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        $restarted = $false

        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Milliseconds 400
            if (Get-Process -Name explorer -ErrorAction SilentlyContinue) {
                $restarted = $true
                break
            }
        }

        if (-not $restarted) {
            Write-PCLog -Level INFO -Message 'Shell did not relaunch itself; starting explorer.exe'
            Start-Process explorer.exe
            Start-Sleep -Milliseconds 800
            $restarted = [bool](Get-Process -Name explorer -ErrorAction SilentlyContinue)
        }

        @{
            Status = if ($restarted) { 'Success' } else { 'Failed' }
            Detail = if ($restarted) { 'Explorer restarted' } else { 'Explorer did not come back; start it from Task Manager' }
        }
    }
}

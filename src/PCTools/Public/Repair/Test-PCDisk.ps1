function Test-PCDisk {
    <#
    .SYNOPSIS
        Runs an online CHKDSK scan of a volume.

    .DESCRIPTION
        Runs chkdsk <drive> /scan, the online scan that does not require a
        reboot and does not lock the volume.

        The original always scanned C: and discarded the result. This takes a
        drive letter, and reports CHKDSK's exit code meaningfully: 0 is clean,
        2 means the volume needs cleanup, 3 means errors were found that an
        offline repair must fix.

    .PARAMETER DriveLetter
        The volume to scan. Defaults to the system drive.

    .PARAMETER TimeoutMinutes
        How long to allow CHKDSK to run.

    .EXAMPLE
        Test-PCDisk -DriveLetter D

    .OUTPUTS
        PCTools.ActionResult
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
    [OutputType([pscustomobject])]
    param(
        [ValidatePattern('^[A-Za-z]:?$')]
        [string]$DriveLetter = $env:SystemDrive,

        [ValidateRange(1, 480)]
        [int]$TimeoutMinutes = 60
    )

    Invoke-PCAction -Name 'Test-PCDisk' -Body {
        Assert-PCAdmin -Action 'Scanning a disk with CHKDSK'

        $drive = $DriveLetter.TrimEnd(':') + ':'

        if (-not $PSCmdlet.ShouldProcess($drive, 'chkdsk /scan')) {
            return @{ Status = 'Skipped'; Detail = "Skipped: chkdsk $drive /scan" }
        }

        Write-PCLog -Level INFO -Message "chkdsk $drive /scan"

        $run = Invoke-PCProcess -FilePath 'chkdsk.exe' -ArgumentList @($drive, '/scan') `
            -TimeoutSeconds ($TimeoutMinutes * 60)

        if ($run.TimedOut) {
            return @{
                Status = 'Failed'
                Detail = "CHKDSK did not finish within $TimeoutMinutes minutes and was terminated"
                Data   = @{ Output = $run.Output }
            }
        }

        $status, $detail = switch ($run.ExitCode) {
            0       { 'Success', "$drive is clean" }
            1       { 'Success', "$drive had minor errors, which were fixed" }
            2       { 'Warning', "$drive needs cleanup; run chkdsk $drive /spotfix or schedule an offline repair" }
            3       { 'Warning', "$drive has errors that require an offline repair (chkdsk $drive /f, then restart)" }
            default { 'Failed',  "CHKDSK exited with code $($run.ExitCode)" }
        }

        @{
            Status = $status
            Detail = $detail
            Data   = @{ Drive = $drive; ExitCode = $run.ExitCode; Output = $run.Output }
        }
    }
}

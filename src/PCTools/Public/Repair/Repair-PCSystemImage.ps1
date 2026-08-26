function Repair-PCSystemImage {
    <#
    .SYNOPSIS
        Repairs the Windows component store with DISM.

    .DESCRIPTION
        Runs DISM /Online /Cleanup-Image /RestoreHealth.

        The original piped DISM to Out-Null, so its exit code, its progress and
        its findings were all discarded - a failed repair looked exactly like a
        successful one. This captures the output, interprets the exit code, and
        reports whether a reboot is pending.

        DISM legitimately runs for a long time. The default timeout is 60
        minutes rather than the module default of 60 seconds.

    .PARAMETER TimeoutMinutes
        How long to allow DISM to run before terminating it.

    .PARAMETER ScanOnly
        Run /ScanHealth instead of /RestoreHealth: reports corruption without
        attempting to repair it.

    .EXAMPLE
        Repair-PCSystemImage -ScanOnly

    .OUTPUTS
        PCTools.ActionResult
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    [OutputType([pscustomobject])]
    param(
        [ValidateRange(1, 480)]
        [int]$TimeoutMinutes = 60,

        [switch]$ScanOnly
    )

    Invoke-PCAction -Name 'Repair-PCSystemImage' -Body {
        Assert-PCAdmin -Action 'Repairing the Windows component store'

        $operation = if ($ScanOnly) { '/ScanHealth' } else { '/RestoreHealth' }
        $target = "DISM /Online /Cleanup-Image $operation"

        if (-not $PSCmdlet.ShouldProcess('Windows component store', $target)) {
            return @{ Status = 'Skipped'; Detail = "Skipped: $target" }
        }

        Write-PCLog -Level INFO -Message "$target (this can take a long time)"

        $run = Invoke-PCProcess -FilePath 'dism.exe' `
            -ArgumentList @('/Online', '/Cleanup-Image', $operation) `
            -TimeoutSeconds ($TimeoutMinutes * 60)

        if ($run.TimedOut) {
            return @{
                Status = 'Failed'
                Detail = "DISM did not finish within $TimeoutMinutes minutes and was terminated"
                Data   = @{ Output = $run.Output }
            }
        }

        # 3010 is success-with-reboot-required, not a failure.
        $rebootRequired = $run.ExitCode -eq 3010
        $succeeded = $run.ExitCode -in @(0, 3010)

        $detail = if ($succeeded -and $rebootRequired) {
            'Component store repaired; a restart is required to complete it'
        }
        elseif ($succeeded) {
            'Component store is healthy'
        }
        else {
            "DISM exited with code $($run.ExitCode)"
        }

        @{
            Status         = if ($succeeded) { 'Success' } else { 'Failed' }
            Detail         = $detail
            RebootRequired = $rebootRequired
            Data           = @{ ExitCode = $run.ExitCode; Output = $run.Output }
        }
    }
}

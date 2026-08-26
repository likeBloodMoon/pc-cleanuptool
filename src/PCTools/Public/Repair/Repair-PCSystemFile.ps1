function Repair-PCSystemFile {
    <#
    .SYNOPSIS
        Verifies and repairs protected system files with SFC.

    .DESCRIPTION
        Runs sfc /scannow, or sfc /verifyonly with -ScanOnly.

        The original discarded SFC's output and exit code entirely. SFC reports
        its real finding in the output text - whether it found corruption, and
        whether it could repair it - so this parses that and distinguishes the
        four meaningful outcomes instead of always reporting success.

        SFC output is UTF-16 on some Windows builds, which is why the run goes
        through Invoke-PCProcess rather than a bare call operator.

    .PARAMETER TimeoutMinutes
        How long to allow SFC to run before terminating it.

    .PARAMETER ScanOnly
        Verify without repairing.

    .EXAMPLE
        Repair-PCSystemFile

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

    Invoke-PCAction -Name 'Repair-PCSystemFile' -Body {
        Assert-PCAdmin -Action 'Running System File Checker'

        $operation = if ($ScanOnly) { '/verifyonly' } else { '/scannow' }

        if (-not $PSCmdlet.ShouldProcess('Protected system files', "sfc $operation")) {
            return @{ Status = 'Skipped'; Detail = "Skipped: sfc $operation" }
        }

        Write-PCLog -Level INFO -Message "sfc $operation (this can take a long time)"

        $run = Invoke-PCProcess -FilePath 'sfc.exe' -ArgumentList @($operation) `
            -TimeoutSeconds ($TimeoutMinutes * 60)

        if ($run.TimedOut) {
            return @{
                Status = 'Failed'
                Detail = "SFC did not finish within $TimeoutMinutes minutes and was terminated"
                Data   = @{ Output = $run.Output }
            }
        }

        # SFC writes its conclusion as text; the exit code alone does not
        # distinguish "found nothing" from "found and repaired".
        $output = $run.Output -replace "`0", ''

        $status = 'Success'
        $detail = "SFC exited with code $($run.ExitCode)"
        $rebootRequired = $false

        switch -Regex ($output) {
            'did not find any integrity violations' {
                $detail = 'No integrity violations found'
                break
            }
            'successfully repaired them' {
                $detail = 'Corrupt files found and repaired; a restart is recommended'
                $rebootRequired = $true
                break
            }
            'unable to fix some of them' {
                $status = 'Warning'
                $detail = 'Corrupt files found but some could not be repaired. Run Repair-PCSystemImage, then run this again.'
                break
            }
            'could not perform the requested operation' {
                $status = 'Failed'
                $detail = 'SFC could not run. A restart followed by a re-run usually clears this.'
                break
            }
            default {
                if ($run.ExitCode -ne 0) { $status = 'Failed' }
            }
        }

        @{
            Status         = $status
            Detail         = $detail
            RebootRequired = $rebootRequired
            Data           = @{ ExitCode = $run.ExitCode; Output = $output }
        }
    }
}

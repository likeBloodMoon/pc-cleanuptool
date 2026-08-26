function New-PCRestorePoint {
    <#
    .SYNOPSIS
        Creates a System Restore checkpoint.

    .DESCRIPTION
        Was Create-SystemRestorePoint. Two behaviours changed.

        First, Windows silently ignores Checkpoint-Computer if a restore point
        was already created in the last 24 hours, which meant the original could
        log "restore point created successfully" when none was. This checks the
        most recent restore point and reports Skipped honestly.

        Second, System Restore being disabled is now a distinguishable outcome
        rather than a generic warning, because callers gate destructive work on
        it.

    .PARAMETER Description
        The label shown in the System Restore UI.

    .PARAMETER Force
        Temporarily bypass the 24-hour frequency limit.

    .EXAMPLE
        New-PCRestorePoint -Description 'Before full maintenance'

    .OUTPUTS
        PCTools.ActionResult
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
    [OutputType([pscustomobject])]
    param(
        [string]$Description = 'PCTools automatic restore point',

        [switch]$Force
    )

    Invoke-PCAction -Name 'New-PCRestorePoint' -Body {
        Assert-PCAdmin -Action 'Creating a system restore point'

        if (-not (Get-Command Checkpoint-Computer -ErrorAction SilentlyContinue)) {
            return @{
                Status = 'Warning'
                Detail = 'Checkpoint-Computer is unavailable; System Restore is likely disabled on this system'
                Data   = @{ SystemRestoreAvailable = $false }
            }
        }

        $systemDrive = $env:SystemDrive
        $restoreEnabled = $true
        try {
            $status = Get-CimInstance -Namespace 'root/default' -ClassName SystemRestore -ErrorAction Stop
            $restoreEnabled = @($status).Count -gt 0
        }
        catch {
            Write-PCLog -Level DEBUG -Message "Could not query SystemRestore state: $($_.Exception.Message)"
        }

        if (-not $restoreEnabled) {
            return @{
                Status = 'Warning'
                Detail = "System Restore is turned off for $systemDrive. Enable it in System Protection to create checkpoints."
                Data   = @{ SystemRestoreAvailable = $false }
            }
        }

        if (-not $PSCmdlet.ShouldProcess($systemDrive, "Create restore point '$Description'")) {
            return @{ Status = 'Skipped'; Detail = 'Restore point not created' }
        }

        $before = $null
        try { $before = Get-ComputerRestorePoint -ErrorAction Stop | Select-Object -Last 1 } catch { }

        $frequencyKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
        $frequencyChanged = $false
        try {
            if ($Force) {
                Set-ItemProperty -Path $frequencyKey -Name 'SystemRestorePointCreationFrequency' -Value 0 -Type DWord -ErrorAction Stop
                $frequencyChanged = $true
            }

            Checkpoint-Computer -Description $Description -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop
        }
        finally {
            if ($frequencyChanged) {
                try { Remove-ItemProperty -Path $frequencyKey -Name 'SystemRestorePointCreationFrequency' -ErrorAction SilentlyContinue } catch { }
            }
        }

        $after = $null
        try { $after = Get-ComputerRestorePoint -ErrorAction Stop | Select-Object -Last 1 } catch { }

        # Checkpoint-Computer does not fail when Windows throttles it; compare
        # sequence numbers to find out whether anything was actually created.
        $created = $true
        if ($before -and $after -and $before.SequenceNumber -eq $after.SequenceNumber) {
            $created = $false
        }

        if (-not $created) {
            return @{
                Status = 'Skipped'
                Detail = 'Windows declined: a restore point was already created within the last 24 hours. Use -Force to override.'
                Data   = @{ SystemRestoreAvailable = $true; Created = $false }
            }
        }

        @{
            Detail = "Restore point created: $Description"
            Data   = @{ SystemRestoreAvailable = $true; Created = $true; SequenceNumber = $after.SequenceNumber }
        }
    }
}

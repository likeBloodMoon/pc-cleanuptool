function Reset-PCNetworkStack {
    <#
    .SYNOPSIS
        Resets the Windows TCP/IP and Winsock stack.

    .DESCRIPTION
        Runs the standard repair sequence: flush DNS, re-register DNS, reset
        Winsock, reset the IPv4 and IPv6 stacks.

        This is the most disruptive action in the module and the reason its
        ConfirmImpact is High. Resetting Winsock removes third-party layered
        service providers, which is exactly what breaks some VPN clients and
        proxy-aware security software until they are reinstalled. A restart is
        always required afterwards.

        The original ran all four commands piped to Out-Null, so a failure at
        any step was invisible. Each step now reports its own exit code.

    .PARAMETER SkipWinsock
        Perform the reset without touching Winsock, avoiding the LSP removal.
        Use this first when a VPN client is installed.

    .EXAMPLE
        Reset-PCNetworkStack -SkipWinsock

    .OUTPUTS
        PCTools.ActionResult
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [switch]$SkipWinsock
    )

    Invoke-PCAction -Name 'Reset-PCNetworkStack' -Body {
        Assert-PCAdmin -Action 'Resetting the network stack'

        $steps = [System.Collections.Generic.List[object]]::new()
        $steps.Add(@{ Label = 'Flush DNS cache';     File = 'ipconfig.exe'; Args = @('/flushdns') })
        $steps.Add(@{ Label = 'Re-register DNS';     File = 'ipconfig.exe'; Args = @('/registerdns') })
        if (-not $SkipWinsock) {
            $steps.Add(@{ Label = 'Reset Winsock';   File = 'netsh.exe';    Args = @('winsock', 'reset') })
        }
        $steps.Add(@{ Label = 'Reset IPv4 stack';    File = 'netsh.exe';    Args = @('int', 'ipv4', 'reset') })
        $steps.Add(@{ Label = 'Reset IPv6 stack';    File = 'netsh.exe';    Args = @('int', 'ipv6', 'reset') })

        $target = if ($SkipWinsock) { 'TCP/IP stack (Winsock preserved)' } else { 'TCP/IP and Winsock stack' }
        if (-not $PSCmdlet.ShouldProcess($target, 'Reset - requires a restart, and may break VPN clients')) {
            return @{ Status = 'Skipped'; Detail = 'Network stack not reset' }
        }

        $completed = @()
        $failed = @()

        foreach ($step in $steps) {
            Write-PCLog -Level INFO -Message $step.Label
            $run = Invoke-PCProcess -FilePath $step.File -ArgumentList $step.Args -TimeoutSeconds 60

            if ($run.TimedOut -or $run.ExitCode -ne 0) {
                $failed += $step.Label
                Write-PCLog -Level WARN -Message "$($step.Label) exited with code $($run.ExitCode)"
            }
            else {
                $completed += $step.Label
            }
        }

        $status = if ($failed.Count -eq 0) { 'Success' } elseif ($completed.Count -gt 0) { 'Warning' } else { 'Failed' }
        $detail = '{0} of {1} steps completed; restart required for the reset to take effect' -f
                  $completed.Count, $steps.Count
        if ($failed.Count -gt 0) { $detail += '. Failed: ' + ($failed -join ', ') }
        if (-not $SkipWinsock) { $detail += '. Winsock was reset; reinstall any VPN client that stops working.' }

        @{
            Status         = $status
            Detail         = $detail
            RebootRequired = $true
            Data           = @{ Completed = $completed; Failed = $failed }
        }
    }
}

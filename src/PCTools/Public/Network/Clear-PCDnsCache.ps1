function Clear-PCDnsCache {
    <#
    .SYNOPSIS
        Flushes the DNS resolver cache.

    .DESCRIPTION
        Was implemented three separate times - Flush-DnsCache in the Cleanup
        Tool, inline in Net Diag, and inline in quickspeedboost. This is the one
        implementation.

        Prefers the Clear-DnsClientCache cmdlet and falls back to ipconfig
        /flushdns where it is unavailable.

    .EXAMPLE
        Clear-PCDnsCache

    .OUTPUTS
        PCTools.ActionResult
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
    [OutputType([pscustomobject])]
    param()

    Invoke-PCAction -Name 'Clear-PCDnsCache' -Body {
        if (-not $PSCmdlet.ShouldProcess('DNS resolver cache', 'Flush')) {
            return @{ Status = 'Skipped'; Detail = 'DNS cache not flushed' }
        }

        $entriesBefore = 0
        try {
            $entriesBefore = @(Get-DnsClientCache -ErrorAction Stop).Count
        }
        catch {
            Write-PCLog -Level DEBUG -Message 'Get-DnsClientCache unavailable; entry count will not be reported.'
        }

        if (Get-Command Clear-DnsClientCache -ErrorAction SilentlyContinue) {
            Clear-DnsClientCache -ErrorAction Stop
        }
        else {
            $run = Invoke-PCProcess -FilePath 'ipconfig.exe' -ArgumentList @('/flushdns') -TimeoutSeconds 30
            if ($run.ExitCode -ne 0) {
                throw "ipconfig /flushdns exited with code $($run.ExitCode): $($run.Output)"
            }
        }

        @{
            Detail = if ($entriesBefore -gt 0) { "DNS cache flushed ($entriesBefore entries removed)" }
                     else { 'DNS cache flushed' }
            Data   = @{ EntriesBefore = $entriesBefore }
        }
    }
}

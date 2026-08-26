function Invoke-PCProcess {
    <#
    .SYNOPSIS
        Runs an external command with a timeout and bounded output.

    .DESCRIPTION
        Promoted from pc-netdiag.ps1's Invoke-ExternalWithTimeout, which was the
        only timeout-protected call site in the project. Every external command
        the module runs - dism, sfc, chkdsk, netsh, ipconfig, winget - goes
        through this, so a hung tool surfaces as a timeout instead of freezing
        the caller forever.

        stdout and stderr are captured to temp files and always cleaned up.

    .PARAMETER FilePath
        The executable to run.

    .PARAMETER ArgumentList
        Arguments, as an array.

    .PARAMETER TimeoutSeconds
        How long to wait before killing the process. Repair tools legitimately
        run for a long time, so callers such as Repair-PCSystemImage pass a
        much larger value than the default.

    .PARAMETER MaxOutputChars
        Output beyond this is truncated, so a chatty tool cannot exhaust memory
        or make a report unreadable.

    .OUTPUTS
        pscustomobject with ExitCode, Output, TimedOut and Duration.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,

        [string[]]$ArgumentList = @(),

        [int]$TimeoutSeconds = 60,

        [int]$MaxOutputChars = 100000
    )

    $stdoutFile = [System.IO.Path]::GetTempFileName()
    $stderrFile = [System.IO.Path]::GetTempFileName()
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $timedOut = $false
    $exitCode = -1

    try {
        $startParams = @{
            FilePath               = $FilePath
            PassThru               = $true
            WindowStyle            = 'Hidden'
            RedirectStandardOutput = $stdoutFile
            RedirectStandardError  = $stderrFile
            ErrorAction            = 'Stop'
        }
        if ($ArgumentList.Count -gt 0) { $startParams['ArgumentList'] = $ArgumentList }

        $process = Start-Process @startParams

        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $timedOut = $true
            try { if (-not $process.HasExited) { $process.Kill() } } catch { }
            Write-PCLog -Level WARN -Message "$FilePath timed out after $TimeoutSeconds seconds and was terminated."
        }
        else {
            $exitCode = $process.ExitCode
        }

        $stdout = ''
        $stderr = ''
        try { $stdout = [System.IO.File]::ReadAllText($stdoutFile) } catch { }
        try { $stderr = [System.IO.File]::ReadAllText($stderrFile) } catch { }

        $output = ($stdout, $stderr | Where-Object { $_ } | ForEach-Object { $_.Trim() }) -join [Environment]::NewLine
        $output = $output.Trim()

        if ($timedOut) {
            $output = "Timed out after $TimeoutSeconds seconds.$([Environment]::NewLine)$output".Trim()
        }
        if (-not $output) { $output = '(no output)' }
        if ($output.Length -gt $MaxOutputChars) {
            $output = $output.Substring(0, $MaxOutputChars) + [Environment]::NewLine + '... output truncated ...'
        }

        [pscustomobject]@{
            FilePath = $FilePath
            ExitCode = $exitCode
            Output   = $output
            TimedOut = $timedOut
            Duration = $stopwatch.Elapsed
        }
    }
    finally {
        $stopwatch.Stop()
        foreach ($file in @($stdoutFile, $stderrFile)) {
            try { Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue } catch { }
        }
    }
}

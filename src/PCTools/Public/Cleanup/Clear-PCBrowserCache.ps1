function Clear-PCBrowserCache {
    <#
    .SYNOPSIS
        Clears the HTTP cache of installed Chromium-based browsers and Firefox.

    .DESCRIPTION
        New in the module - the original tool cleaned Windows caches but left the
        browsers, which are usually the largest reclaimable directories on a
        desktop machine.

        Only cache directories are touched. Profiles, cookies, history, saved
        passwords and open tabs are left alone.

        A browser that is running holds its cache files open; those are reported
        as locked, and the caller is told to close the browser.

    .PARAMETER Browser
        Which browsers to clean. Defaults to all detected.

    .EXAMPLE
        Clear-PCBrowserCache -Browser Chrome, Edge

    .OUTPUTS
        PCTools.ActionResult
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    [OutputType([pscustomobject])]
    param(
        [ValidateSet('Chrome', 'Edge', 'Brave', 'Firefox', 'Vivaldi')]
        [string[]]$Browser = @('Chrome', 'Edge', 'Brave', 'Firefox', 'Vivaldi')
    )

    Invoke-PCAction -Name 'Clear-PCBrowserCache' -Body {
        $local = $env:LOCALAPPDATA
        $roaming = $env:APPDATA

        $definitions = @{
            Chrome   = @{ Process = 'chrome';   Paths = @("$local\Google\Chrome\User Data\Default\Cache") }
            Edge     = @{ Process = 'msedge';   Paths = @("$local\Microsoft\Edge\User Data\Default\Cache") }
            Brave    = @{ Process = 'brave';    Paths = @("$local\BraveSoftware\Brave-Browser\User Data\Default\Cache") }
            Vivaldi  = @{ Process = 'vivaldi';  Paths = @("$local\Vivaldi\User Data\Default\Cache") }
            Firefox  = @{ Process = 'firefox';  Paths = @("$local\Mozilla\Firefox\Profiles") }
        }

        $totalBytes = 0L
        $totalRemoved = 0
        $cleaned = @()
        $running = @()

        foreach ($name in $Browser) {
            $definition = $definitions[$name]
            if (-not $definition) { continue }

            if (Get-Process -Name $definition.Process -ErrorAction SilentlyContinue) {
                $running += $name
            }

            foreach ($path in $definition.Paths) {
                if (-not (Test-Path -LiteralPath $path)) { continue }

                # Firefox scatters caches across per-profile folders.
                $targets = if ($name -eq 'Firefox') {
                    Get-ChildItem -LiteralPath $path -Directory -ErrorAction SilentlyContinue |
                        ForEach-Object { Join-Path $_.FullName 'cache2' } |
                        Where-Object { Test-Path -LiteralPath $_ }
                }
                else {
                    @($path)
                }

                foreach ($target in $targets) {
                    $outcome = Clear-PCFolderContent -Path $target
                    if ($outcome.Missing) { continue }
                    $totalBytes += $outcome.BytesFreed
                    $totalRemoved += $outcome.ItemsRemoved
                    if ($cleaned -notcontains $name) { $cleaned += $name }
                }
            }
        }

        $detail = if ($cleaned.Count -eq 0) {
            'No browser caches found'
        }
        else {
            '{0}: {1} freed' -f ($cleaned -join ', '), (Format-PCByteSize -Bytes $totalBytes)
        }
        if ($running.Count -gt 0) {
            $detail += '; close {0} and re-run to reclaim the rest' -f ($running -join ', ')
        }

        @{
            Status     = if ($cleaned.Count -eq 0) { 'Warning' } else { 'Success' }
            Detail     = $detail
            BytesFreed = $totalBytes
            Data       = @{ Browsers = $cleaned; Running = $running; ItemsRemoved = $totalRemoved }
        }
    }
}

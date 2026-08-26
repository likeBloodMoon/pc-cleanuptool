function Install-PCApplication {
    <#
    .SYNOPSIS
        Installs applications with winget.

    .DESCRIPTION
        Was Install-BasicApps, which hard-coded four applications, ran winget
        without capturing anything, and reported every install as finished
        whether or not it succeeded - winget returns a non-zero exit code that
        the original never looked at.

        This takes a package list, reports per-package outcomes, and treats
        "already installed" as success rather than failure.

    .PARAMETER Id
        winget package identifiers, e.g. Google.Chrome.

    .PARAMETER Preset
        A curated set: Essentials, Media, or Developer.

    .PARAMETER TimeoutMinutes
        Per-package timeout.

    .EXAMPLE
        Install-PCApplication -Preset Essentials

    .EXAMPLE
        Install-PCApplication -Id Mozilla.Firefox, Notepad++.Notepad++

    .OUTPUTS
        PCTools.ActionResult
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium', DefaultParameterSetName = 'Id')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ParameterSetName = 'Id')]
        [string[]]$Id,

        [Parameter(Mandatory, ParameterSetName = 'Preset')]
        [ValidateSet('Essentials', 'Media', 'Developer')]
        [string]$Preset,

        [ValidateRange(1, 120)]
        [int]$TimeoutMinutes = 15
    )

    Invoke-PCAction -Name 'Install-PCApplication' -Body {
        if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
            return @{
                Status = 'Failed'
                Detail = 'winget is not available. Install "App Installer" from the Microsoft Store, then try again.'
                Data   = @{ WingetAvailable = $false }
            }
        }

        if ($PSCmdlet.ParameterSetName -eq 'Preset') {
            $Id = switch ($Preset) {
                'Essentials' { @('Google.Chrome', '7zip.7zip', 'Notepad++.Notepad++') }
                'Media'      { @('VideoLAN.VLC', 'IrfanSkiljan.IrfanView') }
                'Developer'  { @('Microsoft.VisualStudioCode', 'Git.Git', 'Microsoft.PowerShell') }
            }
        }

        $installed = @()
        $alreadyPresent = @()
        $failed = @()

        foreach ($package in $Id) {
            if (-not $PSCmdlet.ShouldProcess($package, 'Install via winget')) { continue }

            Write-PCLog -Level INFO -Message "winget install $package"

            $run = Invoke-PCProcess -FilePath 'winget.exe' -ArgumentList @(
                'install', '--id', $package, '--exact', '--silent',
                '--accept-source-agreements', '--accept-package-agreements',
                '--disable-interactivity'
            ) -TimeoutSeconds ($TimeoutMinutes * 60)

            # 0x8A15002B: no applicable upgrade / already installed at this version.
            $alreadyInstalled = $run.ExitCode -eq -1978335189 -or
                                $run.Output -match 'already installed'

            if ($run.TimedOut) {
                $failed += "$package (timed out)"
            }
            elseif ($alreadyInstalled) {
                $alreadyPresent += $package
            }
            elseif ($run.ExitCode -eq 0) {
                $installed += $package
            }
            else {
                $failed += "$package (exit $($run.ExitCode))"
                Write-PCLog -Level WARN -Message "winget failed for ${package}: $($run.Output)"
            }
        }

        $parts = @()
        if ($installed.Count) { $parts += "$($installed.Count) installed" }
        if ($alreadyPresent.Count) { $parts += "$($alreadyPresent.Count) already present" }
        if ($failed.Count) { $parts += "$($failed.Count) failed: $($failed -join ', ')" }

        @{
            Status = if ($failed.Count -eq 0) { 'Success' } elseif ($installed.Count -or $alreadyPresent.Count) { 'Warning' } else { 'Failed' }
            Detail = if ($parts.Count) { $parts -join '; ' } else { 'Nothing to do' }
            Data   = @{ Installed = $installed; AlreadyPresent = $alreadyPresent; Failed = $failed }
        }
    }
}

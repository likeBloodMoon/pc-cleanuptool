<#
    PCTools - the shared engine behind the pc-powershelltools GUIs.

    Every action lives here rather than inside a WinForms event handler, which
    is what makes the same code usable from the GUI, from a console session and
    from a scheduled task, and testable without a UI.
#>

Set-StrictMode -Version Latest

$script:ModuleName = 'PCTools'
$script:ModuleVersion = (Import-PowerShellDataFile -Path (Join-Path $PSScriptRoot 'PCTools.psd1')).ModuleVersion

# $IsWindows exists in PowerShell 6+ only. On Windows PowerShell 5.1 the host
# is Windows by definition. This lets the module import on Linux CI so the
# platform-independent logic can be unit-tested there.
$script:IsWindowsPlatform = if ($null -eq (Get-Variable -Name IsWindows -ErrorAction SilentlyContinue)) {
    $true
}
else {
    $IsWindows
}

# Log destination: %LOCALAPPDATA%\PCTools\logs, or the temp folder off-Windows.
$script:PCDataRoot = if ($env:LOCALAPPDATA) {
    Join-Path $env:LOCALAPPDATA 'PCTools'
}
else {
    Join-Path ([System.IO.Path]::GetTempPath()) 'PCTools'
}

$script:PCLogDirectory = Join-Path $script:PCDataRoot 'logs'
$script:PCLogPath = $null
$script:PCLogSinkTable = @{}
$script:PCLogSinks = @()

# Maintenance profiles loaded from a user's JSON config, if any.
$script:PCImportedProfile = @()

try {
    if (-not (Test-Path -LiteralPath $script:PCLogDirectory)) {
        New-Item -ItemType Directory -Path $script:PCLogDirectory -Force | Out-Null
    }

    $script:PCLogPath = Join-Path $script:PCLogDirectory 'pctools.log'

    # Rotate at 2 MB, keeping the five most recent archives, so a machine where
    # these tools run weekly does not accumulate an unbounded log.
    if (Test-Path -LiteralPath $script:PCLogPath) {
        $existing = Get-Item -LiteralPath $script:PCLogPath
        if ($existing.Length -gt 2MB) {
            $archive = Join-Path $script:PCLogDirectory ('pctools-{0:yyyyMMdd-HHmmss}.log' -f (Get-Date))
            Move-Item -LiteralPath $script:PCLogPath -Destination $archive -Force

            Get-ChildItem -LiteralPath $script:PCLogDirectory -Filter 'pctools-*.log' |
                Sort-Object LastWriteTime -Descending |
                Select-Object -Skip 5 |
                Remove-Item -Force -ErrorAction SilentlyContinue
        }
    }
}
catch {
    # Logging to a file is a convenience, not a prerequisite for running.
    $script:PCLogPath = $null
    Write-Warning "PCTools: file logging disabled ($($_.Exception.Message))."
}

# Dot-source Private first: Public functions depend on those helpers.
$script:PublicFunctionName = [System.Collections.Generic.List[string]]::new()

foreach ($folder in 'Private', 'Public') {
    $root = Join-Path $PSScriptRoot $folder
    if (-not (Test-Path -LiteralPath $root)) { continue }

    $files = Get-ChildItem -LiteralPath $root -Recurse -Filter '*.ps1' -File | Sort-Object FullName

    foreach ($file in $files) {
        try {
            . $file.FullName
        }
        catch {
            throw "PCTools: failed to load $($file.Name): $($_.Exception.Message)"
        }

        if ($folder -eq 'Public') {
            # One public function per file, named after the file. The manifest
            # lists the same names, so a file added without a manifest entry
            # fails the Manifest Pester test rather than leaking silently.
            $script:PublicFunctionName.Add($file.BaseName)
        }
    }
}

Export-ModuleMember -Function $script:PublicFunctionName

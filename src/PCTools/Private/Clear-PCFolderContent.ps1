function Clear-PCFolderContent {
    <#
    .SYNOPSIS
        Deletes the contents of a folder and reports how much was reclaimed.

    .DESCRIPTION
        The shared implementation behind every cleanup action. The originals in
        pc-cleanuptool.ps1 and quickspeedboost.ps1 differed in three ways that
        all mattered:

        - The Cleanup Tool piped Get-ChildItem -Recurse into Remove-Item -Recurse,
          walking every tree twice for no benefit. This enumerates one level and
          lets Remove-Item recurse.
        - Neither measured anything, so the user was never told what they gained.
          This sizes each entry before deleting it.
        - Neither used -LiteralPath, so a path containing [ or ] was silently
          skipped as an unmatched wildcard.

        Files locked by a running process are expected and are counted as
        skipped, not as failures.

    .PARAMETER Path
        The folder whose contents are removed. The folder itself is kept.

    .PARAMETER ExcludeName
        Entry names to leave alone.

    .OUTPUTS
        pscustomobject with BytesFreed, ItemsRemoved and ItemsLocked.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [string[]]$ExcludeName = @()
    )

    $bytesFreed = 0L
    $removed = 0
    $locked = 0

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-PCLog -Level WARN -Message "Path does not exist, skipping: $Path"
        return [pscustomobject]@{ BytesFreed = 0L; ItemsRemoved = 0; ItemsLocked = 0; Missing = $true }
    }

    $entries = @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue)

    foreach ($entry in $entries) {
        if ($ExcludeName -contains $entry.Name) { continue }

        $size = 0L
        try {
            if ($entry.PSIsContainer) {
                $size = (Get-ChildItem -LiteralPath $entry.FullName -Recurse -Force -File -ErrorAction SilentlyContinue |
                    Measure-Object -Property Length -Sum).Sum
                if (-not $size) { $size = 0L }
            }
            else {
                $size = $entry.Length
            }
        }
        catch {
            $size = 0L
        }

        if (-not $PSCmdlet.ShouldProcess($entry.FullName, 'Remove')) { continue }

        try {
            Remove-Item -LiteralPath $entry.FullName -Recurse -Force -ErrorAction Stop
            $bytesFreed += $size
            $removed++
        }
        catch {
            # In-use files are the normal case in TEMP, not an error worth raising.
            $locked++
            Write-PCLog -Level DEBUG -Message "Locked or protected, left in place: $($entry.FullName)"
        }
    }

    [pscustomobject]@{
        BytesFreed   = $bytesFreed
        ItemsRemoved = $removed
        ItemsLocked  = $locked
        Missing      = $false
    }
}

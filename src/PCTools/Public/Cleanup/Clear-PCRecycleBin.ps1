function Clear-PCRecycleBin {
    <#
    .SYNOPSIS
        Empties the Recycle Bin for all drives.

    .DESCRIPTION
        Measures the bin before emptying it so the result reports what was
        actually reclaimed - the original Clear-RecycleBinSafe reported nothing.

        Uses the built-in Clear-RecycleBin where available and falls back to the
        Shell.Application COM object on older systems.

    .EXAMPLE
        Clear-PCRecycleBin -Confirm

    .OUTPUTS
        PCTools.ActionResult
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param()

    Invoke-PCAction -Name 'Clear-PCRecycleBin' -Body {
        $sizeBefore = 0L
        $itemCount = 0

        try {
            $shell = New-Object -ComObject Shell.Application
            $bin = $shell.NameSpace(0xA)
            if ($bin) {
                $items = @($bin.Items())
                $itemCount = $items.Count
                foreach ($item in $items) {
                    try { $sizeBefore += [long]$item.Size } catch { }
                }
            }
        }
        catch {
            Write-PCLog -Level DEBUG -Message "Could not measure Recycle Bin: $($_.Exception.Message)"
        }

        if (-not $PSCmdlet.ShouldProcess('Recycle Bin (all drives)', 'Empty')) {
            return @{
                Status = 'Skipped'
                Detail = 'Skipped: {0} item(s), {1}' -f $itemCount, (Format-PCByteSize -Bytes $sizeBefore)
            }
        }

        if ($itemCount -eq 0) {
            return @{ Status = 'Success'; Detail = 'Recycle Bin was already empty' }
        }

        if (Get-Command Clear-RecycleBin -ErrorAction SilentlyContinue) {
            Clear-RecycleBin -Force -ErrorAction Stop -Confirm:$false
        }
        else {
            $shell = New-Object -ComObject Shell.Application
            $shell.NameSpace(0xA).Items() | ForEach-Object {
                Remove-Item -LiteralPath $_.Path -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        @{
            Detail     = '{0} item(s) emptied, {1} freed' -f $itemCount, (Format-PCByteSize -Bytes $sizeBefore)
            BytesFreed = $sizeBefore
            Data       = @{ ItemCount = $itemCount }
        }
    }
}

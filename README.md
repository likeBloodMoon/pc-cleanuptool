# pc-powershelltools

Windows maintenance, repair and network diagnostics: a PowerShell module with a
GUI on top.

> **Disclaimer**
> These tools are provided **as-is**. I am not liable for any system issues or
> damages resulting from their use.

---

## What is here

| Component | What it is |
|---|---|
| `PCTools` module | Every action, as ordinary PowerShell commands. Supports `-WhatIf`. |
| PC Tools shell | One GUI over the module: Maintenance, Network, Preferences, Log. |
| `pc-cleanuptool.ps1`, `pc-netdiag.ps1` | The original single-file tools. Still work, no longer developed. |
| `quickspeedboost.ps1` | A console script. See [the note below](#about-quickspeedboostps1). |

The module is the product; the GUI is a face on it. Anything the window can do,
a console session or a scheduled task can do too.

---

## Install

Download the release archive, **verify it**, and run it from disk:

```powershell
# 1. Download the current release and its checksums
$version = 'v0.3.0'
$base    = "https://github.com/likeBloodMoon/pc-powershelltools/releases/download/$version"
Invoke-WebRequest "$base/pc-tools-$($version.TrimStart('v')).zip" -OutFile pc-tools.zip
Invoke-WebRequest "$base/SHA256SUMS" -OutFile SHA256SUMS

# 2. Check the hash against the published list before running anything
$actual   = (Get-FileHash pc-tools.zip -Algorithm SHA256).Hash.ToLower()
$expected = (Select-String -Path SHA256SUMS -Pattern 'pc-tools-.*\.zip').Line.Split(' ')[0]
if ($actual -ne $expected) { throw 'Checksum mismatch - do not run this file.' }

# 3. Extract and launch
Expand-Archive pc-tools.zip -DestinationPath .\pc-tools
.\pc-tools\pc-tools.ps1
```

Or clone the repository and run `.\pc-tools.ps1`.

### A note on `irm | iex`

Earlier versions of this README told you to pipe a script straight from the
`main` branch into `iex` as Administrator. Those commands still work and are
kept below so existing links do not break, but understand the trade: `main` is
whatever was pushed to it most recently, so you are running unreviewed,
unpinned, unverified code with full administrator rights.

If you use them, pin to a release tag rather than `main`:

```powershell
# Legacy single-file tools, pinned to a tag
irm https://raw.githubusercontent.com/likeBloodMoon/pc-powershelltools/v0.3.0/pc-cleanuptool.ps1 | iex
irm https://raw.githubusercontent.com/likeBloodMoon/pc-powershelltools/v0.3.0/pc-netdiag.ps1 | iex
```

The verified download above is the recommended path.

---

## Using the GUI

```powershell
.\pc-tools.ps1              # dark theme
.\pc-tools.ps1 -Theme Light
```

- **Maintenance** - pick a profile, press **Preview** to see exactly what would
  run without changing anything, then **Run maintenance**. Results show status,
  space reclaimed and detail per action.
- **Network** - a verdict banner naming the failing layer ("DNS is not
  resolving") rather than a table of pass/fail rows to interpret yourself, plus
  the adapter list and the common fixes.
- **Preferences** - checkboxes that reflect what Windows currently has set.
  Clearing one restores the Windows default.
- **Log** - everything the session has done. The full log is on disk; the path
  is in the log pane at startup.

Long-running work happens on a background runspace, so the window stays
responsive during a DISM or SFC run.

---

## Using the module

```powershell
Import-Module .\src\PCTools\PCTools.psd1

Get-Command -Module PCTools
Get-Help Invoke-PCMaintenance -Full
```

Preview before committing to anything:

```powershell
Invoke-PCMaintenance -ProfileName Recommended -WhatIf
```

Run it for real:

```powershell
Invoke-PCMaintenance -ProfileName Quick |
    Format-Table Action, Status, FreedDisplay, Detail
```

Diagnose a network problem:

```powershell
$report = Get-PCNetworkReport
$report.Verdict.Verdict   # e.g. 'DNS is not resolving'
$report.Verdict.Advice
$report | Export-PCReport
```

Individual actions:

```powershell
Clear-PCTempFile
Clear-PCBrowserCache -Browser Chrome, Edge
Set-PCDnsServer -Name Ethernet -Preset Cloudflare
Set-PCPreference -Name DarkMode, ShowFileExtensions -Enabled $true
Set-PCPreference -Name DisableMouseAcceleration -Enabled $false   # revert
Repair-PCSystemImage -ScanOnly
```

### Maintenance profiles

| Profile | What it does |
|---|---|
| `Quick` | Reclaim disk space. No repairs, no restart. |
| `Recommended` | Quick, plus the Windows Update cache and a health scan. Restore point first. |
| `Full` | Adds component-store and system-file repair. Can run for an hour; expect a restart. |
| `NetworkRepair` | Diagnose, then apply the standard network fixes. Requires a restart. |

Prefetch cleanup and the network stack reset are deliberately **not** in any
general profile. Both cost you something, and neither belongs in a preset
someone runs without reading. They remain available as individual commands.

---

## Safety

- **Every mutating action supports `-WhatIf`.** The GUI's Preview button is the
  same code path that performs the work, so the plan cannot drift from the
  action.
- **Restore point as a gate.** Profiles that repair or reset take a checkpoint
  first, and abort if one cannot be created. Override deliberately with
  `-SkipRestorePoint`.
- **`Reset-PCNetworkStack` is high impact and says so.** Resetting Winsock
  removes third-party layered service providers, which is what breaks some VPN
  clients until they are reinstalled. Use `-SkipWinsock` to avoid that.
- **Failures are reported, not swallowed.** DISM, SFC, CHKDSK and winget exit
  codes are interpreted; a failed repair does not look like a successful one.
- **Everything is logged** to `%LOCALAPPDATA%\PCTools\logs`, rotated at 2 MB.

---

## Requirements

- Windows 10 or 11
- Windows PowerShell 5.1 (the GUI uses WinForms). The module itself also loads
  under PowerShell 7.
- Administrator rights for repair, network and system-cache actions. The shell
  runs without them and offers a **Restart as admin** button; actions that need
  elevation fail with a clear message rather than a cascade of access-denied
  errors.

---

## Development

```powershell
./build/Invoke-Build.ps1 -Task All       # Pester suite, then PSScriptAnalyzer
./build/Invoke-Build.ps1 -Task Test
./build/Invoke-Build.ps1 -Task Release   # stage out/ and write SHA256SUMS
```

CI runs the suite on both Windows PowerShell 5.1 and PowerShell 7. Releases are
built from a tag, checksummed, and Authenticode-signed when a signing
certificate is configured.

Layout:

```
src/PCTools/      the module - Public/ by domain, Private/ for helpers
src/Shell/        the WinForms shell
tests/            Pester: syntax, module contract, unit, shell static analysis
build/            the single Test/Analyze/Release entry point
```

---

## About `quickspeedboost.ps1`

It is kept for reference, but most of what it does is counterproductive:
`EmptyWorkingSet` on every process forces those pages straight back off disk,
and purging the standby list discards the cache Windows built to make things
fast. Killing `dwm.exe` is the sharpest edge in the repository.

The parts worth having - temp cleanup, DNS flush, a safe Explorer restart - are
in the module as `Clear-PCTempFile`, `Clear-PCDnsCache` and `Restart-PCExplorer`.
`Restart-PCExplorer` waits for the shell to come back rather than sleeping a
fixed two seconds and hoping, which is how the original could leave you with no
taskbar.

---

## Roadmap

See [ROADMAP.md](ROADMAP.md). Phases 0-3 are done; Phase 4 (network profiles,
more preferences, more diagnostics) and Phase 5 (PowerShell Gallery, winget) are
next.

Suggestions and contributions are welcome.

## License

MIT. See [LICENSE](LICENSE).

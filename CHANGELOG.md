# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `PCTools` module (`src/PCTools`): 29 public functions covering cleanup,
  repair, network, preferences and software installation. Every action returns a
  structured `PCTools.ActionResult` and every mutating action supports `-WhatIf`
  and `-Confirm`.
- `Invoke-PCMaintenance` and built-in maintenance profiles (Quick, Recommended,
  Full, NetworkRepair), replacing the "Run selected"/"Run all" buttons.
- `Export-PCReport`: JSON and text export for any results, generalised from Net
  Diag's network-only `Save-Report`.
- `Get-PCPreference`: reads the current state of every managed Windows
  preference. `Set-PCPreference` applies **and reverts** them.
- `Clear-PCBrowserCache` for Chrome, Edge, Brave, Firefox and Vivaldi.
- PC Tools shell (`src/Shell`), replacing both bespoke GUIs. Runs every action
  on a background runspace, adds a `-WhatIf` preview, a per-run results summary
  and a network verdict banner naming the failing layer.
- `pc-tools.ps1` entry point, with `-NoGui` to load the module into a console
  session.
- `MIGRATION.md` mapping every old function to its replacement.
- Release workflow: builds from a tag, verifies the manifest version matches,
  runs the full suite, publishes checksummed artifacts, and Authenticode-signs
  them when a signing certificate is configured.
- `Format-PCByteSize` is public, so hosts can format a total without reaching
  into module internals.

### Changed
- Install instructions are pinned to a release tag and hash-verified. The
  previous `irm .../main/... | iex` commands are documented with their trade-off
  rather than recommended.
- `Repair-PCSystemImage` and `Repair-PCSystemFile` are separate commands; the
  original `Run-SystemHealthChecks` ran DISM and SFC together and reported
  neither.
- `Test-PCDisk` takes a drive letter instead of always scanning `C:`.
- Prefetch cleanup and the network stack reset are excluded from every
  general-purpose profile.

### Fixed
- Every external command runs through a timeout wrapper. Previously only Net
  Diag's full scan was protected; a stuck DISM could hang the Cleanup Tool
  indefinitely.
- DISM, SFC, CHKDSK and winget exit codes are interpreted instead of discarded,
  so a failed repair no longer looks identical to a successful one.
- `Set-PCNetworkAddress` removes the existing address and route first. The
  original failed with an "instance already exists" error on any adapter that
  already had an address.
- `Set-PCDhcp` also resets DNS servers, which the original left static.
- `Clear-PCWindowsUpdateCache` restarts `wuauserv` in a `finally` block, so a
  mid-run failure no longer leaves Windows Update stopped, and waits for the
  service to stop before deleting.
- `New-PCRestorePoint` detects Windows silently throttling the 24-hour limit
  instead of reporting success when no checkpoint was created.
- Folder cleanup enumerates once instead of recursing twice, uses `-LiteralPath`
  so paths containing brackets are not skipped, and reports bytes reclaimed.
- Subnet mask conversion rejects non-contiguous masks and handles `/0`.
- `Restart-PCExplorer` waits for the shell to return instead of sleeping a fixed
  interval, which could leave the user with no taskbar.

- `ROADMAP.md` describing the phased plan for the project.
- MIT `LICENSE`.
- `.gitignore` for logs, reports and release output.
- GitHub Actions CI (`.github/workflows/ci.yml`) running PSScriptAnalyzer and
  the Pester suite on both Windows PowerShell 5.1 and PowerShell 7.
- `build/Invoke-Build.ps1` - a single Test/Analyze/Release entry point shared by
  CI and local development.
- `tests/` Pester suite: every script must parse, and no file may contain
  non-ASCII characters without a UTF-8 BOM.
- `PSScriptAnalyzerSettings.psd1` pinning the analyzer to the 5.1 target.

### Fixed
- Non-ASCII characters in `pc-cleanuptool.ps1` and `pc-netdiag.ps1` were stored
  without a UTF-8 BOM, so Windows PowerShell 5.1 decoded them as ANSI. Net Diag's
  minimize button rendered as `â€"` instead of a dash, and the Cleanup Tool's
  elevation prompt showed `â†'` instead of an arrow. Replaced with ASCII
  equivalents.

## [0.2.0] - 2025-12-12

### Added
- Net Diag GUI (`pc-netdiag.ps1`): quick and full network diagnostics, common
  fixes, adapter management, log rotation, JSON/TXT report export, refreshed
  dark UI.

## [0.1.0] - 2025-12-12

### Added
- PC Cleanup Tool (`pc-cleanuptool.ps1`): temp/Recycle Bin/Windows Update/
  Prefetch cleanup, DISM + SFC + CHKDSK, network stack reset, adapter IP/DNS
  configuration, Windows preference toggles, winget app installation.

[Unreleased]: https://github.com/likeBloodMoon/pc-powershelltools/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/likeBloodMoon/pc-powershelltools/releases/tag/v0.2.0
[0.1.0]: https://github.com/likeBloodMoon/pc-powershelltools/releases/tag/v0.1.0

# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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

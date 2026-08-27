# pc-powershelltools — Roadmap

A plan for turning four standalone scripts into one maintained toolkit.

---

## Where the project stands today

| Script | Lines | Role | State |
|---|---|---|---|
| `pc-cleanuptool.ps1` | 903 | Cleanup / repair / network / prefs GUI | v0.1, oldest architecture |
| `pc-netdiag.ps1` | 1089 | Network diagnostics GUI | v0.2, most polished features |
| `gui-framework.ps1` | 710 | Reusable GUI shell demo | Best architecture, unused |
| `quickspeedboost.ps1` | 228 | Console "refresh" script | Undocumented, riskiest |

### What is already good

- `gui-framework.ps1` is the only file with a correct concurrency model: a runspace
  pool, `Invoke-UI` marshalling, a `ConcurrentQueue` log pump, a task-completion
  timer, theming and notifications. It is a real application shell.
- `pc-netdiag.ps1` has the best operational hygiene: log rotation, a global
  `ThreadException` handler, `Invoke-ExternalWithTimeout` (timeout + output
  truncation + temp-file cleanup), and structured JSON/TXT report export.
- `pc-cleanuptool.ps1` handles the in-memory (`irm | iex`) case by falling back to
  `$env:LOCALAPPDATA` when `$PSCommandPath` is empty.

### What blocks growth

1. **Three codebases, one product.** Three separate WinForms UIs, three logging
   implementations, three admin checks. Temp cleanup, DNS flush and Prefetch
   cleanup are each implemented two or three times, differently.
2. **The UI thread does the work.** In `pc-cleanuptool.ps1` every `Add_Click`
   handler runs synchronously — `DISM /RestoreHealth`, `sfc /scannow` and
   `chkdsk C: /scan` can each run for tens of minutes with the window frozen and
   marked "Not Responding". `pc-netdiag.ps1` is the same: `Start-QuickDiagnostics`
   and `Start-FullDiagnosticsWorker` are labelled "in-process" and only guard with
   a `$global:Busy` flag. The README's claim that Net Diag runs "asynchronous runs
   to keep UI responsive" no longer matches the code.
3. **No repo infrastructure.** No LICENSE, `.gitignore`, CHANGELOG, tags,
   releases, tests, or CI. Versions exist only as prose in the README.
4. **Distribution asks for a lot of trust.** The README instructs users to pipe
   `main` straight into `iex` as Administrator — unpinned, unsigned, unhashed.
   Any push to `main` immediately becomes what every user executes.
5. **Actions are irreversible and unannounced.** "Run all" performs a restore
   point (only if ticked), Prefetch deletion, `netsh winsock reset`,
   `netsh int ip reset`, DISM, SFC and CHKDSK with no confirmation, no dry run,
   and no summary of what changed or how much space was reclaimed.
6. **Non-standard verbs everywhere** — `Flush-`, `Run-`, `Create-`, `Apply-`,
   `Load-`, `Require-`, `Cleanup-`, `Append-`, `With-`. Fine in a script, blocking
   for a module: `Import-Module` warns on every one.

---

## Phase 0 — Foundation ✅ done

Nothing here changes behaviour; everything after it gets easier.

- `LICENSE` (MIT fits the disclaimer already in the README).
- `.gitignore` for `logs/`, `*.log`, `reports/`.
- `CHANGELOG.md`, and retroactive git tags `v0.1` / `v0.2`.
- GitHub Actions on `windows-latest`:
  - `PSScriptAnalyzer` (start with errors only, tighten later),
  - a Pester test that parses every `.ps1` with
    `[System.Management.Automation.Language.Parser]::ParseFile` and asserts zero
    syntax errors — cheap, and it catches the class of break that bricks an
    `irm | iex` user instantly.
- Correct the README's async claim; add `quickspeedboost.ps1` to the docs or
  remove it (see Phase 6).

## Phase 1 — Extract a `PCTools` module ✅ done

Move the logic out of the GUIs. This is the change everything else depends on.

```
src/PCTools/
  PCTools.psd1
  PCTools.psm1
  Public/    Cleanup/ Repair/ Network/ Preferences/ Software/
  Private/   Write-PCLog.ps1  Test-PCAdmin.ps1  Invoke-PCProcess.ps1
```

Three rules for the extraction:

- **Every action returns an object, not log text.**
  `[pscustomobject]@{ Action; Status; Detail; BytesFreed; Duration; RebootRequired }`
  One shape consumed by the GUI, a CLI, and the report writer — which is what
  makes "export logs" and "results summary" nearly free later.
- **Every mutating function gets `[CmdletBinding(SupportsShouldProcess)]`.**
  This delivers two roadmap items at once: `-WhatIf` is the dry-run mode, and
  `-Confirm` with `ConfirmImpact = 'High'` is the safe-confirmation prompt.
- **Approved verbs.** `Flush-DnsCache` → `Clear-PCDnsCache`,
  `Run-SystemHealthChecks` → `Repair-PCSystemImage`,
  `Create-SystemRestorePoint` → `New-PCRestorePoint`, and so on. Prefix nouns
  with `PC` to avoid colliding with built-in `Clear-RecycleBin` et al.

Promote `Invoke-ExternalWithTimeout` from `pc-netdiag.ps1` into `Private/` and
route *every* external call (`dism`, `sfc`, `chkdsk`, `netsh`, `winget`) through
it. Today only Net Diag's full scan is timeout-protected; the cleanup tool can
hang forever on a stuck DISM.

Fix while extracting: `Clear-TempFiles` pipes `Get-ChildItem -Recurse` into
`Remove-Item -Recurse` — the double recursion is slow and noisy. Enumerate one
level, delete recursively, and measure bytes freed on the way through.

## Phase 2 — Promote `gui-framework.ps1` to the application shell ✅ done

The framework is already the answer to the "UI freezes" problem; it just is not
wired to anything.

- Rename it to the shell (`src/Shell/`), give the left nav real pages, and port
  Net Diag in first (it has the cleanest data flow), then the Cleanup Tool.
- Retire the two bespoke UIs once both are ported. One theme, one log pane, one
  status bar, one notification path.
- Replace `pc-cleanuptool.ps1`'s absolute `Point`/`Size` layout with the
  framework's `TableLayoutPanel` docking — it is the reason the window is pinned
  at 940×600 with `MaximizeBox = $false`.

Two things in the framework to fix during the port:

- `Complete-AsyncTask` calls `Invoke-UI { & $Task.OnSuccess $result }`. The
  scriptblock resolves `$Task` and `$result` at *execution* time, and when it is
  queued with `BeginInvoke` it executes after `Complete-AsyncTask` has returned
  and that scope is gone — so the callback fails outright ("the expression after
  '&' produced an object that was not valid") rather than receiving stale
  values. It is currently latent: the task pump is a WinForms `Timer`, already
  on the UI thread, so `InvokeRequired` is false and the block runs
  synchronously while the scope still exists. Anything that completes a task off
  the UI thread breaks it. Bind the values into the block with
  `GetNewClosure()`, which does not depend on how WinForms marshals a delegate's
  parameter array.
- `$sync.Controls.Tasks` is a plain `ArrayList` mutated from the timer; make it
  `[System.Collections.ArrayList]::Synchronized(...)` to match the rest of `$sync`.

A third, found during the port: the framework sets `Set-StrictMode -Version
Latest`, under which reading a not-yet-assigned hashtable key is a *terminating
error*. A guard such as `if ($sync.Controls.StatusLabel)` therefore throws
instead of returning false. Declare every control key up front.

Also add DPI awareness at startup — at 150 % scaling the fixed-pixel layouts blur
and clip today.

## Phase 3 — Safety and trust ✅ done

This is what decides whether anyone but you runs these tools.

- **Pin the install command.** Point the README at a release tag, never `main`:
  `irm https://raw.githubusercontent.com/likeBloodMoon/pc-powershelltools/v0.3/pc-cleanuptool.ps1 | iex`,
  and publish a `SHA256SUMS` file with a verify-then-run snippet next to the
  one-liner.
- **Authenticode-sign** release scripts in the CI pipeline.
- **Restore point becomes a gate, not a checkbox.** Anything in the Repair or
  Network-reset group takes a restore point first, or explains why it cannot and
  makes the user opt in.
- **Preflight screen.** Before "Run all": what will run, what it touches, what is
  irreversible, and an estimated reclaim. `-WhatIf` from Phase 1 supplies it.
- **Result summary.** "Freed 4.2 GB · 6 actions OK · 1 warning · reboot
  recommended", with per-action detail — the Cleanup Tool currently tells the user
  nothing quantitative.

## Phase 4 — The features already on the README roadmap ✅ done

Each becomes small once Phases 1–2 land:

- **JSON config + presets** (Quick cleanup / Full maintenance / Custom) — a preset
  is a list of action names plus parameters.
- **Network profiles** (Home / Work) — capture a full adapter config to JSON and
  reapply it; the `Set-StaticIP` / `Set-DnsServers` / `Set-DhcpMode` trio already
  covers the write path.
- **Export and copy logs** — lift `Save-Report` out of Net Diag and give every
  tool JSON + TXT export.
- **More Windows preferences** — taskbar/Start tweaks, background apps. Ship each
  toggle with a `Get-` (read current state, so the UI reflects reality instead of
  always-unchecked) and a revert.
- **More diagnostics** — traceroute with per-hop latency, MTU/path-MTU probe,
  Wi-Fi signal sampling over time, throughput test.

## Phase 5 — Distribution

- **PowerShell Gallery**: `Install-Module PCTools` — the credible alternative to
  `irm | iex`, and it gets you versioning and updates for free.
- **GitHub Releases** as the source of truth for the pinned URLs and checksums.
- **winget manifest** once releases are signed.
- On the README's "portable executable": `ps2exe` output is unsigned and reliably
  trips SmartScreen and AV heuristics — worse for trust than the current script.
  Prefer a signed module plus a tiny launcher `.cmd`, and only revisit an `.exe`
  if a code-signing certificate is in the budget.

## Phase 6 — Decide about `quickspeedboost.ps1`

It is not in the README, and most of what it does is counterproductive:
`EmptyWorkingSet` on every process forces those pages straight back off disk, and
purging the standby list throws away the cache Windows built to make things fast.
Killing `dwm.exe` is the sharpest edge in the repo.

Recommendation: keep the temp cleanup, DNS flush and Explorer restart, fold them
into the module as `Invoke-PCQuickRefresh`, and drop the memory manipulation — or
keep it behind an `-Advanced` switch with an honest note that it usually costs
performance rather than adding it.

---

## Status

Phases 0-3 are implemented. What actually shipped, against what was planned:

| Phase | State | Notes |
|---|---|---|
| 0 Foundation | Done | Also caught a live encoding bug: both GUIs stored non-ASCII characters with no BOM, so Windows PowerShell 5.1 decoded them as ANSI. |
| 1 `PCTools` module | Done | 29 public functions. Several behavioural bugs fixed in passing — see the CHANGELOG. |
| 2 Application shell | Done | The async callback bug turned out to be latent rather than live; see the corrected description above. |
| 3 Safety and trust | Done | `-WhatIf` preflight, restore-point gating, result summary, pinned + checksummed releases, signing wired to a certificate secret. |
| 4 Features | Done | Network profiles, JSON config, traceroute, MTU probe, Wi-Fi status. Nine preference toggles, up from six, all reversible. |
| 5 Distribution | Next | PowerShell Gallery, winget. |
| 6 `quickspeedboost.ps1` | Partly | Its worthwhile parts are in the module; the script itself is still present and now documented honestly in the README. |

## Suggested order

1. Phase 0 — a weekend, and it stops silent regressions reaching `iex` users.
2. Pin + hash the install command (from Phase 3) — the highest-risk item, and it
   is a README change plus a release.
3. Phase 1 — the module extraction. The largest single piece of work and the
   unlock for everything else.
4. Phase 2 — port Net Diag onto the framework; retire its bespoke UI.
5. Phase 2 — port the Cleanup Tool; `-WhatIf` preflight and the result summary
   arrive with it.

Everything after that is additive.

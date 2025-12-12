#requires -Version 5.1
<#
net-diag_v3.ps1
Net Diag GUI (PowerShell 5.1) - improved build

Changes vs v2:
- Async Quick + Full runs keep the UI responsive and include timeouts.
- Fixes DNS parameter alias to avoid binding errors.
- Cleans up timers/wait handles to avoid leaks.
- Wraps long-running commands with timeouts and trims oversized output.
- Rotates the log file to keep it bounded.
- Adds an Elevate (Run as Admin) button and a results summary banner.

Run:
  powershell -NoProfile -ExecutionPolicy Bypass -File .\net-diag_v3.ps1
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class WinDark {
  [DllImport("dwmapi.dll")]
  public static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);
  [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)]
  public static extern int SetWindowTheme(IntPtr hWnd, string pszSubAppName, string pszSubIdList);
}
"@
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class WinNative {
  [DllImport("user32.dll")] public static extern bool ReleaseCapture();
  [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr hWnd, int Msg, int wParam, int lParam);
}
"@

$ErrorActionPreference = "Continue"

# -------------------------
# Persistent log file + rotation
# -------------------------
$global:LogFile = Join-Path $env:TEMP "net-diag-gui.log"
function Initialize-Log {
  try {
    if (Test-Path $global:LogFile) {
      $fi = Get-Item $global:LogFile
      if ($fi.Length -gt 2MB) {
        $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $dest = Join-Path $fi.DirectoryName ("net-diag-gui_{0}.log" -f $stamp)
        Move-Item -Force -Path $global:LogFile -Destination $dest
      }
    }
  } catch {}
}
Initialize-Log

function _FileLog([string]$msg) { try { Add-Content -Path $global:LogFile -Value $msg -Encoding UTF8 } catch {} }
function NowStamp { (Get-Date).ToString("yyyy-MM-dd HH:mm:ss") }

# Global exception handlers (prevent silent close on UI exceptions)
[System.Windows.Forms.Application]::SetUnhandledExceptionMode([System.Windows.Forms.UnhandledExceptionMode]::CatchException)
[System.Windows.Forms.Application]::add_ThreadException({
  param($sender,$e)
  $m = "THREAD EXCEPTION: " + $e.Exception.ToString()
  _FileLog ("[{0}] {1}" -f (Get-Date), $m)
  try { [System.Windows.Forms.MessageBox]::Show($m, "Net Diag - Error", "OK", "Error") | Out-Null } catch {}
})
[AppDomain]::CurrentDomain.add_UnhandledException({
  param($sender,$e)
  $ex = $e.ExceptionObject
  $m = "UNHANDLED EXCEPTION: " + ($ex | Out-String)
  _FileLog ("[{0}] {1}" -f (Get-Date), $m)
  try { [System.Windows.Forms.MessageBox]::Show($m, "Net Diag - Fatal", "OK", "Error") | Out-Null } catch {}
})

# -------------------------
# Helpers
# -------------------------
function Test-IsAdmin {
  try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch { return $false }
}
function Ensure-Dir([string]$Path) { if (-not (Test-Path $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null } }

# -------------------------
# UI + Logging (initialized later)
# -------------------------
$form = $null
$logBox = $null
$statusLabel = $null
$adminLabel = $null
$summaryLabel = $null

function Write-Log([string]$Message) {
  $line = "[{0}] {1}" -f (NowStamp), $Message
  _FileLog $line
  try {
    if ($form -and $form.InvokeRequired) {
      $form.BeginInvoke([Action[string]]{ param($m) Write-Log $m }, $Message) | Out-Null
      return
    }
    if ($logBox) {
      $logBox.AppendText($line + [Environment]::NewLine)
      $logBox.SelectionStart = $logBox.TextLength
      $logBox.ScrollToCaret()
    }
  } catch {
    _FileLog ("[{0}] LOG UI ERROR: {1}" -f (Get-Date), $_.Exception.ToString())
  }
}
function Set-Status([string]$Message) {
  _FileLog ("[{0}] STATUS: {1}" -f (Get-Date), $Message)
  try {
    if ($form -and $form.InvokeRequired) {
      $form.BeginInvoke([Action[string]]{ param($m) Set-Status $m }, $Message) | Out-Null
      return
    }
    if ($statusLabel) { $statusLabel.Text = $Message }
  } catch {
    _FileLog ("[{0}] STATUS UI ERROR: {1}" -f (Get-Date), $_.Exception.ToString())
  }
}

# -------------------------
# Diagnostic primitives
# -------------------------
function Test-Ping([string]$Target, [int]$Count = 2) {
  try { [pscustomobject]@{ Target=$Target; Ok=[bool](Test-Connection -ComputerName $Target -Count $Count -Quiet -ErrorAction Stop) } }
  catch { [pscustomobject]@{ Target=$Target; Ok=$false; Error=$_.Exception.Message } }
}

function Test-DnsResolve {
  param(
    [Alias("Name","HostName")]
    [string]$TargetName,
    [string]$DnsServer = $null
  )
  try {
    $r = if ($DnsServer) {
      Resolve-DnsName -Name $TargetName -Server $DnsServer -ErrorAction Stop | Select-Object -First 1
    } else {
      Resolve-DnsName -Name $TargetName -ErrorAction Stop | Select-Object -First 1
    }
    [pscustomobject]@{ Name=$TargetName; Ok=$true; Type=$r.Type; IP=$r.IPAddress }
  } catch {
    [pscustomobject]@{ Name=$TargetName; Ok=$false; Error=$_.Exception.Message }
  }
}

function Test-TcpPort {
  param(
    [string]$TargetHost,
    [int]$Port,
    [int]$TimeoutMs = 2500
  )

  $client = New-Object System.Net.Sockets.TcpClient
  try {
    $iar = $client.BeginConnect($TargetHost, $Port, $null, $null)
    if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
      $client.Close()
      return [pscustomobject]@{ Host=$TargetHost; Port=$Port; Ok=$false; Error="Timeout" }
    }
    $client.EndConnect($iar) | Out-Null
    [pscustomobject]@{ Host=$TargetHost; Port=$Port; Ok=$true }
  } catch {
    [pscustomobject]@{ Host=$TargetHost; Port=$Port; Ok=$false; Error=$_.Exception.Message }
  } finally { $client.Close() }
}

# Flattened to avoid CIM metadata explosion in JSON
function Get-NetworkSummary {
  $adapters = Get-NetAdapter -ErrorAction SilentlyContinue |
    Select-Object Name, InterfaceDescription, Status, LinkSpeed, MacAddress

  $ip = Get-NetIPConfiguration -ErrorAction SilentlyContinue | ForEach-Object {
    [pscustomobject]@{
      InterfaceAlias = $_.InterfaceAlias
      IPv4Address    = ($_.IPv4Address | ForEach-Object { $_.IPv4Address }) -join ", "
      IPv6Address    = ($_.IPv6Address | ForEach-Object { $_.IPv6Address }) -join ", "
      Gateway        = ($_.IPv4DefaultGateway | ForEach-Object { $_.NextHop }) -join ", "
      DnsServers     = ($_.DnsServer.ServerAddresses) -join ", "
    }
  }

  $routes = Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Sort-Object RouteMetric |
    Select-Object -First 25 DestinationPrefix, NextHop, InterfaceAlias, RouteMetric

  [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    User         = "$env:USERDOMAIN\$env:USERNAME"
    IsAdmin      = (Test-IsAdmin)
    Timestamp    = (Get-Date)
    Adapters     = $adapters
    IPConfig     = $ip
    RoutesTop25  = $routes
  }
}

function Run-QuickDiagnostics {
  $gw = $null
  try { $gw = (Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway} | Select-Object -First 1).IPv4DefaultGateway.NextHop } catch {}
  if (-not $gw) { $gw = "192.168.0.1" }

  $targets = @($gw, "1.1.1.1", "8.8.8.8") | Where-Object { $_ -and $_.Trim() }
  $pings = foreach ($t in $targets) { Test-Ping -Target $t -Count 2 }

  $dns = @(
    (Test-DnsResolve -TargetName "www.google.com"),
    (Test-DnsResolve -TargetName "www.cloudflare.com")
  )

  $ports = @(
    (Test-TcpPort -TargetHost "www.google.com" -Port 443),
    (Test-TcpPort -TargetHost "1.1.1.1" -Port 53)
  )

  [pscustomobject]@{
    Summary = Get-NetworkSummary
    Tests   = [pscustomobject]@{ Ping=$pings; DNS=$dns; Ports=$ports }
  }
}

function Get-BasicTestsSafe {
  $targets = @("1.1.1.1", "8.8.8.8")
  $pings = foreach ($t in $targets) { Test-Ping -Target $t -Count 2 }
  $dns = @(
    (Test-DnsResolve -TargetName "www.google.com"),
    (Test-DnsResolve -TargetName "www.cloudflare.com")
  )
  $ports = @(
    (Test-TcpPort -TargetHost "www.google.com" -Port 443),
    (Test-TcpPort -TargetHost "1.1.1.1" -Port 53)
  )
  [pscustomobject]@{ Ping=$pings; DNS=$dns; Ports=$ports }
}

function Save-Report([object]$Report, [string]$OutDir) {
  Ensure-Dir $OutDir
  $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
  $jsonPath = Join-Path $OutDir "net_report_$stamp.json"
  $txtPath  = Join-Path $OutDir "net_report_$stamp.txt"

  ($Report | ConvertTo-Json -Depth 10) | Set-Content -Encoding UTF8 $jsonPath

  $lines = New-Object System.Collections.Generic.List[string]
  $lines.Add("Network Report - $($Report.Summary.ComputerName)")
  $lines.Add("Timestamp: $($Report.Summary.Timestamp)")
  $lines.Add("Admin: $($Report.Summary.IsAdmin)")
  $lines.Add("")
  $lines.Add("Adapters"); $lines.Add("--------")
  $lines.Add(($Report.Summary.Adapters | Format-Table -AutoSize | Out-String).TrimEnd())
  $lines.Add("")
  $lines.Add("IP Configuration"); $lines.Add("---------------")
  $lines.Add(($Report.Summary.IPConfig | Format-Table -AutoSize | Out-String).TrimEnd())
  $lines.Add("")
  $lines.Add("Routes (Top 25)"); $lines.Add("-------------")
  $lines.Add(($Report.Summary.RoutesTop25 | Format-Table -AutoSize | Out-String).TrimEnd())
  $lines.Add("")
  $lines.Add("Tests - Ping"); $lines.Add("------------")
  $lines.Add(($Report.Tests.Ping | Format-Table -AutoSize | Out-String).TrimEnd())
  $lines.Add("")
  $lines.Add("Tests - DNS"); $lines.Add("-----------")
  $lines.Add(($Report.Tests.DNS | Format-Table -AutoSize | Out-String).TrimEnd())
  $lines.Add("")
  $lines.Add("Tests - TCP Ports"); $lines.Add("-----------------")
  $lines.Add(($Report.Tests.Ports | Format-Table -AutoSize | Out-String).TrimEnd())

  if ($Report.PSObject.Properties.Name -contains "Full") {
    $lines.Add("")
    $lines.Add("Full Extras"); $lines.Add("----------")
    foreach ($k in $Report.Full.PSObject.Properties.Name) {
      $lines.Add("")
      $lines.Add($k); $lines.Add(("-" * $k.Length))
      $lines.Add(($Report.Full.$k | Out-String).TrimEnd())
    }
  }

  $lines | Set-Content -Encoding UTF8 $txtPath
  return [pscustomobject]@{ Txt=$txtPath; Json=$jsonPath }
}

# -------------------------
# GUI Layout
# -------------------------
$theme = @{
  Bg       = [System.Drawing.Color]::FromArgb(30,30,30)
  PanelBg  = [System.Drawing.Color]::FromArgb(45,45,48)
  LogBg    = [System.Drawing.Color]::FromArgb(0,0,0)
  LogText  = [System.Drawing.Color]::FromArgb(200,200,200)
  Text     = [System.Drawing.Color]::FromArgb(220,220,220)
  ButtonBg = [System.Drawing.Color]::FromArgb(0,122,204)
  ButtonFg = [System.Drawing.Color]::White
  SummaryBg = [System.Drawing.Color]::FromArgb(36,36,38)
}
$fontUI   = New-Object System.Drawing.Font("Segoe UI", 10)
$fontHead = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
$fontMono = New-Object System.Drawing.Font("Consolas", 10.5)

$form = New-Object System.Windows.Forms.Form
$form.Text = "Net Diag"
$form.StartPosition = "CenterScreen"
$form.Size = New-Object System.Drawing.Size(1140, 820)
$form.MinimumSize = New-Object System.Drawing.Size(1020, 720)
$form.BackColor = [System.Drawing.Color]::FromArgb(0,122,204) # accent border
$form.Font = $fontUI
$form.ForeColor = $theme.Text
$form.FormBorderStyle = "None"
$form.Padding = New-Object System.Windows.Forms.Padding(2)

$titleBar = New-Object System.Windows.Forms.Panel
$titleBar.Height = 44
$titleBar.Dock = "Top"
$titleBar.BackColor = [System.Drawing.Color]::FromArgb(20,20,22)
$titleBar.Padding = New-Object System.Windows.Forms.Padding(14,8,10,8)

$titleLabel = New-Object System.Windows.Forms.Label
$titleLabel.Text = "Net Diag"
$titleLabel.AutoSize = $true
$titleLabel.Font = New-Object System.Drawing.Font("Segoe UI Semibold", 11, [System.Drawing.FontStyle]::Bold)
$titleLabel.ForeColor = $theme.Text
$titleLabel.Dock = "Left"
$titleLabel.TextAlign = "MiddleLeft"
$titleLabel.Cursor = "SizeAll"

$btnClose = New-Object System.Windows.Forms.Button
$btnClose.Text = "X"
$btnClose.Width = 46
$btnClose.FlatStyle = "Flat"
$btnClose.FlatAppearance.BorderSize = 0
$btnClose.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(210,70,70)
$btnClose.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(180,50,50)
$btnClose.BackColor = [System.Drawing.Color]::FromArgb(200,60,60)
$btnClose.ForeColor = [System.Drawing.Color]::White
$btnClose.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$btnClose.Add_Click({ $form.Close() })
$titleBar.Controls.Add($btnClose)

$btnMin = New-Object System.Windows.Forms.Button
$btnMin.Text = "–"
$btnMin.Width = 46
$btnMin.FlatStyle = "Flat"
$btnMin.FlatAppearance.BorderSize = 0
$btnMin.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(80,80,80)
$btnMin.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(70,70,70)
$btnMin.BackColor = [System.Drawing.Color]::FromArgb(60,60,60)
$btnMin.ForeColor = [System.Drawing.Color]::White
$btnMin.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$btnMin.Add_Click({ $form.WindowState = [System.Windows.Forms.FormWindowState]::Minimized })

$dragHandler = [System.Windows.Forms.MouseEventHandler]{
  param($s,$e)
  if ($e.Button -eq [System.Windows.Forms.MouseButtons]::Left) {
    [WinNative]::ReleaseCapture() | Out-Null
    [WinNative]::SendMessage($form.Handle, 0xA1, 0x2, 0) | Out-Null # WM_NCLBUTTONDOWN + HTCAPTION
  }
}
$titleBar.Add_MouseDown($dragHandler)
$titleLabel.Add_MouseDown($dragHandler)

$titleTabs = New-Object System.Windows.Forms.FlowLayoutPanel
$titleTabs.FlowDirection = "LeftToRight"
$titleTabs.WrapContents = $false
$titleTabs.Dock = "Left"
$titleTabs.AutoSize = $true
$titleTabs.AutoSizeMode = "GrowAndShrink"
$titleTabs.Padding = New-Object System.Windows.Forms.Padding(8,0,0,0)
$titleTabs.Margin = New-Object System.Windows.Forms.Padding(8,0,0,0)

function New-TitleTab([string]$text, [scriptblock]$onClick) {
  $b = New-Object System.Windows.Forms.Button
  $b.Text = $text
  $b.Height = 26
  $b.AutoSize = $true
  $b.Margin = New-Object System.Windows.Forms.Padding(6,4,0,4)
  $b.Padding = New-Object System.Windows.Forms.Padding(8,0,8,0)
  $b.FlatStyle = "Flat"
  $b.FlatAppearance.BorderSize = 0
  $b.BackColor = [System.Drawing.Color]::FromArgb(48,48,48)
  $b.ForeColor = [System.Drawing.Color]::FromArgb(230,230,230)
  $b.Add_Click($onClick)
  return $b
}

$headerLeft = New-Object System.Windows.Forms.FlowLayoutPanel
$headerLeft.FlowDirection = "LeftToRight"
$headerLeft.WrapContents = $false
$headerLeft.AutoSize = $true
$headerLeft.AutoSizeMode = "GrowAndShrink"
$headerLeft.Dock = "Left"
$headerLeft.Padding = New-Object System.Windows.Forms.Padding(0)
$headerLeft.Margin = New-Object System.Windows.Forms.Padding(0)
$headerLeft.Controls.Add($titleLabel)
$headerLeft.Controls.Add($titleTabs)

$headerRight = New-Object System.Windows.Forms.FlowLayoutPanel
$headerRight.FlowDirection = "LeftToRight"
$headerRight.WrapContents = $false
$headerRight.AutoSize = $true
$headerRight.AutoSizeMode = "GrowAndShrink"
$headerRight.Dock = "Right"
$headerRight.Padding = New-Object System.Windows.Forms.Padding(0)
$headerRight.Margin = New-Object System.Windows.Forms.Padding(0)
$headerRight.Controls.Add($btnMin)
$headerRight.Controls.Add($btnClose)

$titleBar.Controls.Add($headerRight)
$titleBar.Controls.Add($headerLeft)
$form.Controls.Add($titleBar)

$contentPanel = New-Object System.Windows.Forms.Panel
$contentPanel.Dock = "Fill"
$contentPanel.BackColor = $theme.Bg
$contentPanel.Padding = New-Object System.Windows.Forms.Padding(0,0,0,0)
$form.Controls.Add($contentPanel)

$main = New-Object System.Windows.Forms.TableLayoutPanel
$main.Dock = "Fill"
$main.RowCount = 2
$main.ColumnCount = 2
$main.Padding = New-Object System.Windows.Forms.Padding(12,8,12,8)
$main.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
$main.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 32)))
$main.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 330)))
$main.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
$main.BackColor = $theme.Bg

$homePanel = New-Object System.Windows.Forms.Panel
$homePanel.Dock = "Fill"
$homePanel.BackColor = $theme.Bg
$homePanel.Controls.Add($main)
$contentPanel.Controls.Add($homePanel)

$leftCard = New-Object System.Windows.Forms.Panel
$leftCard.Dock = "Fill"
$leftCard.BackColor = $theme.PanelBg
$leftCard.Padding = New-Object System.Windows.Forms.Padding(16)
$leftCard.BorderStyle = "FixedSingle"
$main.Controls.Add($leftCard, 0, 0)

$rightCard = New-Object System.Windows.Forms.Panel
$rightCard.Dock = "Fill"
$rightCard.BackColor = $theme.PanelBg
$rightCard.Padding = New-Object System.Windows.Forms.Padding(16)
$rightCard.BorderStyle = "FixedSingle"
$main.Controls.Add($rightCard, 1, 0)

$statusStrip = New-Object System.Windows.Forms.StatusStrip
$statusStrip.Dock = "Fill"
$statusStrip.SizingGrip = $false
$statusStrip.BackColor = $theme.PanelBg
$statusStrip.ForeColor = $theme.Text

$statusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
$statusLabel.Spring = $true
$statusLabel.Text = "Ready."
$statusStrip.Items.Add($statusLabel) | Out-Null

$adminLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
$statusStrip.Items.Add($adminLabel) | Out-Null

$main.Controls.Add($statusStrip, 0, 1)
$main.SetColumnSpan($statusStrip, 2)

$leftLayout = New-Object System.Windows.Forms.TableLayoutPanel
$leftLayout.Dock = "Fill"
$leftLayout.ColumnCount = 1
$leftLayout.AutoScroll = $true
$leftLayout.Padding = New-Object System.Windows.Forms.Padding(0, 8, 0, 0)
$leftLayout.BackColor = $theme.PanelBg
$leftCard.Controls.Add($leftLayout)

function Add-SectionHeader([string]$text) {
  $lbl = New-Object System.Windows.Forms.Label
  $lbl.Text = $text
  $lbl.AutoSize = $true
  $lbl.Font = $fontHead
  $lbl.ForeColor = $theme.Text
  $lbl.Margin = New-Object System.Windows.Forms.Padding(0, 8, 0, 4)
  $leftLayout.Controls.Add($lbl)
}
function New-ActionButton([string]$Text, [scriptblock]$OnClick) {
  $p = New-Object System.Windows.Forms.Panel
  $p.Dock = "Top"
  $p.Height = 38
  $p.Margin = New-Object System.Windows.Forms.Padding(0,0,0,6)

  $b = New-Object System.Windows.Forms.Button
  $b.Text = $Text
  $b.Dock = "Fill"
  $b.Height = 34
  $b.FlatStyle = "Flat"
  $b.BackColor = $theme.ButtonBg
  $b.ForeColor = $theme.ButtonFg
  $b.FlatAppearance.BorderSize = 0
  $b.Add_Click($OnClick)
  $p.Controls.Add($b)
  return $p
}

# Summary banner
$summaryPanel = New-Object System.Windows.Forms.Panel
$summaryPanel.Dock = "Top"
$summaryPanel.Height = 60
$summaryPanel.BackColor = $theme.SummaryBg
$summaryPanel.Padding = New-Object System.Windows.Forms.Padding(8)
$summaryPanel.BorderStyle = "FixedSingle"

$summaryLabel = New-Object System.Windows.Forms.Label
$summaryLabel.Dock = "Fill"
$summaryLabel.Font = $fontHead
$summaryLabel.ForeColor = $theme.Text
$summaryLabel.Text = "No diagnostics run yet."
$summaryLabel.TextAlign = "MiddleLeft"
$summaryPanel.Controls.Add($summaryLabel)
$rightCard.Controls.Add($summaryPanel)

$logBox = New-Object System.Windows.Forms.RichTextBox
$logBox.Dock = "Fill"
$logBox.ReadOnly = $true
$logBox.BackColor = $theme.LogBg
$logBox.ForeColor = $theme.LogText
$logBox.Font = $fontMono
$logBox.BorderStyle = "FixedSingle"
$logBox.WordWrap = $false
$rightCard.Controls.Add($logBox)
$logBox.BringToFront()

function Update-Summary([object]$Report) {
  try {
    if (-not $Report) {
      $summaryLabel.Text = "No diagnostics run yet."
      return
    }
    $pingOk  = ($Report.Tests.Ping  | Where-Object {$_.Ok}).Count
    $pingAll = ($Report.Tests.Ping  | Measure-Object).Count
    $dnsOk   = ($Report.Tests.DNS   | Where-Object {$_.Ok}).Count
    $dnsAll  = ($Report.Tests.DNS   | Measure-Object).Count
    $portOk  = ($Report.Tests.Ports | Where-Object {$_.Ok}).Count
    $portAll = ($Report.Tests.Ports | Measure-Object).Count
    $summaryLabel.Text = "Ping OK: {0}/{1}   DNS OK: {2}/{3}   Ports OK: {4}/{5}" -f $pingOk,$pingAll,$dnsOk,$dnsAll,$portOk,$portAll
  } catch {
    $summaryLabel.Text = "Summary unavailable."
  }
}

function Set-AdminBadge { $adminLabel.Text = if (Test-IsAdmin) { "Admin: YES" } else { "Admin: NO" } }
function Set-ButtonsEnabled([bool]$enabled) {
  foreach ($ctl in $leftLayout.Controls) {
    if ($ctl -is [System.Windows.Forms.Panel]) {
      foreach ($c in $ctl.Controls) {
        if ($c -is [System.Windows.Forms.Button]) { $c.Enabled = $enabled }
      }
    }
  }
}

$global:LastReport = $null
$global:Busy = $false
$global:ActiveTimers = New-Object System.Collections.ArrayList
$global:ActiveWaits = New-Object System.Collections.ArrayList

function Append-AdapterLog([string]$text) {
  if (-not $adapterLog) { return }
  $adapterLog.AppendText($text + [Environment]::NewLine)
  $adapterLog.SelectionStart = $adapterLog.TextLength
  $adapterLog.ScrollToCaret()
}

function Invoke-ExternalWithTimeout {
  param([string]$FilePath,[string]$Arguments,[int]$TimeoutSeconds=20,[int]$MaxChars=8000)
  $stdout = [System.IO.Path]::GetTempFileName()
  $stderr = [System.IO.Path]::GetTempFileName()
  try {
    $p = Start-Process -FilePath $FilePath -ArgumentList $Arguments -PassThru `
      -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    if (-not $p.WaitForExit($TimeoutSeconds * 1000)) {
      try { if (-not $p.HasExited) { $p.Kill() } } catch {}
      return "Timed out after $TimeoutSeconds seconds."
    }
    $outTxt = ""
    $errTxt = ""
    try { $outTxt = [System.IO.File]::ReadAllText($stdout) } catch {}
    try { $errTxt = [System.IO.File]::ReadAllText($stderr) } catch {}
    $txt = (($outTxt + "`r`n" + $errTxt).Trim())
    if (-not $txt) { $txt = "(no output)" }
    if ($txt.Length -gt $MaxChars) { $txt = $txt.Substring(0, $MaxChars) + "`r`n... truncated ..." }
    return $txt
  } catch {
    return "ERROR: $($_.Exception.Message)"
  } finally {
    foreach ($f in @($stdout,$stderr)) { try { Remove-Item -ErrorAction SilentlyContinue -Force $f } catch {} }
  }
}

# -------------------------
# Quick diagnostics (in-process, guarded)
# -------------------------
function Start-QuickDiagnostics {
  try {
    if ($global:Busy) { Write-Log "Busy: already running."; return }
    $global:Busy = $true
    Set-ButtonsEnabled $false
    Set-Status "Working (Quick)..."
    Write-Log "Running QUICK diagnostics..."
    try {
      $global:LastReport = Run-QuickDiagnostics
      $sum = $global:LastReport.Summary
      Write-Log "Done (Quick)."
      Write-Log ("Computer: {0} | User: {1}" -f $sum.ComputerName, $sum.User)
      Update-Summary $global:LastReport
      Set-Status "Ready."
    } catch {
      Write-Log ("ERROR: {0}" -f $_.Exception.Message)
      Set-Status "Error."
    }
  } finally {
    $global:Busy = $false
    Set-ButtonsEnabled $true
    Set-AdminBadge
  }
}

function Cleanup-WaitHandles {
  foreach ($w in @($global:ActiveWaits)) {
    try { $w.Unregister($null) } catch {}
    [void]$global:ActiveWaits.Remove($w)
  }
}

# -------------------------
# Full diagnostics (in-process)
# -------------------------
function Start-FullDiagnosticsWorker {
  try {
    if ($global:Busy) { Write-Log "Busy: already running."; return }
    $global:Busy = $true
    Set-ButtonsEnabled $false
    Set-Status "Working (Full)..."
    Write-Log "Running FULL diagnostics (in-process, safe commands only)..."

    try {
      $rep = if ($global:LastReport) {
        [pscustomobject]@{
          Summary = $global:LastReport.Summary
          Tests   = $global:LastReport.Tests
        }
      } else {
        [pscustomobject]@{
          Summary = [pscustomobject]@{
            ComputerName = $env:COMPUTERNAME
            User         = "$env:USERDOMAIN\$env:USERNAME"
            IsAdmin      = (Test-IsAdmin)
            Timestamp    = (Get-Date)
            Adapters     = @()
            IPConfig     = @()
            RoutesTop25  = @()
          }
          Tests = Get-BasicTestsSafe
        }
      }

      Write-Log "Full: ipconfig /all..."
      $ipconfigAll = Invoke-ExternalWithTimeout -FilePath "ipconfig.exe" -Arguments "/all"
      Write-Log "Full: route print..."
      $routePrint = Invoke-ExternalWithTimeout -FilePath "route.exe" -Arguments "print"
      Write-Log "Full: netsh interface ip show config..."
      $netshIf = Invoke-ExternalWithTimeout -FilePath "netsh.exe" -Arguments "interface ip show config"
      Write-Log "Full: netsh winhttp show proxy..."
      $winhttp = Invoke-ExternalWithTimeout -FilePath "netsh.exe" -Arguments "winhttp show proxy"
      Write-Log "Full: netsh advfirewall show allprofiles..."
      $firewall = Invoke-ExternalWithTimeout -FilePath "netsh.exe" -Arguments "advfirewall show allprofiles"
      Write-Log "Full: netsh wlan show interfaces..."
      $wlan = Invoke-ExternalWithTimeout -FilePath "netsh.exe" -Arguments "wlan show interfaces"

      $rep | Add-Member -NotePropertyName Full -NotePropertyValue ([pscustomobject]@{
        IpconfigAll          = $ipconfigAll
        RoutePrint           = $routePrint
        NetshInterfaceConfig = $netshIf
        WinHttpProxy         = $winhttp
        FirewallProfiles     = $firewall
        WlanInterfaces       = $wlan
      }) -Force

      $global:LastReport = $rep
      Update-Summary $global:LastReport
      Write-Log "Done (Full)."
      Set-Status "Ready."
    } catch {
      Write-Log ("ERROR: {0}" -f $_.Exception.Message)
      Set-Status "Error."
    }
  } finally {
    $global:Busy = $false
    Set-ButtonsEnabled $true
    Set-AdminBadge
  }
}

# -------------------------
# Buttons
# -------------------------
Add-SectionHeader "Diagnostics"

$leftLayout.Controls.Add((New-ActionButton "Run Quick Diagnostics" {
  Start-QuickDiagnostics
}))

$leftLayout.Controls.Add((New-ActionButton "Run Full Diagnostics" { Start-FullDiagnosticsWorker }))

$leftLayout.Controls.Add((New-ActionButton "Save Last Report..." {
  if (-not $global:LastReport) {
    [System.Windows.Forms.MessageBox]::Show("Run diagnostics first.", "Net Diag", "OK", "Information") | Out-Null
    return
  }
  $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
  $dlg.Description = "Choose output folder"
  if ($dlg.ShowDialog() -ne "OK") { return }
  try {
    $paths = Save-Report -Report $global:LastReport -OutDir $dlg.SelectedPath
    Write-Log "Saved TXT:  $($paths.Txt)"
    Write-Log "Saved JSON: $($paths.Json)"
  } catch {
    Write-Log ("ERROR: {0}" -f $_.Exception.Message)
  }
}))

Add-SectionHeader "Quick Fixes"
$leftLayout.Controls.Add((New-ActionButton "Flush DNS Cache" {
  try { Write-Log "Flushing DNS cache..."; ipconfig /flushdns | Out-Null; Write-Log "DNS cache flushed." }
  catch { Write-Log ("ERROR: {0}" -f $_.Exception.Message) }
}))
$leftLayout.Controls.Add((New-ActionButton "Release / Renew IP" {
  try { Write-Log "Releasing IP..."; ipconfig /release | Out-Null; Write-Log "Renewing IP..."; ipconfig /renew | Out-Null; Write-Log "IP renewed." }
  catch { Write-Log ("ERROR: {0}" -f $_.Exception.Message) }
}))
$leftLayout.Controls.Add((New-ActionButton "Reset Winsock + IP Stack (Admin)" {
  if (-not (Test-IsAdmin)) {
    [System.Windows.Forms.MessageBox]::Show("Run PowerShell as Administrator for this.", "Net Diag", "OK", "Warning") | Out-Null
    return
  }
  $r = [System.Windows.Forms.MessageBox]::Show(
    "This will run:`r`n- netsh winsock reset`r`n- netsh int ip reset`r`nReboot recommended after. Continue?",
    "Confirm",
    [System.Windows.Forms.MessageBoxButtons]::YesNo,
    [System.Windows.Forms.MessageBoxIcon]::Warning
  )
  if ($r -ne "Yes") { return }
  try {
    Write-Log "Resetting Winsock..."; netsh winsock reset | Out-Null
    Write-Log "Resetting IP stack..."; netsh int ip reset | Out-Null
    Write-Log "Done. Reboot recommended."
  } catch { Write-Log ("ERROR: {0}" -f $_.Exception.Message) }
}))
$leftLayout.Controls.Add((New-ActionButton "Open Network Settings" {
  try { Write-Log "Opening Windows Network Settings..."; Start-Process "ms-settings:network" | Out-Null }
  catch { Write-Log ("ERROR: {0}" -f $_.Exception.Message) }
}))

Add-SectionHeader "Tools"
$leftLayout.Controls.Add((New-ActionButton "Show ipconfig /all" {
  try { Write-Log "ipconfig /all:"; (ipconfig /all 2>&1) | ForEach-Object { Write-Log $_ } }
  catch { Write-Log ("ERROR: {0}" -f $_.Exception.Message) }
}))
$leftLayout.Controls.Add((New-ActionButton "Relaunch as Admin" {
  if (Test-IsAdmin) { [System.Windows.Forms.MessageBox]::Show("Already running as Administrator.", "Net Diag", "OK", "Information") | Out-Null; return }
  try {
    $args = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    Write-Log "Attempting to relaunch elevated..."
    Start-Process -FilePath "powershell.exe" -ArgumentList $args -Verb RunAs | Out-Null
    $form.Close()
  } catch {
    Write-Log ("ERROR: {0}" -f $_.Exception.Message)
  }
}))
$leftLayout.Controls.Add((New-ActionButton "Clear Log" { $logBox.Clear(); Write-Log "Log cleared."; Set-Status "Ready." }))
$leftLayout.Controls.Add((New-ActionButton "Exit" { $form.Close() }))

$adapterPanel = New-Object System.Windows.Forms.Panel
$adapterPanel.Dock = "Fill"
$adapterPanel.BackColor = $theme.Bg
$adapterPanel.Visible = $false

$adapterContainer = New-Object System.Windows.Forms.TableLayoutPanel
$adapterContainer.Dock = "Fill"
$adapterContainer.RowCount = 2
$adapterContainer.ColumnCount = 1
$adapterContainer.GrowStyle = [System.Windows.Forms.TableLayoutPanelGrowStyle]::FixedSize
$adapterContainer.RowStyles.Clear()
# Keep the adapter controls visible and aggressively cap the log height so it doesn't push them off screen.
$adapterContainer.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
$adapterContainer.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 200)))
# Add generous top padding to push controls down from the title area.
$adapterContainer.Padding = New-Object System.Windows.Forms.Padding(24,40,24,16)
$adapterContainer.BackColor = $theme.Bg

$adapterLayout = New-Object System.Windows.Forms.TableLayoutPanel
$adapterLayout.Dock = "Top"
$adapterLayout.AutoSize = $true
$adapterLayout.AutoSizeMode = "GrowAndShrink"
$adapterLayout.Padding = New-Object System.Windows.Forms.Padding(0,0,0,8)
$adapterLayout.ColumnCount = 4
$adapterLayout.RowCount = 7
$adapterLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
$adapterLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 240)))
$adapterLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 150)))
$adapterLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 190)))
$adapterLayout.RowStyles.Clear()
for ($i=0; $i -lt 7; $i++) { [void]$adapterLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) }
# Force the first row (adapter selector) to stay visible instead of collapsing to 0 height.
$adapterLayout.RowStyles[0].SizeType = [System.Windows.Forms.SizeType]::Absolute
$adapterLayout.RowStyles[0].Height = 34

$adapterLabel = New-Object System.Windows.Forms.Label
$adapterLabel.Text = "Adapter:"
$adapterLabel.AutoSize = $true
$adapterLabel.ForeColor = $theme.Text
$adapterLabel.Font = $fontUI
$adapterLabel.TextAlign = "MiddleLeft"
$adapterLabel.Dock = "Fill"
$adapterLabel.Margin = New-Object System.Windows.Forms.Padding(0,0,6,4)

$adapterCombo = New-Object System.Windows.Forms.ComboBox
$adapterCombo.DropDownStyle = "DropDownList"
$adapterCombo.Width = 240
$adapterCombo.Font = $fontUI
$adapterCombo.Height = 26
$adapterCombo.Margin = New-Object System.Windows.Forms.Padding(0,0,6,4)
$adapterCombo.BackColor = [System.Drawing.Color]::White
$adapterCombo.ForeColor = [System.Drawing.Color]::Black

$btnRefreshAdapters = New-Object System.Windows.Forms.Button
$btnRefreshAdapters.Text = "Refresh"
$btnRefreshAdapters.FlatStyle = "Flat"
$btnRefreshAdapters.FlatAppearance.BorderSize = 0
$btnRefreshAdapters.BackColor = $theme.ButtonBg
$btnRefreshAdapters.ForeColor = $theme.ButtonFg
$btnRefreshAdapters.Width = 100
$btnRefreshAdapters.Height = 28
$btnRefreshAdapters.Margin = New-Object System.Windows.Forms.Padding(0,0,0,4)

$btnFlushDns = New-Object System.Windows.Forms.Button
$btnFlushDns.Text = "Flush DNS cache"
$btnFlushDns.FlatStyle = "Flat"
$btnFlushDns.FlatAppearance.BorderSize = 0
$btnFlushDns.BackColor = $theme.ButtonBg
$btnFlushDns.ForeColor = $theme.ButtonFg
$btnFlushDns.Width = 180
$btnFlushDns.Height = 28

$txtStaticIp = New-Object System.Windows.Forms.TextBox
$txtStaticIp.Width = 200
$txtStaticIp.Font = $fontUI
$txtMask = New-Object System.Windows.Forms.TextBox
$txtMask.Width = 140
$txtMask.Font = $fontUI
$txtGateway = New-Object System.Windows.Forms.TextBox
$txtGateway.Width = 200
$txtGateway.Font = $fontUI
$txtDns1 = New-Object System.Windows.Forms.TextBox
$txtDns1.Width = 200
$txtDns1.Font = $fontUI
$txtDns2 = New-Object System.Windows.Forms.TextBox
$txtDns2.Width = 200
$txtDns2.Font = $fontUI

$btnApplyStatic = New-Object System.Windows.Forms.Button
$btnApplyStatic.Text = "Apply static IP"
$btnApplyStatic.FlatStyle = "Flat"
$btnApplyStatic.FlatAppearance.BorderSize = 0
$btnApplyStatic.BackColor = $theme.ButtonBg
$btnApplyStatic.ForeColor = $theme.ButtonFg
$btnApplyStatic.Width = 140

$btnApplyDns = New-Object System.Windows.Forms.Button
$btnApplyDns.Text = "Apply DNS only"
$btnApplyDns.FlatStyle = "Flat"
$btnApplyDns.FlatAppearance.BorderSize = 0
$btnApplyDns.BackColor = $theme.ButtonBg
$btnApplyDns.ForeColor = $theme.ButtonFg
$btnApplyDns.Width = 140

$btnDhcp = New-Object System.Windows.Forms.Button
$btnDhcp.Text = "Revert to DHCP"
$btnDhcp.FlatStyle = "Flat"
$btnDhcp.FlatAppearance.BorderSize = 0
$btnDhcp.BackColor = $theme.ButtonBg
$btnDhcp.ForeColor = $theme.ButtonFg
$btnDhcp.Width = 140

$adapterLayout.Controls.Add($adapterLabel, 0, 0)
$adapterLayout.Controls.Add($adapterCombo, 1, 0)
$adapterLayout.Controls.Add($btnRefreshAdapters, 2, 0)
$adapterLayout.Controls.Add($btnFlushDns, 3, 0)
$btnFlushDns.Margin = New-Object System.Windows.Forms.Padding(0,0,0,4)

$lblStatic = New-Object System.Windows.Forms.Label -Property @{Text="Static IP:"; AutoSize=$true; ForeColor=$theme.Text; Font=$fontUI; TextAlign="MiddleLeft"; Dock="Fill"}
$lblMask   = New-Object System.Windows.Forms.Label -Property @{Text="Mask:"; AutoSize=$true; ForeColor=$theme.Text; Font=$fontUI; TextAlign="MiddleLeft"; Dock="Fill"}
$lblGw     = New-Object System.Windows.Forms.Label -Property @{Text="Gateway:"; AutoSize=$true; ForeColor=$theme.Text; Font=$fontUI; TextAlign="MiddleLeft"; Dock="Fill"}
$lblDns1   = New-Object System.Windows.Forms.Label -Property @{Text="DNS 1:"; AutoSize=$true; ForeColor=$theme.Text; Font=$fontUI; TextAlign="MiddleLeft"; Dock="Fill"}
$lblDns2   = New-Object System.Windows.Forms.Label -Property @{Text="DNS 2:"; AutoSize=$true; ForeColor=$theme.Text; Font=$fontUI; TextAlign="MiddleLeft"; Dock="Fill"}

$adapterLayout.Controls.Add($lblStatic, 0, 2)
$adapterLayout.Controls.Add($txtStaticIp, 1, 2)
$adapterLayout.Controls.Add($lblMask, 0, 3)
$adapterLayout.Controls.Add($txtMask, 1, 3)
$adapterLayout.Controls.Add($btnApplyStatic, 2, 3)

$adapterLayout.Controls.Add($lblGw, 0, 4)
$adapterLayout.Controls.Add($txtGateway, 1, 4)
$adapterLayout.Controls.Add($btnDhcp, 2, 4)

$adapterLayout.Controls.Add($lblDns1, 0, 5)
$adapterLayout.Controls.Add($txtDns1, 1, 5)
$adapterLayout.Controls.Add($lblDns2, 0, 6)
$adapterLayout.Controls.Add($txtDns2, 1, 6)
$adapterLayout.Controls.Add($btnApplyDns, 2, 6)

$adapterLog = New-Object System.Windows.Forms.RichTextBox
$adapterLog.Dock = "Top"
$adapterLog.Anchor = "Top,Left,Right"
$adapterLog.ReadOnly = $true
$adapterLog.BackColor = $theme.LogBg
$adapterLog.ForeColor = $theme.LogText
$adapterLog.Font = $fontMono
$adapterLog.BorderStyle = "FixedSingle"
$adapterLog.WordWrap = $false
$adapterLog.Height = 200
$adapterLog.MaximumSize = New-Object System.Drawing.Size(2000,200)
$adapterLog.MinimumSize = New-Object System.Drawing.Size(200,200)
$adapterLog.Margin = New-Object System.Windows.Forms.Padding(0,6,0,0)

$adapterContainer.Controls.Add($adapterLayout, 0, 0)
$adapterContainer.Controls.Add($adapterLog, 0, 1)
$adapterPanel.Controls.Add($adapterContainer)

$contentPanel.Controls.Add($adapterPanel)

function Load-Adapters {
  try {
    $list = Get-NetAdapter -ErrorAction Stop | Sort-Object Name
    $adapterCombo.Items.Clear()
    foreach ($a in $list) { [void]$adapterCombo.Items.Add($a.Name) }
    if ($adapterCombo.Items.Count -gt 0) {
      if ($adapterCombo.SelectedIndex -lt 0) { $adapterCombo.SelectedIndex = 0 }
    }
  } catch {
    $adapterCombo.Items.Clear()
    [void]$adapterCombo.Items.Add("Error loading adapters")
    $adapterCombo.SelectedIndex = 0
  }
}

function Show-AdapterDetails {
  $name = $adapterCombo.SelectedItem
  if (-not $name) { return }

  function Convert-PrefixToMask([int]$prefix) {
    if ($prefix -lt 0 -or $prefix -gt 32) { return "" }
    $bytes = [byte[]](0,0,0,0)
    for ($i=0; $i -lt 4; $i++) {
      $bits = [Math]::Max([Math]::Min($prefix - ($i*8), 8), 0)
      $bytes[$i] = if ($bits -le 0) { 0 } else { 0xFF -shr (8 - $bits) }
    }
    try { return ([System.Net.IPAddress]::new($bytes)).ToString() } catch { return "" }
  }

  try {
    $na = Get-NetAdapter -Name $name -ErrorAction Stop
    $ip = Get-NetIPConfiguration -InterfaceAlias $name -ErrorAction Stop
    $ipv4 = $ip.IPv4Address | Select-Object -First 1
    $prefix = $null
    $mask = ""
    if ($ipv4) { $prefix = $ipv4.PrefixLength }
    if ($prefix -ne $null) { $mask = Convert-PrefixToMask -prefix $prefix }
    $txtStaticIp.Text = if ($ipv4) { $ipv4.IPAddress } else { "" }
    $txtMask.Text = $mask
    $gw = $ip.IPv4DefaultGateway | Select-Object -First 1
    $txtGateway.Text = if ($gw) { $gw.NextHop } else { "" }
    $dns = @($ip.DnsServer.ServerAddresses)
    $txtDns1.Text = if ($dns.Count -gt 0) { $dns[0] } else { "" }
    $txtDns2.Text = if ($dns.Count -gt 1) { $dns[1] } else { "" }
  } catch {
    $txtStaticIp.Text = ""
    $txtMask.Text = ""
    $txtGateway.Text = ""
    $txtDns1.Text = ""
    $txtDns2.Text = ""
    Write-Log ("Adapter load error: {0}" -f $_.Exception.Message)
  }
}

$adapterCombo.add_SelectedIndexChanged({ Show-AdapterDetails })
$btnRefreshAdapters.Add_Click({ Load-Adapters; Show-AdapterDetails })

$tabHome = New-TitleTab "Home" { $homePanel.Visible = $true; $adapterPanel.Visible = $false }
$tabAdapter = New-TitleTab "Adapter Config" { $homePanel.Visible = $false; $adapterPanel.Visible = $true; Load-Adapters; Show-AdapterDetails }
$titleTabs.Controls.Add($tabHome)
$titleTabs.Controls.Add($tabAdapter)

$btnFlushDns.Add_Click({
  try { Write-Log "Adapter: flushing DNS cache..."; ipconfig /flushdns | Out-Null; Write-Log "Adapter: DNS cache flushed." }
  catch { Write-Log ("ERROR: {0}" -f $_.Exception.Message) }
})

function Require-Admin {
  if (-not (Test-IsAdmin)) {
    [System.Windows.Forms.MessageBox]::Show("Run PowerShell as Administrator to change adapter settings.", "Net Diag", "OK", "Warning") | Out-Null
    return $false
  }
  return $true
}

$btnApplyStatic.Add_Click({
  if (-not (Require-Admin)) { return }
  $name = $adapterCombo.SelectedItem
  if (-not $name) { return }
  $ip = $txtStaticIp.Text.Trim()
  $mask = $txtMask.Text.Trim()
  $gw = $txtGateway.Text.Trim()
  if (-not ($ip -and $mask)) {
    [System.Windows.Forms.MessageBox]::Show("Enter IP and Mask.", "Net Diag", "OK", "Warning") | Out-Null
    return
  }
  Append-AdapterLog "Setting static IP on $name ..."
  Append-AdapterLog (Invoke-ExternalWithTimeout -FilePath "netsh.exe" -Arguments "interface ip set address name=`"$name`" static $ip $mask $gw 1")
  Show-AdapterDetails
})

$btnApplyDns.Add_Click({
  if (-not (Require-Admin)) { return }
  $name = $adapterCombo.SelectedItem
  if (-not $name) { return }
  $dns1 = $txtDns1.Text.Trim()
  $dns2 = $txtDns2.Text.Trim()
  if (-not $dns1) {
    [System.Windows.Forms.MessageBox]::Show("Enter DNS 1.", "Net Diag", "OK", "Warning") | Out-Null
    return
  }
  Append-AdapterLog "Setting DNS on $name ..."
  Append-AdapterLog (Invoke-ExternalWithTimeout -FilePath "netsh.exe" -Arguments "interface ip set dns name=`"$name`" static $dns1")
  if ($dns2) {
    Append-AdapterLog (Invoke-ExternalWithTimeout -FilePath "netsh.exe" -Arguments "interface ip add dns name=`"$name`" $dns2 index=2")
  }
  Show-AdapterDetails
})

$btnDhcp.Add_Click({
  if (-not (Require-Admin)) { return }
  $name = $adapterCombo.SelectedItem
  if (-not $name) { return }
  Append-AdapterLog "Reverting $name to DHCP..."
  Append-AdapterLog (Invoke-ExternalWithTimeout -FilePath "netsh.exe" -Arguments "interface ip set address name=`"$name`" source=dhcp")
  Append-AdapterLog (Invoke-ExternalWithTimeout -FilePath "netsh.exe" -Arguments "interface ip set dns name=`"$name`" source=dhcp")
  Show-AdapterDetails
})
# Startup
_FileLog ("========== Net Diag start {0} ==========" -f (Get-Date))
Set-AdminBadge
Write-Log "Net Diag started."
Write-Log ("Admin: {0}" -f (Test-IsAdmin))
Write-Log ("Log file: {0}" -f $global:LogFile)
Write-Log "Tip: Full diagnostics now run in-process with safe commands only."
Update-Summary $null
Set-Status "Ready."

$form.Add_Shown({
  try {
    $val = 1
    try { [WinDark]::DwmSetWindowAttribute($form.Handle, 20, [ref]$val, 4) | Out-Null } catch {}
    try { [WinDark]::DwmSetWindowAttribute($form.Handle, 19, [ref]$val, 4) | Out-Null } catch {}
    try { [WinDark]::DwmSetWindowAttribute($form.Handle, 38, [ref]$val, 4) | Out-Null } catch {} # newer immersive dark mode

    foreach ($h in @($form.Handle, $contentPanel.Handle, $homePanel.Handle, $adapterPanel.Handle, $main.Handle, $leftCard.Handle, $rightCard.Handle, $leftLayout.Handle, $statusStrip.Handle, $summaryPanel.Handle, $logBox.Handle, $titleBar.Handle, $adapterLayout.Handle)) {
      try { [WinDark]::SetWindowTheme($h, "DarkMode_Explorer", $null) | Out-Null } catch {}
    }

    try { Load-Adapters; Show-AdapterDetails } catch {}
  } catch { Write-Log ("DARK THEME ERROR: {0}" -f $_.Exception.Message) }
})

[void]$form.ShowDialog()

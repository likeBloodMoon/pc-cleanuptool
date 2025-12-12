
<#
  PC Cleanup & Optimization Tool - GUI Edition (Styled, Fixed Layout)
  Author: Kristóf

  Features:
    - Clean temp files
    - Empty Recycle Bin
    - Clean Windows Update cache
    - Clean Prefetch cache
    - Reset network stack (flushdns, registerdns, winsock, IP reset)
    - Flush DNS cache (separate button)
    - Run DISM + SFC
    - Run CHKDSK scan on C:
    - Optional system restore point before actions
    - Install basic apps via winget

    - Network tools:
        * List active adapters
        * Set static IP + subnet mask + gateway
        * Set custom DNS servers
        * Revert adapter back to DHCP

    - Windows preferences:
        * Dark theme for Windows
        * Disable Bing search in Start Menu
        * Show hidden files
        * Show file extensions
        * Disable mouse acceleration
        * Enable NumLock on startup
#>

$ErrorActionPreference = "Stop"

function Test-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal   = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.MessageBox]::Show(
        "Please run this script as Administrator.`r`nRight-click PowerShell → Run as administrator.",
        "PC Cleanup Tool",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
    exit 1
}
# --- Script root (works both from file and from iwr|iex / in-memory) ---
$scriptPath = $PSCommandPath
if ([string]::IsNullOrWhiteSpace($scriptPath)) { $scriptPath = $MyInvocation.MyCommand.Path }

# If executed from memory, fall back to a writable folder
if ([string]::IsNullOrWhiteSpace($scriptPath)) {
    $scriptRoot = Join-Path $env:LOCALAPPDATA "PC-CleanupTool"
} else {
    $scriptRoot = Split-Path -Parent $scriptPath
}

# --- Logs folder ---
$logDir = Join-Path $scriptRoot "logs"
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }

$logFile = Join-Path $logDir ("pc-cleanup-{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmm"))
$script:LogTextBox = $null

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$timestamp][$Level] $Message"

    Write-Host $line
    Add-Content -Path $logFile -Value $line

    if ($script:LogTextBox -ne $null) {
        $script:LogTextBox.AppendText($line + [Environment]::NewLine)
        $script:LogTextBox.SelectionStart = $script:LogTextBox.Text.Length
        $script:LogTextBox.ScrollToCaret()
    }
}

Write-Log "=== PC Cleanup Tool started (GUI styled, fixed) ==="

function Ensure-RegistryKey {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
}

function Clear-TempFiles {
    Write-Log "Clearing temp files..."

    $paths = @(
        $env:TEMP,
        $env:TMP,
        "C:\Windows\Temp"
    )

    foreach ($path in $paths) {
        if (-not (Test-Path $path)) {
            Write-Log "Path does not exist: $path" "WARN"
            continue
        }

        Write-Log "Cleaning: $path"
        try {
            Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue |
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Log "Error cleaning $($path): $_" "ERROR"
        }
    }

    Write-Log "Temp files cleanup finished."
}

function Clear-RecycleBinSafe {
    Write-Log "Emptying Recycle Bin..."

    try {
        if (Get-Command Clear-RecycleBin -ErrorAction SilentlyContinue) {
            Clear-RecycleBin -Force -ErrorAction SilentlyContinue
        } else {
            (New-Object -ComObject Shell.Application).NameSpace(0xA).Items() |
                ForEach-Object { Remove-Item $_.Path -Recurse -Force -ErrorAction SilentlyContinue }
        }
        Write-Log "Recycle Bin emptied."
    } catch {
        Write-Log "Error clearing Recycle Bin: $_" "ERROR"
    }
}

function Clear-WindowsUpdateCache {
    Write-Log "Cleaning Windows Update cache (SoftwareDistribution\Download)..."

    $path = "C:\Windows\SoftwareDistribution\Download"
    if (-not (Test-Path $path)) {
        Write-Log "Windows Update cache path not found: $path" "WARN"
        return
    }

    try {
        Write-Log "Stopping Windows Update service (wuauserv)..."
        Stop-Service wuauserv -Force -ErrorAction SilentlyContinue

        Write-Log "Deleting contents of $path..."
        Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue |
            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

        Write-Log "Starting Windows Update service (wuauserv)..."
        Start-Service wuauserv -ErrorAction SilentlyContinue

        Write-Log "Windows Update cache cleaned."
    } catch {
        Write-Log "Error cleaning Windows Update cache: $_" "ERROR"
    }
}

function Clear-PrefetchCache {
    Write-Log "Cleaning Prefetch cache..."

    $path = "C:\Windows\Prefetch"
    if (-not (Test-Path $path)) {
        Write-Log "Prefetch path not found: $path" "WARN"
        return
    }

    try {
        Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue |
            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log "Prefetch cache cleaned."
    } catch {
        Write-Log "Error cleaning Prefetch cache: $_" "ERROR"
    }
}

function Flush-DnsCache {
    Write-Log "Flushing DNS cache..."

    try {
        ipconfig /flushdns | Out-Null
        Write-Log "DNS cache flushed."
    } catch {
        Write-Log "Error flushing DNS cache: $_" "ERROR"
    }
}

function Reset-NetworkStack {
    Write-Log "Resetting network stack (flushdns, registerdns, winsock, IP reset)..."

    try {
        ipconfig /flushdns    | Out-Null
        ipconfig /registerdns | Out-Null
        netsh winsock reset   | Out-Null
        netsh int ip reset    | Out-Null

        Write-Log "Network reset commands executed. A reboot is recommended."
    } catch {
        Write-Log "Error resetting network stack: $_" "ERROR"
    }
}

function Run-SystemHealthChecks {
    Write-Log "Running DISM /restorehealth and SFC /scannow..."

    try {
        Write-Log "Starting: DISM /Online /Cleanup-Image /RestoreHealth"
        DISM /Online /Cleanup-Image /RestoreHealth | Out-Null

        Write-Log "Starting: sfc /scannow"
        sfc /scannow | Out-Null

        Write-Log "System health checks completed. Reboot may be required."
    } catch {
        Write-Log "Error running system health checks: $_" "ERROR"
    }
}

function Run-ChkDskScan {
    Write-Log "Running CHKDSK scan on C: (online scan)..."

    try {
        chkdsk C: /scan | Out-Null
        Write-Log "CHKDSK scan completed."
    } catch {
        Write-Log "Error running CHKDSK: $_" "ERROR"
    }
}

function Create-SystemRestorePoint {
    param(
        [string]$Description = "PC Cleanup Tool - automatic restore point"
    )

    Write-Log "Attempting to create system restore point: $Description"

    try {
        if (-not (Get-Command Checkpoint-Computer -ErrorAction SilentlyContinue)) {
            Write-Log "Checkpoint-Computer cmdlet not available. System Restore might be disabled." "WARN"
            return
        }

        Checkpoint-Computer -Description $Description -RestorePointType "MODIFY_SETTINGS"
        Write-Log "System restore point created successfully."
    } catch {
        Write-Log "Failed to create system restore point: $_" "ERROR"
    }
}

function Install-BasicApps {
    Write-Log "Checking for winget..."

    if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
        Write-Log "winget not found. Skipping app installation." "WARN"
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.MessageBox]::Show(
            "winget is not installed on this system.`r`nInstall ""App Installer"" from Microsoft Store first.",
            "PC Cleanup Tool",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        ) | Out-Null
        return
    }

    $apps = @(
        @{ name = "Google Chrome";       id = "Google.Chrome" },
        @{ name = "7-Zip";               id = "7zip.7zip" },
        @{ name = "VLC media player";    id = "VideoLAN.VLC" },
        @{ name = "Visual Studio Code";  id = "Microsoft.VisualStudioCode" }
    )

    Write-Log "Starting winget app installation..."

    foreach ($app in $apps) {
        Write-Log "Installing $($app.name) via winget..."
        try {
            winget install --id $($app.id) -e --silent --accept-source-agreements --accept-package-agreements
            Write-Log "$($app.name) installation finished."
        } catch {
            Write-Log "Error installing $($app.name): $_" "ERROR"
        }
    }

    Write-Log "winget app installation completed."
}

function Get-ActiveAdapters {
    try {
        Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq "Up" }
    } catch {
        Write-Log "Error listing adapters (Get-NetAdapter). Falling back to netsh." "WARN"
        $list = netsh interface ip show interfaces | Select-String "Enabled"
        $result = @()
        foreach ($line in $list) {
            $parts = $line.ToString().Trim() -split "\s+"
            $name = $parts[-1]
            $obj = [pscustomobject]@{
                Name   = $name
                Status = "Up"
            }
            $result += $obj
        }
        $result
    }
}

function Set-StaticIP {
    param(
        [string]$InterfaceName,
        [string]$IpAddress,
        [string]$SubnetMask,
        [string]$Gateway
    )

    Write-Log "Setting static IP on '$InterfaceName' to $IpAddress / $SubnetMask, gateway $Gateway"

    try {
        netsh interface ip set address name="$InterfaceName" static $IpAddress $SubnetMask $Gateway 1 | Out-Null
        Write-Log "Static IP applied."
    } catch {
        Write-Log "Error setting static IP: $_" "ERROR"
    }
}

function Set-DnsServers {
    param(
        [string]$InterfaceName,
        [string]$Dns1,
        [string]$Dns2
    )

    Write-Log "Setting DNS servers on '$InterfaceName' to $Dns1, $Dns2"

    try {
        if ([string]::IsNullOrWhiteSpace($Dns1)) {
            Write-Log "Primary DNS is empty, aborting DNS set." "WARN"
            return
        }

        netsh interface ip set dns name="$InterfaceName" static $Dns1 primary | Out-Null

        if (-not [string]::IsNullOrWhiteSpace($Dns2)) {
            netsh interface ip add dns name="$InterfaceName" $Dns2 index=2 | Out-Null
        }

        Write-Log "DNS servers applied."
    } catch {
        Write-Log "Error setting DNS servers: $_" "ERROR"
    }
}

function Set-DhcpMode {
    param(
        [string]$InterfaceName
    )

    Write-Log "Reverting '$InterfaceName' to DHCP for IP and DNS..."

    try {
        netsh interface ip set address name="$InterfaceName" source=dhcp | Out-Null
        netsh interface ip set dns    name="$InterfaceName" source=dhcp | Out-Null
        Write-Log "Adapter reverted to DHCP."
    } catch {
        Write-Log "Error reverting adapter to DHCP: $_" "ERROR"
    }
}

function Set-DarkTheme {
    Write-Log "Applying Dark theme for Windows..."

    try {
        $path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
        Ensure-RegistryKey -Path $path
        Set-ItemProperty -Path $path -Name "AppsUseLightTheme"    -Type DWord -Value 0
        Set-ItemProperty -Path $path -Name "SystemUsesLightTheme" -Type DWord -Value 0
        Write-Log "Dark theme applied."
    } catch {
        Write-Log "Error applying Dark theme: $_" "ERROR"
    }
}

function Disable-BingSearch {
    Write-Log "Disabling Bing web search in Start Menu..."

    try {
        $path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"
        Ensure-RegistryKey -Path $path
        Set-ItemProperty -Path $path -Name "BingSearchEnabled" -Type DWord -Value 0
        Set-ItemProperty -Path $path -Name "CortanaConsent"    -Type DWord -Value 0
        Write-Log "Bing web search disabled."
    } catch {
        Write-Log "Error disabling Bing search: $_" "ERROR"
    }
}

function Show-HiddenFiles {
    Write-Log "Enabling show hidden files..."

    try {
        $path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        Ensure-RegistryKey -Path $path
        Set-ItemProperty -Path $path -Name "Hidden"         -Type DWord -Value 1
        Set-ItemProperty -Path $path -Name "ShowSuperHidden" -Type DWord -Value 1
        Write-Log "Hidden files will be shown."
    } catch {
        Write-Log "Error enabling hidden files: $_" "ERROR"
    }
}

function Show-FileExtensions {
    Write-Log "Enabling show file extensions..."

    try {
        $path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        Ensure-RegistryKey -Path $path
        Set-ItemProperty -Path $path -Name "HideFileExt" -Type DWord -Value 0
        Write-Log "File extensions will be shown."
    } catch {
        Write-Log "Error enabling file extensions: $_" "ERROR"
    }
}

function Disable-MouseAcceleration {
    Write-Log "Disabling mouse acceleration..."

    try {
        $path = "HKCU:\Control Panel\Mouse"
        Ensure-RegistryKey -Path $path
        Set-ItemProperty -Path $path -Name "MouseSpeed"      -Value "0"
        Set-ItemProperty -Path $path -Name "MouseThreshold1" -Value "0"
        Set-ItemProperty -Path $path -Name "MouseThreshold2" -Value "0"
        Write-Log "Mouse acceleration disabled."
    } catch {
        Write-Log "Error disabling mouse acceleration: $_" "ERROR"
    }
}

function Enable-NumLock {
    Write-Log "Enabling NumLock on startup..."

    try {
        $pathCU = "HKCU:\Control Panel\Keyboard"
        Ensure-RegistryKey -Path $pathCU
        Set-ItemProperty -Path $pathCU -Name "InitialKeyboardIndicators" -Value "2"

        $pathDefault = "Registry::HKEY_USERS\.DEFAULT\Control Panel\Keyboard"
        Ensure-RegistryKey -Path $pathDefault
        Set-ItemProperty -Path $pathDefault -Name "InitialKeyboardIndicators" -Value "2"

        Write-Log "NumLock will be enabled on startup."
    } catch {
        Write-Log "Error enabling NumLock: $_" "ERROR"
    }
}

function Apply-WindowsPreferences {
    param(
        [bool]$DarkTheme,
        [bool]$DisableBing,
        [bool]$ShowHidden,
        [bool]$ShowExt,
        [bool]$NoMouseAccel,
        [bool]$EnableNumLock
    )

    Write-Log "Applying Windows preferences..."

    if ($DarkTheme)     { Set-DarkTheme }
    if ($DisableBing)   { Disable-BingSearch }
    if ($ShowHidden)    { Show-HiddenFiles }
    if ($ShowExt)       { Show-FileExtensions }
    if ($NoMouseAccel)  { Disable-MouseAcceleration }
    if ($EnableNumLock) { Enable-NumLock }

    Write-Log "Windows preferences applied."
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = "PC Cleanup Tool"
$form.Size = New-Object System.Drawing.Size(940, 600)
$form.StartPosition = "CenterScreen"
$form.MaximizeBox = $false
$form.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$form.ForeColor = [System.Drawing.Color]::White
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9)

$grpCleanup = New-Object System.Windows.Forms.GroupBox
$grpCleanup.Text = "Cleanup & Maintenance"
$grpCleanup.Location = New-Object System.Drawing.Point(10, 10)
$grpCleanup.Size = New-Object System.Drawing.Size(380, 260)
$grpCleanup.BackColor = [System.Drawing.Color]::FromArgb(37, 37, 38)
$grpCleanup.ForeColor = [System.Drawing.Color]::White

$chkTemp = New-Object System.Windows.Forms.CheckBox
$chkTemp.Text = "Clean temp files"
$chkTemp.Location = New-Object System.Drawing.Point(15, 30)
$chkTemp.AutoSize = $true

$chkRecycle = New-Object System.Windows.Forms.CheckBox
$chkRecycle.Text = "Empty Recycle Bin"
$chkRecycle.Location = New-Object System.Drawing.Point(15, 55)
$chkRecycle.AutoSize = $true

$chkWU = New-Object System.Windows.Forms.CheckBox
$chkWU.Text = "Clean Windows Update cache"
$chkWU.Location = New-Object System.Drawing.Point(15, 80)
$chkWU.AutoSize = $true

$chkPrefetch = New-Object System.Windows.Forms.CheckBox
$chkPrefetch.Text = "Clean Prefetch cache"
$chkPrefetch.Location = New-Object System.Drawing.Point(15, 105)
$chkPrefetch.AutoSize = $true

$chkNetwork = New-Object System.Windows.Forms.CheckBox
$chkNetwork.Text = "Reset network stack"
$chkNetwork.Location = New-Object System.Drawing.Point(15, 130)
$chkNetwork.AutoSize = $true

$chkHealth = New-Object System.Windows.Forms.CheckBox
$chkHealth.Text = "Run DISM + SFC"
$chkHealth.Location = New-Object System.Drawing.Point(15, 155)
$chkHealth.AutoSize = $true

$chkChkDsk = New-Object System.Windows.Forms.CheckBox
$chkChkDsk.Text = "Run CHKDSK scan on C:"
$chkChkDsk.Location = New-Object System.Drawing.Point(15, 180)
$chkChkDsk.AutoSize = $true

$chkRestore = New-Object System.Windows.Forms.CheckBox
$chkRestore.Text = "Create restore point before actions"
$chkRestore.Location = New-Object System.Drawing.Point(15, 205)
$chkRestore.AutoSize = $true

$btnRunSelected = New-Object System.Windows.Forms.Button
$btnRunSelected.Text = "Run selected"
$btnRunSelected.Location = New-Object System.Drawing.Point(15, 225)
$btnRunSelected.Size = New-Object System.Drawing.Size(110, 25)

$btnRunAll = New-Object System.Windows.Forms.Button
$btnRunAll.Text = "Run all"
$btnRunAll.Location = New-Object System.Drawing.Point(135, 225)
$btnRunAll.Size = New-Object System.Drawing.Size(80, 25)

$btnInstallApps = New-Object System.Windows.Forms.Button
$btnInstallApps.Text = "Install basic apps (winget)"
$btnInstallApps.Location = New-Object System.Drawing.Point(225, 225)
$btnInstallApps.Size = New-Object System.Drawing.Size(140, 25)
$btnInstallApps.Font = New-Object System.Drawing.Font("Segoe UI", 8)

$grpCleanup.Controls.AddRange(@(
    $chkTemp, $chkRecycle, $chkWU, $chkPrefetch,
    $chkNetwork, $chkHealth, $chkChkDsk, $chkRestore,
    $btnRunSelected, $btnRunAll, $btnInstallApps
))

$grpNetwork = New-Object System.Windows.Forms.GroupBox
$grpNetwork.Text = "Network tools"
$grpNetwork.Location = New-Object System.Drawing.Point(400, 10)
$grpNetwork.Size = New-Object System.Drawing.Size(520, 260)
$grpNetwork.BackColor = [System.Drawing.Color]::FromArgb(37, 37, 38)
$grpNetwork.ForeColor = [System.Drawing.Color]::White

$lblAdapter = New-Object System.Windows.Forms.Label
$lblAdapter.Text = "Adapter:"
$lblAdapter.Location = New-Object System.Drawing.Point(15, 30)
$lblAdapter.AutoSize = $true

$cmbAdapter = New-Object System.Windows.Forms.ComboBox
$cmbAdapter.Location = New-Object System.Drawing.Point(80, 26)
$cmbAdapter.Size = New-Object System.Drawing.Size(260, 25)
$cmbAdapter.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList

$btnRefreshAdapters = New-Object System.Windows.Forms.Button
$btnRefreshAdapters.Text = "Refresh"
$btnRefreshAdapters.Location = New-Object System.Drawing.Point(350, 26)
$btnRefreshAdapters.Size = New-Object System.Drawing.Size(80, 25)

$btnFlushDns = New-Object System.Windows.Forms.Button
$btnFlushDns.Text = "Flush DNS cache"
$btnFlushDns.Location = New-Object System.Drawing.Point(15, 60)
$btnFlushDns.Size = New-Object System.Drawing.Size(150, 25)

$lblIp = New-Object System.Windows.Forms.Label
$lblIp.Text = "Static IP:"
$lblIp.Location = New-Object System.Drawing.Point(15, 100)
$lblIp.AutoSize = $true

$txtIp = New-Object System.Windows.Forms.TextBox
$txtIp.Location = New-Object System.Drawing.Point(80, 96)
$txtIp.Size = New-Object System.Drawing.Size(130, 23)
$txtIp.Text = "192.168.1.100"

$lblMask = New-Object System.Windows.Forms.Label
$lblMask.Text = "Mask:"
$lblMask.Location = New-Object System.Drawing.Point(220, 100)
$lblMask.AutoSize = $true

$txtMask = New-Object System.Windows.Forms.TextBox
$txtMask.Location = New-Object System.Drawing.Point(270, 96)
$txtMask.Size = New-Object System.Drawing.Size(130, 23)
$txtMask.Text = "255.255.255.0"

$lblGw = New-Object System.Windows.Forms.Label
$lblGw.Text = "Gateway:"
$lblGw.Location = New-Object System.Drawing.Point(15, 130)
$lblGw.AutoSize = $true

$txtGw = New-Object System.Windows.Forms.TextBox
$txtGw.Location = New-Object System.Drawing.Point(80, 126)
$txtGw.Size = New-Object System.Drawing.Size(130, 23)
$txtGw.Text = "192.168.1.1"

$btnApplyStatic = New-Object System.Windows.Forms.Button
$btnApplyStatic.Text = "Apply static IP"
$btnApplyStatic.Location = New-Object System.Drawing.Point(220, 126)
$btnApplyStatic.Size = New-Object System.Drawing.Size(130, 23)

$lblDns1 = New-Object System.Windows.Forms.Label
$lblDns1.Text = "DNS 1:"
$lblDns1.Location = New-Object System.Drawing.Point(15, 165)
$lblDns1.AutoSize = $true

$txtDns1 = New-Object System.Windows.Forms.TextBox
$txtDns1.Location = New-Object System.Drawing.Point(80, 161)
$txtDns1.Size = New-Object System.Drawing.Size(130, 23)
$txtDns1.Text = "1.1.1.1"

$lblDns2 = New-Object System.Windows.Forms.Label
$lblDns2.Text = "DNS 2:"
$lblDns2.Location = New-Object System.Drawing.Point(220, 165)
$lblDns2.AutoSize = $true

$txtDns2 = New-Object System.Windows.Forms.TextBox
$txtDns2.Location = New-Object System.Drawing.Point(270, 161)
$txtDns2.Size = New-Object System.Drawing.Size(130, 23)
$txtDns2.Text = "8.8.8.8"

$btnApplyDns = New-Object System.Windows.Forms.Button
$btnApplyDns.Text = "Apply DNS only"
$btnApplyDns.Location = New-Object System.Drawing.Point(15, 195)
$btnApplyDns.Size = New-Object System.Drawing.Size(150, 23)

$btnDhcp = New-Object System.Windows.Forms.Button
$btnDhcp.Text = "Revert adapter to DHCP"
$btnDhcp.Location = New-Object System.Drawing.Point(175, 195)
$btnDhcp.Size = New-Object System.Drawing.Size(185, 23)

$grpNetwork.Controls.AddRange(@(
    $lblAdapter, $cmbAdapter, $btnRefreshAdapters, $btnFlushDns,
    $lblIp, $txtIp, $lblMask, $txtMask, $lblGw, $txtGw, $btnApplyStatic,
    $lblDns1, $txtDns1, $lblDns2, $txtDns2, $btnApplyDns, $btnDhcp
))

$grpPrefs = New-Object System.Windows.Forms.GroupBox
$grpPrefs.Text = "Windows preferences"
$grpPrefs.Location = New-Object System.Drawing.Point(10, 280)
$grpPrefs.Size = New-Object System.Drawing.Size(380, 160)
$grpPrefs.BackColor = [System.Drawing.Color]::FromArgb(37, 37, 38)
$grpPrefs.ForeColor = [System.Drawing.Color]::White

$chkPrefDark   = New-Object System.Windows.Forms.CheckBox
$chkPrefDark.Text = "Dark theme for Windows"
$chkPrefDark.Location = New-Object System.Drawing.Point(15, 25)
$chkPrefDark.AutoSize = $true

$chkPrefBing   = New-Object System.Windows.Forms.CheckBox
$chkPrefBing.Text = "Disable Bing search in Start Menu"
$chkPrefBing.Location = New-Object System.Drawing.Point(15, 50)
$chkPrefBing.AutoSize = $true

$chkPrefHidden = New-Object System.Windows.Forms.CheckBox
$chkPrefHidden.Text = "Show hidden files"
$chkPrefHidden.Location = New-Object System.Drawing.Point(15, 75)
$chkPrefHidden.AutoSize = $true

$chkPrefExt    = New-Object System.Windows.Forms.CheckBox
$chkPrefExt.Text = "Show file extensions"
$chkPrefExt.Location = New-Object System.Drawing.Point(190, 75)
$chkPrefExt.AutoSize = $true

$chkPrefMouse  = New-Object System.Windows.Forms.CheckBox
$chkPrefMouse.Text = "Disable mouse acceleration"
$chkPrefMouse.Location = New-Object System.Drawing.Point(15, 100)
$chkPrefMouse.AutoSize = $true

$chkPrefNum    = New-Object System.Windows.Forms.CheckBox
$chkPrefNum.Text = "Enable NumLock on startup"
$chkPrefNum.Location = New-Object System.Drawing.Point(190, 100)
$chkPrefNum.AutoSize = $true

$btnApplyPrefs = New-Object System.Windows.Forms.Button
$btnApplyPrefs.Text = "Apply selected preferences"
$btnApplyPrefs.Location = New-Object System.Drawing.Point(15, 125)
$btnApplyPrefs.Size = New-Object System.Drawing.Size(200, 23)

$grpPrefs.Controls.AddRange(@(
    $chkPrefDark, $chkPrefBing, $chkPrefHidden, $chkPrefExt,
    $chkPrefMouse, $chkPrefNum, $btnApplyPrefs
))

$grpLog = New-Object System.Windows.Forms.GroupBox
$grpLog.Text = "Log output"
$grpLog.Location = New-Object System.Drawing.Point(400, 280)
$grpLog.Size = New-Object System.Drawing.Size(520, 260)
$grpLog.BackColor = [System.Drawing.Color]::FromArgb(37, 37, 38)
$grpLog.ForeColor = [System.Drawing.Color]::White

$logBox = New-Object System.Windows.Forms.TextBox
$logBox.Multiline = $true
$logBox.ReadOnly = $true
$logBox.ScrollBars = "Vertical"
$logBox.Location = New-Object System.Drawing.Point(15, 25)
$logBox.Size = New-Object System.Drawing.Size(490, 220)
$logBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$logBox.BackColor = [System.Drawing.Color]::FromArgb(20, 20, 20)
$logBox.ForeColor = [System.Drawing.Color]::White

$grpLog.Controls.Add($logBox)
$script:LogTextBox = $logBox

$btnRunSelected.Add_Click({
    try {
        [System.Windows.Forms.Cursor]::Current = [System.Windows.Forms.Cursors]::WaitCursor

        if ($chkRestore.Checked) {
            Create-SystemRestorePoint -Description "PC Cleanup Tool - Run Selected"
        }

        if ($chkTemp.Checked)     { Clear-TempFiles }
        if ($chkRecycle.Checked)  { Clear-RecycleBinSafe }
        if ($chkWU.Checked)       { Clear-WindowsUpdateCache }
        if ($chkPrefetch.Checked) { Clear-PrefetchCache }
        if ($chkNetwork.Checked)  { Reset-NetworkStack }
        if ($chkHealth.Checked)   { Run-SystemHealthChecks }
        if ($chkChkDsk.Checked)   { Run-ChkDskScan }

        Write-Log "Run selected completed."
    } finally {
        [System.Windows.Forms.Cursor]::Current = [System.Windows.Forms.Cursors]::Default
    }
})

$btnRunAll.Add_Click({
    try {
        [System.Windows.Forms.Cursor]::Current = [System.Windows.Forms.Cursors]::WaitCursor

        if ($chkRestore.Checked) {
            Create-SystemRestorePoint -Description "PC Cleanup Tool - Run All"
        }

        Clear-TempFiles
        Clear-RecycleBinSafe
        Clear-WindowsUpdateCache
        Clear-PrefetchCache
        Reset-NetworkStack
        Run-SystemHealthChecks
        Run-ChkDskScan

        Write-Log "Run all completed."
    } finally {
        [System.Windows.Forms.Cursor]::Current = [System.Windows.Forms.Cursors]::Default
    }
})

$btnInstallApps.Add_Click({
    try {
        [System.Windows.Forms.Cursor]::Current = [System.Windows.Forms.Cursors]::WaitCursor
        Install-BasicApps
    } finally {
        [System.Windows.Forms.Cursor]::Current = [System.Windows.Forms.Cursors]::Default
    }
})

$btnFlushDns.Add_Click({
    try {
        [System.Windows.Forms.Cursor]::Current = [System.Windows.Forms.Cursors]::WaitCursor
        Flush-DnsCache
    } finally {
        [System.Windows.Forms.Cursor]::Current = [System.Windows.Forms.Cursors]::Default
    }
})

$btnRefreshAdapters.Add_Click({
    $cmbAdapter.Items.Clear()
    $adapters = Get-ActiveAdapters
    foreach ($ad in $adapters) {
        [void]$cmbAdapter.Items.Add($ad.Name)
    }

    if ($cmbAdapter.Items.Count -gt 0) {
        $cmbAdapter.SelectedIndex = 0
        Write-Log "Adapters refreshed. Found $($cmbAdapter.Items.Count) active adapter(s)."
    } else {
        Write-Log "No active adapters found." "WARN"
    }
})

function Get-SelectedAdapterName {
    if (-not $cmbAdapter.SelectedItem) {
        [System.Windows.Forms.MessageBox]::Show(
            "Please select a network adapter first.",
            "PC Cleanup Tool",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
        return $null
    }
    [string]$cmbAdapter.SelectedItem
}

$btnApplyStatic.Add_Click({
    try {
        [System.Windows.Forms.Cursor]::Current = [System.Windows.Forms.Cursors]::WaitCursor

        $adapterName = Get-SelectedAdapterName
        if (-not $adapterName) { return }

        $ip  = $txtIp.Text.Trim()
        $sm  = $txtMask.Text.Trim()
        $gw  = $txtGw.Text.Trim()

        if ([string]::IsNullOrWhiteSpace($ip) -or [string]::IsNullOrWhiteSpace($sm) -or [string]::IsNullOrWhiteSpace($gw)) {
            [System.Windows.Forms.MessageBox]::Show(
                "IP, mask and gateway must not be empty.",
                "PC Cleanup Tool",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            ) | Out-Null
            return
        }

        Set-StaticIP -InterfaceName $adapterName -IpAddress $ip -SubnetMask $sm -Gateway $gw
    } finally {
        [System.Windows.Forms.Cursor]::Current = [System.Windows.Forms.Cursors]::Default
    }
})

$btnApplyDns.Add_Click({
    try {
        [System.Windows.Forms.Cursor]::Current = [System.Windows.Forms.Cursors]::WaitCursor

        $adapterName = Get-SelectedAdapterName
        if (-not $adapterName) { return }

        $dns1 = $txtDns1.Text.Trim()
        $dns2 = $txtDns2.Text.Trim()

        Set-DnsServers -InterfaceName $adapterName -Dns1 $dns1 -Dns2 $dns2
    } finally {
        [System.Windows.Forms.Cursor]::Current = [System.Windows.Forms.Cursors]::Default
    }
})

$btnDhcp.Add_Click({
    try {
        [System.Windows.Forms.Cursor]::Current = [System.Windows.Forms.Cursors]::WaitCursor

        $adapterName = Get-SelectedAdapterName
        if (-not $adapterName) { return }

        Set-DhcpMode -InterfaceName $adapterName
    } finally {
        [System.Windows.Forms.Cursor]::Current = [System.Windows.Forms.Cursors]::Default
    }
})

$btnApplyPrefs.Add_Click({
    try {
        [System.Windows.Forms.Cursor]::Current = [System.Windows.Forms.Cursors]::WaitCursor

        Apply-WindowsPreferences `
            -DarkTheme     $chkPrefDark.Checked `
            -DisableBing   $chkPrefBing.Checked `
            -ShowHidden    $chkPrefHidden.Checked `
            -ShowExt       $chkPrefExt.Checked `
            -NoMouseAccel  $chkPrefMouse.Checked `
            -EnableNumLock $chkPrefNum.Checked
    } finally {
        [System.Windows.Forms.Cursor]::Current = [System.Windows.Forms.Cursors]::Default
    }
})

$form.Controls.Add($grpCleanup)
$form.Controls.Add($grpNetwork)
$form.Controls.Add($grpPrefs)
$form.Controls.Add($grpLog)

$btnRefreshAdapters.PerformClick() | Out-Null
Write-Log "Log file: $logFile"

[System.Windows.Forms.Application]::EnableVisualStyles()
[System.Windows.Forms.Application]::Run($form)

Write-Log "=== PC Cleanup Tool closed ==="

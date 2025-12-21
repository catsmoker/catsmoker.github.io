<#
.SYNOPSIS
    FreeMixKit v5.4 (Spicetify Fix)
    Standalone system utility suite.

.DESCRIPTION
    - Fixed Spotify Pro to run as Non-Admin (via Scheduled Task injection).
    - Updated Adobe Free to use gen.paramore.su.
    - Full TUI control (Arrow Keys).
    
.NOTES
    Author: catsmoker (Refactored by Assistant)
    Privileges: Administrator Required (Auto-Elevates)
#>

# ==============================================================================
# 1. SETUP & ADMIN CHECK
# ==============================================================================

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}

# Console visual setup
$Host.UI.RawUI.WindowTitle = "FreeMixKit v5.4 - System Suite"
[Console]::BackgroundColor = "Black"
[Console]::ForegroundColor = "Green"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Clear-Host

# ==============================================================================
# 2. STATIC SYSTEM INFO
# ==============================================================================
Write-Host "Loading System Information..." -ForegroundColor DarkGray
$SysInfo = @{
    OS   = (Get-CimInstance Win32_OperatingSystem).Caption
    CPU  = (Get-CimInstance Win32_Processor).Name
    RAM  = "{0:N1} GB" -f ((Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1GB)
}
Clear-Host

# ==============================================================================
# 3. MODULE LIBRARY
# ==============================================================================

$Modules = @{}

# --- MAINTENANCE ---
$Modules["CleanSystem"] = {
    Write-Log "Cleaning System Junk..."
    $count = 0
    $count += (Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object).Count
    $count += (Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object).Count
    $count += (Remove-Item -Path "C:\Windows\Prefetch\*" -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object).Count
    Clear-DnsClientCache -ErrorAction SilentlyContinue
    Write-Log "Cleanup Complete. Removed approx $count files." "Success"
}

$Modules["SystemRepair"] = {
    Write-Log "Starting SFC & DISM..." "Warn"
    Write-Log "NOTE: This will take 5-10 minutes. Do not close." "Warn"
    Write-Host " [1/2] Scanning System Files (SFC)..." -ForegroundColor Gray
    sfc.exe /scannow
    Write-Host " [2/2] Restoring Health (DISM)..." -ForegroundColor Gray
    DISM.exe /Online /Cleanup-Image /RestoreHealth
    Write-Log "Repair Sequence Finished." "Success"
}

$Modules["MalwareScan"] = {
    Write-Log "Checking for MRT (Malware Removal Tool)..."
    $mrt = "$env:SystemRoot\System32\MRT.exe"
    if (-not (Test-Path $mrt)) {
        Write-Log "Downloading MRT..." "Warn"
        try {
            Invoke-WebRequest "https://go.microsoft.com/fwlink/?LinkID=212732" -OutFile "$env:TEMP\MRT.exe"
            $mrt = "$env:TEMP\MRT.exe"
        } catch { Write-Log "Download failed." "Error"; return }
    }
    Start-Process $mrt -Wait
}

$Modules["SystemReport"] = {
    $path = "$([Environment]::GetFolderPath('Desktop'))\SystemReport_$(Get-Date -Format 'yyyyMMdd-HHmm').txt"
    Write-Log "Gathering Data..."
    $out =  "=== FREEMIXKIT REPORT ===`r`nDate: $(Get-Date)`r`n`r`n[SYSTEM]`r`nOS: $($SysInfo.OS)`r`nCPU: $($SysInfo.CPU)`r`nRAM: $($SysInfo.RAM)`r`n"
    $out += "`r`n[DISK]`r`n" + (Get-PhysicalDisk | Select-Object FriendlyName, MediaType, HealthStatus, Size | Format-Table -AutoSize | Out-String)
    $out | Out-File $path
    Write-Log "Report saved to Desktop." "Success"
    Invoke-Item $path
}

# --- APPS ---
$Modules["AdobeFree"] = {
    Write-Log "Opening GenP Download Portal..."
    Write-Log "ACTION REQUIRED: Cloudflare blocks scripts." "Warn"
    Write-Host "   1. Site will open in browser." -ForegroundColor Gray
    Write-Host "   2. Click 'Download' manually." -ForegroundColor Gray
    Start-Process "https://gen.paramore.su"
}

$Modules["SoftwareUpdate"] = {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Log "Installing Winget..." "Warn"
        Invoke-WebRequest -Uri "https://aka.ms/getwinget" -OutFile "$env:TEMP\winget.msixbundle"
        Add-AppxPackage -Path "$env:TEMP\winget.msixbundle"
    }
    Write-Log "Starting Global Software Update..."
    winget upgrade --all --include-unknown --accept-source-agreements --accept-package-agreements
}

$Modules["SpotifyPro"] = {
    Write-Log "Preparing Spicetify Installation..."
    
    # 1. Create the installation script in TEMP
    $tempDir = $env:TEMP
    $installScript = Join-Path $tempDir "Install-Spicetify.ps1"
    
    # We add a pause at the end so you can see if it worked or failed
    $scriptContent = @'
    Write-Host "=== Spicetify Installer (Non-Admin Mode) ===" -ForegroundColor Cyan
    Write-Host "Downloading and running installer..." -ForegroundColor Gray
    try {
        irm https://raw.githubusercontent.com/spicetify/marketplace/main/resources/install.ps1 | iex
    } catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }
    Write-Host "`nInstallation attempt finished." -ForegroundColor Yellow
    Write-Host "Press ENTER to close this window..."
    Read-Host
'@
    Set-Content -Path $installScript -Value $scriptContent -Force

    # 2. Use Scheduled Tasks to de-escalate privileges (Run as User, not Admin)
    $taskName = "FreeMixKit_Spicetify_UserInstall"
    $currentUser = $env:USERNAME
    
    Write-Log "Spicetify requires Non-Admin rights." "Info"
    Write-Log "Launching separate terminal as user: $currentUser..."

    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$installScript`""
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(2)
    # RunLevel Limited = Standard User Permissions (Solves the Admin issue)
    $principal = New-ScheduledTaskPrincipal -UserId $currentUser -LogonType Interactive -RunLevel Limited 

    try {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
        Start-ScheduledTask -TaskName $taskName
        
        Write-Log "Installer launched in a new window!" "Success"
        Write-Log "Check the new window to complete setup." "Info"
        
        # Give it a moment to fire before we clean up the task
        Start-Sleep -Seconds 3
    } catch {
        Write-Log "Failed to launch user-mode task: $($_.Exception.Message)" "Error"
    }
}

$Modules["DiscordPro"] = {
    Write-Log "Downloading LegCord Installer..."
    try {
        $url = ((Invoke-RestMethod "https://api.github.com/repos/Legcord/Legcord/releases/latest").assets | Where name -match ".exe" | Select -First 1).browser_download_url
        $dest = "$env:TEMP\Legcord_Installer.exe"
        Invoke-WebRequest $url -OutFile $dest
        Start-Process $dest -Wait
    } catch { Write-Log "Download failed." "Error" }
}

# --- ACTIVATION ---
$Modules["ActivateWindows"] = { Write-Log "Launching MAS..."; irm https://get.activated.win | iex }
$Modules["ActivateIDM"] = { Write-Log "Launching IAS..."; irm https://coporton.com/ias | iex }
$Modules["CTTUtility"] = { Write-Log "Launching WinUtil..."; irm https://christitus.com/win | iex }

# --- TWEAKS ---
$Modules["ToggleUpdates"] = {
    try {
        $srv = Get-Service wuauserv
        if ($srv.StartType -eq 'Disabled') {
            Set-Service wuauserv -StartupType Manual; Write-Log "Updates ENABLED." "Success"
        } else {
            Stop-Service wuauserv -Force; Set-Service wuauserv -StartupType Disabled; Write-Log "Updates DISABLED." "Warn"
        }
    } catch { Write-Log "Failed. TrustedInstaller required?" "Error" }
}

$Modules["ToggleDefender"] = {
    Write-Log "Toggling Defender..."
    $pref = Get-MpPreference
    if ($pref.DisableRealtimeMonitoring) {
        Set-MpPreference -DisableRealtimeMonitoring $false; Write-Log "Defender ENABLED." "Success"
    } else {
        Set-MpPreference -DisableRealtimeMonitoring $true; 
        if (-not (Get-MpPreference).DisableRealtimeMonitoring) { Write-Log "Failed. Disable 'Tamper Protection' manually first." "Error"; Start-Process "windowsdefender:" }
        else { Write-Log "Defender DISABLED." "Warn" }
    }
}

$Modules["DisableTelemetry"] = {
    Write-Log "Disabling Telemetry..."
    $paths = @("HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection")
    foreach ($p in $paths) { if (-not (Test-Path $p)) { New-Item $p -Force | Out-Null }; Set-ItemProperty $p "AllowTelemetry" 0 -Force }
    Write-Log "Telemetry Disabled." "Success"
}

$Modules["RegistryOptimize"] = {
    Write-Log "Applying Registry Tweaks..."
    Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" "NtfsDisableLastAccessUpdate" 1 -Force
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" "SystemResponsiveness" 0 -Force
    Write-Log "Optimized." "Success"
}

# --- NETWORK ---
$Modules["SetGoogleDNS"] = { Get-NetAdapter | Where Status -eq Up | Set-DnsClientServerAddress -ServerAddresses ("8.8.8.8","8.8.4.4"); Write-Log "DNS Set: Google" "Success" }
$Modules["SetCloudflareDNS"] = { Get-NetAdapter | Where Status -eq Up | Set-DnsClientServerAddress -ServerAddresses ("1.1.1.1","1.0.0.1"); Write-Log "DNS Set: Cloudflare" "Success" }
$Modules["ResetNetwork"] = { Get-NetAdapter | Where Status -eq Up | Set-DnsClientServerAddress -ResetServerAddresses; ipconfig /flushdns; netsh winsock reset; Write-Log "Network Reset." "Success" }

# --- UTILS ---
$Modules["RegistryBackup"] = {
    $path = "$([Environment]::GetFolderPath('Desktop'))\RegBackup_$(Get-Date -Format 'yyyyMMdd').reg"
    Start-Process reg.exe -ArgumentList "export HKLM `"$path`" /y" -Wait -NoNewWindow
    Write-Log "Backup saved to Desktop." "Success"
}

$Modules["FixResolution"] = {
    Write-Log "Downloading CRU..."
    $url = "https://www.monitortests.com/download/cru/cru-1.5.3.zip"
    Invoke-WebRequest $url -OutFile "$env:TEMP\cru.zip"
    Expand-Archive "$env:TEMP\cru.zip" -DestinationPath "$env:TEMP\CRU" -Force
    Start-Process "$env:TEMP\CRU\CRU.exe" -Wait
    Start-Process "$env:TEMP\CRU\restart64.exe" -Wait
}

$Modules["AddShortcut"] = {
    $path = "$([Environment]::GetFolderPath('Desktop'))\FreeMixKit.lnk"
    $ws = New-Object -ComObject WScript.Shell
    $s = $ws.CreateShortcut($path)
    $s.TargetPath = "powershell.exe"
    $s.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    $s.IconLocation = "$env:SystemRoot\System32\shell32.dll,238"
    $s.Save()
    try {
        $bytes = [System.IO.File]::ReadAllBytes($path); $bytes[0x15] = $bytes[0x15] -bor 0x20; [System.IO.File]::WriteAllBytes($path, $bytes)
        Write-Log "Admin Shortcut created." "Success"
    } catch { Write-Log "Shortcut created (Standard)." "Warn" }
}

# ==============================================================================
# 4. HELPER FUNCTIONS
# ==============================================================================

function Write-Log($Message, $Type="Info") {
    $c = switch ($Type) { "Info" {"White"} "Success" {"Cyan"} "Warn" {"Yellow"} "Error" {"Red"} }
    Write-Host " [$((Get-Date).ToString('HH:mm:ss'))] " -NoNewline -ForegroundColor DarkGray
    Write-Host $Message -ForegroundColor $c
}

# ==============================================================================
# 5. MENU CONFIGURATION
# ==============================================================================

$Menu = @(
    @{L="[ MAINTENANCE ]";     Type="Header"}
    @{L="Clean System Junk";   A="CleanSystem";    D="Clear Temp, Prefetch & Flush DNS"}
    @{L="System Repair";       A="SystemRepair";   D="Run SFC & DISM (Fix Corrupt OS)"}
    @{L="Malware Scan";        A="MalwareScan";    D="Run Microsoft MRT Scanner"}
    @{L="System Report";       A="SystemReport";   D="Generate Specs text file on Desktop"}
    
    @{L="[ SOFTWARE & APPS ]"; Type="Header"}
    @{L="Adobe Free (GenP)";   A="AdobeFree";      D="Open gen.paramore.su (New Source)"}
    @{L="Software Update";     A="SoftwareUpdate"; D="Upgrade all apps (Winget)"}
    @{L="Spotify Pro";         A="SpotifyPro";     D="Install Spicetify (Safe Non-Admin Mode)"}
    @{L="Discord Pro";         A="DiscordPro";     D="Install LegCord (Better Discord)"}

    @{L="[ ACTIVATION ]";      Type="Header"}
    @{L="Activate Windows";    A="ActivateWindows";D="Microsoft Activation Scripts (MAS)"}
    @{L="Activate IDM";        A="ActivateIDM";    D="IDM Activation Script"}
    
    @{L="[ TWEAKS & PRIVACY ]";Type="Header"}
    @{L="Toggle Updates";      A="ToggleUpdates";  D="Enable/Disable Windows Updates"}
    @{L="Toggle Defender";     A="ToggleDefender"; D="Toggle Real-time Protection"}
    @{L="Disable Telemetry";   A="DisableTelemetry";D="Block Windows Data Collection"}
    @{L="Registry Optimize";   A="RegistryOptimize";D="Apply Speed Tweaks to Registry"}

    @{L="[ NETWORK ]";         Type="Header"}
    @{L="Set Google DNS";      A="SetGoogleDNS";   D="Set DNS to 8.8.8.8"}
    @{L="Set Cloudflare DNS";  A="SetCloudflareDNS";D="Set DNS to 1.1.1.1"}
    @{L="Reset Network";       A="ResetNetwork";   D="Reset IP, Winsock & DNS"}

    @{L="[ UTILITIES ]";       Type="Header"}
    @{L="CTT WinUtil";         A="CTTUtility";     D="Launch Chris Titus Tech Utility"}
    @{L="Registry Backup";     A="RegistryBackup"; D="Backup HKLM to Desktop"}
    @{L="Fix Resolution";      A="FixResolution";  D="Custom Resolution Utility (CRU)"}
    @{L="Add Shortcut";        A="AddShortcut";    D="Create Admin Shortcut on Desktop"}
    
    @{L="[ EXIT ]";            Type="Header"}
    @{L="Exit";                A="EXIT";           D="Close Application"}
)

$NavItems = $Menu | Where-Object { $_.Type -ne "Header" }
$SelectionIndex = 0

# ==============================================================================
# 6. MAIN LOOP
# ==============================================================================

while ($true) {
    Clear-Host
    Write-Host "==========================================================" -ForegroundColor Blue
    Write-Host "   FREEMIXKIT v5.4 " -NoNewline -ForegroundColor Cyan
    Write-Host "|  " -NoNewline -ForegroundColor Gray
    Write-Host "ARROWS" -NoNewline -ForegroundColor Yellow
    Write-Host " to Navigate, " -NoNewline -ForegroundColor Gray
    Write-Host "ENTER" -NoNewline -ForegroundColor Yellow
    Write-Host " to Select" -ForegroundColor Gray
    Write-Host "==========================================================" -ForegroundColor Blue
    
    Write-Host " OS: $($SysInfo.OS) | CPU: $($SysInfo.CPU) | RAM: $($SysInfo.RAM)" -ForegroundColor DarkGray
    Write-Host "==========================================================" -ForegroundColor Blue

    $currentNavIndex = 0
    foreach ($item in $Menu) {
        if ($item.Type -eq "Header") {
            Write-Host "`n $($item.L)" -ForegroundColor DarkGray
            continue
        }
        if ($currentNavIndex -eq $SelectionIndex) {
            Write-Host " > $($item.L.PadRight(20))" -NoNewline -BackgroundColor DarkGray -ForegroundColor White
            Write-Host " : $($item.D)" -ForegroundColor Cyan
        } else {
            Write-Host "   $($item.L.PadRight(20))" -NoNewline -ForegroundColor Green
            Write-Host " : $($item.D)" -ForegroundColor DarkGray
        }
        $currentNavIndex++
    }

    $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    switch ($key.VirtualKeyCode) {
        38 { if ($SelectionIndex -gt 0) { $SelectionIndex-- } else { $SelectionIndex = $NavItems.Count - 1 } }
        40 { if ($SelectionIndex -lt $NavItems.Count - 1) { $SelectionIndex++ } else { $SelectionIndex = 0 } }
        13 { 
            $action = $NavItems[$SelectionIndex].A
            if ($action -eq "EXIT") { Clear-Host; exit }
            Clear-Host
            Write-Host "----------------------------------------------------------" -ForegroundColor DarkGray
            Write-Host " RUNNING: $($NavItems[$SelectionIndex].L)" -ForegroundColor Cyan
            Write-Host "----------------------------------------------------------" -ForegroundColor DarkGray
            if ($Modules.ContainsKey($action)) { try { & $Modules[$action] } catch { Write-Log "Error: $($_.Exception.Message)" "Error" } } 
            else { Write-Log "Module Missing" "Error" }
            Write-Host "`n----------------------------------------------------------" -ForegroundColor DarkGray
            Write-Host "Press any key to return..." -ForegroundColor Gray
            $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
        }
    }
}

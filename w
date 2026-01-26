<#
.SYNOPSIS
    FreeMixKit v5.7 (Grid Edition)
    Standalone system utility suite.

.NOTES
    Author: catsmoker (Refactored by Assistant)
    Privileges: Administrator Required
#>

# ==============================================================================
# 1. SETUP & ADMIN CHECK
# ==============================================================================

$Host.UI.RawUI.WindowTitle = "FreeMixKit v5.7"
try {
    # Force big window (120x40 is good for grid)
    $bufferSize = New-Object Management.Automation.Host.Size(120, 2000)
    $windowSize = New-Object Management.Automation.Host.Size(120, 40)
    if ($Host.UI.RawUI.BufferSize.Width -lt $windowSize.Width) { $Host.UI.RawUI.BufferSize = $bufferSize }
    $Host.UI.RawUI.WindowSize = $windowSize
    $Host.UI.RawUI.BufferSize = $bufferSize
}
catch { Write-Host "Resize not supported." -ForegroundColor DarkGray }

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}

[Console]::BackgroundColor = "Black"
[Console]::ForegroundColor = "Green"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Clear-Host

# ==============================================================================
# 2. STATIC SYSTEM INFO
# ==============================================================================
$SysInfo = @{
    OS  = (Get-CimInstance Win32_OperatingSystem).Caption
    CPU = (Get-CimInstance Win32_Processor).Name
    RAM = "{0:N1} GB" -f ((Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1GB)
}

# ==============================================================================
# 3. HELPER FUNCTIONS
# ==============================================================================

function Write-Log($Message, $Type = "Info") {
    $c = switch ($Type) { "Info" { "White" } "Success" { "Cyan" } "Warn" { "Yellow" } "Error" { "Red" } }
    Write-Host " [$((Get-Date).ToString('HH:mm:ss'))] " -NoNewline -ForegroundColor DarkGray
    Write-Host $Message -ForegroundColor $c
}

# ==============================================================================
# 4. MODULE LIBRARY
# ==============================================================================

$Modules = @{}

# --- DEVELOPER ---
$Modules["DevChoice"] = {
    Write-Log "Starting Developer Environment Setup..." "Warn"
    Write-Log "Installing: VS Redists, .NET, Node, Python, Java, Tools, Bibata Cursor."
    
    # 1. Winget
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Log "Installing Winget..."
        Invoke-WebRequest -Uri "https://aka.ms/getwinget" -OutFile "$env:TEMP\winget.msixbundle"
        Add-AppxPackage -Path "$env:TEMP\winget.msixbundle"
    }

    # 2. Packages
    $packages = @(
        "Microsoft.DotNet.SDK.10", "Microsoft.DotNet.Runtime.10", "OpenJS.NodeJS.LTS", "Python.Python.3", "EclipseAdoptium.Temurin.21.JDK",
        "Microsoft.PowerShell", "Git.Git", "Gyan.FFmpeg", "7zip.7zip", "Notepad++.Notepad++", "AdrienAllard.FileConverter", "Google.GeminiCLI",
        "Microsoft.VCRedist.2005.x86", "Microsoft.VCRedist.2005.x64", "Microsoft.VCRedist.2008.x86", "Microsoft.VCRedist.2008.x64",
        "Microsoft.VCRedist.2010.x86", "Microsoft.VCRedist.2010.x64", "Microsoft.VCRedist.2012.x86", "Microsoft.VCRedist.2012.x64",
        "Microsoft.VCRedist.2013.x86", "Microsoft.VCRedist.2013.x64", "Microsoft.VCRedist.2015+.x86", "Microsoft.VCRedist.2015+.x64"
    )

    foreach ($id in $packages) {
        Write-Host " -> $id..." -ForegroundColor Gray
        try { winget install $id -s winget --accept-package-agreements --accept-source-agreements --disable-interactivity }
        catch { Write-Host "Failed: $id" -ForegroundColor Red }
    }

    # 3. Notepad Fix
    Write-Log "Replacing Notepad with Notepad++..."
    Get-AppxPackage *Microsoft.WindowsNotepad* | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
    $reg = @"
Windows Registry Editor Version 5.00
[HKEY_CLASSES_ROOT\.txt]
@="txtfile"
"PerceivedType"="text"
"Content Type"="text/plain"
[HKEY_CLASSES_ROOT\.txt\ShellNew]
"NullFile"=""
[HKEY_CLASSES_ROOT\txtfile]
@="Text Document"
[HKEY_CLASSES_ROOT\txtfile\ShellNew]
"NullFile"=""
"@
    $reg | Out-File "$env:TEMP\nppfix.reg" -Encoding ASCII -Force
    Start-Process reg.exe -Argument "import `"$env:TEMP\nppfix.reg`"" -Wait -NoNewWindow
    
    # 4. Bibata
    Write-Log "Installing Bibata Cursor..."
    try {
        $zip = "$env:TEMP\Bibata.zip"; $dest = "$env:TEMP\Bibata"
        Invoke-WebRequest "https://github.com/ful1e5/Bibata_Cursor/releases/download/v2.0.7/Bibata-Modern-Classic-Windows.zip" -OutFile $zip
        Expand-Archive $zip -Dest $dest -Force
        $inf = Get-ChildItem "$dest" -Recurse -Filter "*.inf" | Select-Object -First 1
        if ($inf) { Start-Process "RUNDLL32.EXE" -Arg "SETUPAPI.DLL,InstallHinfSection DefaultInstall 128 $($inf.FullName)" -Wait }
    }
    catch { Write-Log "Cursor Failed" "Error" }

    Write-Log "Done!" "Success"
}

# --- MAINTENANCE ---
$Modules["CleanSystem"] = {
    Write-Log "Cleaning..."
    Remove-Item "$env:TEMP\*" -Recurse -Force -EA SilentlyContinue
    Remove-Item "C:\Windows\Temp\*" -Recurse -Force -EA SilentlyContinue
    Remove-Item "C:\Windows\Prefetch\*" -Recurse -Force -EA SilentlyContinue
    Clear-DnsClientCache
    Write-Log "Cleaned." "Success"
}
$Modules["SystemRepair"] = { sfc /scannow; DISM /Online /Cleanup-Image /RestoreHealth; Write-Log "Done." "Success" }
$Modules["MalwareScan"] = { 
    $mrt = "$env:SystemRoot\System32\MRT.exe"
    if (!(Test-Path $mrt)) { Invoke-WebRequest "https://go.microsoft.com/fwlink/?LinkID=212732" -OutFile "$env:TEMP\MRT.exe"; $mrt = "$env:TEMP\MRT.exe" }
    Start-Process $mrt -Wait 
}
$Modules["MalwareScanAdv"] = {
    Write-Host "WARNING: DOWNLOADING 400MB+ (Tron Script)" -Bx Red -Fx White
    try {
        $l = (Invoke-WebRequest "https://bmrf.org/repos/tron/" -UseBasicParsing).Links.href | Where-Object { $_ -match "Tron v.+?\.exe" } | Select-Object -First 1
        If ($l) { Invoke-WebRequest "https://bmrf.org/repos/tron/$l" -OutFile "$env:TEMP\$l"; Start-Process "$env:TEMP\$l" -Wait }
    }
    catch { Write-Log "Error fetching Tron." "Error" }
}
$Modules["SystemReport"] = { 
    $f = "$env:USERPROFILE\Desktop\SysReport.txt"
    "OS: $($SysInfo.OS)`nCPU: $($SysInfo.CPU)`nRAM: $($SysInfo.RAM)" | Out-File $f
    Invoke-Item $f 
}

# --- APPS ---
$Modules["AdobeFree"] = {
    Write-Log "Opening Creative Cloud..."
    Start-Process "https://www.adobe.com/download/creative-cloud"
    Write-Log "Opening GenP..."
    Start-Process "https://gen.paramore.su"
}
$Modules["SoftwareUpdate"] = {
    if (!(Get-Command winget -EA SilentlyContinue)) { 
        Write-Log "Installing Choco to get Winget..."
        Set-ExecutionPolicy Bypass -Scope Process -Force
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        choco install winget -y
    }
    winget upgrade --all --include-unknown --accept-source-agreements --accept-package-agreements
}
$Modules["SpotifyPro"] = {
    # ===============================
    # Spotify → Spicetify Installer
    # ===============================

    Write-Log "Checking Spotify installation..." "Info"

    $spotifyExe = "$env:APPDATA\Spotify\Spotify.exe"

    if (-not (Test-Path $spotifyExe)) {

        if (Get-Command winget -ErrorAction SilentlyContinue) {
            Write-Log "Installing Spotify using winget..." "Info"
            winget install --id Spotify.Spotify --accept-package-agreements --accept-source-agreements
        }
        else {
            Write-Log "Winget not found. Using direct installer..." "Info"

            $spotifyInstaller = "$env:TEMP\SpotifySetup.exe"
            Invoke-WebRequest "https://download.scdn.co/SpotifySetup.exe" -OutFile $spotifyInstaller

            Start-Process $spotifyInstaller -ArgumentList "/silent" -Wait
        }

        # Wait until Spotify exists
        for ($i = 0; $i -lt 15; $i++) {
            if (Test-Path $spotifyExe) { break }
            Start-Sleep 2
        }

        if (-not (Test-Path $spotifyExe)) {
            Write-Log "Spotify installation failed or timed out." "Error"
            return
        }
    }
    else {
        Write-Log "Spotify already installed." "Info"
    }

    # ===============================
    # Prepare Spicetify Installer
    # ===============================

    Write-Log "Preparing Spicetify Installation..." "Info"

    $tempDir = $env:TEMP
    $installScript = Join-Path $tempDir "Install-Spicetify.ps1"

    $scriptContent = @'
Write-Host "=== Spicetify Installer ===" -ForegroundColor Cyan
try {
    irm https://raw.githubusercontent.com/spicetify/marketplace/main/resources/install.ps1 | iex
}
catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host "Press ENTER to close..."
Read-Host
'@

    Set-Content -Path $installScript -Value $scriptContent -Force

    # ===============================
    # Run as Standard User
    # ===============================

    $taskName = "FreeMixKit_Spicetify_User"
    $currentUser = $env:USERNAME

    Write-Log "Launching Spicetify installer as user: $currentUser..." "Info"

    $action = New-ScheduledTaskAction `
        -Execute "powershell.exe" `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$installScript`""

    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(2)
    $principal = New-ScheduledTaskPrincipal -UserId $currentUser -LogonType Interactive -RunLevel Limited

    try {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
        Start-ScheduledTask -TaskName $taskName

        Write-Log "Spicetify installer launched successfully." "Success"
    }
    catch {
        Write-Log "Failed to launch Spicetify installer." "Error"
    }

}

$Modules["DiscordPro"] = {
    try { 
        $u = ((Invoke-RestMethod "https://api.github.com/repos/Legcord/Legcord/releases/latest").assets | Where-Object name -match ".exe" | Select-Object -First 1).browser_download_url
        Invoke-WebRequest $u -OutFile "$env:TEMP\legcord.exe"; Start-Process "$env:TEMP\legcord.exe" -Wait
    }
    catch { Write-Log "Failed." }
}

# --- ACTIVATION ---
$Modules["ActivateWindows"] = { Invoke-RestMethod https://get.activated.win | Invoke-Expression }
$Modules["ActivateIDM"] = { Invoke-RestMethod https://coporton.com/ias | Invoke-Expression }

# --- TWEAKS & NETWORK ---
$Modules["ToggleUpdates"] = { try { if ((Get-Service wuauserv).StartType -eq 'Disabled') { Set-Service wuauserv -StartupType Manual }else { Stop-Service wuauserv -Force; Set-Service wuauserv -StartupType Disabled } } catch {} }
$Modules["ToggleDefender"] = { $p = Get-MpPreference; Set-MpPreference -DisableRealtimeMonitoring (!$p.DisableRealtimeMonitoring) }
$Modules["DisableTelemetry"] = { "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" | ForEach-Object { New-Item $_ -Force -EA SilentlyContinue; Set-ItemProperty $_ "AllowTelemetry" 0 -Force } }
$Modules["RegistryOptimize"] = { Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" "NtfsDisableLastAccessUpdate" 1; Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" "SystemResponsiveness" 0 }
$Modules["SetGoogleDNS"] = { Get-NetAdapter | Where-Object Status -eq Up | Set-DnsClientServerAddress -ServerAddresses "8.8.8.8", "8.8.4.4" }
$Modules["SetCloudflareDNS"] = { Get-NetAdapter | Where-Object Status -eq Up | Set-DnsClientServerAddress -ServerAddresses "1.1.1.1", "1.0.0.1" }
$Modules["ResetNetwork"] = { Get-NetAdapter | Where-Object Status -eq Up | Set-DnsClientServerAddress -ResetServerAddresses; ipconfig /flushdns; netsh winsock reset }

# --- UTILS ---
$Modules["CTTUtility"] = { Invoke-RestMethod https://christitus.com/win | Invoke-Expression }
$Modules["RegistryBackup"] = { Start-Process reg.exe -Arg "export HKLM `"$env:USERPROFILE\Desktop\Backup.reg`" /y" -Wait }
$Modules["FixResolution"] = { Invoke-WebRequest "https://www.monitortests.com/download/cru/cru-1.5.3.zip" -OutFile "$env:TEMP\cru.zip"; Expand-Archive "$env:TEMP\cru.zip" "$env:TEMP\CRU" -Force; Start-Process "$env:TEMP\CRU\CRU.exe" -Wait; Start-Process "$env:TEMP\CRU\restart64.exe" -Wait }
$Modules["RemoveWindowsAI"] = { try { & ([scriptblock]::Create((Invoke-RestMethod "https://raw.githubusercontent.com/zoicware/RemoveWindowsAI/main/RemoveWindowsAi.ps1"))) -nonInteractive } catch {} }

$Modules["AddShortcut"] = {
    $iconUrl = "https://catsmoker.github.io/freemixkit_icon.ico"
    $iconPath = "$env:USERPROFILE\Pictures\freemixkit_icon.ico"
    try { Invoke-WebRequest $iconUrl -OutFile $iconPath -ErrorAction SilentlyContinue } catch {}

    $s = (New-Object -ComObject WScript.Shell).CreateShortcut("$env:USERPROFILE\Desktop\FreeMixKit.lnk")
    $s.TargetPath = "powershell.exe"
    $s.Arguments = "-NoProfile -ExecutionPolicy Bypass -Command `"irm https://catsmoker.github.io/w | iex`""
    if (Test-Path $iconPath) { $s.IconLocation = $iconPath }
    $s.Save()
    
    # 3. Set RunAsAdministrator (Byte Patching)
    try {
        $bytes = [System.IO.File]::ReadAllBytes("$env:USERPROFILE\Desktop\FreeMixKit.lnk")
        $bytes[0x15] = $bytes[0x15] -bor 0x20 # Bit 5 = RunAsAdmin
        [System.IO.File]::WriteAllBytes("$env:USERPROFILE\Desktop\FreeMixKit.lnk", $bytes)
    }
    catch {}
}

# ==============================================================================
# 5. GRID MENU CONFIGURATION
# ==============================================================================

# Define Columns. Type: H=Header, I=Item
$Col1 = @(
    @{T = "H"; L = "[ DEVELOPER ]" }
    @{T = "I"; L = "DEV CHOICE (Full)"; A = "DevChoice"; D = "Installs: VS Redists, .NET, Node.js, Python, Java, PowerShell, Git, FFmpeg, 7zip, Notepad++, File Converter, GeminiCLI, Bibata Cursor." }
    @{T = "H"; L = "" }
    @{T = "H"; L = "[ MAINTENANCE ]" }
    @{T = "I"; L = "Clean System Junk"; A = "CleanSystem"; D = "Removes temp files, prefetch, and clears DNS cache." }
    @{T = "I"; L = "System Repair"; A = "SystemRepair"; D = "Runs SFC Scannow and DISM RestoreHealth." }
    @{T = "I"; L = "Malware Scan"; A = "MalwareScan"; D = "Runs the built-in Microsoft Malicious Software Removal Tool." }
    @{T = "I"; L = "Malware Scan Adv"; A = "MalwareScanAdv"; D = "Downloads and runs Tron Script (Heavy/Advanced deep clean)." }
    @{T = "I"; L = "System Report"; A = "SystemReport"; D = "Generates a text file with system specs on your desktop." }
    @{T = "H"; L = "" }
    @{T = "H"; L = "[ ACTIVATION ]" }
    @{T = "I"; L = "Activate Windows"; A = "ActivateWindows"; D = "Runs MAS (Microsoft Activation Scripts) to activate Windows." }
    @{T = "I"; L = "Activate IDM"; A = "ActivateIDM"; D = "Activates Internet Download Manager (IDM)." }
    @{T = "H"; L = "" }
    @{T = "H"; L = "[ TWEAKS ]" }
    @{T = "I"; L = "Toggle Updates"; A = "ToggleUpdates"; D = "Enables or Disables Windows Update service." }
    @{T = "I"; L = "Toggle Defender"; A = "ToggleDefender"; D = "Toggles Real-time monitoring for Windows Defender." }
    @{T = "I"; L = "Disable Telemetry"; A = "DisableTelemetry"; D = "Disables Windows data collection policies." }
    @{T = "I"; L = "Registry Optimize"; A = "RegistryOptimize"; D = "Tweaks NTFS access updates and System Responsiveness." }
)

$Col2 = @(
    @{T = "H"; L = "[ SOFTWARE ]" }
    @{T = "I"; L = "Adobe Free (GenP)"; A = "AdobeFree"; D = "Downloads Creative Cloud and GenP activator." }
    @{T = "I"; L = "Software Update"; A = "SoftwareUpdate"; D = "Upgrades all installed software via Winget." }
    @{T = "I"; L = "Spotify Pro"; A = "SpotifyPro"; D = "Installs Spicetify for Spotify customization/ad-blocking." }
    @{T = "I"; L = "Discord Pro"; A = "DiscordPro"; D = "Installs Legcord (BetterDiscord alternative)." }
    @{T = "H"; L = "" }
    @{T = "H"; L = "[ NETWORK ]" }
    @{T = "I"; L = "Set Google DNS"; A = "SetGoogleDNS"; D = "Sets DNS to 8.8.8.8 / 8.8.4.4." }
    @{T = "I"; L = "Set Cloudflare DNS"; A = "SetCloudflareDNS"; D = "Sets DNS to 1.1.1.1 / 1.0.0.1." }
    @{T = "I"; L = "Reset Network"; A = "ResetNetwork"; D = "Resets DNS and Winsock settings." }
    @{T = "H"; L = "" }
    @{T = "H"; L = "[ UTILITIES ]" }
    @{T = "I"; L = "CTT WinUtil"; A = "CTTUtility"; D = "Launches Chris Titus Tech's Windows Utility." }
    @{T = "I"; L = "Registry Backup"; A = "RegistryBackup"; D = "Backs up the HKLM registry hive to Desktop." }
    @{T = "I"; L = "Fix Resolution"; A = "FixResolution"; D = "Uses CRU to restart graphics driver and fix resolution." }
    @{T = "H"; L = "" }
    @{T = "H"; L = "[ AI & EXIT ]" }
    @{T = "I"; L = "Remove Windows AI"; A = "RemoveWindowsAI"; D = "Removes Copilot and Recall features." }
    @{T = "I"; L = "Add Shortcut"; A = "AddShortcut"; D = "Creates a shortcut for this script on the Desktop." }
    @{T = "I"; L = "Exis Application"; A = "EXIT"; D = "Closes the application." }
)

# Build Navigation Grid
# NavGrid is an array where item = {Col=0/1, Row=IndexInCol, Label, Action}
$NavItems = @()

# Process Col 1
for ($i = 0; $i -lt $Col1.Count; $i++) {
    if ($Col1[$i].T -eq "I") { $NavItems += @{C = 0; R = $i; L = $Col1[$i].L; A = $Col1[$i].A; D = $Col1[$i].D } }
}
# Process Col 2
for ($i = 0; $i -lt $Col2.Count; $i++) {
    if ($Col2[$i].T -eq "I") { $NavItems += @{C = 1; R = $i; L = $Col2[$i].L; A = $Col2[$i].A; D = $Col2[$i].D } }
}

$SelIdx = 0 # Index in $NavItems

# ==============================================================================
# 6. RENDER LOOP
# ==============================================================================

Clear-Host
while ($true) {
    [Console]::SetCursorPosition(0, 0)
    Write-Host "========================================================================================================================" -F Blue
    Write-Host "   FREEMIXKIT v5.7" -NoNewline -F Cyan
    Write-Host " | Use " -NoNewline -F Gray; Write-Host "ARROWS" -NoNewline -F Yellow; Write-Host " to Navigate (Left/Right to switch columns)" -F Gray
    Write-Host "========================================================================================================================" -F Blue
    Write-Host " OS: $($SysInfo.OS) | CPU: $($SysInfo.CPU) | RAM: $($SysInfo.RAM)" -F DarkGray
    Write-Host "------------------------------------------------------------------------------------------------------------------------" -F Blue
    
    $startY = 5
    
    # RENDER COL 1
    $y = $startY
    $x = 2
    for ($i = 0; $i -lt $Col1.Count; $i++) {
        [Console]::SetCursorPosition($x, $y)
        $item = $Col1[$i]
        
        if ($item.T -eq "H") { 
            Write-Host $item.L -F DarkGray
        }
        else {
            # Check if selected
            $isSel = ($NavItems[$SelIdx].C -eq 0 -and $NavItems[$SelIdx].R -eq $i)
            if ($isSel) { Write-Host " > $($item.L) " -B DarkGray -F White }
            else { Write-Host "   $($item.L) " -F Green }
        }
        $y++
    }

    # RENDER COL 2
    $y = $startY
    $x = 60
    for ($i = 0; $i -lt $Col2.Count; $i++) {
        [Console]::SetCursorPosition($x, $y)
        $item = $Col2[$i]
        
        if ($item.T -eq "H") { 
            Write-Host $item.L -F DarkGray
        }
        else {
            # Check if selected
            $isSel = ($NavItems[$SelIdx].C -eq 1 -and $NavItems[$SelIdx].R -eq $i)
            if ($isSel) { Write-Host " > $($item.L) " -B DarkGray -F White }
            else { Write-Host "   $($item.L) " -F Green }
        }
        $y++
    }
    
    # Helper Stats area below
    $maxY = $startY + [Math]::Max($Col1.Count, $Col2.Count) + 1
    [Console]::SetCursorPosition(0, $maxY)
    Write-Host "========================================================================================================================" -F Blue

    $curr = $NavItems[$SelIdx]

    [Console]::SetCursorPosition(0, $maxY + 1)
    # Clear 2 lines (240 chars) to handle wrapping text
    Write-Host (" " * 240) -NoNewline
    
    [Console]::SetCursorPosition(2, $maxY + 1)
    Write-Host "INFO: $($curr.D)" -F Yellow

    # INPUT HANDLING
    $k = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

    switch ($k.VirtualKeyCode) {
        38 {
            # UP
            # Find prev item in same column
            $prev = $NavItems | Where-Object { $_.C -eq $curr.C -and $_.R -lt $curr.R } | Select-Object -Last 1
            if ($prev) { $SelIdx = $NavItems.IndexOf($prev) }
        }
        40 {
            # DOWN
            # Find next item in same column
            $next = $NavItems | Where-Object { $_.C -eq $curr.C -and $_.R -gt $curr.R } | Select-Object -First 1
            if ($next) { $SelIdx = $NavItems.IndexOf($next) }
        }
        39 {
            # RIGHT
            if ($curr.C -eq 0) {
                # Jump to Col 1, similar Row Y
                $target = $NavItems | Where-Object { $_.C -eq 1 } | Sort-Object { [Math]::Abs($_.R - $curr.R) } | Select-Object -First 1
                if ($target) { $SelIdx = $NavItems.IndexOf($target) }
            }
        }
        37 {
            # LEFT
            if ($curr.C -eq 1) {
                # Jump to Col 0, similar Row Y
                $target = $NavItems | Where-Object { $_.C -eq 0 } | Sort-Object { [Math]::Abs($_.R - $curr.R) } | Select-Object -First 1
                if ($target) { $SelIdx = $NavItems.IndexOf($target) }
            }
        }
        13 {
            # ENTER
            $action = $curr.A
            if ($action -eq "EXIT") { Clear-Host; exit }
            
            [Console]::SetCursorPosition(2, $maxY + 2)
            Write-Host "Executing: $($curr.L)..." -F Cyan
            if ($Modules.ContainsKey($action)) { try { & $Modules[$action] } catch { Write-Log "Error: $($_.Exception.Message)" "Error" } }
            
            [Console]::SetCursorPosition(2, $maxY + 4)
            Write-Host "Press any key..." -F Gray
            $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
            Clear-Host
        }
    }
}

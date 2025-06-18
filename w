<#
.NOTES
    Author          : catsmoker
    Email           : catsmoker.lab@gmail.com
    Website         : https://catsmoker.github.io
    GitHub          : https://github.com/catsmoker/AetherKit
    Version         : 3.0
#>

# Check if the script is running as administrator
Write-Host "Checking if running as administrator..."
$adminCheck = [System.Security.Principal.WindowsPrincipal] [System.Security.Principal.WindowsIdentity]::GetCurrent()
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
if (-not $adminCheck.IsInRole($adminRole)) {
    $separator = "============================================================="
    $adminMessage = "Attention Required!"
    Write-Host $separator -ForegroundColor Yellow
    Write-Host ""
    Write-Host $adminMessage -ForegroundColor Red -BackgroundColor Black
    Write-Host ""
    Write-Host "Oops! It looks like this script is not running with administrator privileges." -ForegroundColor Magenta
    Write-Host "For optimal performance and access to all features, we need to restart this script with elevated rights." -ForegroundColor Magenta
    Write-Host ""
    Write-Host "Attempting to relaunch with administrative privileges... Please wait." -ForegroundColor Green
    Write-Host ""
    Write-Host $separator -ForegroundColor Yellow

    # Restart the script with administrative privileges
    $newProcess = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs -Wait
    exit
} else {
    Write-Host "Script is running as administrator."
}

# Check if the script is running on a supported operating system
$osVersion = [System.Environment]::OSVersion.Version
if ($osVersion.Major -lt 10 -or ($osVersion.Major -eq 10 -and $osVersion.Minor -lt 0)) {
    Write-Host "This script is only supported on Windows 10 or newer." -ForegroundColor Red
    Write-Host "Your current OS version is $($osVersion.Major).$($osVersion.Minor)."
    exit
}

# Load necessary assemblies for UI
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Main Form
$mainForm = New-Object System.Windows.Forms.Form
$mainForm.Text = "AetherKit v3.0 by catsmoker"
$mainForm.Size = New-Object System.Drawing.Size(900, 700)
$mainForm.StartPosition = "CenterScreen"
$mainForm.BackColor = [System.Drawing.Color]::FromArgb(18, 18, 22)
$mainForm.ForeColor = [System.Drawing.Color]::White
$mainForm.FormBorderStyle = 'FixedDialog'
$mainForm.MaximizeBox = $false
$mainForm.Font = New-Object System.Drawing.Font("Segoe UI", 10)

# Title Label
$titleLabel = New-Object System.Windows.Forms.Label
$titleLabel.Text = "AetherKit v3.0"
$titleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 20, [System.Drawing.FontStyle]::Bold)
$titleLabel.Size = New-Object System.Drawing.Size(850, 40)
$titleLabel.Location = New-Object System.Drawing.Point(25, 20)
$titleLabel.TextAlign = [System.Windows.Forms.HorizontalAlignment]::Center
$titleLabel.ForeColor = [System.Drawing.Color]::FromArgb(200, 200, 200)
$mainForm.Controls.Add($titleLabel)

# Subtitle Label
$subtitleLabel = New-Object System.Windows.Forms.Label
$subtitleLabel.Text = "by catsmoker | https://catsmoker.github.io"
$subtitleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Regular)
$subtitleLabel.Size = New-Object System.Drawing.Size(850, 20)
$subtitleLabel.Location = New-Object System.Drawing.Point(25, 60)
$subtitleLabel.TextAlign = [System.Windows.Forms.HorizontalAlignment]::Center
$subtitleLabel.ForeColor = [System.Drawing.Color]::FromArgb(150, 150, 150)
$mainForm.Controls.Add($subtitleLabel)

# Helper function to create styled buttons
Function Create-Button {
    param($Text, $X, $Y, $ClickAction, $TooltipText)
    $button = New-Object System.Windows.Forms.Button
    $button.Text = $Text
    $button.Size = New-Object System.Drawing.Size(260, 50)
    $button.Location = New-Object System.Drawing.Point($X, $Y)
    $button.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Regular)
    $button.BackColor = [System.Drawing.Color]::FromArgb(40, 40, 50)
    $button.ForeColor = [System.Drawing.Color]::White
    $button.FlatStyle = 'Flat'
    $button.FlatAppearance.BorderSize = 1
    $button.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(60, 60, 70)
    $button.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(60, 60, 80)
    $button.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(80, 80, 100)
    $button.Add_Click($ClickAction)
    
    # Add tooltip
    $tooltip = New-Object System.Windows.Forms.ToolTip
    $tooltip.SetToolTip($button, $TooltipText)
    
    return $button
}

Function Create-ToolButton {
    param($Text, $X, $Y, $ClickAction, $TooltipText)
    $button = New-Object System.Windows.Forms.Button
    $button.Text = $Text
    $button.Size = New-Object System.Drawing.Size(200, 40)
    $button.Location = New-Object System.Drawing.Point($X, $Y)
    $button.Font = New-Object System.Drawing.Font("Segoe UI", 9.5, [System.Drawing.FontStyle]::Regular)
    $button.BackColor = [System.Drawing.Color]::FromArgb(50, 50, 60)
    $button.ForeColor = [System.Drawing.Color]::White
    $button.FlatStyle = 'Flat'
    $button.FlatAppearance.BorderSize = 1
    $button.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(70, 70, 90)
    $button.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(70, 70, 100)
    $button.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(90, 90, 120)
    $button.Add_Click($ClickAction)
    
    $tooltip = New-Object System.Windows.Forms.ToolTip
    $tooltip.SetToolTip($button, $TooltipText)
    
    return $button
}


# Menu Buttons (arranged in a grid)
$buttonClean = Create-Button -Text "Clean Windows" -X 50 -Y 120 -ClickAction { CleanWindows } -TooltipText "Cleans temporary files, Recycle Bin, and DNS cache."
$mainForm.Controls.Add($buttonClean)

$buttonFix = Create-Button -Text "Scan and Fix Windows" -X 330 -Y 120 -ClickAction { FixWindows } -TooltipText "Runs chkdsk, sfc, and DISM to repair Windows."
$mainForm.Controls.Add($buttonFix)

$buttonApps = Create-Button -Text "Apps/Upgrades" -X 610 -Y 120 -ClickAction { DownloadApps } -TooltipText "Install or upgrade software using winget."
$mainForm.Controls.Add($buttonApps)

$buttonActivateIDM = Create-Button -Text "Activate IDM" -X 50 -Y 190 -ClickAction { ActivateIDM } -TooltipText "Activates Internet Download Manager."
$mainForm.Controls.Add($buttonActivateIDM)

$buttonActivateWindows = Create-Button -Text "Activate Windows" -X 330 -Y 190 -ClickAction { ActivateWindows } -TooltipText "Activates Windows using an external script."
$mainForm.Controls.Add($buttonActivateWindows)

$buttonActivateOffice = Create-Button -Text "Activate Office" -X 610 -Y 190 -ClickAction { ActivateOffice } -TooltipText "Activates Microsoft Office."
$mainForm.Controls.Add($buttonActivateOffice)

$buttonAtlas = Create-Button -Text "Windows Update" -X 50 -Y 260 -ClickAction { windowsps } -TooltipText "Installs Windows updates via PSWindowsUpdate."
$mainForm.Controls.Add($buttonAtlas)

$buttonCTT = Create-Button -Text "CTT Windows Utility" -X 330 -Y 260 -ClickAction { CTT } -TooltipText "Runs Chris Titus Tech's Windows Utility."
$mainForm.Controls.Add($buttonCTT)

$buttonMRT = Create-Button -Text "Virus Scan" -X 610 -Y 260 -ClickAction { ScanWithMRT } -TooltipText "Runs Windows Malicious Software Removal Tool."
$mainForm.Controls.Add($buttonMRT)

$buttonNetwork = Create-Button -Text "Network Tools" -X 50 -Y 330 -ClickAction { NetworkTools } -TooltipText "Network configuration and diagnostic tools."
$mainForm.Controls.Add($buttonNetwork)

$buttonRegistry = Create-Button -Text "Registry Tools" -X 330 -Y 330 -ClickAction { RegistryTools } -TooltipText "Registry maintenance and backup tools."
$mainForm.Controls.Add($buttonRegistry)

$buttonReport = Create-Button -Text "System Report" -X 610 -Y 330 -ClickAction { SystemReport } -TooltipText "Generate comprehensive system report."
$mainForm.Controls.Add($buttonReport)

$buttonAddShortcut = Create-Button -Text "Add Shortcut" -X 50 -Y 400 -ClickAction { AddShortcut } -TooltipText "Adds a desktop shortcut for AetherKit."
$mainForm.Controls.Add($buttonAddShortcut)

$buttonPowerTools = Create-Button -Text "Power Tools" -X 330 -Y 400 -ClickAction { PowerTools } -TooltipText "Advanced system utilities."
$mainForm.Controls.Add($buttonPowerTools)

$buttonExit = Create-Button -Text "Exit" -X 610 -Y 400 -ClickAction { Exit-Script } -TooltipText "Exits the script and opens the developer's website."
$mainForm.Controls.Add($buttonExit)

# Progress Bar
$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Size = New-Object System.Drawing.Size(800, 20)
$progressBar.Location = New-Object System.Drawing.Point(50, 500)
$progressBar.Style = 'Continuous'
$progressBar.ForeColor = [System.Drawing.Color]::FromArgb(100, 200, 100)
$progressBar.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 40)
$mainForm.Controls.Add($progressBar)

# Status Label
$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Text = "Ready"
$statusLabel.Size = New-Object System.Drawing.Size(800, 20)
$statusLabel.Location = New-Object System.Drawing.Point(50, 530)
$statusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$statusLabel.ForeColor = [System.Drawing.Color]::FromArgb(150, 150, 150)
$mainForm.Controls.Add($statusLabel)

# Functions
Function CleanWindows {
    Clear-Host
    $statusLabel.Text = "Cleaning Windows..."
    $progressBar.Value = 0

    $totalTasks = 0
    $completedTasks = 0

    function Update-ProgressStatus {
        param (
            [string]$TaskName,
            [int]$CurrentValue,
            [int]$MaxValue
        )
        $statusLabel.Text = "Cleaning Windows: $TaskName"
        if ($MaxValue -gt 0) {
            $progressBar.Value = (($completedTasks + ($CurrentValue / $MaxValue)) / $totalTasks) * 100
        } else {
            $progressBar.Value = (($completedTasks) / $totalTasks) * 100
        }
    }

    $cleaningTasks = @(
        "Global Temp Folder",
        "User Temp Folder",
        "Windows Temp Files",
        "Prefetch Files",
        "Recycle Bin",
        "DNS Cache",
        "Event Logs",
        "Browser Caches (Edge, Chrome, Firefox)",
        "Windows Update Cleanup",
        "Old User Profiles"
    )
    $totalTasks = $cleaningTasks.Count

    Update-ProgressStatus "Global Temp Folder" 0 1
    $globalTempPath = [System.IO.Path]::GetTempPath()
    Write-Host "Clearing global temp folder: $globalTempPath"
    $globalFiles = Get-ChildItem -Path $globalTempPath -Recurse -Force -ErrorAction SilentlyContinue
    $count = 0
    foreach ($file in $globalFiles) {
        $count++
        Update-ProgressStatus "Global Temp Folder" $count $globalFiles.Count
        Remove-Item -Path $file.FullName -Recurse -Force -ErrorAction SilentlyContinue
    }
    $completedTasks++

    Update-ProgressStatus "User Temp Folder" 0 1
    $userTempPath = $env:TEMP
    Write-Host "Clearing user temp folder: $userTempPath"
    $userFiles = Get-ChildItem -Path $userTempPath -Recurse -Force -ErrorAction SilentlyContinue
    $count = 0
    foreach ($file in $userFiles) {
        $count++
        Update-ProgressStatus "User Temp Folder" $count $userFiles.Count
        Remove-Item -Path $file.FullName -Recurse -Force -ErrorAction SilentlyContinue
    }
    $completedTasks++

    Update-ProgressStatus "Windows Temp Files" 0 1
    Write-Host "Deleting temporary files from C:\Windows\Temp..."
    Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
    $completedTasks++

    Update-ProgressStatus "Prefetch Files" 0 1
    Write-Host "Deleting prefetch files..."
    Remove-Item -Path "C:\Windows\Prefetch\*" -Recurse -Force -ErrorAction SilentlyContinue
    $completedTasks++

    Update-ProgressStatus "Recycle Bin" 0 1
    Write-Host "Emptying Recycle Bin..."
    try {
        $shell = New-Object -ComObject Shell.Application
        $recycleBin = $shell.Namespace(0xA) # 0xA is the constant for the Recycle Bin
        $recycleBin.Items() | ForEach-Object { $_.InvokeVerb("delete") }
    } catch {
        Write-Warning "Could not empty Recycle Bin: $($_.Exception.Message)"
    }
    $completedTasks++

    Update-ProgressStatus "DNS Cache" 0 1
    Write-Host "Flushing DNS Cache..."
    ipconfig /flushdns | Out-Null
    $completedTasks++

    Update-ProgressStatus "Event Logs" 0 1
    Write-Host "Clearing all event logs..."
    Get-WinEvent -ListLog * | ForEach-Object {
        try {
            Write-Output "Clearing $($_.LogName)"
            wevtutil cl "$($_.LogName)"
        } catch {
            Write-Warning "Failed to clear log $($_.LogName): $($_.Exception.Message)"
        }
    }
    $completedTasks++

    Update-ProgressStatus "Browser Caches (Edge, Chrome, Firefox)" 0 1
    Write-Host "Clearing browser caches..."

    Write-Host "  Clearing Microsoft Edge cache..."
    $edgeCachePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache\*"
    Remove-Item -Path $edgeCachePath -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host "  Clearing Google Chrome cache..."
    $chromeCachePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache\*"
    Remove-Item -Path $chromeCachePath -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host "  Clearing Mozilla Firefox cache..."
    $firefoxProfilesBase = "$env:APPDATA\Mozilla\Firefox\Profiles\"
    if (Test-Path $firefoxProfilesBase -PathType Container) {
        Get-ChildItem -Path $firefoxProfilesBase -Directory | ForEach-Object {
            $firefoxProfilePath = $_.FullName
            Remove-Item -Path "$firefoxProfilePath\Cache2\entries\*" -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -Path "$firefoxProfilePath\startupCache\*" -Recurse -Force -ErrorAction SilentlyContinue
        }
    } else {
        Write-Output "  Firefox profiles directory not found: $firefoxProfilesBase (Firefox might not be installed or used by this user)."
    }
    $completedTasks++

    Update-ProgressStatus "Windows Update Cleanup" 0 1
    Write-Host "Performing Windows Update cleanup..."
    try {
        $dismProcess = Start-Process -FilePath "dism.exe" -ArgumentList "/Online /Cleanup-Image /StartComponentCleanup /ResetBase" -Wait -NoNewWindow -PassThru -ErrorAction Stop
        if ($dismProcess.ExitCode -ne 0) {
            Write-Warning "DISM command exited with error code $($dismProcess.ExitCode)."
        }
    } catch {
        Write-Warning "Failed to perform Windows Update cleanup: $($_.Exception.Message). Ensure you are running as Administrator."
    }
    $completedTasks++

    Update-ProgressStatus "Old User Profiles" 0 1
    Write-Host "Checking for and removing old user profiles..."
    $currentUsers = @($env:USERNAME, "Public", "Default", "Default User", "All Users")
    Get-CimInstance -Class Win32_UserProfile | Where-Object {
        $_.LocalPath -notmatch "C:\\Users\\($($currentUsers -join '|'))" -and
        $_.Special -eq $false -and
        $_.Loaded -eq $false
    } | ForEach-Object {
        Write-Host "  Removing old user profile: $($_.LocalPath)"
        try {
            $_.Delete()
            Write-Host "    Successfully removed $($_.LocalPath)"
        } catch {
            Write-Warning "    Failed to delete profile $($_.LocalPath): $($_.Exception.Message)"
        }
    }
    $completedTasks++

    $progressBar.Value = 100
    $statusLabel.Text = "Cleanup completed!"
    Write-Host "All specified cleaning tasks have been completed!"
}

Function AddShortcut {
    $shortcutPath = Join-Path -Path ([Environment]::GetFolderPath("Desktop")) -ChildPath "AetherKit.lnk"

    if (Test-Path -Path $shortcutPath -PathType Leaf) {
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.MessageBox]::Show(
            "Shortcut already exists: $shortcutPath", 
            "Shortcut Exists", 
            [System.Windows.Forms.MessageBoxButtons]::OK, 
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
        Write-Host "Shortcut already exists: $shortcutPath" -ForegroundColor Green
    } else {
        Write-Host "Creating shortcut on desktop..."
        $targetPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        $arguments = '-NoProfile -ExecutionPolicy Bypass -Command "irm https://catsmoker.github.io/W | iex"'

        $iconUrl = "https://catsmoker.github.io/favicon.ico"
        $localIconPath = "$env:TEMP\aetherkit_icon.ico"

        Invoke-WebRequest -Uri $iconUrl -OutFile $localIconPath -UseBasicParsing

        $wshShell = New-Object -ComObject WScript.Shell
        $shortcut = $wshShell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = $targetPath
        $shortcut.Arguments = $arguments
        $shortcut.WorkingDirectory = [System.IO.Path]::GetDirectoryName($targetPath)
        $shortcut.IconLocation = $localIconPath
        $shortcut.Save()

        # Set run as administrator
        $bytes = [System.IO.File]::ReadAllBytes($shortcutPath)
        $bytes[0x15] = $bytes[0x15] -bor 0x20 # Set byte 21 (0x15) bit 6 (0x20) to enable run as admin
        [System.IO.File]::WriteAllBytes($shortcutPath, $bytes)
        
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.MessageBox]::Show(
            "Shortcut created successfully: $shortcutPath", 
            "Shortcut Created", 
            [System.Windows.Forms.MessageBoxButtons]::OK, 
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
        Write-Host "Shortcut created successfully: $shortcutPath" -ForegroundColor Green
    }
}

Function FixWindows {
    Clear-Host
    $statusLabel.Text = "Scanning and fixing Windows..."
    $progressBar.Value = 0

    # Run chkdsk
    Write-Host "Running chkdsk..."
    Start-Process -FilePath "chkdsk.exe" -ArgumentList "/scan /perf" -NoNewWindow -Wait

    # Run sfc /scannow
    Write-Host "Running sfc /scannow..."
    Start-Process -FilePath "sfc.exe" -ArgumentList "/scannow" -NoNewWindow -Wait

    # Run DISM
    Write-Host "Running DISM..."
    Start-Process -FilePath "DISM.exe" -ArgumentList "/Online /Cleanup-Image /RestoreHealth" -NoNewWindow -Wait

    $progressBar.Value = 100
    $statusLabel.Text = "Fix completed!"
}

Function DownloadApps {
    Clear-Host
    $statusLabel.Text = "Opening Apps/Drivers menu..."
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Host "winget is not installed. Attempting to install..."
        $installerUrl = "https://aka.ms/getwinget"
        $installerPath = "$env:TEMP\AppInstaller.msixbundle"

        try {
            Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath
            Write-Host "Downloaded winget installer."
            Add-AppxPackage -Path $installerPath
            Write-Host "winget installation completed."
        } catch {
            Write-Host "Failed to download or install winget. Please try again."
            Write-Host $_.Exception.Message
            Pause
            return
        }
    } else {
        Write-Host "winget is already installed."
    }

    $Form = New-Object System.Windows.Forms.Form
    $Form.Text = "Install Software | AetherKit by catsmoker"
    $Form.Size = New-Object System.Drawing.Size(500, 650)
    $Form.StartPosition = "CenterScreen"
    $Form.BackColor = [System.Drawing.Color]::FromArgb(18, 18, 22)
    $Form.FormBorderStyle = 'FixedDialog'
    $Form.MaximizeBox = $false
    $Form.Font = New-Object System.Drawing.Font("Segoe UI", 10)

    $Label = New-Object System.Windows.Forms.Label
    $Label.Location = New-Object System.Drawing.Size(20, 20)
    $Label.Size = New-Object System.Drawing.Size(460, 30)
    $Label.Text = "Select software to install:"
    $Label.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
    $Label.ForeColor = [System.Drawing.Color]::FromArgb(200, 200, 200)
    $Form.Controls.Add($Label)

    $Panel = New-Object System.Windows.Forms.Panel
    $Panel.Location = New-Object System.Drawing.Size(20, 60)
    $Panel.Size = New-Object System.Drawing.Size(460, 450)
    $Panel.AutoScroll = $true
    $Panel.BorderStyle = 'FixedSingle'
    $Panel.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 40)
    $Form.Controls.Add($Panel)

    $softwareItems = @{
        "Ungoogled Chromium" = "eloston.ungoogled-chromium"
        "Mozilla Firefox" = "Mozilla.Firefox"
        "Waterfox" = "Waterfox.Waterfox"
        "Brave Browser" = "Brave.Brave"
        "Google Chrome" = "Google.Chrome"
        "LibreWolf" = "LibreWolf.LibreWolf"
        "Tor Browser" = "TorProject.TorBrowser"
        "Discord" = "Discord.Discord"
        "Discord Canary" = "Discord.Discord.Canary"
        "Steam" = "Valve.Steam"
        "Playnite" = "Playnite.Playnite"
        "Heroic" = "HeroicGamesLauncher.HeroicGamesLauncher"
        "Everything" = "voidtools.Everything"
        "Mozilla Thunderbird" = "Mozilla.Thunderbird"
        "foobar2000" = "PeterPawlowski.foobar2000"
        "IrfanView" = "IrfanSkiljan.IrfanView"
        "Git" = "Git.Git"
        "VLC" = "VideoLAN.VLC"
        "PuTTY" = "PuTTY.PuTTY"
        "Ditto" = "Ditto.Ditto"
        "7-Zip" = "7zip.7zip"
        "Teamspeak" = "TeamSpeakSystems.TeamSpeakClient"
        "Spotify" = "Spotify.Spotify"
        "OBS Studio" = "OBSProject.OBSStudio"
        "MSI Afterburner" = "Guru3D.Afterburner"
        "CPU-Z" = "CPUID.CPU-Z"
        "GPU-Z" = "TechPowerUp.GPU-Z"
        "Notepad++" = "Notepad++.Notepad++"
        "VSCode" = "Microsoft.VisualStudioCode"
        "VSCodium" = "VSCodium.VSCodium"
        "BCUninstaller" = "Klocman.BulkCrapUninstaller"
        "HWiNFO" = "REALiX.HWiNFO"
        "Lightshot" = "Skillbrains.Lightshot"
        "ShareX" = "ShareX.ShareX"
        "Snipping Tool" = "9MZ95KL8MR0L"
        "ExplorerPatcher" = "valinet.ExplorerPatcher"
        "MemReduct" = "Henry++.MemReduct"
    }

    $y = 10
    foreach ($name in $softwareItems.Keys) {
        $checkbox = New-Object System.Windows.Forms.CheckBox
        $checkbox.Location = New-Object System.Drawing.Size(10, $y)
        $checkbox.Size = New-Object System.Drawing.Size(440, 25)
        $checkbox.Text = $name
        $checkbox.Name = $softwareItems[$name]
        $checkbox.ForeColor = [System.Drawing.Color]::White
        $checkbox.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 40)
        $checkbox.Font = New-Object System.Drawing.Font("Segoe UI", 10)
        $Panel.Controls.Add($checkbox)
        $y += 30
    }

    $InstallButton = Create-Button -Text "Install" -X 200 -Y 530 -ClickAction {
        $checkedBoxes = $Panel.Controls | Where-Object { $_ -is [System.Windows.Forms.CheckBox] -and $_.Checked }
        if ($checkedBoxes.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show("Please select at least one software package to install.", "No package selected", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        } else {
            Start-Process "winget" -ArgumentList "upgrade --all" -NoNewWindow -Wait
            $installPackages = $checkedBoxes | ForEach-Object { $_.Name }
            foreach ($package in $installPackages) {
                Start-Process "winget" -ArgumentList "install -e --id $package --accept-package-agreements --accept-source-agreements --disable-interactivity --force" -NoNewWindow
            }
            [System.Windows.Forms.MessageBox]::Show("Installation started. Please wait for the processes to complete.", "Installation Started", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        }
    } -TooltipText "Install selected software packages."
    $Form.Controls.Add($InstallButton)

    [void] $Form.ShowDialog()
    $statusLabel.Text = "Ready"
}

Function ActivateWindows {
    Clear-Host
    $statusLabel.Text = "Activating Windows..."
    $progressBar.Value = 0
    Start-Process "powershell" -ArgumentList "irm https://get.activated.win | iex"
    $progressBar.Value = 100
    $statusLabel.Text = "Windows activated!"
}

Function ActivateOffice {
    Clear-Host
    $statusLabel.Text = "Activating Microsoft Office..."
    $progressBar.Value = 0
    Start-Process "powershell" -ArgumentList "irm https://officerator.github.io/ | iex"
    $progressBar.Value = 100
    $statusLabel.Text = "Microsoft Office activated!"
}

Function ActivateIDM {
    Clear-Host
    $statusLabel.Text = "Activating IDM..."
    $progressBar.Value = 0
    Start-Process "powershell" -ArgumentList "irm https://coporton.com/ias | iex"
    $progressBar.Value = 100
    $statusLabel.Text = "IDM activated!"
}

Function windowsps {
    Clear-Host
    $statusLabel.Text = "Windows Update..."
    $progressBar.Value = 0
    Install-Module PSWindowsUpdate -Force
    Add-WUServiceManager -MicrosoftUpdate
    Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot | Out-File "C:\($env.computername-Get-Date -f 'yyyy-MM-dd')-MSUpdates.log" -Force
    $progressBar.Value = 100
    $statusLabel.Text = "Windows Update completed!"
}

Function CTT {
    Clear-Host
    $statusLabel.Text = "CTT Windows Utility..."
    $progressBar.Value = 0
    Start-Process "powershell" -ArgumentList "iwr -useb https://christitus.com/win | iex"
    $progressBar.Value = 100
    $statusLabel.Text = "CTT completed!"
}

Function ScanWithMRT {
    Clear-Host
    $statusLabel.Text = "Scanning with Windows Malicious Software Removal Tool..."
    $progressBar.Value = 0

    $mrtPath = "C:\Windows\System32\MRT.exe"
    
    if (Test-Path $mrtPath) {
        Write-Host "Starting MRT scan..."
        Start-Process -FilePath $mrtPath -Wait
        $progressBar.Value = 100
        $statusLabel.Text = "MRT scan completed!"
        Write-Host "MRT scan finished."
    } else {
        Write-Host "MRT.exe not found. Attempting to download..." -ForegroundColor Yellow
        $statusLabel.Text = "MRT.exe not found. Downloading..."

        try {
            # Direct download link for MRT
            $mrtUrl = "https://go.microsoft.com/fwlink/?LinkID=212732"
            $tempPath = "$env:TEMP\mrt.exe"

            Write-Host "Downloading MRT from Microsoft..."
            Invoke-WebRequest -Uri $mrtUrl -OutFile $tempPath -UseBasicParsing
            Write-Host "MRT downloaded successfully to $tempPath"

            Move-Item -Path $tempPath -Destination $mrtPath -Force -ErrorAction SilentlyContinue
            if (Test-Path $mrtPath) {
                Write-Host "MRT moved to $mrtPath"
                Start-Process -FilePath $mrtPath -ArgumentList "/Q" -NoNewWindow -Wait
                $progressBar.Value = 100
                $statusLabel.Text = "MRT downloaded and scan completed!"
                Write-Host "MRT scan finished."
            } else {
                Write-Host "Failed to move MRT to System32. Running from temp location..."
                Start-Process -FilePath $tempPath -ArgumentList "/Q" -NoNewWindow -Wait
                $progressBar.Value = 100
                $statusLabel.Text = "MRT scan completed from temp location!"
                Write-Host "MRT scan finished from temp location."
            }
        } catch {
            $statusLabel.Text = "Failed to download/run MRT!"
            Write-Host "Error downloading or running MRT: $_" -ForegroundColor Red
            $progressBar.Value = 0
        }
    }
}

Function NetworkTools {
    $netForm = New-Object System.Windows.Forms.Form
    $netForm.Text = "Network Tools | AetherKit"
    $netForm.Size = New-Object System.Drawing.Size(480, 380)
    $netForm.StartPosition = "CenterScreen"
    $netForm.BackColor = [System.Drawing.Color]::FromArgb(25, 25, 30)
    $netForm.ForeColor = [System.Drawing.Color]::White
    $netForm.FormBorderStyle = 'FixedDialog'
    $netForm.MaximizeBox = $false
    
    # Header
    $headerLabel = New-Object System.Windows.Forms.Label
    $headerLabel.Text = "Network Configuration Tools"
    $headerLabel.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
    $headerLabel.Size = New-Object System.Drawing.Size(440, 30)
    $headerLabel.Location = New-Object System.Drawing.Point(20, 15)
    $headerLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
    $netForm.Controls.Add($headerLabel)
    
    # Buttons with consistent spacing
    $dnsGoogle = Create-ToolButton -Text "Google DNS" -X 30 -Y 60 -ClickAction {
        Set-DNS -Primary "8.8.8.8" -Secondary "8.8.4.4"
    } -TooltipText "Set DNS to Google (8.8.8.8 and 8.8.4.4)"
    $netForm.Controls.Add($dnsGoogle)
    
    $dnsCloudflare = Create-ToolButton -Text "Cloudflare DNS" -X 250 -Y 60 -ClickAction {
        Set-DNS -Primary "1.1.1.1" -Secondary "1.0.0.1"
    } -TooltipText "Set DNS to Cloudflare (1.1.1.1 and 1.0.0.1)"
    $netForm.Controls.Add($dnsCloudflare)
    
    $dnsReset = Create-ToolButton -Text "Reset to DHCP" -X 30 -Y 110 -ClickAction {
        Reset-DNS
    } -TooltipText "Reset DNS to automatic (DHCP)"
    $netForm.Controls.Add($dnsReset)
    
    $netInfo = Create-ToolButton -Text "Network Info" -X 250 -Y 110 -ClickAction {
        ipconfig /all | Out-GridView -Title "Network Information"
    } -TooltipText "Display detailed network configuration"
    $netForm.Controls.Add($netInfo)
    
    $netReset = Create-ToolButton -Text "Reset Adapters" -X 30 -Y 160 -ClickAction {
        Reset-NetworkAdapters
    } -TooltipText "Restart all network adapters"
    $netForm.Controls.Add($netReset)
    
    $flushDNS = Create-ToolButton -Text "Flush DNS" -X 250 -Y 160 -ClickAction {
        ipconfig /flushdns
        [System.Windows.Forms.MessageBox]::Show("DNS cache has been flushed", "DNS Flushed")
    } -TooltipText "Clear DNS resolver cache"
    $netForm.Controls.Add($flushDNS)
    
    $ipRenew = Create-ToolButton -Text "Renew IP" -X 30 -Y 210 -ClickAction {
        ipconfig /release
        ipconfig /renew
        [System.Windows.Forms.MessageBox]::Show("IP address has been renewed", "IP Renewed")
    } -TooltipText "Release and renew IP address"
    $netForm.Controls.Add($ipRenew)
    
    $winsockReset = Create-ToolButton -Text "Reset Winsock" -X 250 -Y 210 -ClickAction {
        netsh winsock reset
        [System.Windows.Forms.MessageBox]::Show("Winsock catalog has been reset. Reboot recommended.", "Winsock Reset")
    } -TooltipText "Reset Winsock catalog to default"
    $netForm.Controls.Add($winsockReset)
    
    $closeButton = Create-ToolButton -Text "Close" -X 180 -Y 270 -ClickAction { $netForm.Close() } -TooltipText "Close this window"
    $netForm.Controls.Add($closeButton)
    
    [void]$netForm.ShowDialog()
}

Function Set-DNS {
    param($Primary, $Secondary)
    
    $statusLabel.Text = "Setting DNS servers..."
    $progressBar.Value = 0
    
    try {
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        $count = 0
        foreach ($adapter in $adapters) {
            $count++
            $progressBar.Value = ($count / $adapters.Count) * 100
            Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses $Primary,$Secondary
        }
        $progressBar.Value = 100
        [System.Windows.Forms.MessageBox]::Show("DNS set to $Primary/$Secondary", "DNS Updated")
        $statusLabel.Text = "DNS configuration updated"
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to set DNS: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        $statusLabel.Text = "DNS configuration failed"
    }
}

Function Reset-DNS {
    $statusLabel.Text = "Resetting DNS to DHCP..."
    $progressBar.Value = 0
    
    try {
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        $count = 0
        foreach ($adapter in $adapters) {
            $count++
            $progressBar.Value = ($count / $adapters.Count) * 100
            Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ResetServerAddresses
        }
        $progressBar.Value = 100
        [System.Windows.Forms.MessageBox]::Show("DNS reset to DHCP", "DNS Reset")
        $statusLabel.Text = "DNS reset completed"
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to reset DNS: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        $statusLabel.Text = "DNS reset failed"
    }
}

Function Reset-NetworkAdapters {
    $statusLabel.Text = "Resetting network adapters..."
    $progressBar.Value = 0
    
    try {
        $adapters = Get-NetAdapter
        $count = 0
        foreach ($adapter in $adapters) {
            $count++
            $progressBar.Value = ($count / $adapters.Count) * 100
            Disable-NetAdapter -Name $adapter.Name -Confirm:$false
            Enable-NetAdapter -Name $adapter.Name -Confirm:$false
        }
        $progressBar.Value = 100
        [System.Windows.Forms.MessageBox]::Show("Network adapters reset", "Reset Complete")
        $statusLabel.Text = "Network adapters reset"
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to reset adapters: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        $statusLabel.Text = "Adapter reset failed"
    }
}

Function RegistryTools {
    $regForm = New-Object System.Windows.Forms.Form
    $regForm.Text = "Registry Tools | AetherKit"
    $regForm.Size = New-Object System.Drawing.Size(480, 300)
    $regForm.StartPosition = "CenterScreen"
    $regForm.BackColor = [System.Drawing.Color]::FromArgb(25, 25, 30)
    $regForm.ForeColor = [System.Drawing.Color]::White
    $regForm.FormBorderStyle = 'FixedDialog'
    $regForm.MaximizeBox = $false
    
    # Header
    $headerLabel = New-Object System.Windows.Forms.Label
    $headerLabel.Text = "Registry Management Tools"
    $headerLabel.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
    $headerLabel.Size = New-Object System.Drawing.Size(440, 30)
    $headerLabel.Location = New-Object System.Drawing.Point(20, 15)
    $headerLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
    $regForm.Controls.Add($headerLabel)
    
    # Buttons with consistent spacing
    $cleanReg = Create-ToolButton -Text "Clean Registry" -X 30 -Y 60 -ClickAction {
        Clean-Registry
    } -TooltipText "Perform safe registry cleaning"
    $regForm.Controls.Add($cleanReg)
    
    $backupReg = Create-ToolButton -Text "Backup Registry" -X 250 -Y 60 -ClickAction {
        Backup-Registry
    } -TooltipText "Create a full registry backup"
    $regForm.Controls.Add($backupReg)
    
    $restoreReg = Create-ToolButton -Text "Restore Registry" -X 30 -Y 110 -ClickAction {
        Restore-Registry
    } -TooltipText "Restore registry from backup"
    $regForm.Controls.Add($restoreReg)
    
    $regOptimize = Create-ToolButton -Text "Optimize Registry" -X 250 -Y 110 -ClickAction {
        Optimize-Registry
    } -TooltipText "Optimize registry performance"
    $regForm.Controls.Add($regOptimize)
    
    $closeButton = Create-ToolButton -Text "Close" -X 180 -Y 170 -ClickAction { $regForm.Close() } -TooltipText "Close this window"
    $regForm.Controls.Add($closeButton)
    
    [void]$regForm.ShowDialog()
}

Function Clean-Registry {
    $statusLabel.Text = "Cleaning registry..."
    $progressBar.Value = 0
    
    try {
        # Safe registry cleaning operations
        $tempKeys = @(
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU"
        )
        
        $count = 0
        foreach ($key in $tempKeys) {
            $count++
            $progressBar.Value = ($count / $tempKeys.Count) * 100
            if (Test-Path $key) {
                Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue
                New-Item -Path $key -Force | Out-Null
            }
        }
        
        $progressBar.Value = 100
        [System.Windows.Forms.MessageBox]::Show("Registry cleaned", "Complete")
        $statusLabel.Text = "Registry cleaning completed"
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to clean registry: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        $statusLabel.Text = "Registry cleaning failed"
    }
}

Function Backup-Registry {
    $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveFileDialog.Filter = "Registry Files (*.reg)|*.reg"
    $saveFileDialog.FileName = "RegistryBackup_$(Get-Date -Format 'yyyyMMdd').reg"
    $saveFileDialog.InitialDirectory = [Environment]::GetFolderPath("Desktop")
    
    if ($saveFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $statusLabel.Text = "Backing up registry..."
        $progressBar.Value = 0
        
        try {
            reg export HKLM $saveFileDialog.FileName
            $progressBar.Value = 50
            reg export HKCU $saveFileDialog.FileName /y
            $progressBar.Value = 100
            
            [System.Windows.Forms.MessageBox]::Show("Registry backup saved to $($saveFileDialog.FileName)", "Backup Complete")
            $statusLabel.Text = "Registry backup completed"
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Failed to backup registry: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            $statusLabel.Text = "Registry backup failed"
        }
    }
}

Function Restore-Registry {
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Filter = "Registry Files (*.reg)|*.reg"
    $openFileDialog.InitialDirectory = [Environment]::GetFolderPath("Desktop")
    
    if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $statusLabel.Text = "Restoring registry..."
        $progressBar.Value = 0
        
        try {
            reg import $openFileDialog.FileName
            $progressBar.Value = 100
            
            [System.Windows.Forms.MessageBox]::Show("Registry restored from $($openFileDialog.FileName). Reboot recommended.", "Restore Complete")
            $statusLabel.Text = "Registry restore completed"
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Failed to restore registry: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            $statusLabel.Text = "Registry restore failed"
        }
    }
}

Function Optimize-Registry {
    $statusLabel.Text = "Optimizing registry..."
    $progressBar.Value = 0
    
    try {
        # Disable NTFS last access time updates
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "NtfsDisableLastAccessUpdate" -Value 1
        $progressBar.Value = 25
        
        # Enable large system cache
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "LargeSystemCache" -Value 1
        $progressBar.Value = 50
        
        # Disable paging executive
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePagingExecutive" -Value 1
        $progressBar.Value = 75
        
        # Set I/O page lock limit
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "IoPageLockLimit" -Type DWord -Value 0x10000000
        $progressBar.Value = 100
        
        [System.Windows.Forms.MessageBox]::Show("Registry optimization complete. Reboot recommended.", "Optimization Complete")
        $statusLabel.Text = "Registry optimization completed"
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to optimize registry: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        $statusLabel.Text = "Registry optimization failed"
    }
}

Function SystemReport {
    $statusLabel.Text = "Generating system report..."
    $progressBar.Value = 0
    
    $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveFileDialog.Filter = "Text Files (*.txt)|*.txt"
    $saveFileDialog.FileName = "SystemReport_$(Get-Date -Format 'yyyyMMdd').txt"
    $saveFileDialog.InitialDirectory = [Environment]::GetFolderPath("Desktop")
    
    if ($saveFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        try {
            # System Information
            "=== SYSTEM INFORMATION ===" | Out-File $saveFileDialog.FileName
            systeminfo | Out-File $saveFileDialog.FileName -Append
            $progressBar.Value = 20
            
            # Network Information
            "`n=== NETWORK INFORMATION ===" | Out-File $saveFileDialog.FileName -Append
            ipconfig /all | Out-File $saveFileDialog.FileName -Append
            $progressBar.Value = 40
            
            # Installed Programs
            "`n=== INSTALLED PROGRAMS ===" | Out-File $saveFileDialog.FileName -Append
            Get-WmiObject -Class Win32_Product | Select-Object Name, Version | Out-File $saveFileDialog.FileName -Append
            $progressBar.Value = 60
            
            # Running Services
            "`n=== RUNNING SERVICES ===" | Out-File $saveFileDialog.FileName -Append
            Get-Service | Where-Object { $_.Status -eq "Running" } | Select-Object DisplayName, Status | Out-File $saveFileDialog.FileName -Append
            $progressBar.Value = 80
            
            # Disk Information
            "`n=== DISK INFORMATION ===" | Out-File $saveFileDialog.FileName -Append
            Get-PhysicalDisk | Select-Object FriendlyName, Size, HealthStatus | Out-File $saveFileDialog.FileName -Append
            $progressBar.Value = 100
            
            [System.Windows.Forms.MessageBox]::Show("System report generated at $($saveFileDialog.FileName)", "Report Complete")
            $statusLabel.Text = "System report generated"
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Failed to generate system report: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            $statusLabel.Text = "System report failed"
        }
    }
}

Function PowerTools {
    $toolsForm = New-Object System.Windows.Forms.Form
    $toolsForm.Text = "Power Tools | AetherKit"
    $toolsForm.Size = New-Object System.Drawing.Size(480, 380)
    $toolsForm.StartPosition = "CenterScreen"
    $toolsForm.BackColor = [System.Drawing.Color]::FromArgb(25, 25, 30)
    $toolsForm.ForeColor = [System.Drawing.Color]::White
    $toolsForm.FormBorderStyle = 'FixedDialog'
    $toolsForm.MaximizeBox = $false
    
    # Header
    $headerLabel = New-Object System.Windows.Forms.Label
    $headerLabel.Text = "Advanced System Tools"
    $headerLabel.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
    $headerLabel.Size = New-Object System.Drawing.Size(440, 30)
    $headerLabel.Location = New-Object System.Drawing.Point(20, 15)
    $headerLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
    $toolsForm.Controls.Add($headerLabel)
    
    # Buttons with consistent spacing
    $disableUpdates = Create-ToolButton -Text "Disable Updates" -X 30 -Y 60 -ClickAction {
        $statusLabel.Text = "Disabling Windows Updates..."
        Set-Service -Name wuauserv -StartupType Disabled
        Stop-Service -Name wuauserv -Force
        [System.Windows.Forms.MessageBox]::Show("Windows Update service disabled", "Complete")
        $statusLabel.Text = "Windows Updates disabled"
    } -TooltipText "Disable Windows automatic updates"
    $toolsForm.Controls.Add($disableUpdates)
    
    $enableUpdates = Create-ToolButton -Text "Enable Updates" -X 250 -Y 60 -ClickAction {
        $statusLabel.Text = "Enabling Windows Updates..."
        Set-Service -Name wuauserv -StartupType Automatic
        Start-Service -Name wuauserv
        [System.Windows.Forms.MessageBox]::Show("Windows Update service enabled", "Complete")
        $statusLabel.Text = "Windows Updates enabled"
    } -TooltipText "Enable Windows automatic updates"
    $toolsForm.Controls.Add($enableUpdates)
    
    $disableDefender = Create-ToolButton -Text "Disable Defender" -X 30 -Y 110 -ClickAction {
        $statusLabel.Text = "Disabling Windows Defender..."
        Set-MpPreference -DisableRealtimeMonitoring $true
        [System.Windows.Forms.MessageBox]::Show("Windows Defender real-time protection disabled", "Complete")
        $statusLabel.Text = "Windows Defender disabled"
    } -TooltipText "Disable Windows Defender temporarily"
    $toolsForm.Controls.Add($disableDefender)
    
    $enableDefender = Create-ToolButton -Text "Enable Defender" -X 250 -Y 110 -ClickAction {
        $statusLabel.Text = "Enabling Windows Defender..."
        Set-MpPreference -DisableRealtimeMonitoring $false
        [System.Windows.Forms.MessageBox]::Show("Windows Defender real-time protection enabled", "Complete")
        $statusLabel.Text = "Windows Defender enabled"
    } -TooltipText "Enable Windows Defender"
    $toolsForm.Controls.Add($enableDefender)
    
    $disableTelemetry = Create-ToolButton -Text "Disable Telemetry" -X 30 -Y 160 -ClickAction {
        $statusLabel.Text = "Disabling telemetry..."
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0
        [System.Windows.Forms.MessageBox]::Show("Telemetry disabled", "Complete")
        $statusLabel.Text = "Telemetry disabled"
    } -TooltipText "Disable Windows telemetry"
    $toolsForm.Controls.Add($disableTelemetry)
    
    $repairStartMenu = Create-ToolButton -Text "Repair Start Menu" -X 250 -Y 160 -ClickAction {
        $statusLabel.Text = "Repairing Start Menu..."
        Get-AppXPackage -AllUsers | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
        [System.Windows.Forms.MessageBox]::Show("Start Menu repaired", "Complete")
        $statusLabel.Text = "Start Menu repaired"
    } -TooltipText "Fix Start Menu and taskbar issues"
    $toolsForm.Controls.Add($repairStartMenu)
    
    $closeButton = Create-ToolButton -Text "Close" -X 180 -Y 220 -ClickAction { $toolsForm.Close() } -TooltipText "Close this window"
    $toolsForm.Controls.Add($closeButton)
    
    [void]$toolsForm.ShowDialog()
}

Function Exit-Script {
    Clear-Host
    Write-Host "Exiting script. Opening developer's website..."
    Start-Process "https://catsmoker.github.io"
    $mainForm.Close()
}

# Display the main form
[void]$mainForm.ShowDialog()

#==================================================================================================
#
# WARNING: DO NOT modify this file!
#
#==================================================================================================
<#
.NOTES
    Author         : catsmoker
    Email          : catsmoker.lab@gmail.com
    Website        : https://catsmoker.github.io
    GitHub         : https://github.com/catsmoker/cs_script
    Version        : 1.9
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
$mainForm.Text = "CS Script v1.9 by catsmoker"
$mainForm.Size = New-Object System.Drawing.Size(900, 600)
$mainForm.StartPosition = "CenterScreen"
$mainForm.BackColor = [System.Drawing.Color]::FromArgb(18, 18, 22) # Darker modern background
$mainForm.ForeColor = [System.Drawing.Color]::White
$mainForm.FormBorderStyle = 'FixedDialog'
$mainForm.MaximizeBox = $false
$mainForm.Font = New-Object System.Drawing.Font("Segoe UI", 10)

# Title Label
$titleLabel = New-Object System.Windows.Forms.Label
$titleLabel.Text = "CS Script v1.9"
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

# Menu Buttons (arranged in a grid)
$buttonClean = Create-Button -Text "Clean Windows" -X 50 -Y 120 -ClickAction { CleanWindows } -TooltipText "Cleans temporary files, Recycle Bin, and DNS cache."
$mainForm.Controls.Add($buttonClean)

$buttonFix = Create-Button -Text "Scan and Fix Windows" -X 330 -Y 120 -ClickAction { FixWindows } -TooltipText "Runs chkdsk, sfc, and DISM to repair Windows."
$mainForm.Controls.Add($buttonFix)

$buttonApps = Create-Button -Text "Apps/Upgrades" -X 610 -Y 120 -ClickAction { DownloadApps } -TooltipText "Install or upgrade software using winget."
$mainForm.Controls.Add($buttonApps)

$buttonActivateIDM = Create-Button -Text "Activate IDM" -X 50 -Y 190 -ClickAction { ActivateIDM } -TooltipText "Activates Internet Download Manager."
$mainForm.Controls.Add($buttonActivateIDM)

$buttonActivateWindows = Create-Button -Text "Activate Windows/office" -X 330 -Y 190 -ClickAction { ActivateWindows } -TooltipText "Activates Windows using an external script."
$mainForm.Controls.Add($buttonActivateWindows)

$buttonAtlas = Create-Button -Text "Windows Update" -X 610 -Y 190 -ClickAction { windowsps } -TooltipText "Installs Windows updates via PSWindowsUpdate."
$mainForm.Controls.Add($buttonAtlas)

$buttonCTT = Create-Button -Text "CTT Windows Utility" -X 50 -Y 260 -ClickAction { CTT } -TooltipText "Runs Chris Titus Tech's Windows Utility."
$mainForm.Controls.Add($buttonCTT)

$buttonMRT = Create-Button -Text "Virus Scan" -X 330 -Y 260 -ClickAction { ScanWithMRT } -TooltipText "Runs Windows Malicious Software Removal Tool."
$mainForm.Controls.Add($buttonMRT)

$buttonAddShortcut = Create-Button -Text "Add Shortcut" -X 330 -Y 330 -ClickAction { AddShortcut } -TooltipText "Adds a Shortcut."
$mainForm.Controls.Add($buttonAddShortcut)

$buttonExit = Create-Button -Text "Exit" -X 610 -Y 260 -ClickAction { Exit-Script } -TooltipText "Exits the script and opens the developer's website."
$mainForm.Controls.Add($buttonExit)

# Progress Bar
$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Size = New-Object System.Drawing.Size(800, 20)
$progressBar.Location = New-Object System.Drawing.Point(50, 450)
$progressBar.Style = 'Continuous'
$progressBar.ForeColor = [System.Drawing.Color]::FromArgb(100, 200, 100)
$progressBar.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 40)
$mainForm.Controls.Add($progressBar)

# Status Label
$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Text = "Ready"
$statusLabel.Size = New-Object System.Drawing.Size(800, 20)
$statusLabel.Location = New-Object System.Drawing.Point(50, 480)
$statusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$statusLabel.ForeColor = [System.Drawing.Color]::FromArgb(150, 150, 150)
$mainForm.Controls.Add($statusLabel)

# Functions
Function CleanWindows {
    Clear-Host
    $statusLabel.Text = "Cleaning Windows..."
    $progressBar.Value = 0

    # Clean Global Temp Folder
    $globalTempPath = [System.IO.Path]::GetTempPath()
    Write-Host "Clearing global temp folder: $globalTempPath"
    $globalFiles = Get-ChildItem -Path $globalTempPath -Recurse -Force -ErrorAction SilentlyContinue
    $count = 0
    foreach ($file in $globalFiles) {
        $count++
        $progressBar.Value = ($count / $globalFiles.Count) * 100
        Remove-Item -Path $file.FullName -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Clean User Temp Folder
    $userTempPath = $env:TEMP
    Write-Host "Clearing user temp folder: $userTempPath"
    $userFiles = Get-ChildItem -Path $userTempPath -Recurse -Force -ErrorAction SilentlyContinue
    $count = 0
    foreach ($file in $userFiles) {
        $count++
        $progressBar.Value = ($count / $userFiles.Count) * 100
        Remove-Item -Path $file.FullName -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Delete temp files
    Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\Windows\Prefetch\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue

    # Clean Recycle Bin
    Write-Host "Emptying Recycle Bin..."
    $null = (New-Object -ComObject Shell.Application).NameSpace(0xA).Items() | ForEach-Object { $_.InvokeVerb("delete") }

    # Flush DNS Cache
    Write-Host "Flushing DNS Cache..."
    ipconfig /flushdns

    # Clear all event logs
    Get-WinEvent -ListLog * | ForEach-Object {
    Write-Output "Clearing $($_.LogName)"
    wevtutil cl "$($_.LogName)"
    }

    $progressBar.Value = 100
    $statusLabel.Text = "Cleanup completed!"
}

Function AddShortcut {
$fileName = "CS_script.lnk"
$desktopPath = [Environment]::GetFolderPath("Desktop")
$filePath = Join-Path -Path $desktopPath -ChildPath $fileName

if (Test-Path -Path $filePath -PathType Leaf) {
# Message
    Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.MessageBox]::Show(
    "Shortcut already installed $shortcutPath", 
    "Installation Complete", 
    [System.Windows.Forms.MessageBoxButtons]::OK, 
    [System.Windows.Forms.MessageBoxIcon]::Information
)
Write-Host "Shortcut already installed $shortcutPath" -ForegroundColor Green

} else {
    Write-Host "File not found on desktop."
# Define the path to the shortcut and the target PowerShell command
$shortcutPath = [System.IO.Path]::Combine([System.Environment]::GetFolderPath('Desktop'), 'CS_script.lnk')
$targetPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
$arguments = '-NoProfile -ExecutionPolicy Bypass -Command "irm https://catsmoker.github.io/w | iex"'

# Define the URL for the icon and the path to save it locally
$iconUrl = "https://catsmoker.github.io/web/assets/ico/favicon.ico"
$localIconPath = "$env:TEMP\favicon.ico"

# Download the icon
Invoke-WebRequest -Uri $iconUrl -OutFile $localIconPath -UseBasicParsing

# Create the shortcut
$wshShell = New-Object -ComObject WScript.Shell
$shortcut = $wshShell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $targetPath
$shortcut.Arguments = $arguments
$shortcut.WorkingDirectory = [System.IO.Path]::GetDirectoryName($targetPath)
$shortcut.IconLocation = $localIconPath
$shortcut.Save()

# Open the shortcut properties and try to trigger 'Run as administrator'
$shell = New-Object -ComObject Shell.Application
$folder = $shell.Namespace([System.IO.Path]::GetDirectoryName($shortcutPath))
$item = $folder.ParseName([System.IO.Path]::GetFileName($shortcutPath))

# Launch Properties dialog and send keys
$item.InvokeVerb("Properties")
Start-Sleep -Milliseconds 1500
[System.Windows.Forms.SendKeys]::SendWait("%d")         # ALT+D: open Advanced
Start-Sleep -Milliseconds 500
[System.Windows.Forms.SendKeys]::SendWait(" ")          # SPACE: check the box
Start-Sleep -Milliseconds 200
[System.Windows.Forms.SendKeys]::SendWait("{ENTER}")    # ENTER: close Advanced
Start-Sleep -Milliseconds 200
[System.Windows.Forms.SendKeys]::SendWait("{ENTER}")    # ENTER: close Properties
# Message
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.MessageBox]::Show(
    "Shortcut created successfully $shortcutPath", 
    "Installation Complete", 
    [System.Windows.Forms.MessageBoxButtons]::OK, 
    [System.Windows.Forms.MessageBoxIcon]::Information
)
Write-Host "Shortcut created successfully $shortcutPath" -ForegroundColor Green
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
    # Check if winget is installed
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Host "winget is not installed. Attempting to install..."

        # Download the latest version of the App Installer from the Microsoft Store
        $installerUrl = "https://aka.ms/getwinget"
        
        # Define the path for the installer
        $installerPath = "$env:TEMP\AppInstaller.msixbundle"

        # Download the installer
        try {
            Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath
            Write-Host "Downloaded winget installer."

            # Install the downloaded package
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

    # Create the main form for apps
    $Form = New-Object System.Windows.Forms.Form
    $Form.Text = "Install Software | cs_script by catsmoker"
    $Form.Size = New-Object System.Drawing.Size(500, 650)
    $Form.StartPosition = "CenterScreen"
    $Form.BackColor = [System.Drawing.Color]::FromArgb(18, 18, 22)
    $Form.FormBorderStyle = 'FixedDialog'
    $Form.MaximizeBox = $false
    $Form.Font = New-Object System.Drawing.Font("Segoe UI", 10)

    # Create a label
    $Label = New-Object System.Windows.Forms.Label
    $Label.Location = New-Object System.Drawing.Size(20, 20)
    $Label.Size = New-Object System.Drawing.Size(460, 30)
    $Label.Text = "Select software to install:"
    $Label.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
    $Label.ForeColor = [System.Drawing.Color]::FromArgb(200, 200, 200)
    $Form.Controls.Add($Label)

    # Create a Panel to hold the checkboxes
    $Panel = New-Object System.Windows.Forms.Panel
    $Panel.Location = New-Object System.Drawing.Size(20, 60)
    $Panel.Size = New-Object System.Drawing.Size(460, 450)
    $Panel.AutoScroll = $true
    $Panel.BorderStyle = 'FixedSingle'
    $Panel.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 40)
    $Form.Controls.Add($Panel)

    # Create a list of software items
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

    # Add checkboxes for each software item
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

    # Create Install button
    $InstallButton = Create-Button -Text "Install" -X 200 -Y 530 -ClickAction {
        $checkedBoxes = $Panel.Controls | Where-Object { $_ -is [System.Windows.Forms.CheckBox] -and $_.Checked }
        if ($checkedBoxes.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show("Please select at least one software package to install.", "No package selected", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        } else {
            # Run the upgrade command first
            Start-Process "winget" -ArgumentList "upgrade --all" -NoNewWindow -Wait

            $installPackages = $checkedBoxes | ForEach-Object { $_.Name }

            # Run the installation commands
            foreach ($package in $installPackages) {
                Start-Process "winget" -ArgumentList "install -e --id $package --accept-package-agreements --accept-source-agreements --disable-interactivity --force" -NoNewWindow
            }

            [System.Windows.Forms.MessageBox]::Show("Installation started. Please wait for the processes to complete.", "Installation Started", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        }
    } -TooltipText "Install selected software packages."
    $Form.Controls.Add($InstallButton)

    # Show the form
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
    Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot | Out-File "C:\($env.computername-Get-Date -f yyyy-MM-dd)-MSUpdates.log" -Force
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

    # Path to MRT.exe
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
            # URL for the latest MRT (Windows Malicious Software Removal Tool) from Microsoft
            $mrtUrl = "https://www.microsoft.com/en-us/download/confirmation.aspx?id=16"
            $tempPath = "$env:TEMP\mrt.exe"

            # Download MRT
            Write-Host "Downloading MRT from Microsoft..."
            $response = Invoke-WebRequest -Uri $mrtUrl -UseBasicParsing
            $downloadLink = ($response.Links | Where-Object { $_.href -match "mrt.exe" } | Select-Object -First 1).href
            
            if ($downloadLink) {
                Invoke-WebRequest -Uri $downloadLink -OutFile $tempPath
                Write-Host "MRT downloaded successfully to $tempPath"

                # Move to System32 if possible
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
            } else {
                throw "Could not find MRT download link."
            }
        } catch {
            $statusLabel.Text = "Failed to download/run MRT!"
            Write-Host "Error downloading or running MRT: $_" -ForegroundColor Red
            $progressBar.Value = 0
        }
    }
}

Function Exit-Script {
    Clear-Host
    Start-Process "https://catsmoker.github.io"
    $mainForm.Close()
}

# Show the Main Form
[void]$mainForm.ShowDialog()

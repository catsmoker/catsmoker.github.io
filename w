#============================================================================
#
# WARNING: DO NOT modify this file!
#
#============================================================================
<#
.NOTES
    Author         : catsmoker
    Email          : catsmoker.lab@gmail.com
    Website        : https://catsmoker.github.io
    GitHub         : https://github.com/catsmoker/cs_script
    Version        : 1.8
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

# Define the path to the shortcut and the target PowerShell command
$shortcutPath = [System.IO.Path]::Combine([System.Environment]::GetFolderPath('Desktop'), 'CS_script.lnk')
$targetPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
$arguments = "-NoProfile -ExecutionPolicy Bypass -Command `"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command 'irm https://catsmoker.github.io/w | iex'`""

# Define the URL for the icon and the path to save it locally
$iconUrl = "https://catsmoker.github.io/web/assets/ico/favicon.ico"
$localIconPath = "C:\favicon.ico"

# Download the icon and save it locally
Invoke-WebRequest -Uri $iconUrl -OutFile $localIconPath

# Create a WScript.Shell COM object to create the shortcut
$wshShell = New-Object -ComObject WScript.Shell
$shortcut = $wshShell.CreateShortcut($shortcutPath)

# Set the properties of the shortcut
$shortcut.TargetPath = $targetPath
$shortcut.Arguments = $arguments
$shortcut.WorkingDirectory = [System.IO.Path]::GetDirectoryName($targetPath)
$shortcut.IconLocation = $localIconPath

# Save the shortcut
$shortcut.Save()

# Load necessary assemblies for UI
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Main Form
$mainForm = New-Object System.Windows.Forms.Form
$mainForm.Text = "CS Script v1.8 by catsmoker"
$mainForm.Size = New-Object System.Drawing.Size(800, 600)
$mainForm.StartPosition = "CenterScreen"
$mainForm.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$mainForm.ForeColor = [System.Drawing.Color]::White
$mainForm.FormBorderStyle = 'FixedDialog'
$mainForm.MaximizeBox = $false

# Title Label
$titleLabel = New-Object System.Windows.Forms.Label
$titleLabel.Text = "CS Script v1.8"
$titleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 18, [System.Drawing.FontStyle]::Bold)
$titleLabel.Size = New-Object System.Drawing.Size(400, 40)
$titleLabel.Location = New-Object System.Drawing.Point(200, 20)
$titleLabel.TextAlign = [System.Windows.Forms.HorizontalAlignment]::Center
$mainForm.Controls.Add($titleLabel)

# Subtitle Label
$subtitleLabel = New-Object System.Windows.Forms.Label
$subtitleLabel.Text = "by catsmoker | https://catsmoker.github.io"
$subtitleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Italic)
$subtitleLabel.Size = New-Object System.Drawing.Size(400, 20)
$subtitleLabel.Location = New-Object System.Drawing.Point(200, 60)
$subtitleLabel.TextAlign = [System.Windows.Forms.HorizontalAlignment]::Center
$mainForm.Controls.Add($subtitleLabel)

# Menu Buttons
$buttonClean = New-Object System.Windows.Forms.Button
$buttonClean.Text = "Clean Windows"
$buttonClean.Size = New-Object System.Drawing.Size(200, 40)
$buttonClean.Location = New-Object System.Drawing.Point(50, 120)
$buttonClean.Font = New-Object System.Drawing.Font("Segoe UI", 12)
$buttonClean.BackColor = [System.Drawing.Color]::FromArgb(70, 130, 180)
$buttonClean.ForeColor = [System.Drawing.Color]::White
$buttonClean.FlatStyle = 'Flat'
$buttonClean.FlatAppearance.BorderSize = 0
$buttonClean.Add_Click({ Clean-Windows })
$mainForm.Controls.Add($buttonClean)

$buttonFix = New-Object System.Windows.Forms.Button
$buttonFix.Text = "Scan and Fix Windows"
$buttonFix.Size = New-Object System.Drawing.Size(200, 40)
$buttonFix.Location = New-Object System.Drawing.Point(50, 180)
$buttonFix.Font = New-Object System.Drawing.Font("Segoe UI", 12)
$buttonFix.BackColor = [System.Drawing.Color]::FromArgb(70, 130, 180)
$buttonFix.ForeColor = [System.Drawing.Color]::White
$buttonFix.FlatStyle = 'Flat'
$buttonFix.FlatAppearance.BorderSize = 0
$buttonFix.Add_Click({ Fix-Windows })
$mainForm.Controls.Add($buttonFix)

$buttonApps = New-Object System.Windows.Forms.Button
$buttonApps.Text = "Apps/upgrades"
$buttonApps.Size = New-Object System.Drawing.Size(200, 40)
$buttonApps.Location = New-Object System.Drawing.Point(50, 240)
$buttonApps.Font = New-Object System.Drawing.Font("Segoe UI", 12)
$buttonApps.BackColor = [System.Drawing.Color]::FromArgb(70, 130, 180)
$buttonApps.ForeColor = [System.Drawing.Color]::White
$buttonApps.FlatStyle = 'Flat'
$buttonApps.FlatAppearance.BorderSize = 0
$buttonApps.Add_Click({ Download-Apps })
$mainForm.Controls.Add($buttonApps)

$buttonActivate = New-Object System.Windows.Forms.Button
$buttonActivate.Text = "Activate Windows"
$buttonActivate.Size = New-Object System.Drawing.Size(200, 40)
$buttonActivate.Location = New-Object System.Drawing.Point(50, 300)
$buttonActivate.Font = New-Object System.Drawing.Font("Segoe UI", 12)
$buttonActivate.BackColor = [System.Drawing.Color]::FromArgb(70, 130, 180)
$buttonActivate.ForeColor = [System.Drawing.Color]::White
$buttonActivate.FlatStyle = 'Flat'
$buttonActivate.FlatAppearance.BorderSize = 0
$buttonActivate.Add_Click({ Activate-Windows })
$mainForm.Controls.Add($buttonActivate)

$buttonAtlas = New-Object System.Windows.Forms.Button
$buttonAtlas.Text = "windows-Update"
$buttonAtlas.Size = New-Object System.Drawing.Size(200, 40)
$buttonAtlas.Location = New-Object System.Drawing.Point(50, 360)
$buttonAtlas.Font = New-Object System.Drawing.Font("Segoe UI", 12)
$buttonAtlas.BackColor = [System.Drawing.Color]::FromArgb(70, 130, 180)
$buttonAtlas.ForeColor = [System.Drawing.Color]::White
$buttonAtlas.FlatStyle = 'Flat'
$buttonAtlas.FlatAppearance.BorderSize = 0
$buttonAtlas.Add_Click({ windows-ps })
$mainForm.Controls.Add($buttonAtlas)

$buttonCTT = New-Object System.Windows.Forms.Button
$buttonCTT.Text = "CTT Windows Utility"
$buttonCTT.Size = New-Object System.Drawing.Size(200, 40)
$buttonCTT.Location = New-Object System.Drawing.Point(50, 420)
$buttonCTT.Font = New-Object System.Drawing.Font("Segoe UI", 12)
$buttonCTT.BackColor = [System.Drawing.Color]::FromArgb(70, 130, 180)
$buttonCTT.ForeColor = [System.Drawing.Color]::White
$buttonCTT.FlatStyle = 'Flat'
$buttonCTT.FlatAppearance.BorderSize = 0
$buttonCTT.Add_Click({ CTT })
$mainForm.Controls.Add($buttonCTT)

$buttonExit = New-Object System.Windows.Forms.Button
$buttonExit.Text = "Exit"
$buttonExit.Size = New-Object System.Drawing.Size(200, 40)
$buttonExit.Location = New-Object System.Drawing.Point(50, 480)
$buttonExit.Font = New-Object System.Drawing.Font("Segoe UI", 12)
$buttonExit.BackColor = [System.Drawing.Color]::FromArgb(70, 130, 180)
$buttonExit.ForeColor = [System.Drawing.Color]::White
$buttonExit.FlatStyle = 'Flat'
$buttonExit.FlatAppearance.BorderSize = 0
$buttonExit.Add_Click({ Exit-Script })
$mainForm.Controls.Add($buttonExit)

# Progress Bar
$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Size = New-Object System.Drawing.Size(500, 20)
$progressBar.Location = New-Object System.Drawing.Point(50, 530)
$progressBar.Style = 'Continuous'
$mainForm.Controls.Add($progressBar)

# Status Label
$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Text = "Ready"
$statusLabel.Size = New-Object System.Drawing.Size(500, 20)
$statusLabel.Location = New-Object System.Drawing.Point(50, 560)
$statusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$mainForm.Controls.Add($statusLabel)

# Functions
Function Clean-Windows {
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

    # Clean Recycle Bin
    Write-Host "Emptying Recycle Bin..."
    $null = (New-Object -ComObject Shell.Application).NameSpace(0xA).Items() | ForEach-Object { $_.InvokeVerb("delete") }

    # Flush DNS Cache
    Write-Host "Flushing DNS Cache..."
    ipconfig /flushdns

    $progressBar.Value = 100
    $statusLabel.Text = "Cleanup completed!"
}

Function Fix-Windows {
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

Function Download-Apps {
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

    # Load necessary assemblies for GUI
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    # Create the main form
    $Form = New-Object System.Windows.Forms.Form
    $Form.Text = "Install Software | cs_script by catsmoker"
    $Form.Size = New-Object System.Drawing.Size(450, 600)
    $Form.StartPosition = "CenterScreen"
    $Form.BackColor = [System.Drawing.Color]::FromArgb(50, 50, 50)  # Dark background
    $Form.FormBorderStyle = 'FixedDialog'
    $Form.MaximizeBox = $false

    # Create a label
    $Label = New-Object System.Windows.Forms.Label
    $Label.Location = New-Object System.Drawing.Size(20, 20)
    $Label.Size = New-Object System.Drawing.Size(400, 30)
    $Label.Text = "Select software to install:"
    $Label.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
    $Label.ForeColor = [System.Drawing.Color]::White
    $Form.Controls.Add($Label)

    # Create a Panel to hold the checkboxes
    $Panel = New-Object System.Windows.Forms.Panel
    $Panel.Location = New-Object System.Drawing.Size(20, 60)
    $Panel.Size = New-Object System.Drawing.Size(400, 400)  # Adjust height for 15 items with room for scrolling
    $Panel.AutoScroll = $true  # Enable scrolling
    $Panel.BorderStyle = 'FixedSingle'
    $Panel.BackColor = [System.Drawing.Color]::FromArgb(35, 35, 35)  # Slightly darker panel background
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
    $y = 0
    foreach ($name in $softwareItems.Keys) {
        $checkbox = New-Object System.Windows.Forms.CheckBox
        $checkbox.Location = New-Object System.Drawing.Size(10, $y)
        $checkbox.Size = New-Object System.Drawing.Size(360, 25)
        $checkbox.Text = $name
        $checkbox.Name = $softwareItems[$name]
        $checkbox.ForeColor = [System.Drawing.Color]::White
        $checkbox.BackColor = [System.Drawing.Color]::FromArgb(35, 35, 35)
        $checkbox.Font = New-Object System.Drawing.Font("Segoe UI", 10)
        $Panel.Controls.Add($checkbox)
        $y += 30
    }

    # Create Install button
    $InstallButton = New-Object System.Windows.Forms.Button
    $InstallButton.Location = New-Object System.Drawing.Size(185, 480)
    $InstallButton.Size = New-Object System.Drawing.Size(100, 40)
    $InstallButton.Text = "Install"
    $InstallButton.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $InstallButton.BackColor = [System.Drawing.Color]::FromArgb(70, 130, 180)  # SteelBlue color
    $InstallButton.ForeColor = [System.Drawing.Color]::White
    $InstallButton.FlatStyle = 'Flat'
    $InstallButton.FlatAppearance.BorderSize = 0
    $InstallButton.Add_Click({
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
    })
    $Form.Controls.Add($InstallButton)

    # Show the form
    [void] $Form.ShowDialog()
    $statusLabel.Text = "Ready"
}

Function Activate-Windows {
    $statusLabel.Text = "Activating Windows..."
    $progressBar.Value = 0
    Start-Process "powershell" -ArgumentList "irm https://get.activated.win | iex"
    $progressBar.Value = 100
    $statusLabel.Text = "Windows activated!"
}

Function windows-ps {
    $statusLabel.Text = "windows-ps..."
    $progressBar.Value = 0
    Install-Module PSWindowsUpdate -Force
    Add-WUServiceManager -MicrosoftUpdate
    Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot | Out-File "C:\($env.computername-Get-Date -f yyyy-MM-dd)-MSUpdates.log" -Force
    $progressBar.Value = 100
    $statusLabel.Text = "windows-ps completed!"
}

Function CTT {
    $statusLabel.Text = "CTT Windows Utility..."
    $progressBar.Value = 0
    Start-Process "powershell" -ArgumentList "iwr -useb https://christitus.com/win | iex"
    $progressBar.Value = 100
    $statusLabel.Text = "CTT completed!"
}

Function Exit-Script {
    $mainForm.Close()
}

# Show the Main Form
[void]$mainForm.ShowDialog()

<#
.NOTES
    Author          : catsmoker
    Email           : catsmoker.lab@gmail.com
    Website         : https://catsmoker.github.io
    GitHub          : https://github.com/catsmoker/AetherKit
    Version         : 4.0
    Last Modified   : 07-01-2025
#>

#region Initial Checks and Setup
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
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs -Wait
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
#endregion

#region UI Element Helper Functions
# Helper function to create styled buttons
Function New-Button {
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
    
    $tooltip = New-Object System.Windows.Forms.ToolTip
    $tooltip.SetToolTip($button, $TooltipText)
    
    return $button
}

Function New-ToolButton {
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
#endregion

#region Main Form and Controls
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

# Define the path to the modules folder
$modulePath = Join-Path -Path $PSScriptRoot -ChildPath "modules"

# Menu Buttons (arranged in a grid)
# The ClickAction now dot-sources the corresponding module script
$buttonClean = New-Button -Text "Clean Windows" -X 50 -Y 120 -ClickAction { . "$modulePath\CleanWindows.ps1" } -TooltipText "Cleans temporary files, Recycle Bin, and DNS cache."
$mainForm.Controls.Add($buttonClean)

$buttonFix = New-Button -Text "Scan and Fix Windows" -X 330 -Y 120 -ClickAction { . "$modulePath\FixWindows.ps1" } -TooltipText "Runs chkdsk, sfc, and DISM to repair Windows."
$mainForm.Controls.Add($buttonFix)

$buttonApps = New-Button -Text "Apps/Upgrades" -X 610 -Y 120 -ClickAction { . "$modulePath\DownloadApps.ps1" } -TooltipText "Install or upgrade software using winget."
$mainForm.Controls.Add($buttonApps)

$buttonActivateIDM = New-Button -Text "Activate IDM" -X 50 -Y 190 -ClickAction { . "$modulePath\ActivateIDM.ps1" } -TooltipText "Activates Internet Download Manager."
$mainForm.Controls.Add($buttonActivateIDM)

$buttonActivateWindows = New-Button -Text "Activate Windows" -X 330 -Y 190 -ClickAction { . "$modulePath\ActivateWindows.ps1" } -TooltipText "Activates Windows using an external script."
$mainForm.Controls.Add($buttonActivateWindows)

$buttonspotifypro = New-Button -Text "Spotify Pro" -X 610 -Y 190 -ClickAction { . "$modulePath\SpotifyPro.ps1" } -TooltipText "Add Spotify Premium using an external script."
$mainForm.Controls.Add($buttonspotifypro)

$buttonAtlas = New-Button -Text "Windows Update" -X 50 -Y 260 -ClickAction { . "$modulePath\windowsps.ps1" } -TooltipText "Installs Windows updates via PSWindowsUpdate."
$mainForm.Controls.Add($buttonAtlas)

$buttonCTT = New-Button -Text "CTT Windows Utility" -X 330 -Y 260 -ClickAction { . "$modulePath\CTT.ps1" } -TooltipText "Runs Chris Titus Tech's Windows Utility."
$mainForm.Controls.Add($buttonCTT)

$buttonMRT = New-Button -Text "Virus Scan" -X 610 -Y 260 -ClickAction { . "$modulePath\ScanWithMRT.ps1" } -TooltipText "Runs Windows Malicious Software Removal Tool."
$mainForm.Controls.Add($buttonMRT)

$buttonNetwork = New-Button -Text "Network Tools" -X 50 -Y 330 -ClickAction { . "$modulePath\NetworkTools.ps1" } -TooltipText "Network configuration and diagnostic tools."
$mainForm.Controls.Add($buttonNetwork)

$buttonRegistry = New-Button -Text "Registry Tools" -X 330 -Y 330 -ClickAction { . "$modulePath\RegistryTools.ps1" } -TooltipText "Registry maintenance and backup tools."
$mainForm.Controls.Add($buttonRegistry)

$buttonReport = New-Button -Text "System Report" -X 610 -Y 330 -ClickAction { . "$modulePath\SystemReport.ps1" } -TooltipText "Generate comprehensive system report."
$mainForm.Controls.Add($buttonReport)

$buttonAddShortcut = New-Button -Text "Add Shortcut" -X 50 -Y 400 -ClickAction { . "$modulePath\AddShortcut.ps1" } -TooltipText "Adds a desktop shortcut for AetherKit."
$mainForm.Controls.Add($buttonAddShortcut)

$buttonPowerTools = New-Button -Text "Power Tools" -X 330 -Y 400 -ClickAction { . "$modulePath\PowerTools.ps1" } -TooltipText "Advanced system utilities."
$mainForm.Controls.Add($buttonPowerTools)

$buttonExit = New-Button -Text "Exit" -X 610 -Y 400 -ClickAction { Exit-Script } -TooltipText "Exits the script and opens the developer's website."
$mainForm.Controls.Add($buttonExit)
#endregion

#region Core Functions
Function Exit-Script {
    Clear-Host
    Write-Host "Exiting script. Opening developer's website..."
    Start-Process "https://catsmoker.github.io"
    $mainForm.Close()
}
#endregion

# Display the main form
[void]$mainForm.ShowDialog()
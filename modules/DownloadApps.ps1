#Requires -Version 5.1
#Requires -RunAsAdministrator

# Add necessary .NET assemblies for the GUI
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Set high-DPI awareness for a sharper GUI
[System.Windows.Forms.Application]::EnableVisualStyles()
if ([System.Windows.Forms.Application]::respondsToSelector('SetHighDpiMode')) {
    [System.Windows.Forms.Application]::SetHighDpiMode('SystemAware')
}

Function Test-And-InstallWinget {
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Host "winget is already installed."
        return $true
    }

    $response = [System.Windows.Forms.MessageBox]::Show(
        "Winget is not installed. It is required for this script to function. Would you like to attempt to install it now?",
        "Winget Not Found",
        "YesNo",
        "Warning"
    )

    if ($response -ne 'Yes') {
        return $false
    }

    Write-Host "Attempting to install winget..."
    $installerUrl = "https://aka.ms/getwinget"
    $installerPath = Join-Path $env:TEMP "AppInstaller.msixbundle"

    try {
        $progress = {
            param($source, $progressEventArgs)
            Write-Progress -Activity "Downloading Winget Installer" -Status "$($progressEventArgs.ProgressPercentage)% Complete" -PercentComplete $progressEventArgs.ProgressPercentage
        }
        Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath -ProgressAction $progress
        Write-Host "Downloaded winget installer."
        Add-AppxPackage -Path $installerPath
        Write-Host "Winget installation completed."
        [System.Windows.Forms.MessageBox]::Show("Winget has been successfully installed.", "Success", "OK", "Information")
        return $true
    }
    catch {
        Write-Host "Failed to download or install winget. Error: $($_.Exception.Message)"
        [System.Windows.Forms.MessageBox]::Show("Failed to download or install winget. Please install it manually from the Microsoft Store (search for 'App Installer').", "Error", "OK", "Error")
        return $false
    }
}

# Exit if winget is not found and user chooses not to install
if (-not (Test-And-InstallWinget)) {
    Write-Error "Winget is required. Exiting script."
    exit
}

#endregion

#region --- Software Data Definition ---

$softwareList = @{
    "Browsers" = @{
        "Brave"               = "Brave.Brave"
        "Google Chrome"       = "Google.Chrome"
        "LibreWolf"           = "LibreWolf.LibreWolf"
        "Mozilla Firefox"     = "Mozilla.Firefox"
        "Tor Browser"         = "TorProject.TorBrowser"
        "Ungoogled Chromium"  = "eloston.ungoogled-chromium"
        "Vivaldi"             = "Vivaldi.Vivaldi"
        "Waterfox"            = "Waterfox.Waterfox"
    }
    "Communication" = @{
        "Discord"             = "Discord.Discord"
        "Discord Canary"      = "Discord.Discord.Canary"
        "Mozilla Thunderbird" = "Mozilla.Thunderbird"
        "Signal"              = "OpenWhisperSystems.Signal"
        "Slack"               = "Slack.Slack"
        "TeamSpeak"           = "TeamSpeakSystems.TeamSpeakClient"
        "Telegram"            = "Telegram.TelegramDesktop"
    }
    "Development" = @{
        "Git"                 = "Git.Git"
        "Microsoft VS Code"   = "Microsoft.VisualStudioCode"
        "Microsoft .NET SDK 8"= "Microsoft.DotNet.SDK.8"
        "Node.js LTS"         = "OpenJS.NodeJS.LTS"
        "Notepad++"           = "Notepad++.Notepad++"
        "PowerShell"          = "Microsoft.PowerShell"
        "PuTTY"               = "PuTTY.PuTTY"
        "VSCodium"            = "VSCodium.VSCodium"
        "Windows Terminal"    = "Microsoft.WindowsTerminal"
    }
    "Gaming" = @{
        "Epic Games Launcher" = "EpicGames.EpicGamesLauncher"
        "GOG Galaxy"          = "GOG.Galaxy"
        "Heroic Launcher"     = "HeroicGamesLauncher.HeroicGamesLauncher"
        "Playnite"            = "Playnite.Playnite"
        "Steam"               = "Valve.Steam"
    }
    "Media" = @{
        "Audacity"            = "Audacity.Audacity"
        "foobar2000"          = "PeterPawlowski.foobar2000"
        "IrfanView"           = "IrfanSkiljan.IrfanView"
        "K-Lite Codec Pack"   = "CodecGuide.K-LiteCodecPack.Mega"
        "OBS Studio"          = "OBSProject.OBSStudio"
        "Spotify"             = "Spotify.Spotify"
        "VLC Media Player"    = "VideoLAN.VLC"
    }
    "Utilities" = @{
        "7-Zip"               = "7zip.7zip"
        "BCUninstaller"       = "Klocman.BulkCrapUninstaller"
        "CPU-Z"               = "CPUID.CPU-Z"
        "Ditto"               = "Ditto.Ditto"
        "Everything"          = "voidtools.Everything"
        "ExplorerPatcher"     = "valinet.ExplorerPatcher"
        "GPU-Z"               = "TechPowerUp.GPU-Z"
        "HWiNFO"              = "REALiX.HWiNFO"
        "Lightshot"           = "Skillbrains.Lightshot"
        "MemReduct"           = "Henry++.MemReduct"
        "MSI Afterburner"     = "Guru3D.Afterburner"
        "PowerToys"           = "Microsoft.PowerToys"
        "ShareX"              = "ShareX.ShareX"
        "Snipping Tool"       = "9MZ95KL8MR0L" # This is a Microsoft Store ID
    }
}
#endregion

#region --- GUI Creation ---

$mainForm = New-Object System.Windows.Forms.Form
$mainForm.SuspendLayout()
$mainForm.Text = "AetherKit Software Installer"
$mainForm.Size = New-Object System.Drawing.Size(600, 750)
$mainForm.StartPosition = "CenterScreen"
$mainForm.BackColor = [System.Drawing.Color]::FromArgb(28, 28, 32)
$mainForm.FormBorderStyle = 'FixedDialog'
$mainForm.MaximizeBox = $false
$mainForm.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$mainForm.ForeColor = [System.Drawing.Color]::FromArgb(220, 220, 220)

# --- Top Panel for Search and Select All/None ---
$topPanel = New-Object System.Windows.Forms.Panel
$topPanel.Dock = "Top"
$topPanel.Height = 40
$topPanel.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 50)

$searchLabel = New-Object System.Windows.Forms.Label
$searchLabel.Text = "Search:"
$searchLabel.Location = New-Object System.Drawing.Point(10, 12)
$searchLabel.AutoSize = $true

$searchBox = New-Object System.Windows.Forms.TextBox
$searchBox.Location = New-Object System.Drawing.Point(70, 9)
$searchBox.Size = New-Object System.Drawing.Size(250, 25)
$searchBox.Anchor = "Left"

$selectAllLink = New-Object System.Windows.Forms.LinkLabel
$selectAllLink.Text = "Select All Visible"
$selectAllLink.Location = New-Object System.Drawing.Point(340, 12)
$selectAllLink.AutoSize = $true
$selectAllLink.LinkColor = [System.Drawing.Color]::FromArgb(100, 150, 255)

$deselectAllLink = New-Object System.Windows.Forms.LinkLabel
$deselectAllLink.Text = "Deselect All Visible"
$deselectAllLink.Location = New-Object System.Drawing.Point(460, 12)
$deselectAllLink.AutoSize = $true
$deselectAllLink.LinkColor = [System.Drawing.Color]::FromArgb(100, 150, 255)

$topPanel.Controls.AddRange(@($searchLabel, $searchBox, $selectAllLink, $deselectAllLink))
$mainForm.Controls.Add($topPanel)

# --- Main Panel for Software List ---
$mainPanel = New-Object System.Windows.Forms.Panel
$mainPanel.Dock = "Fill"
$mainPanel.AutoScroll = $true
$mainPanel.Padding = New-Object System.Windows.Forms.Padding(10)
$mainPanel.BorderStyle = 'None'
$mainPanel.BackColor = $mainForm.BackColor

# --- Bottom Panel for Buttons and Status ---
$bottomPanel = New-Object System.Windows.Forms.Panel
$bottomPanel.Dock = "Bottom"
$bottomPanel.Height = 90
$bottomPanel.BackColor = $topPanel.BackColor

$installButton = New-Object System.Windows.Forms.Button
$installButton.Text = "Install Selected"
$installButton.Size = New-Object System.Drawing.Size(150, 35)
$installButton.Location = New-Object System.Drawing.Point(290, 10)
$installButton.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)

$upgradeButton = New-Object System.Windows.Forms.Button
$upgradeButton.Text = "Upgrade All Apps"
$upgradeButton.Size = New-Object System.Drawing.Size(150, 35)
$upgradeButton.Location = New-Object System.Drawing.Point(130, 10)
$upgradeButton.Font = $installButton.Font

$bottomPanel.Controls.AddRange(@($installButton, $upgradeButton))

# --- Status Bar ---
$statusBar = New-Object System.Windows.Forms.StatusStrip
$statusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
$statusLabel.Text = "Ready"
$progressBar = New-Object System.Windows.Forms.ToolStripProgressBar
$progressBar.Size = New-Object System.Drawing.Size(200, 20)
$progressBar.Visible = $false
$statusBar.Items.AddRange(@($statusLabel, $progressBar))

$mainForm.Controls.Add($mainPanel)
$mainForm.Controls.Add($bottomPanel)
$mainForm.Controls.Add($statusBar)

#endregion

#region --- GUI Population & Logic ---

# Function to get all CheckBox controls from the form
Function Get-CheckBoxes($parent) {
    $controls = @()
    foreach ($control in $parent.Controls) {
        if ($control -is [System.Windows.Forms.CheckBox]) {
            $controls += $control
        }
        if ($control.Controls.Count -gt 0) {
            $controls += Get-CheckBoxes -parent $control
        }
    }
    return $controls
}


# Populate the main panel with categorized software
$mainPanel.SuspendLayout()
foreach ($category in $softwareList.Keys | Sort-Object) {
    $groupBox = New-Object System.Windows.Forms.GroupBox
    $groupBox.Text = $category
    $groupBox.Dock = 'Top'
    $groupBox.AutoSize = $true
    $groupBox.Padding = New-Object System.Windows.Forms.Padding(10, 5, 10, 10)
    $groupBox.ForeColor = [System.Drawing.Color]::FromArgb(150, 180, 255)
    
    $flowLayoutPanel = New-Object System.Windows.Forms.FlowLayoutPanel
    $flowLayoutPanel.Dock = 'Fill'
    $flowLayoutPanel.AutoSize = $true
    $flowLayoutPanel.FlowDirection = 'TopDown'
    
    $apps = $softwareList[$category]
    foreach ($appName in $apps.Keys | Sort-Object) {
        $wingetId = $apps[$appName]
        $checkbox = New-Object System.Windows.Forms.CheckBox
        $checkbox.Text = $appName
        $checkbox.Tag = $wingetId # Store the winget ID in the Tag property
        $checkbox.AutoSize = $true
        $checkbox.Padding = New-Object System.Windows.Forms.Padding(5, 2, 5, 2)
        $checkbox.ForeColor = $mainForm.ForeColor
        
        $flowLayoutPanel.Controls.Add($checkbox)
    }
    
    $groupBox.Controls.Add($flowLayoutPanel)
    $mainPanel.Controls.Add($groupBox)
}
$mainPanel.ResumeLayout()


# --- Event Handlers ---

$searchBox.Add_TextChanged({
    $searchText = "*" + $searchBox.Text + "*"
    # Pause layout to prevent flicker during filtering
    $mainPanel.SuspendLayout()

    foreach ($groupBox in $mainPanel.Controls) {
        if ($groupBox -is [System.Windows.Forms.GroupBox]) {
            $anyVisible = $false
            $flowLayoutPanel = $groupBox.Controls[0]
            foreach ($checkbox in $flowLayoutPanel.Controls) {
                if ($checkbox.Text -like $searchText) {
                    $checkbox.Visible = $true
                    $anyVisible = $true
                } else {
                    $checkbox.Visible = $false
                }
            }
            # Hide the entire category groupbox if no items match the search
            $groupBox.Visible = $anyVisible
        }
    }
    $mainPanel.ResumeLayout()
})

$selectAllLink.Add_LinkClicked({
    Get-CheckBoxes -parent $mainPanel | Where-Object { $_.Visible } | ForEach-Object { $_.Checked = $true }
})

$deselectAllLink.Add_LinkClicked({
    Get-CheckBoxes -parent $mainPanel | Where-Object { $_.Visible } | ForEach-Object { $_.Checked = $false }
})

$upgradeButton.Add_Click({
    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "This will attempt to upgrade all of your existing applications using winget. This may take a while. Continue?",
        "Confirm Upgrade",
        "YesNo",
        "Question"
    )
    if ($confirm -ne 'Yes') { return }
    
    $mainForm.Enabled = $false
    $progressBar.Visible = $true
    $progressBar.Style = 'Marquee' # Indeterminate progress for upgrade
    $statusLabel.Text = "Upgrading all packages... this may take a while."
    $mainForm.Update()

    $arguments = "upgrade --all --accept-package-agreements --accept-source-agreements --disable-interactivity"
    $process = Start-Process winget -ArgumentList $arguments -Wait -PassThru -NoNewWindow
    
    if ($process.ExitCode -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("All packages have been successfully upgraded.", "Upgrade Complete", "OK", "Information")
        $statusLabel.Text = "Upgrade finished."
    } else {
        [System.Windows.Forms.MessageBox]::Show("An error occurred during the upgrade process. Check the console for details.", "Upgrade Failed", "OK", "Error")
        $statusLabel.Text = "Upgrade failed."
    }

    $progressBar.Visible = $false
    $mainForm.Enabled = $true
})

$installButton.Add_Click({
    $selectedPackages = (Get-CheckBoxes -parent $mainPanel | Where-Object { $_.Checked }).Tag

    if ($selectedPackages.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Please select at least one application to install.", "No Selection", "OK", "Information")
        return
    }

    $mainForm.Enabled = $false
    $progressBar.Visible = $true
    $progressBar.Style = 'Continuous'
    $progressBar.Value = 0

    $total = $selectedPackages.Count
    $successCount = 0
    
    for ($i = 0; $i -lt $total; $i++) {
        $packageId = $selectedPackages[$i]
        $progress = [int](($i / $total) * 100)
        $statusLabel.Text = "Installing package $($i+1) of ${total}: $packageId"
        $progressBar.Value = $progress
        $mainForm.Update()
        
        Write-Host "Installing $packageId..."
        $arguments = "install -e --id `"$packageId`" --accept-package-agreements --accept-source-agreements --disable-interactivity --force"
        $process = Start-Process winget -ArgumentList $arguments -Wait -PassThru -NoNewWindow
        
        if ($process.ExitCode -eq 0) {
            $successCount++
            Write-Host "$packageId installed successfully."
        } else {
            Write-Warning "$packageId installation failed with exit code $($process.ExitCode)."
        }
    }
    
    $progressBar.Value = 100
    $statusLabel.Text = "Installation run complete. $successCount of $total packages installed successfully."
    [System.Windows.Forms.MessageBox]::Show("Installation run is complete.`n`nSuccessfully installed: $successCount`nFailed: $($total - $successCount)", "Installation Finished", "OK", "Information")

    $progressBar.Visible = $false
    $mainForm.Enabled = $true
})


#endregion

# --- Display Form ---
$mainForm.ResumeLayout()
$mainForm.Add_Shown({$mainForm.Activate()})
[void]$mainForm.ShowDialog()

# --- Cleanup ---
$mainForm.Dispose()
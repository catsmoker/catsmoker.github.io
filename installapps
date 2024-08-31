# Load necessary assemblies
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")

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

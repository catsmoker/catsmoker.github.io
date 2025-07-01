Clear-Host
$statusLabel.Text = "Installing Spotify..."
$progressBar.Value = 0
$mainForm.Refresh()

Start-Process "powershell" -ArgumentList "winget install -e --id Spotify.Spotify" -Wait
$progressBar.Value = 50
$mainForm.Refresh()

$statusLabel.Text = "Installing Spicetify for customization..."
# Create temp BAT file
$tempBat = "$env:TEMP\temp_spicetify_install.bat"
Set-Content -Path $tempBat -Value '@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "iwr -useb https://raw.githubusercontent.com/spicetify/cli/main/install.ps1 | iex"
del "%~f0"
'
# Run the BAT file
Start-Process -FilePath $tempBat

$progressBar.Value = 100
$statusLabel.Text = "Installation complete!"
$mainForm.Refresh()

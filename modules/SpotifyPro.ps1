Clear-Host
$statusLabel.Text = "Installing Spotify..."
$progressBar.Value = 0
$mainForm.Refresh()

Start-Process "powershell" -ArgumentList "winget install -e --id Spotify.Spotify" -Wait
$progressBar.Value = 50
$mainForm.Refresh()

$statusLabel.Text = "Installing Spicetify for customization..."
Start-Process "powershell" -ArgumentList "iwr -useb https://raw.githubusercontent.com/spicetify/marketplace/main/resources/install.ps1 | iex" -Wait

$progressBar.Value = 100
$statusLabel.Text = "Installation complete!"
$mainForm.Refresh()
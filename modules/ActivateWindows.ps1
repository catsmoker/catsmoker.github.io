Clear-Host
$statusLabel.Text = "Activating Windows..."
$progressBar.Value = 0
$mainForm.Refresh()
Start-Process "powershell" -ArgumentList "irm https://get.activated.win | iex"
$progressBar.Value = 100
$statusLabel.Text = "Windows activation process launched!"
$mainForm.Refresh()
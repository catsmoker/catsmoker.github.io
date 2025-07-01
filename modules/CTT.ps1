Clear-Host
$statusLabel.Text = "Launching Chris Titus Tech's Windows Utility..."
$progressBar.Value = 0
$mainForm.Refresh()
Start-Process "powershell" -ArgumentList "iwr -useb https://christitus.com/win | iex"
$progressBar.Value = 100
$statusLabel.Text = "CTT Utility launched!"
$mainForm.Refresh()
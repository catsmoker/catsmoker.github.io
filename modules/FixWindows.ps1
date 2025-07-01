Clear-Host
$statusLabel.Text = "Scanning and fixing Windows..."
$progressBar.Value = 0
$mainForm.Refresh()

# Run chkdsk
Write-Host "Running chkdsk..."
$statusLabel.Text = "Running chkdsk..."; $mainForm.Refresh()
Start-Process -FilePath "chkdsk.exe" -ArgumentList "/scan /perf" -NoNewWindow -Wait
$progressBar.Value = 33

# Run sfc /scannow
Write-Host "Running sfc /scannow..."
$statusLabel.Text = "Running sfc /scannow..."; $mainForm.Refresh()
Start-Process -FilePath "sfc.exe" -ArgumentList "/scannow" -NoNewWindow -Wait
$progressBar.Value = 66

# Run DISM
Write-Host "Running DISM..."
$statusLabel.Text = "Running DISM..."; $mainForm.Refresh()
Start-Process -FilePath "DISM.exe" -ArgumentList "/Online /Cleanup-Image /RestoreHealth" -NoNewWindow -Wait

$progressBar.Value = 100
$statusLabel.Text = "Fix completed!"
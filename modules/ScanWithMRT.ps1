Clear-Host
$statusLabel.Text = "Scanning with Windows Malicious Software Removal Tool..."
$progressBar.Value = 0
$mainForm.Refresh()

$mrtPath = "C:\Windows\System32\MRT.exe"

if (Test-Path $mrtPath) {
    Write-Host "Starting MRT scan..."
    $statusLabel.Text = "Starting MRT... Please follow the on-screen instructions."; $mainForm.Refresh()
    Start-Process -FilePath $mrtPath -Wait
    $progressBar.Value = 100
    $statusLabel.Text = "MRT scan completed!"
    Write-Host "MRT scan finished."
} else {
    Write-Host "MRT.exe not found. Attempting to download..." -ForegroundColor Yellow
    $statusLabel.Text = "MRT.exe not found. Downloading..."; $mainForm.Refresh()

    try {
        $mrtUrl = "https://go.microsoft.com/fwlink/?LinkID=212732"
        $tempPath = "$env:TEMP\mrt.exe"

        Write-Host "Downloading MRT from Microsoft..."
        Invoke-WebRequest -Uri $mrtUrl -OutFile $tempPath -UseBasicParsing
        Write-Host "MRT downloaded successfully to $tempPath"
        $progressBar.Value = 50; $mainForm.Refresh()

        $statusLabel.Text = "Starting MRT... Please follow the on-screen instructions."; $mainForm.Refresh()
        Start-Process -FilePath $tempPath -ArgumentList "/Q" -NoNewWindow -Wait
        $progressBar.Value = 100
        $statusLabel.Text = "MRT scan completed!"
        Write-Host "MRT scan finished from temp location."
    } catch {
        $statusLabel.Text = "Failed to download/run MRT!"
        Write-Host "Error downloading or running MRT: $_" -ForegroundColor Red
        $progressBar.Value = 0
        [System.Windows.Forms.MessageBox]::Show("Error downloading or running MRT: $($_.Exception.Message)", "Error", "OK", "Error")
    }
}
$mainForm.Refresh()
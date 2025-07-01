Clear-Host
$statusLabel.Text = "Starting Windows Update..."
$progressBar.Value = 0
$mainForm.Refresh()

try {
    Write-Host "Installing PSWindowsUpdate module..."
    $statusLabel.Text = "Installing PSWindowsUpdate module..."; $mainForm.Refresh()
    Install-Module PSWindowsUpdate -Force -Scope CurrentUser -ErrorAction Stop
    $progressBar.Value = 25; $mainForm.Refresh()

    Write-Host "Enabling Microsoft Update service..."
    $statusLabel.Text = "Enabling Microsoft Update service..."; $mainForm.Refresh()
    Add-WUServiceManager -MicrosoftUpdate -ErrorAction Stop
    $progressBar.Value = 50; $mainForm.Refresh()

    Write-Host "Checking for and installing updates... This may take a long time."
    $statusLabel.Text = "Installing all available updates... (This can take a very long time)"; $mainForm.Refresh()
    Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot | Out-File "C:\($env.computername-Get-Date -f 'yyyy-MM-dd')-MSUpdates.log" -Force
    
    $progressBar.Value = 100
    $statusLabel.Text = "Windows Update completed! Log saved."
    [System.Windows.Forms.MessageBox]::Show("Updates are complete. A log has been saved to your C: drive. A reboot may be required.", "Update Complete", "OK", "Information")
} catch {
    $statusLabel.Text = "Windows Update failed!"
    [System.Windows.Forms.MessageBox]::Show("An error occurred during the update process: $($_.Exception.Message)", "Update Error", "OK", "Error")
}
$mainForm.Refresh()
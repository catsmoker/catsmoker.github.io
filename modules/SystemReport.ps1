$statusLabel.Text = "Generating system report..."; $progressBar.Value = 0; $mainForm.Refresh()
$saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
$saveFileDialog.Filter = "Text Files (*.txt)|*.txt"
$saveFileDialog.FileName = "SystemReport_$(Get-Date -Format 'yyyyMMdd').txt"
$saveFileDialog.InitialDirectory = [Environment]::GetFolderPath("Desktop")

if ($saveFileDialog.ShowDialog($mainForm) -eq 'OK') {
    try {
        $filePath = $saveFileDialog.FileName
        "AetherKit System Report - Generated on $(Get-Date)" | Out-File $filePath
        $progressBar.Value = 5; $mainForm.Refresh()

        $statusLabel.Text = "Gathering System Information..."; $mainForm.Refresh()
        "`n=== SYSTEM INFORMATION ===" | Out-File $filePath -Append
        systeminfo | Out-File $filePath -Append
        $progressBar.Value = 20; $mainForm.Refresh()
        
        $statusLabel.Text = "Gathering Network Information..."; $mainForm.Refresh()
        "`n=== NETWORK INFORMATION ===" | Out-File $filePath -Append
        ipconfig /all | Out-File $filePath -Append
        $progressBar.Value = 40; $mainForm.Refresh()
        
        $statusLabel.Text = "Gathering Installed Programs..."; $mainForm.Refresh()
        "`n=== INSTALLED PROGRAMS ===" | Out-File $filePath -Append
        Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table | Out-File $filePath -Append
        $progressBar.Value = 60; $mainForm.Refresh()
        
        $statusLabel.Text = "Gathering Running Services..."; $mainForm.Refresh()
        "`n=== RUNNING SERVICES ===" | Out-File $filePath -Append
        Get-Service | Where-Object { $_.Status -eq "Running" } | Select-Object DisplayName, Name, Status | Format-Table | Out-File $filePath -Append
        $progressBar.Value = 80; $mainForm.Refresh()
        
        $statusLabel.Text = "Gathering Disk Information..."; $mainForm.Refresh()
        "`n=== DISK INFORMATION ===" | Out-File $filePath -Append
        Get-PhysicalDisk | Select-Object FriendlyName, Size, HealthStatus, MediaType | Format-Table | Out-File $filePath -Append
        $progressBar.Value = 100; $mainForm.Refresh()
        
        [System.Windows.Forms.MessageBox]::Show("System report generated at $filePath", "Report Complete", "OK", "Information")
        $statusLabel.Text = "System report generated"
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to generate system report: $($_.Exception.Message)", "Error", "OK", "Error")
        $statusLabel.Text = "System report failed"
    }
    $mainForm.Refresh()
} else {
    $statusLabel.Text = "Ready"
}
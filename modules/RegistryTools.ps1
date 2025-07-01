Function Clear-Registry {
    $statusLabel.Text = "Cleaning registry..."; $progressBar.Value = 0; $mainForm.Refresh()
    try {
        $tempKeys = @(
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU"
        )
        $count = 0
        foreach ($key in $tempKeys) {
            $count++
            $progressBar.Value = ($count / $tempKeys.Count) * 100
            if (Test-Path $key) {
                Get-Item -Path $key | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                New-Item -Path $key -Force | Out-Null
            }
        }
        $progressBar.Value = 100
        [System.Windows.Forms.MessageBox]::Show("Safe registry locations (MRUs, RecentDocs) have been cleared.", "Complete", "OK", "Information")
        $statusLabel.Text = "Registry cleaning completed"
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to clean registry: $($_.Exception.Message)", "Error", "OK", "Error")
        $statusLabel.Text = "Registry cleaning failed"
    }
    $mainForm.Refresh()
}

Function Backup-Registry {
    $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveFileDialog.Filter = "Registry Files (*.reg)|*.reg"
    $saveFileDialog.FileName = "RegistryBackup_$(Get-Date -Format 'yyyyMMdd_HHmm').reg"
    $saveFileDialog.InitialDirectory = [Environment]::GetFolderPath("Desktop")
    if ($saveFileDialog.ShowDialog($mainForm) -eq 'OK') {
        $statusLabel.Text = "Backing up registry..."; $progressBar.Value = 0; $mainForm.Refresh()
        try {
            reg.exe export HKLM "$($saveFileDialog.FileName)" /y
            $progressBar.Value = 50; $mainForm.Refresh()
            reg.exe export HKCU "$($saveFileDialog.FileName)" /y
            $progressBar.Value = 100; $mainForm.Refresh()
            [System.Windows.Forms.MessageBox]::Show("Registry backup saved to $($saveFileDialog.FileName)", "Backup Complete", "OK", "Information")
            $statusLabel.Text = "Registry backup completed"
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Failed to backup registry: $($_.Exception.Message)", "Error", "OK", "Error")
            $statusLabel.Text = "Registry backup failed"
        }
        $mainForm.Refresh()
    }
}

Function Restore-Registry {
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Filter = "Registry Files (*.reg)|*.reg"
    $openFileDialog.InitialDirectory = [Environment]::GetFolderPath("Desktop")
    if ($openFileDialog.ShowDialog($mainForm) -eq 'OK') {
        $statusLabel.Text = "Restoring registry..."; $progressBar.Value = 0; $mainForm.Refresh()
        try {
            reg.exe import "$($openFileDialog.FileName)"
            $progressBar.Value = 100; $mainForm.Refresh()
            [System.Windows.Forms.MessageBox]::Show("Registry restored from $($openFileDialog.FileName). A reboot is recommended.", "Restore Complete", "OK", "Warning")
            $statusLabel.Text = "Registry restore completed"
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Failed to restore registry: $($_.Exception.Message)", "Error", "OK", "Error")
            $statusLabel.Text = "Registry restore failed"
        }
        $mainForm.Refresh()
    }
}

Function Optimize-Registry {
    $statusLabel.Text = "Optimizing registry..."; $progressBar.Value = 0; $mainForm.Refresh()
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "NtfsDisableLastAccessUpdate" -Value 1 -ErrorAction Stop
        $progressBar.Value = 25; $mainForm.Refresh()
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "LargeSystemCache" -Value 1 -ErrorAction Stop
        $progressBar.Value = 50; $mainForm.Refresh()
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePagingExecutive" -Value 1 -ErrorAction Stop
        $progressBar.Value = 75; $mainForm.Refresh()
        [System.Windows.Forms.MessageBox]::Show("Registry optimization complete. A reboot is recommended for changes to take effect.", "Optimization Complete", "OK", "Warning")
        $statusLabel.Text = "Registry optimization completed"
        $progressBar.Value = 100
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to optimize registry: $($_.Exception.Message)", "Error", "OK", "Error")
        $statusLabel.Text = "Registry optimization failed"
    }
    $mainForm.Refresh()
}

$regForm = New-Object System.Windows.Forms.Form
$regForm.Text = "Registry Tools | AetherKit"
$regForm.Size = New-Object System.Drawing.Size(480, 260)
$regForm.StartPosition = "CenterScreen"
$regForm.BackColor = [System.Drawing.Color]::FromArgb(25, 25, 30)
$regForm.ForeColor = [System.Drawing.Color]::White
$regForm.FormBorderStyle = 'FixedDialog'
$regForm.MaximizeBox = $false
$regForm.Font = New-Object System.Drawing.Font("Segoe UI", 10)

$headerLabel = New-Object System.Windows.Forms.Label
$headerLabel.Text = "Registry Management Tools"
$headerLabel.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
$headerLabel.Size = New-Object System.Drawing.Size(440, 30)
$headerLabel.Location = New-Object System.Drawing.Point(20, 15)
$headerLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$regForm.Controls.Add($headerLabel)

$backupReg = New-ToolButton -Text "Backup Registry" -X 30 -Y 60 -ClickAction { Backup-Registry } -TooltipText "Create a full registry backup"
$regForm.Controls.Add($backupReg)

$restoreReg = New-ToolButton -Text "Restore Registry" -X 250 -Y 60 -ClickAction { Restore-Registry } -TooltipText "Restore registry from backup"
$regForm.Controls.Add($restoreReg)

$cleanReg = New-ToolButton -Text "Clean Registry (Safe)" -X 30 -Y 110 -ClickAction { Clear-Registry } -TooltipText "Perform safe registry cleaning (clears MRU lists)"
$regForm.Controls.Add($cleanReg)

$regOptimize = New-ToolButton -Text "Optimize Registry" -X 250 -Y 110 -ClickAction { Optimize-Registry } -TooltipText "Apply common performance tweaks to the registry"
$regForm.Controls.Add($regOptimize)

$closeButton = New-ToolButton -Text "Close" -X 140 -Y 170 -ClickAction { $regForm.Close() } -TooltipText "Close this window"
$closeButton.Size = New-Object System.Drawing.Size(200, 40)
$regForm.Controls.Add($closeButton)

[void]$regForm.ShowDialog($mainForm)
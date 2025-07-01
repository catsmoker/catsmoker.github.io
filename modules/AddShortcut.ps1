$shortcutPath = Join-Path -Path ([Environment]::GetFolderPath("Desktop")) -ChildPath "AetherKit.lnk"

if (Test-Path -Path $shortcutPath -PathType Leaf) {
    [System.Windows.Forms.MessageBox]::Show("A shortcut already exists on your desktop.", "Shortcut Exists", "OK", "Information")
    Write-Host "Shortcut already exists: $shortcutPath" -ForegroundColor Green
} else {
    Write-Host "Creating shortcut on desktop..."
    $statusLabel.Text = "Creating desktop shortcut..."; $mainForm.Refresh()
    
    $targetPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    # This command assumes the user is running the script from its intended location.
    # A more robust solution might point directly to the local main.ps1 file.
    # For now, we keep the original web-based command.
    $arguments = '-NoProfile -ExecutionPolicy Bypass -Command "irm https://catsmoker.github.io/w | iex"'
    $iconUrl = "https://catsmoker.github.io/aetherkit_icon.ico"
    $localIconPath = "$env:TEMP\aetherkit_icon.ico"

    try {
        Invoke-WebRequest -Uri $iconUrl -OutFile $localIconPath -UseBasicParsing

        $wshShell = New-Object -ComObject WScript.Shell
        $shortcut = $wshShell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = $targetPath
        $shortcut.Arguments = $arguments
        $shortcut.WorkingDirectory = $PSScriptRoot # Set working directory to the script's location
        $shortcut.IconLocation = $localIconPath
        $shortcut.Save()

        # Set run as administrator flag on the shortcut
        $bytes = [System.IO.File]::ReadAllBytes($shortcutPath)
        $bytes[0x15] = $bytes[0x15] -bor 0x20
        [System.IO.File]::WriteAllBytes($shortcutPath, $bytes)
        
        [System.Windows.Forms.MessageBox]::Show("A shortcut to run AetherKit has been created on your desktop.", "Shortcut Created", "OK", "Information")
        Write-Host "Shortcut created successfully: $shortcutPath" -ForegroundColor Green
        $statusLabel.Text = "Shortcut created on desktop."
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to create the shortcut: $($_.Exception.Message)", "Error", "OK", "Error")
        $statusLabel.Text = "Shortcut creation failed."
    }
}
$mainForm.Refresh()
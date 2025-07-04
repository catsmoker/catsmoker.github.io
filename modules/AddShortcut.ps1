Add-Type -AssemblyName System.Windows.Forms

$shortcutName = "AetherKit.lnk"
$shortcutPath = Join-Path -Path ([Environment]::GetFolderPath("Desktop")) -ChildPath $shortcutName
$iconUrl = "https://catsmoker.github.io/aetherkit_icon.ico"
$iconFileName = "aetherkit_icon.ico"

$iconDirectory = "C:\ProgramData\AetherKit"
$localIconPath = Join-Path -Path $iconDirectory -ChildPath $iconFileName

if (Test-Path -Path $shortcutPath -PathType Leaf) {
    [System.Windows.Forms.MessageBox]::Show("A shortcut already exists on your desktop.", "Shortcut Exists", "OK", "Information")
    Write-Host "Shortcut already exists: $shortcutPath" -ForegroundColor Green
} else {
    Write-Host "Creating shortcut on desktop..."
    
    if (-not (Test-Path -Path $iconDirectory -PathType Container)) {
        Write-Host "Creating icon directory: $iconDirectory"
        New-Item -Path $iconDirectory -ItemType Directory -Force | Out-Null
    }

    $targetPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    $arguments = '-NoProfile -ExecutionPolicy Bypass -Command "irm https://catsmoker.github.io/w | iex"'

    try {
        Write-Host "Downloading icon to $localIconPath"
        Invoke-WebRequest -Uri $iconUrl -OutFile $localIconPath -UseBasicParsing

        Write-Host "Setting icon file to hidden..."
        Set-ItemProperty -Path $localIconPath -Name Attributes -Value ([System.IO.FileAttributes]::Hidden)

        $wshShell = New-Object -ComObject WScript.Shell
        $shortcut = $wshShell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = $targetPath
        $shortcut.Arguments = $arguments
        $shortcut.WorkingDirectory = "C:\"
        $shortcut.IconLocation = $localIconPath
        $shortcut.Save()

        $bytes = [System.IO.File]::ReadAllBytes($shortcutPath)
        $bytes[0x15] = $bytes[0x15] -bor 0x20
        [System.IO.File]::WriteAllBytes($shortcutPath, $bytes)
        
        [System.Windows.Forms.MessageBox]::Show("A shortcut to run AetherKit has been created on your desktop.", "Shortcut Created", "OK", "Information")
        Write-Host "Shortcut created successfully: $shortcutPath" -ForegroundColor Green
        $statusLabel.Text = "Shortcut created on desktop."
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to create the shortcut: $($_.Exception.Message)", "Error", "OK", "Error")
        Write-Host "Failed to create shortcut: $($_.Exception.Message)" -ForegroundColor Red
        $statusLabel.Text = "Shortcut creation failed."
    }
}
$mainForm.Refresh()

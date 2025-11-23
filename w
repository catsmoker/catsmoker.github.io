<#
.NOTES
    Author          : catsmoker (Merged by Assistant)
    Description     : Stable Version - Standalone
    File Name       : freemixkit.ps1
#>

# -----------------------------------------------------------------------------------
# 0. EMBEDDED MODULES STORE
# -----------------------------------------------------------------------------------
# Stores all external module code in memory to make the script standalone.
$EmbeddedModules = @{}

$EmbeddedModules["AddShortcut.ps1"] = @'
Clear-Host
Write-Host "Creating Desktop Shortcut..." -ForegroundColor Yellow

$shortcutName = "FreeMixKit.lnk"
$desktopPath = [Environment]::GetFolderPath("Desktop")
$shortcutPath = Join-Path -Path $desktopPath -ChildPath $shortcutName
$targetPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$arguments = '-NoProfile -ExecutionPolicy Bypass -Command "irm https://catsmoker.github.io/w | iex"'
$iconUrl = "https://catsmoker.github.io/freemixkit_icon.ico"
$localIconPath = Join-Path $env:TEMP "freemixkit_icon.ico"

if (Test-Path -Path $shortcutPath -PathType Leaf) {
    Write-Host "Shortcut already exists at: $shortcutPath" -ForegroundColor Yellow
} else {
    try {
        # Download Icon
        Write-Host "Downloading icon..."
        try {
            Invoke-WebRequest -Uri $iconUrl -OutFile $localIconPath -UseBasicParsing
        } catch {
            Write-Host "Icon download failed, using default icon." -ForegroundColor DarkGray
            $localIconPath = $targetPath # Fallback to powershell icon
        }

        # Create Shortcut
        $wshShell = New-Object -ComObject WScript.Shell
        $shortcut = $wshShell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = $targetPath
        $shortcut.Arguments = $arguments
        $shortcut.WorkingDirectory = $desktopPath
        $shortcut.IconLocation = $localIconPath
        $shortcut.Description = "Launch freemixkit"
        $shortcut.Save()

        # Set RunAs Administrator (The Hex Edit Hack)
        # This bit-flips the shortcut header to flag "Run as Administrator"
        try {
            $bytes = [System.IO.File]::ReadAllBytes($shortcutPath)
            $bytes[0x15] = $bytes[0x15] -bor 0x20
            [System.IO.File]::WriteAllBytes($shortcutPath, $bytes)
            Write-Host "Administrator privileges flag set."
        } catch {
            Write-Host "Could not set admin flag programmatically (Shortcut still created)." -ForegroundColor Yellow
        }

        Write-Host "Shortcut created successfully on Desktop!" -ForegroundColor Green
    } catch {
        Write-Host "Failed to create shortcut: $($_.Exception.Message)" -ForegroundColor Red
    }
}
Write-Host "--- DONE ---"
'@

$EmbeddedModules["RegistryTools.ps1"] = @'
Clear-Host
Write-Host "Registry Tools" -ForegroundColor Yellow
Write-Host "1. Backup Registry"
Write-Host "2. Restore Registry"
Write-Host "3. Clean Registry (Safe)"
Write-Host "4. Optimize Registry"
Write-Host ""

$choice = Read-Host "Select an option (1-4)"

try {
    switch ($choice) {
        "1" {
            Write-Host "Backing up registry..." -ForegroundColor Yellow
            $defaultPath = Join-Path -Path ([Environment]::GetFolderPath("Desktop")) -ChildPath "RegistryBackup_$(Get-Date -Format 'yyyyMMdd_HHmm').reg"
            $backupPath = Read-Host "Enter backup path (default: $defaultPath)"
            if ([string]::IsNullOrWhiteSpace($backupPath)) {
                $backupPath = $defaultPath
            }
            reg.exe export "HKLM" "$backupPath" /y
            Write-Host "Registry backup saved successfully!" -ForegroundColor Green
        }
        "2" {
            Write-Host "Restoring registry..." -ForegroundColor Yellow
            $restorePath = Read-Host "Enter path to registry backup file to restore"
            if (Test-Path $restorePath) {
                reg.exe import "$restorePath"
                Write-Host "Registry restored successfully! Reboot recommended." -ForegroundColor Green
            } else {
                Write-Host "File not found: $restorePath" -ForegroundColor Red
            }
        }
        "3" {
            Write-Host "Cleaning registry..." -ForegroundColor Yellow
            $tempKeys = @(
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU",
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU"
            )
            foreach ($key in $tempKeys) {
                if (Test-Path $key) {
                    Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue
                    New-Item -Path $key -Force | Out-Null
                }
            }
            Write-Host "Registry cleaned successfully!" -ForegroundColor Green
        }
        "4" {
            Write-Host "Optimizing registry..." -ForegroundColor Yellow
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "NtfsDisableLastAccessUpdate" -Value 1 -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "LargeSystemCache" -Value 1 -ErrorAction SilentlyContinue
            Write-Host "Registry optimized successfully! Reboot recommended." -ForegroundColor Green
        }
        default {
            Write-Host "Invalid option. Please select 1-4." -ForegroundColor Red
        }
    }
} catch {
    Write-Host "Error during registry operation: $($_.Exception.Message)" -ForegroundColor Red
}
'@

$EmbeddedModules["SpotifyPro.ps1"] = @'
Clear-Host
Write-Host "Installing Spotify Pro (Spicetify)..." -ForegroundColor Yellow

try {
    # Check if winget is available
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Host "Winget is not installed. Installing winget..." -ForegroundColor Yellow
        $installerUrl = "https://aka.ms/getwinget"
        $installerPath = Join-Path $env:TEMP "AppInstaller.msixbundle"
        Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath
        Add-AppxPackage -Path $installerPath
        Write-Host "Winget installed successfully!" -ForegroundColor Green
    }

    # Check if Spotify is installed
    $spotifyInstalled = $false

    # Check for Spotify installed via registry
    $installedSpotify = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where-Object {$_.DisplayName -like "*Spotify*"}
    if ($installedSpotify) {
        $spotifyInstalled = $true
    }

    # Check for Spotify in common installation paths if not found in registry
    if (-not $spotifyInstalled) {
        $spotifyPaths = @(
            "${env:ProgramFiles}\Spotify\Spotify.exe",
            "${env:ProgramFiles(x86)}\Spotify\Spotify.exe",
            "${env:LOCALAPPDATA}\Spotify\Spotify.exe"
        )

        foreach ($path in $spotifyPaths) {
            if (Test-Path $path) {
                $spotifyInstalled = $true
                break
            }
        }
    }

    # If not found by any method, install via winget
    if (-not $spotifyInstalled) {
        Write-Host "Spotify not found. Installing Spotify via winget..." -ForegroundColor Yellow
        Start-Process -FilePath "winget" -ArgumentList "install", "--id", "Spotify.Spotify" -Wait
    } else {
        Write-Host "Spotify is already installed." -ForegroundColor Green
    }

    # Create a temporary .ps1 file with the installation command
    $tempDir = $env:TEMP
    $tempFile = Join-Path $tempDir "temp_install.ps1"

    # The installation command to be written to the temporary file
    $installCommand = "iwr -useb https://raw.githubusercontent.com/spicetify/marketplace/main/resources/install.ps1 | iex"

    # Write the command to the temporary file
    Set-Content -Path $tempFile -Value $installCommand -Encoding UTF8

    # Verify that the file was created
    if (Test-Path $tempFile) {
        Write-Host "Executing installation as non-elevated process..." -ForegroundColor Yellow

        # Execute the temporary file in a new PowerShell process without admin rights
        # Using a scheduled task to run the script with non-elevated privileges
        $taskName = "SpotifyProTempTask"
        $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File `"$tempFile`""
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(1)
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RunOnlyIfNetworkAvailable
        $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited

        # Register and start the scheduled task
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description "Non-elevated SpotifyPro installation" -Force | Out-Null

        # Start the scheduled task
        Start-ScheduledTask -TaskName $taskName

        # Wait a moment for the task to start
        Start-Sleep -Seconds 2

        # Unregister the task since it will run independently
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

        Write-Host "Spotify Pro installation started as non-elevated process." -ForegroundColor Green
        Write-Host "Note: Temporary file located at: $tempFile" -ForegroundColor Yellow
    } else {
        Write-Host "Failed to create temporary file." -ForegroundColor Red
    }
} catch {
    Write-Host "Failed to install Spotify Pro: $($_.Exception.Message)" -ForegroundColor Red
    # Clean up any scheduled task if it exists
    try {
        Unregister-ScheduledTask -TaskName "SpotifyProTempTask" -Confirm:$false -ErrorAction SilentlyContinue
    } catch {
        # Could not clean up scheduled task - handled silently
    }
}
'@

$EmbeddedModules["SoftwareManagement.ps1"] = @'
Clear-Host
Write-Host "Software Management" -ForegroundColor Yellow
Write-Host "1. Install Winget"
Write-Host "2. Upgrade All Apps"
Write-Host ""

$choice = Read-Host "Select an option (1-2)"

try {
    switch ($choice) {
        "1" {
            Write-Host "Installing winget..." -ForegroundColor Yellow
            if (Get-Command winget -ErrorAction SilentlyContinue) {
                Write-Host "Winget is already installed!" -ForegroundColor Green
            } else {
                $installerUrl = "https://aka.ms/getwinget"
                $installerPath = Join-Path $env:TEMP "AppInstaller.msixbundle"
                Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath
                Add-AppxPackage -Path $installerPath
                Write-Host "Winget installed successfully!" -ForegroundColor Green
            }
        }
        "2" {
            if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
                Write-Host "Winget is not installed. Please install it first." -ForegroundColor Red
            } else {
                Write-Host "Upgrading all packages..." -ForegroundColor Yellow
                winget upgrade --all --accept-package-agreements --accept-source-agreements
                Write-Host "Package upgrade completed!" -ForegroundColor Green
            }
        }
        default {
            Write-Host "Invalid option. Please select 1-2." -ForegroundColor Red
        }
    }
} catch {
    Write-Host "Error during software operation: $($_.Exception.Message)" -ForegroundColor Red
}
'@

$EmbeddedModules["SystemRepair.ps1"] = @'
Clear-Host

Write-Host "Running chkdsk..."
chkdsk.exe /scan /perf

Write-Host "Running sfc /scannow..."
sfc.exe /scannow

Write-Host "Running DISM..."
DISM.exe /Online /Cleanup-Image /RestoreHealth

Write-host "--- DONE ---"
'@

$EmbeddedModules["ActivateIDM.ps1"] = @'
Clear-Host
Write-Host "Activating IDM..."
Start-Process "powershell" -ArgumentList "irm https://coporton.com/ias | iex"
Write-Host "IDM activation process launched!"
'@

$EmbeddedModules["SystemReport.ps1"] = @'
Clear-Host
Write-Host "System Report Generator" -ForegroundColor Yellow

try {
    $defaultPath = Join-Path -Path ([Environment]::GetFolderPath("Desktop")) -ChildPath "SystemReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $filePath = Read-Host "Enter file path for report (default: $defaultPath)"
    if ([string]::IsNullOrWhiteSpace($filePath)) {
        $filePath = $defaultPath
    }

    Write-Host "Generating system report..." -ForegroundColor Yellow

    "freemixkit System Report - Generated on $(Get-Date)" | Out-File $filePath

    Write-Host "Gathering System Information..." -ForegroundColor Yellow
    "`n=== SYSTEM INFORMATION ===" | Out-File $filePath -Append
    systeminfo | Out-File $filePath -Append

    Write-Host "Gathering Network Information..." -ForegroundColor Yellow
    "`n=== NETWORK INFORMATION ===" | Out-File $filePath -Append
    ipconfig /all | Out-File $filePath -Append

    Write-Host "Gathering Installed Programs..." -ForegroundColor Yellow
    "`n=== INSTALLED PROGRAMS ===" | Out-File $filePath -Append
    Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
    Format-Table -AutoSize | Out-File $filePath -Append

    Write-Host "Gathering Running Services..." -ForegroundColor Yellow
    "`n=== RUNNING SERVICES ===" | Out-File $filePath -Append
    Get-Service | Where-Object { $_.Status -eq "Running" } |
    Select-Object DisplayName, Name, Status |
    Format-Table -AutoSize | Out-File $filePath -Append

    Write-Host "Gathering Disk Information..." -ForegroundColor Yellow
    "`n=== DISK INFORMATION ===" | Out-File $filePath -Append
    Get-PhysicalDisk | Select-Object FriendlyName, Size, HealthStatus, MediaType |
    Format-Table -AutoSize | Out-File $filePath -Append

    Write-Host "System report generated successfully at $filePath" -ForegroundColor Green
} catch {
    Write-Host "Failed to generate system report: $($_.Exception.Message)" -ForegroundColor Red
}
'@

$EmbeddedModules["ActivateWindows.ps1"] = @'
Clear-Host
Write-Host "Activating Windows..."
Start-Process "powershell" -ArgumentList "irm https://get.activated.win | iex"
Write-Host "Windows activation process launched!"
'@

$EmbeddedModules["AdobeFree.ps1"] = @'
Clear-Host

Write-Host "Getting GenP download information..."
$apiUrl = "https://api.github.com/repos/Cur10s1tyByt3/GenP/releases/latest"
$releaseInfo = Invoke-RestMethod -Uri $apiUrl

# Find the first asset that is a zip file
$zipAsset = $releaseInfo.assets | Where-Object { $_.name -like "*.zip" } | Select-Object -First 1
$downloadUrl = $zipAsset.browser_download_url
$zipFileName = $zipAsset.name
$zipPath = Join-Path -Path $env:TEMP -ChildPath $zipFileName
$extractPath = Join-Path -Path $env:TEMP -ChildPath "GenP_Extracted"

Write-Host "Downloading GenP archive..."
Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -UseBasicParsing

Write-Host "Download completed, extracting..."
if (Test-Path $extractPath) {
    Remove-Item -Path $extractPath -Recurse -Force
}
New-Item -ItemType Directory -Path $extractPath -Force | Out-Null

Add-Type -AssemblyName System.IO.Compression.FileSystem
$zipArchive = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
[System.IO.Compression.ZipFileExtensions]::ExtractToDirectory($zipArchive, $extractPath)
$zipArchive.Dispose()

Write-Host "Extraction completed, finding executable..."
$exeFiles = Get-ChildItem -Path $extractPath -Recurse -Include "*.exe" | Select-Object -First 1
$exePath = $exeFiles.FullName

Write-Host "Running GenP executable..."
Start-Process -FilePath $exePath -Wait

Write-Host "Adobe Free (GenP) completed!"

# Clean up: remove the zip file and extracted directory after running
Start-Sleep -Seconds 2  # Brief delay to let installer finish
if (Test-Path $zipPath) {
    Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue
}
if (Test-Path $extractPath) {
    Remove-Item -Path $extractPath -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "--- DONE ---"
'@

$EmbeddedModules["CTTUtility.ps1"] = @'
Clear-Host
Write-Host "Launching Chris Titus Tech's Windows Utility..."
Start-Process "powershell" -ArgumentList "iwr -useb https://christitus.com/win | iex"
Write-Host "CTT Utility launched!"
'@

$EmbeddedModules["CleanSystem.ps1"] = @'
Clear-Host

Write-host "Cleaning User Temp Folder..."
Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue

Write-host "Cleaning Windows Temp Folder..."
Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue

Write-host "Cleaning Prefetch..."
Remove-Item -Path "C:\Windows\Prefetch\*" -Recurse -Force -ErrorAction SilentlyContinue

Write-host "Flushing DNS..."
Clear-DnsClientCache -ErrorAction SilentlyContinue

Write-host "--- DONE ---"
'@

$EmbeddedModules["DiscordPro.ps1"] = @'
Clear-Host

Write-Host "Getting Legcord download information..."
$apiUrl = "https://api.github.com/repos/Legcord/Legcord/releases/latest"
$releaseInfo = Invoke-RestMethod -Uri $apiUrl

# Find the appropriate installer for Windows
$installerAsset = $releaseInfo.assets | Where-Object {
    $_.name -like "*win-x64.exe" -or $_.name -like "*win32-x64.exe" -or $_.name -like "*.exe"
} | Select-Object -First 1

$actualDownloadUrl = $installerAsset.browser_download_url
$tempPath = Join-Path -Path $env:TEMP -ChildPath $installerAsset.name

Write-Host "Downloading Legcord installer..."
Invoke-WebRequest -Uri $actualDownloadUrl -OutFile $tempPath -UseBasicParsing

Write-Host "Download completed, running installer..."
Start-Process -FilePath $tempPath -Wait  # Run installer

Write-Host "Discord Pro installation completed!"

# Remove the installer after running
Start-Sleep -Seconds 2  # Brief delay to let installer finish
if (Test-Path $tempPath) {
    Remove-Item -Path $tempPath -Force -ErrorAction SilentlyContinue
}

Write-Host "--- DONE ---"
'@

$EmbeddedModules["FixResolution.ps1"] = @'
Clear-Host

Write-Host "Downloading Custom Resolution Utility..."
$downloadUrl = "https://www.monitortests.com/download/cru/cru-1.5.3.zip"
$zipFileName = "cru-download.zip"
$zipPath = Join-Path -Path $env:TEMP -ChildPath $zipFileName
$extractPath = Join-Path -Path $env:TEMP -ChildPath "CRU_Extracted"

Write-Host "Downloading CRU archive..."
Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -UseBasicParsing

Write-Host "Download completed, extracting..."
if (Test-Path $extractPath) {
    Remove-Item -Path $extractPath -Recurse -Force
}
New-Item -ItemType Directory -Path $extractPath -Force | Out-Null

Add-Type -AssemblyName System.IO.Compression.FileSystem
$zipArchive = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
[System.IO.Compression.ZipFileExtensions]::ExtractToDirectory($zipArchive, $extractPath)
$zipArchive.Dispose()

Write-Host "Extraction completed, finding CRU executable..."
$cruExe = Get-ChildItem -Path $extractPath -Recurse -Name "CRU.exe" | Select-Object -First 1
$cruPath = Join-Path -Path $extractPath -ChildPath $cruExe

Write-Host "Running CRU.exe..."
Start-Process -FilePath $cruPath -Wait

Write-Host "CRU.exe closed, running restart64.exe..."
$resetExe = Get-ChildItem -Path $extractPath -Recurse -Name "restart64.exe" | Select-Object -First 1

if ($null -ne $resetExe) {
    $resetPath = Join-Path -Path $extractPath -ChildPath $resetExe
    Start-Process -FilePath $resetPath -Wait
} else {
    Write-Host "Warning: restart64.exe not found, skipping"
}

Write-Host "--- DONE ---"
'@

$EmbeddedModules["MalwareScan.ps1"] = @'
Clear-Host
Write-Host "Malware Scan - MRT (Microsoft Malicious Software Removal Tool)" -ForegroundColor Yellow

try {
    $mrtPath = "${env:SystemRoot}\System32\MRT.exe"

    if (Test-Path $mrtPath) {
        Write-Host "MRT found. Starting scan..."
        Start-Process -FilePath $mrtPath -Wait
        Write-Host "MRT scan completed!" -ForegroundColor Green
    } else {
        Write-Host "MRT not found. Downloading from Microsoft..." -ForegroundColor Yellow

        $mrtUrl = "https://go.microsoft.com/fwlink/?LinkID=212732"
        $tempPath = "$env:TEMP\MRT.exe"

        Invoke-WebRequest -Uri $mrtUrl -OutFile $tempPath -UseBasicParsing
        Write-Host "MRT downloaded successfully. Starting scan..."

        Start-Process -FilePath $tempPath -ArgumentList "/Q" -NoNewWindow -Wait
        Write-Host "MRT scan completed!" -ForegroundColor Green
    }
} catch {
    Write-Host "Error during malware scan: $($_.Exception.Message)" -ForegroundColor Red
}
'@

$EmbeddedModules["NetworkTools.ps1"] = @'
Clear-Host
Write-Host "Network Tools" -ForegroundColor Yellow
Write-Host "1. Set Google DNS (8.8.8.8, 8.8.4.4)"
Write-Host "2. Set Cloudflare DNS (1.1.1.1, 1.0.0.1)"
Write-Host "3. Reset DNS to DHCP"
Write-Host "4. Reset Network Adapters"
Write-Host "5. Flush DNS Cache"
Write-Host "6. Renew IP Address"
Write-Host "7. Reset Winsock Catalog"
Write-Host ""

$choice = Read-Host "Select an option (1-7)"

try {
    switch ($choice) {
        "1" {
            Write-Host "Setting Google DNS..." -ForegroundColor Yellow
            $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
            foreach ($adapter in $adapters) {
                Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses "8.8.8.8","8.8.4.4"
            }
            Write-Host "Google DNS set successfully!" -ForegroundColor Green
        }
        "2" {
            Write-Host "Setting Cloudflare DNS..." -ForegroundColor Yellow
            $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
            foreach ($adapter in $adapters) {
                Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses "1.1.1.1","1.0.0.1"
            }
            Write-Host "Cloudflare DNS set successfully!" -ForegroundColor Green
        }
        "3" {
            Write-Host "Resetting DNS to DHCP..." -ForegroundColor Yellow
            $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
            foreach ($adapter in $adapters) {
                Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ResetServerAddresses
            }
            Write-Host "DNS reset to DHCP successfully!" -ForegroundColor Green
        }
        "4" {
            Write-Host "Resetting network adapters..." -ForegroundColor Yellow
            $adapters = Get-NetAdapter | Where-Object { $_.InterfaceDescription -notlike "*Loopback*" }
            foreach ($adapter in $adapters) {
                Disable-NetAdapter -Name $adapter.Name -Confirm:$false
            }
            Start-Sleep -Seconds 2
            foreach ($adapter in $adapters) {
                Enable-NetAdapter -Name $adapter.Name -Confirm:$false
            }
            Write-Host "Network adapters reset successfully!" -ForegroundColor Green
        }
        "5" {
            Write-Host "Flushing DNS cache..." -ForegroundColor Yellow
            ipconfig /flushdns | Out-Null
            Write-Host "DNS cache flushed successfully!" -ForegroundColor Green
        }
        "6" {
            Write-Host "Renewing IP address..." -ForegroundColor Yellow
            ipconfig /release | Out-Null
            ipconfig /renew | Out-Null
            Write-Host "IP address renewed successfully!" -ForegroundColor Green
        }
        "7" {
            Write-Host "Resetting Winsock catalog..." -ForegroundColor Yellow
            netsh winsock reset | Out-Null
            Write-Host "Winsock catalog reset! Reboot recommended." -ForegroundColor Green
        }
        default {
            Write-Host "Invalid option. Please select 1-7." -ForegroundColor Red
        }
    }
} catch {
    Write-Host "Error during network operation: $($_.Exception.Message)" -ForegroundColor Red
}
'@

$EmbeddedModules["PowerTools.ps1"] = @'
Clear-Host
Write-Host "Power Tools" -ForegroundColor Yellow
Write-Host "1. Disable Windows Updates"
Write-Host "2. Enable Windows Updates"
Write-Host "3. Disable Windows Defender"
Write-Host "4. Enable Windows Defender"
Write-Host "5. Disable Telemetry"
Write-Host "6. Repair Start Menu"
Write-Host ""

$choice = Read-Host "Select an option (1-6)"

try {
    switch ($choice) {
        "1" {
            Write-Host "Disabling Windows Updates..." -ForegroundColor Yellow
            Set-Service -Name wuauserv -StartupType Disabled -ErrorAction SilentlyContinue
            Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
            Write-Host "Windows Updates disabled successfully!" -ForegroundColor Green
        }
        "2" {
            Write-Host "Enabling Windows Updates..." -ForegroundColor Yellow
            Set-Service -Name wuauserv -StartupType Automatic -ErrorAction SilentlyContinue
            Start-Service -Name wuauserv -ErrorAction SilentlyContinue
            Write-Host "Windows Updates enabled successfully!" -ForegroundColor Green
        }
        "3" {
            Write-Host "Disabling Windows Defender..." -ForegroundColor Yellow
            Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
            Write-Host "Windows Defender disabled successfully!" -ForegroundColor Green
        }
        "4" {
            Write-Host "Enabling Windows Defender..." -ForegroundColor Yellow
            Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
            Write-Host "Windows Defender enabled successfully!" -ForegroundColor Green
        }
        "5" {
            Write-Host "Disabling telemetry..." -ForegroundColor Yellow
            $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
            if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
            Set-ItemProperty -Path $path -Name "AllowTelemetry" -Value 0 -ErrorAction SilentlyContinue
            Write-Host "Telemetry disabled successfully!" -ForegroundColor Green
        }
        "6" {
            Write-Host "Repairing Start Menu..." -ForegroundColor Yellow
            Get-AppXPackage -AllUsers | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
            Write-Host "Start Menu repair completed!" -ForegroundColor Green
        }
        default {
            Write-Host "Invalid option. Please select 1-6." -ForegroundColor Red
        }
    }
} catch {
    Write-Host "Error during power tool operation: $($_.Exception.Message)" -ForegroundColor Red
}
'@


# -----------------------------------------------------------------------------------
# 1. PRE-CHECKS & SETUP
# -----------------------------------------------------------------------------------

$scriptPath = $PSScriptRoot
if ([string]::IsNullOrEmpty($scriptPath)) { $scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path }

# Version (Hardcoded for standalone)
$version = "5.0"

# Admin Check
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    try { Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit } catch {}
}

# Load WPF
Add-Type -AssemblyName PresentationFramework

# Ensure the console is visible
$host.UI.RawUI.WindowTitle = "FreeMixKit v$version - Console Output"
[Console]::BackgroundColor = "Black"
[Console]::ForegroundColor = "Green"
Clear-Host
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " FreeMixKit v$version - Background Log " -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Waiting for user action...`n" -ForegroundColor DarkGray

# -----------------------------------------------------------------------------------
# 2. UI DEFINITION (XAML)
# -----------------------------------------------------------------------------------

[xml]$xaml = @"
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="FreeMixKit v$version"
    Height="600" Width="1152"
    WindowStartupLocation="CenterScreen"
    ResizeMode="CanResize"
    Background="#191928">

    <Window.Resources>
        <Style TargetType="TextBlock">
            <Setter Property="FontFamily" Value="Segoe UI"/>
            <Setter Property="Foreground" Value="#E0E0E0"/>
        </Style>
        <!-- Button Style -->
        <Style TargetType="Button">
            <Setter Property="Background" Value="#3C3C5A"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="FontFamily" Value="Segoe UI"/>
            <Setter Property="FontWeight" Value="Bold"/>
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Margin" Value="5"/>
            <Setter Property="Height" Value="45"/>
            <Setter Property="Width" Value="170"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Name="border" Background="{TemplateBinding Background}" CornerRadius="3">
                            <ContentPresenter HorizontalAlignment="Left" VerticalAlignment="Center" Margin="15,0,0,0"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="border" Property="Background" Value="#4C4C6E"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter TargetName="border" Property="Background" Value="#252530"/>
                                <Setter Property="Foreground" Value="#555555"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <!-- Icon Style -->
        <Style TargetType="Path">
            <Setter Property="Fill" Value="White"/>
            <Setter Property="Stretch" Value="Uniform"/>
            <Setter Property="Height" Value="16"/>
            <Setter Property="Width" Value="16"/>
            <Setter Property="Margin" Value="0,0,10,0"/>
        </Style>
    </Window.Resources>

    <Grid Margin="20">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/> <!-- Header -->
            <RowDefinition Height="Auto"/> <!-- SysInfo -->
            <RowDefinition Height="Auto"/> <!-- Buttons -->
        </Grid.RowDefinitions>

        <!-- Header -->
        <StackPanel Grid.Row="0" Margin="0,0,0,15">
            <Grid>
                <StackPanel>
                    <TextBlock Text="FreeMixKit v$version" FontSize="28" FontWeight="Bold" Foreground="White"/>
                    <TextBlock Text="System Utility Suite" FontSize="14" Foreground="#B4B4C8" Margin="0,5,0,0"/>
                </StackPanel>
                <Button Name="btnWebsite" Content="Visit Website" Width="120" Height="30" 
                        HorizontalAlignment="Right" VerticalAlignment="Top" Background="#0078D7" FontSize="11"/>
            </Grid>
        </StackPanel>

        <!-- SysInfo -->
        <Border Grid.Row="1" Background="#252535" BorderBrush="#3C3C5A" BorderThickness="1" CornerRadius="4" Padding="15" Margin="0,0,0,15">
            <StackPanel>
                <TextBlock Name="txtSysInfo" Text="Loading detailed info..." FontSize="12" LineHeight="20"/>
            </StackPanel>
        </Border>

        <!-- Tool Buttons -->
        <ScrollViewer Grid.Row="2" VerticalScrollBarVisibility="Disabled" HorizontalScrollBarVisibility="Disabled" Margin="0,0,0,0">
            <WrapPanel Name="pnlButtons" Orientation="Horizontal">
                <Button Name="btnClean" ToolTip="Clean System"><StackPanel Orientation="Horizontal"><Path Data="M19,4H15.5L14.5,3H9.5L8.5,4H5V6H19M6,19A2,2 0 0,0 8,21H16A2,2 0 0,0 18,19V7H6V19Z"/><TextBlock Text="Clean System"/></StackPanel></Button>
                <Button Name="btnRepair" ToolTip="System Repair"><StackPanel Orientation="Horizontal"><Path Data="M22.7,19L13.6,9.9C14.5,7.6 14,4.9 12.1,3C10.1,1 7.1,0.6 4.7,1.7L9,6L6,9L1.6,4.7C0.4,7.1 0.9,10.1 2.9,12.1C4.8,14 7.5,14.5 9.8,13.6L18.9,22.7C19.3,23.1 19.9,23.1 20.3,22.7L22.6,20.3C23.1,19.9 23.1,19.3 22.7,19Z"/><TextBlock Text="System Repair"/></StackPanel></Button>
                <Button Name="btnScan" ToolTip="Malware Scan"><StackPanel Orientation="Horizontal"><Path Data="M12,1L3,5V11C3,16.55 6.84,21.74 12,23C17.16,21.74 21,16.55 21,11V5L12,1Z"/><TextBlock Text="Malware Scan"/></StackPanel></Button>
                <Button Name="btnReport" ToolTip="System Report"><StackPanel Orientation="Horizontal"><Path Data="M14,2H6A2,2 0 0,0 4,4V20A2,2 0 0,0 6,22H18A2,2 0 0,0 20,20V8L14,2M18,20H6V4H13V9H18V20Z"/><TextBlock Text="System Report"/></StackPanel></Button>
                <Button Name="btnApps" ToolTip="Software"><StackPanel Orientation="Horizontal"><Path Data="M20,6H16V2H8V6H4A2,2 0 0,0 2,8V20A2,2 0 0,0 4,22H20A2,2 0 0,0 22,20V8A2,2 0 0,0 20,6M10,4H14V6H10V4M20,20H4V8H8V10H16V8H20V20M12,18L16,14H13V12H11V14H8L12,18Z"/><TextBlock Text="Software Tools"/></StackPanel></Button>
                <Button Name="btnIDM" ToolTip="Activate IDM"><StackPanel Orientation="Horizontal"><Path Data="M7,14A2,2 0 0,1 5,12A2,2 0 0,1 7,10A2,2 0 0,1 9,12A2,2 0 0,1 7,14M12.65,10C11.83,7.67 9.61,6 7,6A6,6 0 0,0 1,12A6,6 0 0,0 7,18C9.61,18 11.83,16.33 12.65,14H17V18H21V14H23V10H12.65Z"/><TextBlock Text="Activate IDM"/></StackPanel></Button>
                <Button Name="btnWinAct" ToolTip="Activate Windows"><StackPanel Orientation="Horizontal"><Path Data="M4,6H20V16H4M20,18A2,2 0 0,0 22,16V6C22,4.89 21.1,4 20,4H4C2.89,4 2,4.89 2,6V16A2,2 0 0,0 4,18H0V20H24V18H20Z"/><TextBlock Text="Activate Windows"/></StackPanel></Button>
                <Button Name="btnSpotify" ToolTip="Spotify Pro"><StackPanel Orientation="Horizontal"><Path Data="M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M9,16.5C8.7,16.5 8.5,16.4 8.4,16.2C7,15.3 5.3,15.1 3.1,15.6C2.7,15.7 2.2,15.5 2.1,15.1C2,14.7 2.2,14.2 2.6,14.1C5.1,13.5 7.3,13.8 9.1,14.9C9.4,15.1 9.5,15.5 9.3,15.9C9.2,16.2 8.9,16.5 8.6,16.5H9M12,2Z"/><TextBlock Text="Spotify Pro"/></StackPanel></Button>
                <Button Name="btnCTT" ToolTip="CTT"><StackPanel Orientation="Horizontal"><Path Data="M20,6H16V4A2,2 0 0,0 14,2H10A2,2 0 0,0 8,4V6H4A2,2 0 0,0 2,8V18A2,2 0 0,0 4,20H20A2,2 0 0,0 22,18V8A2,2 0 0,0 20,6M10,4H14V6H10V4Z"/><TextBlock Text="CTT Utility"/></StackPanel></Button>
                <Button Name="btnNet" ToolTip="Network"><StackPanel Orientation="Horizontal"><Path Data="M12,2C6.48,2 2,6.48 2,12C2,17.52 6.48,22 12,22C17.52,22 22,17.52 22,12C22,6.48 17.52,2 12,2M11,19.93C7.05,19.44 4,16.08 4,12C4,11.38 4.08,10.79 4.21,10.21L9,15V16A2,2 0 0,0 11,18V19.93M17.9,17.39C17.64,16.58 16.9,16 16,16H15V13A1,1 0 0,0 14,12H8V10H10A1,1 0 0,0 11,9V7H13A2,2 0 0,0 15,5V4.59C18.39,5.5 20,8.5 20,12C20,14.08 19.2,15.97 17.9,17.39Z"/><TextBlock Text="Network Tools"/></StackPanel></Button>
                <Button Name="btnPower" ToolTip="Power Tools"><StackPanel Orientation="Horizontal"><Path Data="M12,15.5A3.5,3.5 0 0,1 8.5,12A3.5,3.5 0 0,1 12,8.5A3.5,3.5 0 0,1 15.5,12A3.5,3.5 0 0,1 12,15.5M19.43,12.97C19.47,12.65 19.5,12.33 19.5,12C19.5,11.67 19.47,11.35 19.43,11.03L21.54,9.37C21.73,9.22 21.78,8.95 21.66,8.73L19.66,5.27C19.54,5.05 19.27,4.96 19.05,5.05L16.56,6.05C16.04,5.66 15.5,5.32 14.87,5.07L14.5,2.42C14.46,2.18 14.25,2 14,2H10C9.75,2 9.54,2.18 9.5,2.42L9.13,5.07C8.5,5.32 7.96,5.66 7.44,6.05L4.95,5.05C4.73,4.96 4.46,5.05 4.34,5.27L2.34,8.73C2.21,8.95 2.27,9.22 2.46,9.37L4.57,11.03C4.53,11.35 4.5,11.67 4.5,12C4.5,12.33 4.53,12.65 4.57,12.97L2.46,14.63C2.27,14.78 2.21,15.05 2.34,15.27L4.34,18.73C4.46,18.95 4.73,19.04 4.95,18.95L7.44,17.95C7.96,18.34 8.5,18.68 9.13,18.93L9.5,21.58C9.54,21.82 9.75,22 10,22H14C14.25,22 14.46,21.82 14.5,21.58L14.87,18.93C15.5,18.68 16.04,18.34 16.56,17.95L19.05,18.95C19.27,19.04 19.54,18.95 19.66,18.73L21.66,15.27C21.78,15.05 21.73,14.78 21.54,14.63L19.43,12.97Z"/><TextBlock Text="Power Tools"/></StackPanel></Button>
                <Button Name="btnReg" ToolTip="Registry"><StackPanel Orientation="Horizontal"><Path Data="M12,3C7.58,3 4,4.79 4,7C4,9.21 7.58,11 12,11C16.42,11 20,9.21 20,7C20,4.79 16.42,3 12,3M4,9V12C4,14.21 7.58,16 12,16C16.42,16 20,14.21 20,12V9C20,11.21 16.42,13 12,13C7.58,13 4,11.21 4,9M4,14V17C4,19.21 7.58,21 12,21C16.42,21 20,19.21 20,17V14C20,16.21 16.42,18 12,18C7.58,18 4,16.21 4,14Z"/><TextBlock Text="Registry Tools"/></StackPanel></Button>
                <Button Name="btnDiscord" ToolTip="Discord Pro"><StackPanel Orientation="Horizontal"><Path Data="M20,2H4A2,2 0 0,0 2,4V22L6,18H20A2,2 0 0,0 22,16V4A2,2 0 0,0 20,2M6,9H18V11H6M14,14H6V12H14M18,8H6V6H18"/><TextBlock Text="Discord Pro"/></StackPanel></Button>
                <Button Name="btnAdobe" ToolTip="Adobe"><StackPanel Orientation="Horizontal"><Path Data="M17.5,12A1.5,1.5 0 0,1 16,10.5A1.5,1.5 0 0,1 17.5,9A1.5,1.5 0 0,1 19,10.5A1.5,1.5 0 0,1 17.5,12M14.5,8A1.5,1.5 0 0,1 13,6.5A1.5,1.5 0 0,1 14.5,5A1.5,1.5 0 0,1 16,6.5A1.5,1.5 0 0,1 14.5,8M9.5,8A1.5,1.5 0 0,1 8,6.5A1.5,1.5 0 0,1 9.5,5A1.5,1.5 0 0,1 11,6.5A1.5,1.5 0 0,1 9.5,8M6.5,12A1.5,1.5 0 0,1 5,10.5A1.5,1.5 0 0,1 6.5,9A1.5,1.5 0 0,1 8,10.5A1.5,1.5 0 0,1 6.5,12M12,3A9,9 0 0,0 3,12A9,9 0 0,0 12,21C12.32,21 12.5,20.81 12.5,20.5V19A2.5,2.5 0 0,1 15,16.5H16A3,3 0 0,0 19,13.5V12C19,7.03 15.86,3 12,3Z"/><TextBlock Text="Adobe Free"/></StackPanel></Button>
                <Button Name="btnRes" ToolTip="Fix Resolution"><StackPanel Orientation="Horizontal"><Path Data="M20,3H4C2.89,3 2,3.89 2,5V17A2,2 0 0,0 4,19H8V21H16V19H20A2,2 0 0,0 22,17V5C22,3.89 21.1,3 20,3M20,17H4V5H20V17Z"/><TextBlock Text="Fix Resolution"/></StackPanel></Button>
                <Button Name="btnShortcut" ToolTip="Create Shortcut"><StackPanel Orientation="Horizontal"><Path Data="M16,6H13V7.9H16C18.26,7.9 20.1,9.73 20.1,12A4.1,4.1 0 0,1 16,16.1H13V18H16A6,6 0 0,0 22,12C22,8.68 19.31,6 16,6M3.9,12C3.9,9.73 5.74,7.9 8,7.9H11V6H8A6,6 0 0,0 2,12A6,6 0 0,0 8,18H11V16.1H8C5.74,16.1 3.9,14.26 3.9,12M8,13H16V11H8V13Z"/><TextBlock Text="Add Shortcut"/></StackPanel></Button>
            </WrapPanel>
        </ScrollViewer>
    </Grid>
</Window>
"@

# -----------------------------------------------------------------------------------
# 3. BUILD WINDOW & LOGIC
# -----------------------------------------------------------------------------------
$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [Windows.Markup.XamlReader]::Load($reader)

# Map Controls
$pnlButtons = $window.FindName("pnlButtons")
$txtSysInfo = $window.FindName("txtSysInfo")
$btnWebsite = $window.FindName("btnWebsite")

# Map Buttons
$btnClean=$window.FindName("btnClean"); $btnRepair=$window.FindName("btnRepair"); $btnScan=$window.FindName("btnScan");
$btnReport=$window.FindName("btnReport"); $btnApps=$window.FindName("btnApps"); $btnIDM=$window.FindName("btnIDM");
$btnWinAct=$window.FindName("btnWinAct"); $btnSpotify=$window.FindName("btnSpotify"); $btnCTT=$window.FindName("btnCTT");
$btnNet=$window.FindName("btnNet"); $btnPower=$window.FindName("btnPower"); $btnReg=$window.FindName("btnReg");
$btnDiscord=$window.FindName("btnDiscord"); $btnAdobe=$window.FindName("btnAdobe"); $btnRes=$window.FindName("btnRes");
$btnShortcut=$window.FindName("btnShortcut");

# --- LOGIC ---

function Get-SysInfo {
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
        $comp = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
        $cpu = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
        $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction SilentlyContinue
        
        $ramGB = if ($comp) { [math]::Round($comp.TotalPhysicalMemory / 1GB, 1) } else { "N/A" }
        $diskFree = if ($disk) { [math]::Round($disk.FreeSpace / 1GB, 0) } else { "0" }
        $diskTotal = if ($disk) { [math]::Round($disk.Size / 1GB, 0) } else { "0" }

        $info = "User: $env:USERNAME | PC: $env:COMPUTERNAME`n" +
                "OS: $($os.Caption) ($($os.Version))`n" +
                "CPU: $($cpu.Name)`n" +
                "RAM: $ramGB GB | Disk (C:): $diskFree GB Free / $diskTotal GB Total"
        $txtSysInfo.Text = $info
        Write-Host "System Info Loaded." -ForegroundColor Green
    } catch {
        $txtSysInfo.Text = "Basic Info: $env:COMPUTERNAME"
        Write-Host "Basic Info Loaded (Detailed info failed)." -ForegroundColor Yellow
    }
}

# --- STABLE EXECUTION ENGINE (HOST OUTPUT) ---

$global:currentJob = $null
$timer = New-Object System.Windows.Threading.DispatcherTimer

$timer.Interval = [TimeSpan]::FromMilliseconds(200) # Fast poll for console feel
$timer.Add_Tick({
    if ($global:currentJob) {
        # 1. Get Output and Stream to Host
        $results = Receive-Job -Job $global:currentJob | Out-String
        if (-not [string]::IsNullOrWhiteSpace($results)) {
            Write-Host $results.Trim() -ForegroundColor White
        }
        
        # 2. Check errors
        if ($global:currentJob.Error.Count -gt 0) {
            $errors = $global:currentJob.Error | ForEach-Object { $_.ToString() }
            if ($errors) {
                Write-Host ($errors | Out-String).Trim() -ForegroundColor Red
                $global:currentJob.Error.Clear()
            }
        }

        # 3. Check if finished
        if ($global:currentJob.State -ne 'Running') {
            $timer.Stop()
            Remove-Job -Job $global:currentJob -Force
            $global:currentJob = $null
            
            # Re-enable UI
            $pnlButtons.Children | ForEach-Object { $_.IsEnabled = $true }
            Write-Host "`n[TASK COMPLETED]`n" -ForegroundColor Green
        }
    }
})

function Run-Tool {
    param([string]$FileName, [string]$Title)

    if ($global:currentJob) { return } # Prevent double click

    # Internal Module Check
    if (-not $EmbeddedModules.ContainsKey($FileName)) {
        [System.Windows.MessageBox]::Show("Embedded module missing: $FileName", "Error", 0, 16)
        return
    }

    Write-Host "`n----------------------------------------" -ForegroundColor Cyan
    Write-Host " STARTING: $Title" -ForegroundColor Cyan
    Write-Host "----------------------------------------" -ForegroundColor Cyan
    
    # Disable buttons
    $pnlButtons.Children | ForEach-Object { $_.IsEnabled = $false }

    # Start Job using Embedded Content
    $scriptContent = $EmbeddedModules[$FileName]
    $scriptBlock = [ScriptBlock]::Create($scriptContent)
    $global:currentJob = Start-Job -ScriptBlock $scriptBlock
    
    # Start Timer
    $timer.Start()
}

# -----------------------------------------------------------------------------------
# 4. EVENT BINDINGS
# -----------------------------------------------------------------------------------

$window.Add_Loaded({ Get-SysInfo })
$btnWebsite.Add_Click({ Start-Process "https://catsmoker.github.io" })

# Tool Bindings
$btnClean.Add_Click({ Run-Tool "CleanSystem.ps1" "Clean System" })
$btnRepair.Add_Click({ Run-Tool "SystemRepair.ps1" "System Repair" })
$btnScan.Add_Click({ Run-Tool "MalwareScan.ps1" "Malware Scan" })
$btnReport.Add_Click({ Run-Tool "SystemReport.ps1" "System Report" })
$btnApps.Add_Click({ Run-Tool "SoftwareManagement.ps1" "Software Management" })
$btnIDM.Add_Click({ Run-Tool "ActivateIDM.ps1" "Activate IDM" })
$btnWinAct.Add_Click({ Run-Tool "ActivateWindows.ps1" "Activate Windows" })
$btnSpotify.Add_Click({ Run-Tool "SpotifyPro.ps1" "Spotify Pro" })
$btnCTT.Add_Click({ Run-Tool "CTTUtility.ps1" "CTT Utility" })
$btnNet.Add_Click({ Run-Tool "NetworkTools.ps1" "Network Tools" })
$btnPower.Add_Click({ Run-Tool "PowerTools.ps1" "Power Tools" })
$btnReg.Add_Click({ Run-Tool "RegistryTools.ps1" "Registry Tools" })
$btnDiscord.Add_Click({ Run-Tool "DiscordPro.ps1" "Discord Pro" })
$btnAdobe.Add_Click({ Run-Tool "AdobeFree.ps1" "Adobe Free" })
$btnRes.Add_Click({ Run-Tool "FixResolution.ps1" "Fix Resolution" })
$btnShortcut.Add_Click({ Run-Tool "AddShortcut.ps1" "Create Shortcut" })

# -----------------------------------------------------------------------------------
# 5. EXECUTE
# -----------------------------------------------------------------------------------
$window.ShowDialog() | Out-Null

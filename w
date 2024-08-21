#============================================================================
#
# WARNING: DO NOT modify this file
#
#============================================================================
<#
.NOTES
    Author         : catsmoker
	Email          : boulhada08@gmail.com
	Website        : https://catsmoker.github.io
    GitHub         : https://github.com/catsmoker/cs_script
    Version        : 1.6
#>

# Check if the script is running on a supported operating system
$osVersion = [System.Environment]::OSVersion.Version
if ($osVersion.Major -lt 10 -or ($osVersion.Major -eq 10 -and $osVersion.Minor -lt 0))
{
    Write-Host "This script is only supported on Windows 10 or newer." -ForegroundColor Red
    Write-Host "Your current OS version is $($osVersion.Major).$($osVersion.Minor)."
    exit 1
}

# Check if the script is running with administrative privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    Write-Host "Requesting administrative privileges..." -NoNewline
    $currentPath = $MyInvocation.MyCommand.Definition
    if ($PSVersionTable.PSVersion.Major -ge 5)
    {
        # Use the new Start-Process cmdlet with the -Verb RunAs parameter
        Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$currentPath`""
    }
    else
    {
        # Use the old method of creating a new PowerShell process with the -Verb RunAs parameter
        $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$currentPath`""
        Start-Process "powershell.exe" -Verb RunAs -ArgumentList $arguments
    }
    exit
}

# Display the script header
Write-Host "                                                              cs Script v1.6" -ForegroundColor Green
Write-Host "                                                    Please run this as administrator" -ForegroundColor Yellow
Write-Host "                                                      'windows 10 & 11 64bit only'" -ForegroundColor Yellow

# Unblock the script if blocked by the system
Unblock-File -Path $MyInvocation.MyCommand.Definition

# Check if the script is running with the expected administrative privileges
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($currentUser.Owner.Value -ne "S-1-5-32-544")
{
    Write-Host "===========================================" -ForegroundColor Red
    Write-Host "-- Scripts must be run as Administrator ---" -ForegroundColor Red
    Write-Host "-- Right-Click Start -> Terminal(Admin) ---" -ForegroundColor Red
    Write-Host "===========================================" -ForegroundColor Red
    exit 1
}

Function Show-Menu {
    Clear-Host
    Write-Host "                                               cs Script v1.6 (by catsmoker) https://catsmoker.github.io"
    Write-Host "Select an option:"
    Write-Host "0. Clean Windows"
    Write-Host "1. Scan and Fix Windows"
    Write-Host "2. Download Specific Applications"
    Write-Host "3. Activate Windows"
    Write-Host "4. Download Atlas OS Playbook and AME Wizard"
    Write-Host "5. ctt Utility"
    Write-Host "x. Exit"
    $choice = Read-Host "Enter your choice (0-5, or x to exit)"
    Switch ($choice) {
        "0" { Clean-Windows }
        "1" { Fix-Windows }
        "2" { Download-Apps }
        "3" { Activate-Windows }
        "4" { Download-Playbook }
        "5" { Run-CTT }
        "x" { Exit-Script }
        Default { Write-Host "Invalid choice. Please enter a number between 0 to 5 or x."; Pause; Show-Menu }
    }
}

Function Run-CTT {
    Clear-Host
    Write-Host "Running The Ultimate Windows Utility by ctt..."
    Start-Process "powershell" -ArgumentList "iwr -useb https://christitus.com/win | iex"
    Start-Process "https://christitus.com/windows-tool/"
    Pause
    Show-Menu
}

Function Clean-Windows {
    Clear-Host
    Write-Host "Running Disk Cleanup..."
    Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/tuneup:1" -NoNewWindow -Wait
    Pause
    Show-Menu
}

Function Fix-Windows {
    Clear-Host
    Write-Host "Scanning and fixing Windows..."
    Start-Process -FilePath "sfc.exe" -ArgumentList "/scannow" -NoNewWindow -Wait
    Write-Host "Running DISM RestoreHealth..."
    Start-Process -FilePath "DISM.exe" -ArgumentList "/Online /Cleanup-Image /RestoreHealth" -NoNewWindow -Wait
    Write-Host "Done!"
    Pause
    Show-Menu
}

Function Download-Apps {
    Clear-Host
    Write-Host "Downloading specific applications..."
    Write-Host "Select an option:"
    Write-Host "0. all"
    Write-Host "1. Upgrade all packages"
    Write-Host "2. Firefox"
    Write-Host "3. qBittorrent"
    Write-Host "4. Neat Download Manager"
    Write-Host "5. mem reduct"
    Write-Host "6. VLC"
    Write-Host "7. bcuninstaller"
    Write-Host "8. Office 365 Pro Plus"
    Write-Host "x. Exit"
    $choice = Read-Host "Enter your choice (0-8 or x to exit)"

    Switch ($choice) {
        "0" { Install-All-Apps }
        "1" { Upgrade-Packages }
        "2" { Install-Firefox }
        "3" { Install-qBittorrent }
        "4" { Install-NeatDM }
        "5" { Install-MemReduct }
        "6" { Install-VLC }
        "7" { Install-BCU }
        "8" { Install-Office365 }
        "x" { Show-Menu }
        Default { Write-Host "Invalid choice. Please enter a number between 0 to 8 or x."; Pause; Download-Apps }
    }
}

Function Install-All-Apps {
    Clear-Host
    Write-Host "Upgrading all packages using winget..."
    winget upgrade --all
    Install-VLC
    Install-Firefox
    Install-qBittorrent
    Install-MemReduct
    Install-BCU
    Install-NeatDM
    Install-Office365
    Show-Menu
}

Function Upgrade-Packages {
    Clear-Host
    Write-Host "Upgrading all packages using winget..."
    winget upgrade --all
    If ($LASTEXITCODE -ne 0) {
        Write-Host "Please go to https://winget.run/"
        Pause
        Show-Menu
    }
    Write-Host "Done!"
    Pause
    Show-Menu
}

Function Install-VLC {
    Clear-Host
    Write-Host "Installing VLC..."
    winget install -e --id VideoLAN.VLC
    If ($LASTEXITCODE -ne 0) {
        Write-Host "Installation failed. Please go to https://www.videolan.org/vlc/"
        Pause
        Show-Menu
    }
    Write-Host "Done!"
    Pause
    Show-Menu
}

Function Install-Firefox {
    Clear-Host
    Write-Host "Installing Firefox..."
    winget install -e --id Mozilla.Firefox
    If ($LASTEXITCODE -ne 0) {
        Write-Host "Installation failed. Please go to https://www.mozilla.org/en-US/firefox/new/"
        Pause
        Show-Menu
    }
    Write-Host "Done!"
    Pause
    Show-Menu
}

Function Install-qBittorrent {
    Clear-Host
    Write-Host "Installing qBittorrent..."
    winget install -e --id qBittorrent.qBittorrent
    If ($LASTEXITCODE -ne 0) {
        Write-Host "Installation failed. Please go to https://www.qbittorrent.org/download"
        Pause
        Show-Menu
    }
    Write-Host "Done!"
    Pause
    Show-Menu
}

Function Install-NeatDM {
    Clear-Host
    Write-Host "Installing Neat Download Manager..."
    winget install -e --id JavadMotallebi.NeatDownloadManager
    If ($LASTEXITCODE -ne 0) {
        Write-Host "winget installation failed."
        Write-Host "Please go to https://www.neatdownloadmanager.com/index.php/en/"
        $outputPath = [System.IO.Path]::Combine([System.Environment]::GetFolderPath('Desktop'), 'NeatDM_setup.exe')
        Invoke-WebRequest -Uri 'https://www.neatdownloadmanager.com/file/NeatDM_setup.exe' -OutFile $outputPath
        Start-Process -FilePath $outputPath -Wait
        Write-Host "Downloading to Desktop complete."
        Pause
        Show-Menu
    }
    Write-Host "Done!"
    Pause
    Show-Menu
}

Function Install-MemReduct {
    Clear-Host
    Write-Host "Downloading mem reduct..."
    winget install -e --id Henry++.MemReduct
    If ($LASTEXITCODE -ne 0) {
        Write-Host "Installation failed. Please go to https://github.com/henrypp/memreduct/releases"
        Pause
        Show-Menu
    }
    Write-Host "Done!"
    Pause
    Show-Menu
}

Function Install-BCU {
    Clear-Host
    Write-Host "Downloading BC Uninstaller..."
    winget install -e --id Klocman.BulkCrapUninstaller
    If ($LASTEXITCODE -ne 0) {
        Write-Host "Installation failed. Please go to https://www.bcuninstaller.com/"
        Pause
        Show-Menu
    }
    Write-Host "Done!"
    Pause
    Show-Menu
}

Function Install-Office365 {
    Clear-Host
    Write-Host "Downloading Office 365 Pro Plus..."
    $outputPath = [System.IO.Path]::Combine([System.Environment]::GetFolderPath('Desktop'), 'OfficeSetup_2.exe')
    Invoke-WebRequest -Uri 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=O365ProPlusRetail&platform=x64&language=en-us&version=O16GA' -OutFile $outputPath
    Start-Process -FilePath $outputPath -Wait
    Write-Host "Done!"
    Pause
    Show-Menu
}

Function Activate-Windows {
    Clear-Host
    Write-Host "Activating Windows..."
    Write-Host "                             use PowerShell (Recommended)"
    Write-Host "       1. Right-click on the Windows start menu and select PowerShell or Terminal (Not CMD)."
    Write-Host "       2. Copy and paste the code below and press enter"
    Write-Host "       3. irm https://get.activated.win | iex"
    Start-Process "powershell" -ArgumentList "irm https://get.activated.win | iex"
    Start-Process "https://github.com/massgravel/Microsoft-Activation-Scripts?tab=readme-ov-file#download--how-to-use-it"
    Write-Host "Done!"
    Pause
    Show-Menu
}

Function Download-Playbook {
    Clear-Host
    Write-Host "Making a Download file on Desktop..."
    $downloadsPath = [System.IO.Path]::Combine([System.Environment]::GetFolderPath('Desktop'), 'CS Downloads')
    New-Item -Path $downloadsPath -ItemType Directory -ErrorAction SilentlyContinue | Out-Null

    Write-Host "Downloading Atlas OS playbook..."
    $atlasPath = [System.IO.Path]::Combine($downloadsPath, 'AtlasPlaybook_v0.4.0.zip')
    Invoke-WebRequest -Uri 'https://github.com/Atlas-OS/Atlas/releases/download/0.4.0/AtlasPlaybook_v0.4.0.zip' -OutFile $atlasPath
	
	Write-Host "Downloading AME Wizard to Desktop..."
    $amePath = [System.IO.Path]::Combine($downloadsPath, 'AME Wizard Beta.zip')
	Invoke-WebRequest -Uri 'https://download.ameliorated.io/AME%20Wizard%20Beta.zip' -OutFile $amePath
    Write-Host "Please visit https://atlasos.net/"
    Start-Process "https://atlasos.net/"

    Write-Host "Downloads completed successfully!"
    Pause
    Show-Menu
}

Function Exit-Script {
    Clear-Host
    Write-Host "Exiting script."
    Start-Process "https://catsmoker.github.io"
    Pause
    Exit
}

Show-Menu

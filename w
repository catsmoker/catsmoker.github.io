#============================================================================
#
# WARNING: DO NOT modify this file!
#
#============================================================================
<#
.NOTES
    Author         : catsmoker
    Email          : boulhada08@gmail.com
    Website        : https://catsmoker.github.io
    GitHub         : https://github.com/catsmoker/cs_script
    Version        : 1.7
#>

                                                      

# Check if the script is running as administrator
Write-Host "Checking if running as administrator..."
$adminCheck = [System.Security.Principal.WindowsPrincipal] [System.Security.Principal.WindowsIdentity]::GetCurrent()
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
if (-not $adminCheck.IsInRole($adminRole)) {

# text
$separator = "============================================================="
$adminMessage = "$warningSymbol  Attention Required!  $warningSymbol"
Write-Host $separator -ForegroundColor Yellow
Write-Host ""
Write-Host $adminMessage -ForegroundColor Red -BackgroundColor Black
Write-Host ""
Write-Host "Oops! It looks like this script is not running with administrator privileges." -ForegroundColor Magenta
Write-Host "For optimal performance and access to all features, we need to restart this script with elevated rights." -ForegroundColor Magenta
Write-Host ""
Write-Host "Attempting to relaunch with administrative privileges... Please wait." -ForegroundColor Green
Write-Host ""
Write-Host $separator -ForegroundColor Yellow

# Restart the script with administrative privileges
$newProcess = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs -Wait
exit
} else {
Write-Host "Script is running as administrator."
}

# Check if the script is running on a supported operating system
$osVersion = [System.Environment]::OSVersion.Version
if ($osVersion.Major -lt 10 -or ($osVersion.Major -eq 10 -and $osVersion.Minor -lt 0)) {
    Write-Host "This script is only supported on Windows 10 or newer." -ForegroundColor Red
    Write-Host "Your current OS version is $($osVersion.Major).$($osVersion.Minor)."
    exit
}

# Define the path to the shortcut and the target PowerShell command
$shortcutPath = [System.IO.Path]::Combine([System.Environment]::GetFolderPath('Desktop'), 'CS_script.lnk')
$targetPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
$arguments = "-NoProfile -ExecutionPolicy Bypass -Command `"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command 'irm https://catsmoker.github.io/w | iex'`""

# Define the URL for the icon and the path to save it locally
$iconUrl = "https://catsmoker.github.io/assets/ico/favicon.ico"
$localIconPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), 'favicon.ico')

# Download the icon file
Invoke-WebRequest -Uri $iconUrl -OutFile $localIconPath

# Create a WScript.Shell COM object to create the shortcut
$wshShell = New-Object -ComObject WScript.Shell
$shortcut = $wshShell.CreateShortcut($shortcutPath)

# Set the properties of the shortcut
$shortcut.TargetPath = $targetPath
$shortcut.Arguments = $arguments
$shortcut.WorkingDirectory = [System.IO.Path]::GetDirectoryName($targetPath)
$shortcut.IconLocation = $localIconPath

# Save the shortcut
$shortcut.Save()

# Window Title
$Host.UI.RawUI.WindowTitle = "catsmoker: cs_script"

# Change text color to Green and background color to Black
$host.UI.RawUI.ForegroundColor = "Green"
$host.UI.RawUI.BackgroundColor = "Black"

# start
Function Show-Menu {
    Clear-Host
Write-Host " "
Write-Host "                               ________  ________   ________  ________  ________  ___  ________  _________   " -ForegroundColor Cyan
Write-Host "                              |\   ____\|\   ____\ |\   ____\|\   ____\|\   __  \|\  \|\   __  \|\___   ___\ " -ForegroundColor Cyan
Write-Host "                              \ \  \___|\ \  \___|_\ \  \___|\ \  \___|\ \  \|\  \ \  \ \  \|\  \|___ \  \_| " -ForegroundColor Cyan
Write-Host "                               \ \  \    \ \_____  \\ \_____  \ \  \    \ \   _  _\ \  \ \   ____\   \ \  \  " -ForegroundColor Cyan
Write-Host "                                \ \  \____\|____|\  \\|____|\  \ \  \____\ \  \\  \\ \  \ \  \___|    \ \  \ " -ForegroundColor Cyan
Write-Host "                                 \ \_______\____\_\  \ ____\_\  \ \_______\ \__\\ _\\ \__\ \__\        \ \__\" -ForegroundColor Cyan
Write-Host "                                  \|_______|\_________\\_________\|_______|\|__|\|__|\|__|\|__|         \|__|" -ForegroundColor Cyan
Write-Host "                                           \|_________\|_________|                                           " -ForegroundColor Cyan
	Write-Host " "
	Write-Host " "
    Write-Host "                                               cs Script v1.7 (by catsmoker) https://catsmoker.github.io"
    Write-Host " "
	Write-Host " "
    Write-Host "            Select an option:"
    Write-Host " "
	Write-Host " "
    Write-Host "            0. Clean Windows"
    Write-Host " "
    Write-Host "            1. Scan and Fix Windows"
    Write-Host " "
    Write-Host "            2. apps / drivers / updates / fixes"
    Write-Host " "
    Write-Host "            3. Activate Windows"
    Write-Host " "
    Write-Host "            4. Atlas OS Playbook and AME Wizard"
    Write-Host " "
    Write-Host "            5. CTT Utility"
    Write-Host " "
    Write-Host "            x. Exit"
    Write-Host " "
    Write-Host " "
    $choice = Read-Host "Enter your choice (0-5, or x to exit)"
    Switch ($choice) {
        "0" { Clean-Windows }
        "1" { Fix-Windows }
        "2" { Download-Apps }
        "3" { Activate-Windows }
        "4" { Download-Playbook }
        "5" { Run-CTT }
        "x" { Exit-Script }
		"f" { Trigger-f }
        Default { Write-Host "Invalid choice. Please enter a number between 0 to 5 or x."; Pause; Show-Menu }
    }
}

# Define what happens when "f" is typed
function Trigger-f {
    Clear-Host
    Write-Host "Invalid choice. Please enter a number between 0 to 4 or x."
	Write-Host " "
    Write-Host "F in the chat for respects!"
	Write-Host " "
    Write-Host "But wait... why are you pressing F?! You okay?"
	Write-Host " "

    # Ask user to press a key
    $input = Read-Host "Press 'f' to get f**ked or any other key to return to the menu"
    
    # Check if they pressed "f"
    if ($input -eq 'f') {
        Write-Host "You pressed 'f'. Shutting down the computer..."
        # Shutdown the computer
         Stop-Computer
    }
    else {
        Write-Host "You didn't press 'f'. Returning to the menu..."
        Show-Menu  # Assuming Show-Menu is another function you've defined
    }
}

Function Run-CTT {
    Clear-Host
    Write-Host "Running The Ultimate Windows Utility by CTT..."
    Start-Process "powershell" -ArgumentList "iwr -useb https://christitus.com/win | iex"
    Pause
    Show-Menu
}

Function Clean-Windows {
    Clear-Host
    Write-Host "Starting cleanup process..." -ForegroundColor Cyan
    
    # Start timer to track process duration
    $startTime = Get-Date

    # Clean Global Temp Folder
    $globalTempPath = [System.IO.Path]::GetTempPath()
    Write-Host "Clearing global temp folder: $globalTempPath"

    $globalFiles = Get-ChildItem -Path $globalTempPath -Recurse -Force -ErrorAction SilentlyContinue
    $count = 0
    foreach ($file in $globalFiles) {
        $count++
        Write-Progress -Activity "Cleaning global temp folder" -Status "Deleting file $count of $($globalFiles.Count)" -PercentComplete (($count / $globalFiles.Count) * 100)
        Remove-Item -Path $file.FullName -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Progress -Activity "Cleaning global temp folder" -Completed

    # Clean User Temp Folder
    $userTempPath = $env:TEMP
    Write-Host "Clearing user temp folder: $userTempPath"

    $userFiles = Get-ChildItem -Path $userTempPath -Recurse -Force -ErrorAction SilentlyContinue
    $count = 0
    foreach ($file in $userFiles) {
        $count++
        Write-Progress -Activity "Cleaning user temp folder" -Status "Deleting file $count of $($userFiles.Count)" -PercentComplete (($count / $userFiles.Count) * 100)
        Remove-Item -Path $file.FullName -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Progress -Activity "Cleaning user temp folder" -Completed

    # Clean Windows Prefetch Folder
    $prefetchPath = "$env:windir\Prefetch"
    Write-Host "Clearing Windows prefetch folder: $prefetchPath"

    $prefetchFiles = Get-ChildItem -Path $prefetchPath -Recurse -Force -ErrorAction SilentlyContinue
    $count = 0
    foreach ($file in $prefetchFiles) {
        $count++
        Write-Progress -Activity "Cleaning prefetch folder" -Status "Deleting file $count of $($prefetchFiles.Count)" -PercentComplete (($count / $prefetchFiles.Count) * 100)
        Remove-Item -Path $file.FullName -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Progress -Activity "Cleaning prefetch folder" -Completed

    # Clean Recycle Bin
    Write-Host "Emptying Recycle Bin..."
    $null = (New-Object -ComObject Shell.Application).NameSpace(0xA).Items() | ForEach-Object { $_.InvokeVerb("delete") }

    # Clear Windows Update Cache
    $windowsUpdatePath = "$env:windir\SoftwareDistribution\Download"
    Write-Host "Clearing Windows Update cache: $windowsUpdatePath"
    
    $windowsUpdateFiles = Get-ChildItem -Path $windowsUpdatePath -Recurse -Force -ErrorAction SilentlyContinue
    $count = 0
    foreach ($file in $windowsUpdateFiles) {
        $count++
        Write-Progress -Activity "Cleaning Windows Update cache" -Status "Deleting file $count of $($windowsUpdateFiles.Count)" -PercentComplete (($count / $windowsUpdateFiles.Count) * 100)
        Remove-Item -Path $file.FullName -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Progress -Activity "Cleaning Windows Update cache" -Completed

    # Clear Browser Cache (Chrome, Firefox, Edge)
    # Chrome Cache
    $chromeCachePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache"
    if (Test-Path $chromeCachePath) {
        Write-Host "Clearing Chrome browser cache..."
        Get-ChildItem -Path $chromeCachePath -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Firefox Cache
    $firefoxCachePath = "$env:APPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path $firefoxCachePath) {
        Write-Host "Clearing Firefox browser cache..."
        Get-ChildItem -Path $firefoxCachePath -Recurse -Force -Include "cache2" -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Edge Cache
    $edgeCachePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache"
    if (Test-Path $edgeCachePath) {
        Write-Host "Clearing Edge browser cache..."
        Get-ChildItem -Path $edgeCachePath -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Clean Windows Thumbnail Cache
    $thumbnailCachePath = "$env:LOCALAPPDATA\Microsoft\Windows\Explorer"
    Write-Host "Clearing Windows thumbnail cache: $thumbnailCachePath"
    
    Get-ChildItem -Path $thumbnailCachePath -Recurse -Include "*.db" -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

    # Clean Temporary Internet Files
    Write-Host "Clearing Internet Explorer/Edge temporary internet files..."
    RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 8  # 8 = Temporary Internet Files

    # Run Disk Cleanup
    Write-Host "Running Disk Cleanup..."
    $diskCleanupPath = "$env:windir\System32\cleanmgr.exe"
    Start-Process -FilePath $diskCleanupPath -ArgumentList "/sagerun:1" -Wait

    # Calculate and display elapsed time
    $elapsedTime = (Get-Date) - $startTime
    Write-Host "Cleanup completed in $($elapsedTime.TotalSeconds) seconds." -ForegroundColor Green

    Pause
    Show-Menu
}

Function Fix-Windows {
    Clear-Host
    Write-Host "Starting Windows repair process..." -ForegroundColor Cyan
    
    # Start timer to track process duration
    $startTime = Get-Date
    
    Write-Host "Running chkdsk..." -ForegroundColor Yellow
    Start-Process -FilePath "chkdsk.exe" -ArgumentList "/scan /perf" -NoNewWindow -Wait
    Write-Host "chkdsk completed." -ForegroundColor Green

    Write-Host "Running sfc /scannow..." -ForegroundColor Yellow
    Start-Process -FilePath "sfc.exe" -ArgumentList "/scannow" -NoNewWindow -Wait
    Write-Host "sfc completed." -ForegroundColor Green

    Write-Host "Running DISM..." -ForegroundColor Yellow
    Start-Process -FilePath "DISM.exe" -ArgumentList "/Online /Cleanup-Image /RestoreHealth" -NoNewWindow -Wait
    Write-Host "DISM completed." -ForegroundColor Green

    Write-Host "Running sfc again in case DISM repaired system files..." -ForegroundColor Yellow
    Start-Process -FilePath "sfc.exe" -ArgumentList "/scannow" -NoNewWindow -Wait
    Write-Host "Second sfc scan completed." -ForegroundColor Green
    
    # Calculate and display elapsed time
    $elapsedTime = (Get-Date) - $startTime
    Write-Host "Windows repair process completed in $($elapsedTime.TotalMinutes) minutes." -ForegroundColor Green

    Pause
    Show-Menu
}


Function Download-Apps {
    Clear-Host
    Write-Host "Downloading specific applications and drivers..."
	Write-Host " "
    Write-Host "                Select an option:"
	Write-Host " "
    Write-Host "     0. Upgrade all"
	Write-Host " "
    Write-Host "     1. Drivers / updates"
	Write-Host " "
    Write-Host "     2. Applications"
	Write-Host " "
	Write-Host "     3. Fix Digital Flat Panel (640x480 60Hz) problem"
	Write-Host " "
	Write-Host "--------------------------------------------------------------"
	Write-Host " "
	Write-Host "             more apps here:"
	Write-Host " "
	Write-Host "     4. neat"
	Write-Host " "
    Write-Host "     5. Office 365"
	Write-Host " "
 	Write-Host "--------------------------------------------------------------"
  	Write-Host " "
    Write-Host "     x. Exit"
	Write-Host " "
    $choice = Read-Host "Enter your choice (0-5, or x to exit)"
    Switch ($choice) {
        "0" { Upgrade-All }
        "1" { Install-Drivers }
        "2" { Install-apps }
        "3" { cru }
	"4" { Install-neat }
        "5" { Install-Office365 }
        "x" { Show-Menu }
        Default { Write-Host "Invalid choice. Please enter a number between 0 to 5 or x."; Pause; Download-Apps }
    }
}

Function Upgrade-All {
    Write-Host "Upgrading all packages using winget..." -NoNewline
    winget upgrade --all
    Write-Host "Done!"
    Pause
    Download-Apps
}

Function Install-apps {
# URL of the cloud script
$cloudScriptUrl = "https://catsmoker.github.io/installapps"
# Run the cloud-based script
Write-Host "Running the cloud script..." -ForegroundColor Cyan
Start-Process "powershell" -ArgumentList "iwr -useb $cloudScriptUrl | iex"
Write-Host "Script execution completed." -ForegroundColor Green
Write-Host "Done!"
Pause
Download-Apps
}

Function cru {
    Write-Host "cru website..." -NoNewline
    Start-Process "https://www.monitortests.com/forum/Thread-Custom-Resolution-Utility-CRU"
    Write-Host "Done!"
    Pause
    Download-Apps
}

Function Install-neat {
    Write-Host "Installing Neat Download Manager..." -NoNewline
    winget install -e --id JavadMotallebi.NeatDownloadManager
    if ($LASTEXITCODE -ne 0) {
        Write-Host "winget installation failed."
        Write-Host "Please go to https://www.neatdownloadmanager.com/index.php/en/"
        Invoke-WebRequest -Uri 'https://www.neatdownloadmanager.com/file/NeatDM_setup.exe' -OutFile (Join-Path -Path $env:USERPROFILE -ChildPath 'Desktop\NeatDM_setup.exe')
        Start-Process -Wait -FilePath (Join-Path -Path $env:USERPROFILE -ChildPath 'Desktop\NeatDM_setup.exe')
        Write-Host "Downloading to Desktop complete."
        Pause
        Download-Apps
        return
    }
    Write-Host "Done!"
    Pause
    Download-Apps
}

Function Install-Office365 {
    Write-Host "Downloading Office 365 Pro Plus"
    Write-Host "Please go to https://gravesoft.dev/office_c2r_links"
    Invoke-WebRequest -Uri 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=O365ProPlusRetail&platform=x64&language=en-us&version=O16GA' -OutFile (Join-Path -Path $env:USERPROFILE -ChildPath 'Desktop\OfficeSetup_2.exe')
    Start-Process -Wait -FilePath (Join-Path -Path $env:USERPROFILE -ChildPath 'Desktop\OfficeSetup_2.exe')
    Write-Host "Downloading to Desktop complete."
    Pause
    Download-Apps
}

Function Install-Drivers {
    Clear-Host
    Write-Host " Downloading:          drivers / updates..."
	Write-Host " "
	Write-Host "       0. windows updates minitool"
	Write-Host " "
	Write-Host "       1. windows updates using powershell"
	Write-Host " "
    Write-Host "       2. intel"
	Write-Host " "
    Write-Host "       3. amd"
	Write-Host " "
    Write-Host "       4. nvidia"
	Write-Host " "
	Write-Host "       x. Exit"
	Write-Host " "
    Write-Host "Note: Some driver updates may require a system restart to take effect."
$choice = Read-Host "Enter your choice (0-4, or x to exit)"
    Switch ($choice) {
		"0" { windows-update }
		"1" { windows-ps }
        "2" { intel }
        "3" { amd }
        "4" { nvidia }
        "x" { Download-Apps }
        Default { Write-Host "Invalid choice. Please enter a number between 0 to 4 or x."; Pause; Install-Drivers }
    }
}

Function windows-update {
    Write-Host "windows updates minitool website..." -NoNewline
    Start-Process "https://www.majorgeeks.com/mg/getmirror/windows_update_minitool,1.html"
    Write-Host "Done!"
    Pause
    Install-Drivers
}

Function windows-ps {
    Write-Host "windows updates using ps..." -NoNewline
Install-Module PSWindowsUpdate
Add-WUServiceManager -MicrosoftUpdate
Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot | Out-File "C:\($env.computername-Get-Date -f yyyy-MM-dd)-MSUpdates.log" -Force
    Write-Host "Done!"
    Pause
    Install-Drivers
}

Function intel {
    Write-Host "intel..." -NoNewline
    Start-Process "https://www.intel.com/content/www/us/en/support/intel-driver-support-assistant.html"
    Write-Host "Done!"
    Pause
    Install-Drivers
}

Function amd {
    Write-Host "amd..." -NoNewline
    Start-Process "https://www.amd.com/en/support/download/drivers.html"
    Write-Host "Done!"
    Pause
    Install-Drivers
}

Function nvidia {
    Write-Host "nvidia..." -NoNewline
    Start-Process "https://www.nvidia.com/en-us/geforce/geforce-experience/"
    Write-Host "Done!"
    Pause
    Install-Drivers
}

Function Activate-Windows {
    Clear-Host
    Write-Host "Activating Windows..."
    Start-Process "powershell" -ArgumentList "irm https://get.activated.win | iex"
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

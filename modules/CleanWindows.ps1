Clear-Host
$statusLabel.Text = "Cleaning Windows..."
$progressBar.Value = 0
$mainForm.Refresh()

$totalTasks = 0
$completedTasks = 0

function Update-ProgressStatus {
    param (
        [string]$TaskName,
        [int]$CurrentValue,
        [int]$MaxValue
    )
    $statusLabel.Text = "Cleaning Windows: $TaskName"
    if ($MaxValue -gt 0) {
        $progressBar.Value = (($completedTasks + ($CurrentValue / $MaxValue)) / $totalTasks) * 100
    } else {
        $progressBar.Value = (($completedTasks) / $totalTasks) * 100
    }
    $mainForm.Refresh()
}

$cleaningTasks = @(
    "Global Temp Folder", "User Temp Folder", "Windows Temp Files", "Prefetch Files",
    "DNS Cache", "Browser Caches (Edge, Chrome, Firefox)", "Old User Profiles"
)
$totalTasks = $cleaningTasks.Count

Update-ProgressStatus "Global Temp Folder" 0 1
$globalTempPath = [System.IO.Path]::GetTempPath()
Write-Host "Clearing global temp folder: $globalTempPath"
$globalFiles = Get-ChildItem -Path $globalTempPath -Recurse -Force -ErrorAction SilentlyContinue
$count = 0
foreach ($file in $globalFiles) {
    $count++
    Update-ProgressStatus "Global Temp Folder" $count $globalFiles.Count
    Remove-Item -Path $file.FullName -Recurse -Force -ErrorAction SilentlyContinue
}
$completedTasks++

Update-ProgressStatus "User Temp Folder" 0 1
$userTempPath = $env:TEMP
Write-Host "Clearing user temp folder: $userTempPath"
$userFiles = Get-ChildItem -Path $userTempPath -Recurse -Force -ErrorAction SilentlyContinue
$count = 0
foreach ($file in $userFiles) {
    $count++
    Update-ProgressStatus "User Temp Folder" $count $userFiles.Count
    Remove-Item -Path $file.FullName -Recurse -Force -ErrorAction SilentlyContinue
}
$completedTasks++

Update-ProgressStatus "Windows Temp Files" 0 1
Write-Host "Deleting temporary files from C:\Windows\Temp..."
Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
$completedTasks++

Update-ProgressStatus "Prefetch Files" 0 1
Write-Host "Deleting prefetch files..."
Remove-Item -Path "C:\Windows\Prefetch\*" -Recurse -Force -ErrorAction SilentlyContinue
$completedTasks++

Update-ProgressStatus "DNS Cache" 0 1
Write-Host "Flushing DNS Cache..."
ipconfig /flushdns | Out-Null
$completedTasks++

Update-ProgressStatus "Browser Caches (Edge, Chrome, Firefox)" 0 1
Write-Host "Clearing browser caches..."
Write-Host "  Clearing Microsoft Edge cache..."
$edgeCachePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache\*"
Remove-Item -Path $edgeCachePath -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "  Clearing Google Chrome cache..."
$chromeCachePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache\*"
Remove-Item -Path $chromeCachePath -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "  Clearing Mozilla Firefox cache..."
$firefoxProfilesBase = "$env:APPDATA\Mozilla\Firefox\Profiles\"
if (Test-Path $firefoxProfilesBase -PathType Container) {
    Get-ChildItem -Path $firefoxProfilesBase -Directory | ForEach-Object {
        $firefoxProfilePath = $_.FullName
        Remove-Item -Path "$firefoxProfilePath\Cache2\entries\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$firefoxProfilePath\startupCache\*" -Recurse -Force -ErrorAction SilentlyContinue
    }
} else {
    Write-Output "  Firefox profiles directory not found: $firefoxProfilesBase (Firefox might not be installed or used by this user)."
}
$completedTasks++

Update-ProgressStatus "Old User Profiles" 0 1
Write-Host "Checking for and removing old user profiles..."
$currentUsers = @($env:USERNAME, "Public", "Default", "Default User", "All Users")
Get-CimInstance -Class Win32_UserProfile | Where-Object {
    $_.LocalPath -notmatch "C:\\Users\\($($currentUsers -join '|'))" -and
    $_.Special -eq $false -and
    $_.Loaded -eq $false
} | ForEach-Object {
    Write-Host "  Removing old user profile: $($_.LocalPath)"
    try {
        $_.Delete()
        Write-Host "    Successfully removed $($_.LocalPath)"
    } catch {
        Write-Warning "    Failed to delete profile $($_.LocalPath): $($_.Exception.Message)"
    }
}
$completedTasks++

$progressBar.Value = 100
$statusLabel.Text = "Cleanup completed!"
$mainForm.Refresh()
Write-Host "All specified cleaning tasks have been completed!"
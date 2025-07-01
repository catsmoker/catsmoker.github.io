$toolsForm = New-Object System.Windows.Forms.Form
$toolsForm.Text = "Power Tools | AetherKit"
$toolsForm.Size = New-Object System.Drawing.Size(480, 320)
$toolsForm.StartPosition = "CenterScreen"
$toolsForm.BackColor = [System.Drawing.Color]::FromArgb(25, 25, 30)
$toolsForm.ForeColor = [System.Drawing.Color]::White
$toolsForm.FormBorderStyle = 'FixedDialog'
$toolsForm.MaximizeBox = $false
$toolsForm.Font = New-Object System.Drawing.Font("Segoe UI", 10)

$headerLabel = New-Object System.Windows.Forms.Label
$headerLabel.Text = "Advanced System Tools"
$headerLabel.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
$headerLabel.Size = New-Object System.Drawing.Size(440, 30)
$headerLabel.Location = New-Object System.Drawing.Point(20, 15)
$headerLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$toolsForm.Controls.Add($headerLabel)

$disableUpdates = New-ToolButton -Text "Disable Updates" -X 30 -Y 60 -ClickAction {
    $statusLabel.Text = "Disabling Windows Updates..."; $mainForm.Refresh()
    Set-Service -Name wuauserv -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
    [System.Windows.Forms.MessageBox]::Show("Windows Update service has been stopped and set to disabled.", "Complete", "OK", "Information")
    $statusLabel.Text = "Windows Updates disabled"
} -TooltipText "Disable Windows automatic updates service"
$toolsForm.Controls.Add($disableUpdates)

$enableUpdates = New-ToolButton -Text "Enable Updates" -X 250 -Y 60 -ClickAction {
    $statusLabel.Text = "Enabling Windows Updates..."; $mainForm.Refresh()
    Set-Service -Name wuauserv -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name wuauserv -ErrorAction SilentlyContinue
    [System.Windows.Forms.MessageBox]::Show("Windows Update service has been started and set to automatic.", "Complete", "OK", "Information")
    $statusLabel.Text = "Windows Updates enabled"
} -TooltipText "Enable Windows automatic updates service"
$toolsForm.Controls.Add($enableUpdates)

$disableDefender = New-ToolButton -Text "Disable Defender" -X 30 -Y 110 -ClickAction {
    $statusLabel.Text = "Disabling Windows Defender..."; $mainForm.Refresh()
    try { Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop } catch { [System.Windows.Forms.MessageBox]::Show("Could not disable Defender. It might be managed by another policy or antivirus.", "Error", "OK", "Error") }
    [System.Windows.Forms.MessageBox]::Show("Attempted to disable Windows Defender real-time protection.", "Complete", "OK", "Information")
    $statusLabel.Text = "Windows Defender disabled (Attempted)"
} -TooltipText "Disable Windows Defender real-time protection"
$toolsForm.Controls.Add($disableDefender)

$enableDefender = New-ToolButton -Text "Enable Defender" -X 250 -Y 110 -ClickAction {
    $statusLabel.Text = "Enabling Windows Defender..."; $mainForm.Refresh()
    try { Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop } catch { [System.Windows.Forms.MessageBox]::Show("Could not enable Defender. It might be managed by another policy or antivirus.", "Error", "OK", "Error") }
    [System.Windows.Forms.MessageBox]::Show("Attempted to enable Windows Defender real-time protection.", "Complete", "OK", "Information")
    $statusLabel.Text = "Windows Defender enabled (Attempted)"
} -TooltipText "Enable Windows Defender real-time protection"
$toolsForm.Controls.Add($enableDefender)

$disableTelemetry = New-ToolButton -Text "Disable Telemetry" -X 30 -Y 160 -ClickAction {
    $statusLabel.Text = "Disabling telemetry..."; $mainForm.Refresh()
    $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
    Set-ItemProperty -Path $path -Name "AllowTelemetry" -Value 0 -ErrorAction SilentlyContinue
    [System.Windows.Forms.MessageBox]::Show("Basic telemetry disabled. A reboot may be required.", "Complete", "OK", "Information")
    $statusLabel.Text = "Telemetry disabled"
} -TooltipText "Disable Windows telemetry via registry"
$toolsForm.Controls.Add($disableTelemetry)

$repairStartMenu = New-ToolButton -Text "Repair Start Menu" -X 250 -Y 160 -ClickAction {
    $statusLabel.Text = "Repairing Start Menu..."; $mainForm.Refresh()
    Get-AppXPackage -AllUsers | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    [System.Windows.Forms.MessageBox]::Show("Attempted to re-register all built-in apps to repair Start Menu. This may take some time.", "Process Started", "OK", "Information")
    $statusLabel.Text = "Start Menu repair process finished."
} -TooltipText "Re-registers all UWP apps to fix Start Menu issues"
$toolsForm.Controls.Add($repairStartMenu)

$closeButton = New-ToolButton -Text "Close" -X 140 -Y 220 -ClickAction { $toolsForm.Close() } -TooltipText "Close this window"
$closeButton.Size = New-Object System.Drawing.Size(200, 40)
$toolsForm.Controls.Add($closeButton)

[void]$toolsForm.ShowDialog($mainForm)
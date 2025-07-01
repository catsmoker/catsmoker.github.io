Function Set-DNS {
    param($Primary, $Secondary)
    $statusLabel.Text = "Setting DNS servers..."; $progressBar.Value = 0; $mainForm.Refresh()
    try {
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        $count = 0
        foreach ($adapter in $adapters) {
            $count++
            $progressBar.Value = ($count / $adapters.Count) * 100; $mainForm.Refresh()
            Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses $Primary,$Secondary
        }
        $progressBar.Value = 100
        [System.Windows.Forms.MessageBox]::Show("DNS set to $Primary/$Secondary for all active adapters.", "DNS Updated", "OK", "Information")
        $statusLabel.Text = "DNS configuration updated"
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to set DNS: $($_.Exception.Message)", "Error", "OK", "Error")
        $statusLabel.Text = "DNS configuration failed"
    }
    $mainForm.Refresh()
}

Function Reset-DNS {
    $statusLabel.Text = "Resetting DNS to DHCP..."; $progressBar.Value = 0; $mainForm.Refresh()
    try {
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        $count = 0
        foreach ($adapter in $adapters) {
            $count++
            $progressBar.Value = ($count / $adapters.Count) * 100; $mainForm.Refresh()
            Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ResetServerAddresses
        }
        $progressBar.Value = 100
        [System.Windows.Forms.MessageBox]::Show("DNS reset to DHCP for all active adapters.", "DNS Reset", "OK", "Information")
        $statusLabel.Text = "DNS reset completed"
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to reset DNS: $($_.Exception.Message)", "Error", "OK", "Error")
        $statusLabel.Text = "DNS reset failed"
    }
    $mainForm.Refresh()
}

Function Reset-NetworkAdapters {
    $statusLabel.Text = "Resetting network adapters..."; $progressBar.Value = 0; $mainForm.Refresh()
    try {
        $adapters = Get-NetAdapter
        $count = 0
        foreach ($adapter in $adapters) {
            $count++
            $progressBar.Value = ($count / $adapters.Count) * 50; $mainForm.Refresh()
            Disable-NetAdapter -Name $adapter.Name -Confirm:$false
        }
        foreach ($adapter in $adapters) {
            $count++
            $progressBar.Value = 50 + (($count - $adapters.Count) / $adapters.Count) * 50; $mainForm.Refresh()
            Enable-NetAdapter -Name $adapter.Name -Confirm:$false
        }
        $progressBar.Value = 100
        [System.Windows.Forms.MessageBox]::Show("All network adapters have been reset.", "Reset Complete", "OK", "Information")
        $statusLabel.Text = "Network adapters reset"
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to reset adapters: $($_.Exception.Message)", "Error", "OK", "Error")
        $statusLabel.Text = "Adapter reset failed"
    }
    $mainForm.Refresh()
}

$netForm = New-Object System.Windows.Forms.Form
$netForm.Text = "Network Tools | AetherKit"
$netForm.Size = New-Object System.Drawing.Size(480, 380)
$netForm.StartPosition = "CenterScreen"
$netForm.BackColor = [System.Drawing.Color]::FromArgb(25, 25, 30)
$netForm.ForeColor = [System.Drawing.Color]::White
$netForm.FormBorderStyle = 'FixedDialog'
$netForm.MaximizeBox = $false
$netForm.Font = New-Object System.Drawing.Font("Segoe UI", 10)

$headerLabel = New-Object System.Windows.Forms.Label
$headerLabel.Text = "Network Configuration Tools"
$headerLabel.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
$headerLabel.Size = New-Object System.Drawing.Size(440, 30)
$headerLabel.Location = New-Object System.Drawing.Point(20, 15)
$headerLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$netForm.Controls.Add($headerLabel)

$dnsGoogle = New-ToolButton -Text "Google DNS" -X 30 -Y 60 -ClickAction { Set-DNS -Primary "8.8.8.8" -Secondary "8.8.4.4" } -TooltipText "Set DNS to Google (8.8.8.8 and 8.8.4.4)"
$netForm.Controls.Add($dnsGoogle)

$dnsCloudflare = New-ToolButton -Text "Cloudflare DNS" -X 250 -Y 60 -ClickAction { Set-DNS -Primary "1.1.1.1" -Secondary "1.0.0.1" } -TooltipText "Set DNS to Cloudflare (1.1.1.1 and 1.0.0.1)"
$netForm.Controls.Add($dnsCloudflare)

$dnsReset = New-ToolButton -Text "Reset to DHCP" -X 30 -Y 110 -ClickAction { Reset-DNS } -TooltipText "Reset DNS to automatic (DHCP)"
$netForm.Controls.Add($dnsReset)

$netInfo = New-ToolButton -Text "Network Info" -X 250 -Y 110 -ClickAction { ipconfig /all | Out-GridView -Title "Network Information" } -TooltipText "Display detailed network configuration"
$netForm.Controls.Add($netInfo)

$netReset = New-ToolButton -Text "Reset Adapters" -X 30 -Y 160 -ClickAction { Reset-NetworkAdapters } -TooltipText "Restart all network adapters"
$netForm.Controls.Add($netReset)

$flushDNS = New-ToolButton -Text "Flush DNS" -X 250 -Y 160 -ClickAction {
    ipconfig /flushdns
    [System.Windows.Forms.MessageBox]::Show("DNS cache has been flushed.", "DNS Flushed", "OK", "Information")
} -TooltipText "Clear DNS resolver cache"
$netForm.Controls.Add($flushDNS)

$ipRenew = New-ToolButton -Text "Renew IP" -X 30 -Y 210 -ClickAction {
    ipconfig /release; ipconfig /renew
    [System.Windows.Forms.MessageBox]::Show("IP address has been released and renewed.", "IP Renewed", "OK", "Information")
} -TooltipText "Release and renew IP address"
$netForm.Controls.Add($ipRenew)

$winsockReset = New-ToolButton -Text "Reset Winsock" -X 250 -Y 210 -ClickAction {
    netsh winsock reset
    [System.Windows.Forms.MessageBox]::Show("Winsock catalog has been reset. A reboot is recommended.", "Winsock Reset", "OK", "Warning")
} -TooltipText "Reset Winsock catalog to default"
$netForm.Controls.Add($winsockReset)

$closeButton = New-ToolButton -Text "Close" -X 140 -Y 280 -ClickAction { $netForm.Close() } -TooltipText "Close this window"
$closeButton.Size = New-Object System.Drawing.Size(200, 40)
$netForm.Controls.Add($closeButton)

[void]$netForm.ShowDialog($mainForm)
<# .SYNOPSIS Quick OS Install Date Check #>
Write-Host "--- OS INSTALL AGE ---" -ForegroundColor Cyan
Get-CimInstance Win32_OperatingSystem | Select-Object @{Name='OS';Expression={$_.Caption}}, Version, BuildNumber, @{Name='InstallDateLocal';Expression={($_.InstallDate).ToLocalTime()}} | Format-List
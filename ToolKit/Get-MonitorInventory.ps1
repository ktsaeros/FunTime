<#
.SYNOPSIS
    Retrieves Monitor Serial Numbers (decoded from EDID) and active Resolutions.
    Useful for remote asset auditing.
#>

$Monitors = Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID -ErrorAction SilentlyContinue
$Video    = Get-CimInstance -ClassName Win32_VideoController | Select-Object CurrentHorizontalResolution, CurrentVerticalResolution, VideoModeDescription

Write-Host "--- DISPLAY INVENTORY ---" -ForegroundColor Cyan

# 1. Hardware Details (Serials)
if ($Monitors) {
    foreach ($Mon in $Monitors) {
        # Decode the binary arrays
        $Manuf = ($Mon.ManufacturerName -notmatch 0 | ForEach-Object { [char]$_ }) -join ""
        $Name  = ($Mon.UserFriendlyName -notmatch 0 | ForEach-Object { [char]$_ }) -join ""
        $Serial= ($Mon.SerialNumberID   -notmatch 0 | ForEach-Object { [char]$_ }) -join ""
        
        [PSCustomObject]@{
            Type         = "Hardware"
            Manufacturer = $Manuf
            Model        = $Name
            SerialNumber = $Serial
            WeekOfManuf  = $Mon.WeekOfManufacture
            YearOfManuf  = $Mon.YearOfManufacture
        } | Format-List
    }
} else {
    Write-Warning "Could not retrieve WmiMonitorID (Monitor might be generic or VM)."
}

# 2. Logical Resolution
Write-Host "--- LOGICAL RESOLUTION ---" -ForegroundColor Cyan
if ($Video) {
    $Video | Format-Table -AutoSize
} else {
    Write-Warning "No active video controller found."
}
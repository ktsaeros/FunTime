<#
.SYNOPSIS
    Safer Monitor Inventory (v2)
    Added Try/Catch blocks to prevent RMM crashes on bad WMI drivers.
#>

Write-Host "--- DISPLAY INVENTORY ---" -ForegroundColor Cyan

try {
    # 1. Hardware Details (Serials)
    $Monitors = Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID -ErrorAction Stop
    
    if ($Monitors) {
        foreach ($Mon in $Monitors) {
            # Safely decode arrays
            try {
                $Manuf  = ($Mon.ManufacturerName -notmatch 0 | ForEach-Object { [char]$_ }) -join ""
                $Name   = ($Mon.UserFriendlyName -notmatch 0 | ForEach-Object { [char]$_ }) -join ""
                $Serial = ($Mon.SerialNumberID   -notmatch 0 | ForEach-Object { [char]$_ }) -join ""
                
                [PSCustomObject]@{
                    Type         = "Hardware"
                    Manufacturer = $Manuf
                    Model        = $Name
                    SerialNumber = $Serial
                    Year         = $Mon.YearOfManufacture
                } | Format-List
            } catch {
                Write-Warning "Failed to decode monitor data: $($_.Exception.Message)"
            }
        }
    } else {
        Write-Warning "No WmiMonitorID objects found (Generic Monitor or VM)."
    }
} catch {
    Write-Warning "WMI Monitor Query Failed. This is common on older drivers."
    Write-Host "Error Details: $($_.Exception.Message)" -ForegroundColor Red
}

# 2. Logical Resolution
Write-Host "`n--- LOGICAL RESOLUTION ---" -ForegroundColor Cyan
try {
    $Video = Get-CimInstance -ClassName Win32_VideoController -ErrorAction Stop
    if ($Video) {
        $Video | Select-Object VideoModeDescription, CurrentHorizontalResolution, CurrentVerticalResolution | Format-Table -AutoSize
    } else {
        Write-Warning "No active video controller found."
    }
} catch {
    Write-Warning "Failed to query Video Controller."
}
<#
.SYNOPSIS
  Like RAM2, but robustly handles 1+ channels without Format-Table errors.
#>

# … your lookup tables & Decode-SMBiosDevice function here …
# … your steps 1) through 3) (CIM + SMBIOS parse + merge) here …

# ----------------------
#  4) Per-Channel Columns
# ----------------------
# Build up your basic summary
$array      = Get-CimInstance Win32_PhysicalMemoryArray
$modules    = Get-CimInstance Win32_PhysicalMemory
$maxCapGB   = [math]::Round($array.MaxCapacity/1MB,2)
$totalSlots = $array.MemoryDevices
$usedSlots  = $modules.Count
$installedGB= [math]::Round(($modules | Measure-Object Capacity -Sum).Sum/1GB,2)
$speeds     = $modules |
               Group-Object ConfiguredClockSpeed |
               Sort-Object Name |
               ForEach-Object { "$($_.Name) MT/s ×$($_.Count)" }

# Merge CIM+SMBIOS into $report as before…

# Determine unique channels
$channels = ($report.Channel | Sort-Object -Unique) -ne ''

# Prepare rows
$dataRows = @(
  'Manufacturer','BankLabel','DeviceLocator',
  'CapacityGB','SpeedMTs','MemoryType','TypeDetail','SerialNumber'
) | ForEach-Object {
  $prop = $_
  $row  = [ordered]@{ Property = $prop }
  foreach ($chan in $channels) {
    $val = ($report | Where-Object Channel -EQ $chan | Select-Object -Expand $prop)
    $row[$chan] = $val -join ', '
  }
  [PSCustomObject]$row
}

# Always include “Property” plus exactly the channels you found
$props = @('Property') + $channels

# Output the summary
"Maximum supported RAM:   $maxCapGB GB"
"Physical slots:           $usedSlots of $totalSlots"
"Currently installed:      $installedGB GB"
"Module speeds summary:    $($speeds -join ', ')"
""

# Render the per-channel table—no nulls, no errors
$dataRows | Format-Table -AutoSize -Property $props

"`n—and now the raw CIM table:`n"

# … your final detailed table here …
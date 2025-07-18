<#
.SYNOPSIS
  Reports maximum supported RAM, slot usage, module speeds & per-channel totals,
  and then shows a detailed table of each DIMM.

#>

# 1) Array info
$array      = Get-CimInstance Win32_PhysicalMemoryArray
$maxCapGB   = [math]::Round($array.MaxCapacity / 1MB, 2)
$totalSlots = $array.MemoryDevices

# 2) Module list
$modules = Get-CimInstance Win32_PhysicalMemory

# 3) Installed capacity
$installedGB = [math]::Round(($modules | Measure-Object Capacity -Sum).Sum / 1GB, 2)

# 4) Slot usage
$usedSlots = $modules.Count

# 5) Speed summary
$sPEED = $modules |
  Group-Object ConfiguredClockSpeed |
  Sort-Object Name |
  ForEach-Object { "$($_.Name) MHz ×$($_.Count)" }

# 6) Per-channel totals
$channelTotals = $modules |
  ForEach-Object {
    [PSCustomObject]@{
      Channel    = ($_.DeviceLocator -split '-')[0]
      CapacityGB = [math]::Round($_.Capacity / 1GB, 2)
    }
  } |
  Group-Object Channel |
  Sort-Object Name |
  ForEach-Object {
    $c = $_.Name
    $gb = ($_.Group | Measure-Object CapacityGB -Sum).Sum
    "{0}: {1} GB" -f $c, $gb
  }

# 7) Print the summary
"Maximum supported RAM:   $maxCapGB GB"
"Physical slots:           $usedSlots of $totalSlots"
"Currently installed:      $installedGB GB"
"Module speeds:            $($sPEED -join ', ')"
"Per-channel capacities:   $($channelTotals -join ', ')"
""

# 8) And now the detailed table
$modules |
  Select-Object `
    Manufacturer, `
    BankLabel, `
    @{n='SpeedMHz';e={$_.ConfiguredClockSpeed}}, `
    DeviceLocator, `
    @{n='CapacityGB';e={[math]::Round($_.Capacity/1GB,2)}}, `
    TypeDetail, `
    SerialNumber |
  Format-Table -AutoSize
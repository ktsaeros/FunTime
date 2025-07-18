<#
.SYNOPSIS
  Reports max RAM, slot usage, speeds, and per-channel details (with manufacturer, type & serial),
  then prints a detailed table of each DIMM.
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
$speedSummary = $modules |
  Group-Object ConfiguredClockSpeed |
  Sort-Object Name |
  ForEach-Object { "$($_.Name) MHz ×$($_.Count)" }

# 6) Per-channel enriched info
$channelDetails = $modules |
  Group-Object { ($_.DeviceLocator -split '-')[0] } |
  Sort-Object Name |
  ForEach-Object {
    $channel = $_.Name
    # For each module in this channel, build "ChannelA: 8 GB, BANK 0, Manufacturer = RAMAXEL, Type = 128, Serial = 12850EA0"
    $_.Group | ForEach-Object {
      $gb   = [math]::Round($_.Capacity/1GB,2)
      $bank = $_.BankLabel
      $man  = $_.Manufacturer
      $type = $_.TypeDetail
      $sn   = $_.SerialNumber
      "{0}: {1} GB, {2}, Manufacturer = {3}, Type = {4}, Serial = {5}" -f $channel, $gb, $bank, $man, $type, $sn
    }
  }

# 7) Print the summary
"Maximum supported RAM:   $maxCapGB GB"
"Physical slots:           $usedSlots of $totalSlots"
"Currently installed:      $installedGB GB"
"Module speeds:            $($speedSummary -join ', ')"
"Per-channel details:      " 
$channelDetails | ForEach-Object { "  $_" }
""

# 8) And the detailed table again
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
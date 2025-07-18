# Get-MemoryInfo.ps1
$array      = Get-CimInstance Win32_PhysicalMemoryArray
$maxCapGB   = [math]::Round($array.MaxCapacity / 1MB, 2)
$totalSlots = $array.MemoryDevices

$modules        = Get-CimInstance Win32_PhysicalMemory
$installedBytes = ($modules | Measure-Object -Property Capacity -Sum).Sum
$installedGB    = [math]::Round($installedBytes / 1GB, 2)
$usedSlots      = $modules.Count

$speedGroups = $modules |
  Group-Object ConfiguredClockSpeed |
  Sort-Object Name |
  ForEach-Object { "$($_.Name) MHz ×$($_.Count)" }

$channelInfo = $modules |
  ForEach-Object {
    $chan = ($_.DeviceLocator -split '-')[0]
    [PSCustomObject]@{
      Channel    = $chan
      CapacityGB = [math]::Round($_.Capacity / 1GB, 2)
    }
  } |
  Group-Object Channel |
  Sort-Object Name |
  ForEach-Object {
    $chanName = $_.Name
    $totalGB  = ($_.Group | Measure-Object CapacityGB -Sum).Sum
    "${chanName}: ${totalGB} GB"
  }

"Maximum supported RAM:   $maxCapGB GB"
"Physical slots:           $usedSlots of $totalSlots"
"Currently installed:      $installedGB GB"
"Module speeds:            $($speedGroups -join ', ')"
"Per-channel capacities:   $($channelInfo -join ', ')"
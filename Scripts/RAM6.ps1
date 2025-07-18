<#
.SYNOPSIS
  Complete RAM report that always shows:
    • Maximum vs. installed vs. slots
    • Speed summary
    • Columnar per-channel table (even if only one stick)
    • Raw CIM table for reference
#>

# -------------------------------
# 1) Gather basic CIM data
# -------------------------------
$array       = Get-CimInstance Win32_PhysicalMemoryArray
$modules     = Get-CimInstance Win32_PhysicalMemory
$totalSlots  = $array.MemoryDevices
$usedSlots   = $modules.Count
$maxCapGB    = [math]::Round($array.MaxCapacity / 1MB, 2)
$installedGB = [math]::Round(( $modules | Measure-Object Capacity -Sum ).Sum / 1GB, 2)

# Speed summary (MT/s)
$speeds = $modules |
  Group-Object ConfiguredClockSpeed |
  Sort-Object Name |
  ForEach-Object { "$($_.Name) MT/s ×$($_.Count)" }

# -------------------------------
# 2) Decode SMBIOS (type 17) for each stick
# -------------------------------
# lookup tables omitted for brevity — assume Decode-SMBiosDevice is defined above exactly as before
$rawTables = (Get-WmiObject -Namespace root\wmi -Class MSSmBios_RawSMBiosTables).SMBiosData
$idx       = 0
$smbiosList = @()
while ($true) {
  $type = $rawTables[$idx]
  if ($type -eq 127) { break }
  $len  = $rawTables[$idx+1]
  if ($type -eq 17) {
    $smbiosList += Decode-SMBiosDevice -Raw $rawTables -Offset $idx
  }
  $idx += $len
  while ([BitConverter]::ToUInt16($rawTables,$idx) -ne 0) { $idx++ }
  $idx += 2
}

# -------------------------------
# 3) Merge CIM + SMBIOS into $report
# -------------------------------
$report = for ($i = 0; $i -lt $modules.Count; $i++) {
  $m = $modules[$i]
  $s = $smbiosList[$i]
  [PSCustomObject]@{
    Channel       = ($m.DeviceLocator -split '-')[0]
    Manufacturer  = $m.Manufacturer
    BankLabel     = $m.BankLabel
    DeviceLocator = $m.DeviceLocator
    CapacityGB    = $s.CapacityGB
    SpeedMTs      = $s.SpeedMTs
    MemoryType    = $s.MemoryType
    TypeDetail    = $s.TypeDetail
    SerialNumber  = $m.SerialNumber
  }
}

# -------------------------------
# 4) Build the per-channel matrix
# -------------------------------
# detect channels (always an array of names, even if only one)
$channels = @($report.Channel | Sort-Object -Unique)

# prepare rows for each property
$dataRows = @(
  'Manufacturer','BankLabel','DeviceLocator',
  'CapacityGB','SpeedMTs','MemoryType','TypeDetail','SerialNumber'
) | ForEach-Object {
  $prop = $_
  $row  = [ordered]@{ Property = $prop }
  foreach ($c in $channels) {
    $row[$c] = ($report | Where-Object Channel -EQ $c | Select-Object -Expand $prop) -join ', '
  }
  [PSCustomObject]$row
}

# -------------------------------
# 5) Output
# -------------------------------
"Maximum supported RAM:   $maxCapGB GB"
"Physical slots:           $usedSlots of $totalSlots"
"Currently installed:      $installedGB GB"
"Module speeds summary:    $($speeds -join ', ')"
""

# Columnar table: always Property + each channel
$dataRows | Format-Table -AutoSize -Property ( @('Property') + $channels )

"`n—and now the raw CIM table:`n"
# raw table as before
$modules |
  Select-Object Manufacturer,BankLabel,
    @{n='SpeedMHz';e={$_.ConfiguredClockSpeed}},
    DeviceLocator,
    @{n='CapacityGB';e={[math]::Round($_.Capacity/1GB,2)}},
    TypeDetail,SerialNumber |
  Format-Table -AutoSize
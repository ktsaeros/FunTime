<#
.SYNOPSIS
  Robust RAM report. Always prints one column per populated channel,
  with Manufacturer/BankLabel/Locator/Capacity/Speed/Type/Detail/Serial,
  plus raw CIM table at the end.
#>

# -----------------------------------------------------------------------------
#  SMBIOS lookup tables & decoder
# -----------------------------------------------------------------------------
[string[]]$FORM_FACTORS   = @('Invalid','Other','Unknown','SIMM','SIP','Chip','DIP','ZIP',
                             'Proprietary Card','DIMM','TSOP','Row of chips','RIMM','SODIMM','SRIMM','FB-DIMM','Die')
[string[]]$MEMORY_TYPES   = @('Invalid','Other','Unknown','DRAM','EDRAM','VRAM','SRAM','RAM',
                             'ROM','FLASH','EEPROM','FEPROM','EPROM','CDRAM','3DRAM','SDRAM',
                             'SGRAM','RDRAM','DDR','DDR2','DDR2 FB-DIMM','Reserved','Reserved','Reserved',
                             'DDR3','FBD2','DDR4','LPDDR','LPDDR2','LPDDR3','LPDDR4','Logical non-volatile device',
                             'HBM','HBM2','DDR5','LPDDR5')
[string[]]$TYPE_DETAILS   = @('Reserved','Other','Unknown','Fast-paged','Static column','Pseudo-static','RAMBUS','Synchronous',
                             'CMOS','EDO','Window DRAM','Cache DRAM','Non-volatile','Registered','Unbuffered','LRDIMM')

function Decode-SMBiosDevice {
  param([byte[]]$Raw, [int]$Offset)
  $len  = $Raw[$Offset+1]
  $data = $Raw[$Offset..($Offset + $len - 1)]

  # Capacity
  $sizeVal = [BitConverter]::ToUInt16($data,0x0C)
  if    ($sizeVal -eq 0xFFFF) { $size = [BitConverter]::ToUInt32($data,0x1C) }
  elseif (($sizeVal -shr 15) -eq 0) { $size = $sizeVal * 1MB }
  else { $size = ($sizeVal -band 0x7FFF) * 1KB }
  $CapacityGB = [math]::Round($size/1GB,2)

  # Form factor & type
  $FormFactor = $FORM_FACTORS[$data[0x0E]]
  $MemoryType = $MEMORY_TYPES[$data[0x12]]

  # TypeDetail flags
  $td = [BitConverter]::ToUInt16($data,0x13)
  $DetailFlags = (0..15 |
    Where-Object { $td -band (1 -shl $_) } |
    ForEach-Object { $TYPE_DETAILS[$_] }
  ) -join ' | '
  $TypeDetail = "0x{0:X2} ({1})" -f $td, $DetailFlags

  # Speed
  $sp = [BitConverter]::ToUInt16($data,0x15)
  $SpeedMTs = if ($sp -eq 0xFFFF) { [BitConverter]::ToUInt32($data,0x54) } else { $sp }

  return [PSCustomObject]@{
    CapacityGB = $CapacityGB
    FormFactor = $FormFactor
    MemoryType = $MemoryType
    TypeDetail = $TypeDetail
    SpeedMTs   = $SpeedMTs
  }
}

# -----------------------------------------------------------------------------
#  1) Gather CIM info & summary
# -----------------------------------------------------------------------------
$array       = Get-CimInstance Win32_PhysicalMemoryArray
$modules     = Get-CimInstance Win32_PhysicalMemory
$maxCapGB    = [math]::Round($array.MaxCapacity/1MB,2)
$totalSlots  = $array.MemoryDevices
$usedSlots   = $modules.Count
$installedGB = [math]::Round(($modules | Measure-Object Capacity -Sum).Sum/1GB,2)

$speeds = $modules |
  Group-Object ConfiguredClockSpeed |
  Sort-Object Name |
  ForEach-Object { "$($_.Name) MT/s ×$($_.Count)" }

# -----------------------------------------------------------------------------
#  2) Parse raw SMBIOS tables for each Memory Device (type 17)
# -----------------------------------------------------------------------------
$rawTables    = (Get-WmiObject -Namespace root\wmi -Class MSSmBios_RawSMBiosTables).SMBiosData
$index        = 0
$deviceSMBIOS = New-Object System.Collections.Generic.List[PSObject]

while ($true) {
  $type = $rawTables[$index]
  if ($type -eq 127) { break }
  $len = $rawTables[$index+1]
  if ($type -eq 17) {
    $deviceSMBIOS.Add((Decode-SMBiosDevice -Raw $rawTables -Offset $index))
  }
  $index += $len
  while ([BitConverter]::ToUInt16($rawTables,$index) -ne 0) { $index++ }
  $index += 2
}

# -----------------------------------------------------------------------------
#  3) Merge CIM + SMBIOS into a single $report per slot
# -----------------------------------------------------------------------------
$report = for ($i = 0; $i -lt $modules.Count; $i++) {
  $mod = $modules[$i]
  $smb = $deviceSMBIOS[$i]
  [PSCustomObject]@{
    Channel       = ($mod.DeviceLocator -split '-')[0]
    Manufacturer  = $mod.Manufacturer
    BankLabel     = $mod.BankLabel
    DeviceLocator = $mod.DeviceLocator
    CapacityGB    = $smb.CapacityGB
    SpeedMTs      = $smb.SpeedMTs
    MemoryType    = $smb.MemoryType
    TypeDetail    = $smb.TypeDetail
    SerialNumber  = $mod.SerialNumber
  }
}

# -----------------------------------------------------------------------------
#  4) Build & render per-channel columnar table
# -----------------------------------------------------------------------------
# Detect channel names (always strings, no nulls)
$channels = $report.Channel | Sort-Object -Unique

# Prepare table rows
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

# Summary
"Maximum supported RAM:   $maxCapGB GB"
"Physical slots:           $usedSlots of $totalSlots"
"Currently installed:      $installedGB GB"
"Module speeds summary:    $($speeds -join ', ')"
""

# ----------------------
#  Render per-channel table
# ----------------------

# 1) Force $channels to be a non-empty string array
$channels = @($channels | Where-Object { $_ -and $_.Trim() })

# 2) Build the list of columns: always "Property" plus each channel name
$props = @('Property') + $channels

# 3) Render with Format-Table, passing the entire $props array as the -Property argument
$dataRows | Format-Table -AutoSize -Property ( $props )

"`n—and now the raw CIM table:`n"

# -----------------------------------------------------------------------------
#  5) Raw detailed CIM table (for reference)
# -----------------------------------------------------------------------------
$modules |
  Select-Object Manufacturer, BankLabel,
    @{n='SpeedMHz';  e={$_.ConfiguredClockSpeed}},
    DeviceLocator,
    @{n='CapacityGB';e={[math]::Round($_.Capacity/1GB,2)}},
    TypeDetail, SerialNumber |
  Format-Table -AutoSize
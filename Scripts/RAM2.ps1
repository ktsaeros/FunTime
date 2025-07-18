<#
.SYNOPSIS
  Comprehensive RAM report:
    • Max supported, slots used, installed GB
    • Speeds summary
    • Per-channel columnar report including:
        Manufacturer, BankLabel, DeviceLocator, CapacityGB, Speed,
        MemoryType (DDR4, DDR5…), TypeDetail (Synchronous…), SerialNumber
    • Detailed table at the end
#>

# ----------------------
#  Lookup tables (SMBIOS spec)
# ----------------------
[string[]]$FORM_FACTORS = @(
  'Invalid','Other','Unknown','SIMM','SIP','Chip','DIP','ZIP',
  'Proprietary Card','DIMM','TSOP','Row of chips','RIMM','SODIMM','SRIMM','FB-DIMM','Die'
)
[string[]]$MEMORY_TYPES = @(
  'Invalid','Other','Unknown','DRAM','EDRAM','VRAM','SRAM','RAM',
  'ROM','FLASH','EEPROM','FEPROM','EPROM','CDRAM','3DRAM','SDRAM',
  'SGRAM','RDRAM','DDR','DDR2','DDR2 FB-DIMM','Reserved','Reserved','Reserved',
  'DDR3','FBD2','DDR4','LPDDR','LPDDR2','LPDDR3','LPDDR4','Logical non-volatile device',
  'HBM','HBM2','DDR5','LPDDR5'
)
[string[]]$TYPE_DETAILS = @(
  'Reserved','Other','Unknown','Fast-paged','Static column','Pseudo-static','RAMBUS','Synchronous',
  'CMOS','EDO','Window DRAM','Cache DRAM','Non-volatile','Registered','Unbuffered','LRDIMM'
)

function Decode-SMBiosDevice {
  param([byte[]]$Raw, [int]$Offset)
  $len = $Raw[$Offset+1]
  $data = $Raw[$Offset..($Offset + $len - 1)]

  # Size in bytes
  $sizeVal = [BitConverter]::ToUInt16($data,0x0C)
  if    ($sizeVal -eq 0xFFFF) { $size = [BitConverter]::ToUInt32($data,0x1C) }
  elseif (($sizeVal -shr 15) -eq 0) { $size = $sizeVal * 1MB }
  else { $size = ($sizeVal -band 0x7FFF) * 1KB }
  $CapacityGB = [math]::Round($size/1GB,2)

  # FormFactor
  $ff = $data[0x0E]
  $FormFactor = $FORM_FACTORS[$ff]

  # MemoryType
  $mt = $data[0x12]
  $MemoryType = $MEMORY_TYPES[$mt]

  # TypeDetail bitmask
  $td = [BitConverter]::ToUInt16($data,0x13)
  $DetailFlags = (0..15 | Where-Object { ($td -band (1 -shl $_)) } |
                   ForEach-Object { $TYPE_DETAILS[$_] }) -join ' | '

  # Speed
  $sp = [BitConverter]::ToUInt16($data,0x15)
  if ($sp -eq 0xFFFF) { $Speed = [BitConverter]::ToUInt32($data,0x54) }
  else { $Speed = $sp }

  return [PSCustomObject]@{
    CapacityGB    = $CapacityGB
    FormFactor    = $FormFactor
    MemoryType    = $MemoryType
    TypeDetail    = "0x{0:X2} ({1})" -f $td, $DetailFlags
    SpeedMTs      = $Speed
  }
}

# ----------------------
#  1) Basic CIM info
# ----------------------
$array      = Get-CimInstance Win32_PhysicalMemoryArray
$modules    = Get-CimInstance Win32_PhysicalMemory
$maxCapGB   = [math]::Round($array.MaxCapacity/1MB,2)
$usedSlots  = $modules.Count
$totalSlots = $array.MemoryDevices
$installedGB= [math]::Round(($modules | Measure-Object Capacity -Sum).Sum/1GB,2)

# Speed summary
$speeds = $modules |
  Group-Object ConfiguredClockSpeed |
  Sort-Object Name |
  ForEach-Object { "$($_.Name) MT/s ×$($_.Count)" }

# ----------------------
#  2) SMBIOS parse
# ----------------------
$rawTables = (Get-WmiObject -Namespace root\wmi -Class MSSmBios_RawSMBiosTables).SMBiosData
# Walk tables until type 17 (Memory Device)
$index     = 0
$deviceSMBIOS = @()
while ($true) {
  $type = $rawTables[$index]
  if ($type -eq 127) { break }
  $length = $rawTables[$index+1]
  if ($type -eq 17) {
    $deviceSMBIOS += Decode-SMBiosDevice -Raw $rawTables -Offset $index
  }
  # skip formatted + strings
  $index += $length
  while ([BitConverter]::ToUInt16($rawTables,$index) -ne 0) { $index++ }
  $index += 2
}

# ----------------------
#  3) Merge CIM + SMBIOS per module
# ----------------------
$report = for ($i=0; $i -lt $modules.Count; $i++) {
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

# ----------------------
#  4) Per-Channel Columns
# ----------------------
$channels = $report.Channel | Sort-Object -Unique
Write-Host "Maximum supported RAM:   $maxCapGB GB"
Write-Host "Physical slots:           $usedSlots of $totalSlots"
Write-Host "Currently installed:      $installedGB GB"
Write-Host "Module speeds summary:    $($speeds -join ', ')"
Write-Host ""

# Build a table with one column per channel
$colNames = @('Property') + $channels
$dataRows = @(
  'Manufacturer',
  'BankLabel',
  'DeviceLocator',
  'CapacityGB',
  'SpeedMTs',
  'MemoryType',
  'TypeDetail',
  'SerialNumber'
) | ForEach-Object { $prop = $_
    $row = [ordered]@{ Property = $prop }
    foreach ($chan in $channels) {
      $val = ($report | Where-Object Channel -EQ $chan | Select-Object -ExpandProperty $prop)
      $row[$chan] = $val -join ', '
    }
    New-Object PSObject -Property $row
}

$dataRows | Format-Table -AutoSize -Property Property, $channels

Write-Host "`n—and now the raw CIM table:`n"

# ----------------------
#  5) Raw detailed table
# ----------------------
$modules |
  Select-Object Manufacturer,BankLabel,
    @{n='SpeedMHz';e={$_.ConfiguredClockSpeed}},
    DeviceLocator,
    @{n='CapacityGB';e={[math]::Round($_.Capacity/1GB,2)}},
    TypeDetail,SerialNumber |
  Format-Table -AutoSize
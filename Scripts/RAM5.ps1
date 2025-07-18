<#
.SYNOPSIS
  RAM5.ps1 – summary + per‐channel columnar report + raw CIM table,
  handling 1+ channels seamlessly, with DDR type & TypeDetail text.
#>

# ----------------------------
#  SMBIOS lookup tables & decoder
# ----------------------------
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
  $len  = $Raw[$Offset+1]
  $data = $Raw[$Offset..($Offset + $len - 1)]

  # Capacity
  $sizeVal = [BitConverter]::ToUInt16($data,0x0C)
  if    ($sizeVal -eq 0xFFFF)             { $size = [BitConverter]::ToUInt32($data,0x1C) }
  elseif (($sizeVal -shr 15) -eq 0)        { $size = $sizeVal * 1MB }
  else                                     { $size = ($sizeVal -band 0x7FFF) * 1KB }
  $CapacityGB = [math]::Round($size/1GB,2)

  # Memory form factor (unused) and type
  $FormFactor = $FORM_FACTORS[$data[0x0E]]
  $MemoryType = $MEMORY_TYPES[$data[0x12]]

  # TypeDetail
  $td = [BitConverter]::ToUInt16($data,0x13)
  $DetailFlags = (0..15 |
    Where-Object { $td -band (1 -shl $_) } |
    ForEach-Object { $TYPE_DETAILS[$_] }
  ) -join ' | '
  $TypeDetail = "0x{0:X2} ({1})" -f $td, $DetailFlags

  # Speed (MT/s)
  $sp = [BitConverter]::ToUInt16($data,0x15)
  $SpeedMTs = if ($sp -eq 0xFFFF) { [BitConverter]::ToUInt32($data,0x54) } else { $sp }

  return [PSCustomObject]@{
    CapacityGB = $CapacityGB
    MemoryType = $MemoryType
    TypeDetail = $TypeDetail
    SpeedMTs   = $SpeedMTs
  }
}

# ----------------------------
#  1) CIM summary
# ----------------------------
$array       = Get-CimInstance Win32_PhysicalMemoryArray
$modules     = Get-CimInstance Win32_PhysicalMemory
$maxCapGB    = [math]::Round($array.MaxCapacity/1MB,2)
$totalSlots  = $array.MemoryDevices
$usedSlots   = $modules.Count
$installedGB = [math]::Round(( $modules | Measure-Object Capacity -Sum ).Sum/1GB,2)

$speeds = $modules |
  Group-Object ConfiguredClockSpeed |
  Sort-Object Name |
  ForEach-Object { "$($_.Name) MT/s ×$($_.Count)" }

# ----------------------------
#  2) Parse SMBIOS (type 17)
# ----------------------------
$raw = (Get-WmiObject -Namespace root\wmi -Class MSSmBios_RawSMBiosTables).SMBiosData
$idx = 0
$devs = New-Object System.Collections.Generic.List[PSObject]
while ($true) {
  $t = $raw[$idx]; if ($t -eq 127) { break }
  $l = $raw[$idx+1]
  if ($t -eq 17) { $devs.Add( Decode-SMBiosDevice -Raw $raw -Offset $idx ) }
  $idx += $l
  while ([BitConverter]::ToUInt16($raw,$idx) -ne 0) { $idx++ }
  $idx += 2
}

# ----------------------------
#  3) Merge CIM + SMBIOS
# ----------------------------
$report = for ($i=0; $i -lt $modules.Count; $i++) {
  $m = $modules[$i]; $s = $devs[$i]
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

# ----------------------------
#  4) Columnar report
# ----------------------------
# detect channels
$channels = @($report.Channel | Sort-Object -Unique)

# prepare rows
$dataRows = @(
  'Manufacturer','BankLabel','DeviceLocator',
  'CapacityGB','SpeedMTs','MemoryType','TypeDetail','SerialNumber'
) | ForEach-Object {
  $prop = $_
  $row  = [ordered]@{ Property = $prop }
  foreach ($c in $channels) {
    $val = ($report | Where-Object Channel -EQ $c | Select-Object -ExpandProperty $prop)
    $row[$c] = $val -join ', '
  }
  [PSCustomObject]$row
}

# print summary
"Maximum supported RAM:   $maxCapGB GB"
"Physical slots:           $usedSlots of $totalSlots"
"Currently installed:      $installedGB GB"
"Module speeds summary:    $($speeds -join ', ')"
""

# render table
$props = @('Property') + $channels
$dataRows | Format-Table -AutoSize -Property ( $props )

"`n—and now the raw CIM table:`n"

# ----------------------------
#  5) Raw CIM table
# ----------------------------
$modules |
  Select-Object Manufacturer,BankLabel,
    @{n='SpeedMHz';e={$_.ConfiguredClockSpeed}},
    DeviceLocator,
    @{n='CapacityGB';e={[math]::Round($_.Capacity/1GB,2)}},
    TypeDetail,SerialNumber |
  Format-Table -AutoSize
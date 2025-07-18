<#
.SYNOPSIS
  RAM.ps1 – summary + per-channel columnar report + raw CIM table,
  handling 1+ channels seamlessly, with DDR type & TypeDetail text using CIM properties.
#>

# ----------------------------------------------------------------------------
#  Mapping tables for SMBIOSMemoryType and TypeDetail bits
# ----------------------------------------------------------------------------
[string[]]$MEMORY_TYPES = @(
  'Unknown','Other','Unknown','DRAM','EDRAM','VRAM','SRAM','RAM',
  'ROM','FLASH','EEPROM','FEPROM','EPROM','CDRAM','3DRAM','SDRAM',
  'SGRAM','RDRAM','DDR','DDR2','DDR2 FB-DIMM','Reserved','Reserved','Reserved',
  'DDR3','FBD2','DDR4','LPDDR','LPDDR2','LPDDR3','LPDDR4','Logical non-volatile device',
  'HBM','HBM2','DDR5','LPDDR5'
)
[string[]]$TYPE_DETAILS = @(
  'Reserved','Other','Unknown','Fast-paged','Static column','Pseudo-static','RAMBUS','Synchronous',
  'CMOS','EDO','Window DRAM','Cache DRAM','Non-volatile','Registered','Unbuffered','LRDIMM'
)

function Decode-TypeDetail { param([int]$flags)
  $names = 0..15 | Where-Object { $flags -band (1 -shl $_) } | ForEach-Object { $TYPE_DETAILS[$_] }
  return "0x{0:X2} ({1})" -f $flags, ($names -join ' | ')
}

# ----------------------------------------------------------------------------
#  1) Gather basic CIM data and summary
# ----------------------------------------------------------------------------
$array       = Get-CimInstance Win32_PhysicalMemoryArray
$modules     = Get-CimInstance Win32_PhysicalMemory
$totalSlots  = $array.MemoryDevices
$usedSlots   = $modules.Count
$maxCapGB    = [math]::Round($array.MaxCapacity / 1MB, 2)
$installedGB = [math]::Round(( $modules | Measure-Object Capacity -Sum ).Sum / 1GB, 2)

$speeds = $modules |
  Group-Object ConfiguredClockSpeed |
  Sort-Object Name |
  ForEach-Object { "$(($_.Name)) MT/s ×$($_.Count)" }

# ----------------------------------------------------------------------------
#  2) Build combined report from CIM properties
# ----------------------------------------------------------------------------
$report = $modules | ForEach-Object {
  [PSCustomObject]@{
    Channel       = ($_.DeviceLocator -split '-')[0]
    Manufacturer  = $_.Manufacturer
    BankLabel     = $_.BankLabel
    DeviceLocator = $_.DeviceLocator
    CapacityGB    = [math]::Round($_.Capacity/1GB,2)
    SpeedMTs      = $_.ConfiguredClockSpeed
    MemoryType    = if ($_.SMBIOSMemoryType -lt $MEMORY_TYPES.Length) { $MEMORY_TYPES[$_.SMBIOSMemoryType] } else { "Unknown(0x$($_.SMBIOSMemoryType):X)" }
    TypeDetail    = Decode-TypeDetail -flags $_.TypeDetail
    SerialNumber  = $_.SerialNumber
  }
}

# ----------------------------------------------------------------------------
#  3) Summary output
# ----------------------------------------------------------------------------
"Maximum supported RAM:   $maxCapGB GB"
"Physical slots:           $usedSlots of $totalSlots"
"Currently installed:      $installedGB GB"
"Module speeds summary:    $($speeds -join ', ')"
""

# ----------------------------
#  4) Per-channel summary
# ----------------------------
$channels = @($report.Channel | Sort-Object -Unique)

Write-Host "`nPer-channel summary:`n"

foreach ($prop in 'Manufacturer','BankLabel','DeviceLocator','CapacityGB','SpeedMTs','MemoryType','TypeDetail','SerialNumber') {
    $values = foreach ($c in $channels) {
        # grab the value for this property & channel
        $val = $report | Where-Object Channel -eq $c |
               Select-Object -ExpandProperty $prop
        # now just do "$c=$val"
        "$c=$val"
    }
    Write-Host ("{0,-15}: {1}" -f $prop, ($values -join ', '))
}

Write-Host "`n—and now the raw CIM table:`n"

# 5) Raw CIM table for reference
$modules |
  Select-Object Manufacturer,BankLabel,
    @{n='SpeedMHz';e={$_.ConfiguredClockSpeed}},
    DeviceLocator,
    @{n='CapacityGB';e={[math]::Round($_.Capacity/1GB,2)}},
    @{n='MemoryTypeCode';e={$_.SMBIOSMemoryType}},
    TypeDetail,SerialNumber |
  Format-Table -AutoSize
<#
.SYNOPSIS
  RAM.ps1 – summary + per-channel columnar report + raw CIM table,
  handling 1+ channels seamlessly, with DDR type, TypeDetail text, and FormFactor.
#>

# ----------------------------------------------------------------------------
#  Mapping tables for SMBIOSMemoryType, TypeDetail bits, and FormFactor
# ----------------------------------------------------------------------------
[string[]]$MEMORY_TYPES = @(
  'Unknown','Other','Unknown','DRAM','EDRAM','VRAM','SRAM',
  'ROM','FLASH','EEPROM','FEPROM','EPROM','CDRAM','3DRAM','SDRAM',
  'SGRAM','RDRAM','DDR','DDR2','DDR2 FB-DIMM','Reserved','Reserved','Reserved',
  'DDR3','FBD2','DDR4','LPDDR','LPDDR2','LPDDR3','LPDDR4',
  'Logical non-volatile device','HBM','HBM2','DDR5','LPDDR5'
)
[string[]]$TYPE_DETAILS = @(
  'Reserved','Other','Unknown','Fast-paged','Static column','Pseudo-static',
  'RAMBUS','Synchronous','CMOS','EDO','Window DRAM','Cache DRAM','Non-volatile',
  'Registered','Unbuffered','LRDIMM'
)

function Decode-TypeDetail { param([int]$flags)
  $names = 0..15 | Where-Object { $flags -band (1 -shl $_) } | ForEach-Object { $TYPE_DETAILS[$_] }
  return "0x{0:X2} ({1})" -f $flags, ($names -join ' | ')
}

function Decode-MemoryType {
  param([int]$smbiosCode, [string]$formFactor)

  # Canonical mapping (subset)
  $map = @{
    20='DDR'; 21='DDR2'; 22='DDR2 FB-DIMM'; 24='DDR3'; 26='DDR4'; 34='DDR5'
    27='LPDDR'; 28='LPDDR2'; 29='LPDDR3'; 30='LPDDR4'; 35='LPDDR5'
  }

  $label = $map[$smbiosCode]

  # Sanity check: desktop-sized DIMM shouldn't be LPDDR
  if ($null -ne $label -and $formFactor -eq 'DIMM' -and $label -like 'LPDDR*') {
    if ($smbiosCode -ge 34) { $label = 'DDR5' } else { $label = 'DDR4' }
  }

  if (-not $label) { $label = "Unknown($smbiosCode)" }
  return $label
}

function Decode-FormFactor { param([int]$code)
  switch ($code) {
    8  { 'DIMM' }
    12 { 'SODIMM' }
    default { "Unknown($code)" }
  }
}

# ----------------------------------------------------------------------------
#  1) Gather CIM data
# ----------------------------------------------------------------------------
$array       = Get-CimInstance Win32_PhysicalMemoryArray
$modules     = Get-CimInstance Win32_PhysicalMemory

$totalSlots  = $array.MemoryDevices
$usedSlots   = $modules.Count
$maxCapGB    = [math]::Round($array.MaxCapacity / 1MB, 2)
$installedGB = [math]::Round(($modules | Measure-Object Capacity -Sum).Sum / 1GB, 2)

# Speeds summary
$speeds = $modules |
  Group-Object ConfiguredClockSpeed |
  Sort-Object Name |
  ForEach-Object { "$(($_.Name)) MT/s ×$($_.Count)" }

# FormFactor summary
$reportTmp = $modules | ForEach-Object {
  [PSCustomObject]@{ FormFactor = Decode-FormFactor -code $_.FormFactor }
}
$formFactors = $reportTmp |
  Group-Object FormFactor |
  Sort-Object Name |
  ForEach-Object { "$($_.Name)×$($_.Count)" }

# ----------------------------------------------------------------------------
#  2) Build full report including all properties
# ----------------------------------------------------------------------------
$report = $modules | ForEach-Object {
  [PSCustomObject]@{
    Channel       = ($_.DeviceLocator -split '-')[0]
    Manufacturer  = $_.Manufacturer
    BankLabel     = $_.BankLabel
    DeviceLocator = $_.DeviceLocator
    FormFactor    = Decode-FormFactor -code $_.FormFactor
    CapacityGB    = [math]::Round($_.Capacity/1GB,2)
    SpeedMTs      = $_.ConfiguredClockSpeed
    MemoryType    = Decode-MemoryType -smbiosCode $_.SMBIOSMemoryType -formFactor (Decode-FormFactor -code $_.FormFactor)
    TypeDetail    = Decode-TypeDetail -flags $_.TypeDetail
    SerialNumber  = $_.SerialNumber
  }
}

# ----------------------------------------------------------------------------
#  3) Top summary output (Max / Slots / Installed / Speeds / FormFactor)
# ----------------------------------------------------------------------------
Write-Host "Maximum supported RAM:   $maxCapGB GB"
Write-Host ("Physical slots:           {0} slots, {1} used" -f $totalSlots, $usedSlots)
Write-Host "Currently installed:      $installedGB GB"
Write-Host ("Module speeds summary:    {0}" -f ($speeds -join ', '))
Write-Host ("Form factors summary:     {0}" -f ($formFactors -join ', '))
Write-Host ""

# ----------------------------------------------------------------------------
#  4) Per-channel summary
# ----------------------------------------------------------------------------
$channels = $report.Channel | Sort-Object -Unique

Write-Host "Per-channel summary:`n"
foreach ($prop in 'Manufacturer','BankLabel','DeviceLocator','FormFactor','CapacityGB','SpeedMTs','MemoryType','TypeDetail','SerialNumber') {
  $pairs = $channels | ForEach-Object {
    $val = ($report | Where-Object Channel -eq $_ | Select-Object -ExpandProperty $prop)
    "$_=$val"
  }
  Write-Host ("{0,-15}: {1}" -f $prop, ($pairs -join ','))
}

# ----------------------------------------------------------------------------
#  5) Raw CIM table
# ----------------------------------------------------------------------------
$modules |
  Select-Object Manufacturer,BankLabel,
    @{n='SpeedMHz';e={$_.ConfiguredClockSpeed}},
    DeviceLocator,
    @{n='FormFactor';e={Decode-FormFactor -code $_.FormFactor}},
    @{n='CapacityGB';e={[math]::Round($_.Capacity/1GB,2)}},
    @{n='MemoryTypeCode';e={$_.SMBIOSMemoryType}},
    TypeDetail,SerialNumber |
  Format-Table -AutoSize
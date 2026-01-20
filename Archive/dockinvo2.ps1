<# Dock & Display Inventory — PowerShell 5.1 compatible #>

Write-Host "== GPU Driver ==" -ForegroundColor Cyan
Get-PnpDevice -Class Display |
  Select-Object -ExpandProperty InstanceId |
  ForEach-Object {
    $id = $_
    $verProp = $null
    try {
      $verProp = Get-PnpDeviceProperty -InstanceId $id -KeyName 'DEVPKEY_Device_DriverVersion' -ErrorAction Stop
    } catch {}
    $ver = if ($verProp) { $verProp.Data } else { "Unknown" }
    "{0}  Driver={1}" -f $id, $ver
  }

Write-Host "`n== Possible Dock Devices (by name/VID) ==" -ForegroundColor Cyan
# Lenovo VID 17EF; DisplayLink 17E9; Realtek USB NIC 0BDA; also match Dock/USB4/Thunderbolt strings
$vidRegex = 'VID_17EF|VID_17E9|VID_0BDA|Thunderbolt|USB4|DisplayLink|Dock'
Get-CimInstance Win32_PnPEntity |
  Where-Object {
    ($_.Name -match 'Dock|Thunderbolt|USB4|DisplayLink') -or
    ($_.PNPDeviceID -match $vidRegex)
  } |
  Select-Object Name, Manufacturer, PNPDeviceID, Status |
  Sort-Object Name |
  Format-Table -Auto

Write-Host "`n== USB4 / Thunderbolt nodes ==" -ForegroundColor Cyan
Get-PnpDevice | Where-Object { $_.FriendlyName -match 'USB4|Thunderbolt' } |
  Format-Table Status,Class,FriendlyName,InstanceId -Auto

Write-Host "`n== Network Adapters (USB vs PCIe) ==" -ForegroundColor Cyan
Get-PnpDevice -Class Net |
  Select-Object Status, Class, FriendlyName, InstanceId |
  Sort-Object FriendlyName |
  Format-Table -Auto
# Tip: InstanceId beginning with 'USB\VID_' indicates a USB NIC on the dock.

Write-Host "`n== Monitors & Connections ==" -ForegroundColor Cyan
# Map connection types from WmiMonitorConnectionParams.VideoOutputTechnology (handle as UInt32/string)
$vtMap = @{
  '0'  = 'Uninitialized';     '1'  = 'Other';                 '2'  = 'VGA/HD15'
  '3'  = 'S-Video';           '4'  = 'Composite';             '5'  = 'Component'
  '6'  = 'DVI';               '8'  = 'HDMI';                  '9'  = 'LVDS'
  '11' = 'SDI';               '12' = 'DisplayPort External';  '13' = 'DisplayPort Embedded'
  '15' = 'Miracast';          '16' = 'Internal';              '17' = 'USB-C DisplayPort Alt'
  '18' = 'Embedded DisplayPort';                              '19' = 'DVI Embedded'
}

$cons = @()
$ids  = @()
try { $cons = Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorConnectionParams -ErrorAction Stop } catch {}
try { $ids  = Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID              -ErrorAction Stop } catch {}

$monList = @()
foreach ($c in $cons) {
  $inst   = $c.InstanceName
  $code32 = [uint32]$c.VideoOutputTechnology
  $code   = [string]$code32
  $tech   = if ($vtMap.ContainsKey($code)) { $vtMap[$code] } else { "Code $code" }

  $m = $ids | Where-Object { $_.InstanceName -eq $inst }
  $mfg  = ''
  $prod = ''
  if ($m) {
    $mfg  = (($m.ManufacturerName | ForEach-Object { [char]$_ }) -join '').Trim()
    $prod = (($m.UserFriendlyName | ForEach-Object { [char]$_ }) -join '').Trim()
  }

  $monList += [pscustomobject]@{
    InstanceName = $inst
    Connection   = $tech
    Manufacturer = $mfg
    Model        = $prod
  }
}
$monList | Sort-Object Model | Format-Table -Auto

Write-Host "`n== EDID basic dimensions (mm) ==" -ForegroundColor Cyan
try {
  Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorBasicDisplayParams -ErrorAction Stop |
    Select-Object InstanceName, MaxHorizontalImageSize, MaxVerticalImageSize |
    Format-Table -Auto
} catch {}

Write-Host "`nDone." -ForegroundColor Green
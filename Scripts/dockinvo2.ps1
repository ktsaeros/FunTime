<# Dock & Display Inventory (PowerShell 5.1) #>

Write-Host "== GPU Driver ==" -ForegroundColor Cyan
Get-PnpDevice -Class Display |
  Select-Object -ExpandProperty InstanceId |
  ForEach-Object {
    $id = $_
    $ver = (Get-PnpDeviceProperty -InstanceId $id -KeyName 'DEVPKEY_Device_DriverVersion' -ErrorAction SilentlyContinue).Data
    "{0}  Driver={1}" -f $id, $ver
  }

Write-Host "`n== Possible Dock Devices (by name/VID) ==" -ForegroundColor Cyan
# Lenovo VID 17EF; DisplayLink often 17E9; Realtek USB NIC 0BDA; also match Dock/USB4/Thunderbolt strings
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
# Tip: InstanceId starting with 'USB\VID_' indicates a USB NIC (typically on the dock).

Write-Host "`n== Monitors & Connections ==" -ForegroundColor Cyan
# Map connection types from WmiMonitorConnectionParams.VideoOutputTechnology (use UInt32-safe handling)
$vtMap = @{
  '0'="Uninitialized"; '1'="Other"; '2'="VGA/HD15"; '3'="S-Video"; '4'="Composite"; '5'="Component"; '6'="DVI";
  '8'="HDMI"; '9'="LVDS"; '11'="SDI"; '12'="DisplayPort External"; '13'="DisplayPort Embedded";
  '15'="Miracast"; '16'="Internal"; '17'="USB-C DisplayPort Alt"; '18'="Embedded DisplayPort"; '19'="DVI Embedded"
}
$cons = Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorConnectionParams -ErrorAction SilentlyContinue
$ids  = Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID -ErrorAction SilentlyContinue

$monList = foreach($c in $cons){
  $inst = $c.InstanceName
  # guard against very large or unexpected values (treat as string key)
  $codeStr = [string]([uint32]$c.VideoOutputTechnology)
  $tech = $vtMap.ContainsKey($codeStr) ? $vtMap[$codeStr] : ("Code " + $codeStr)
  $m = $ids | Where-Object { $_.InstanceName -eq $inst }
  $mfg = if($m){ ($m.ManufacturerName | ForEach-Object {[char]$_}) -join '' } else { '' }
  $prod= if($m){ ($m.UserFriendlyName | ForEach-Object {[char]$_}) -join '' } else { '' }
  [pscustomobject]@{
    InstanceName = $inst
    Connection   = $tech
    Manufacturer = $mfg.Trim()
    Model        = $prod.Trim()
  }
}
$monList | Sort-Object Model | Format-Table -Auto

Write-Host "`n== EDID basic dimensions (mm) ==" -ForegroundColor Cyan
Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorBasicDisplayParams -ErrorAction SilentlyContinue |
  Select-Object InstanceName, MaxHorizontalImageSize, MaxVerticalImageSize |
  Format-Table -Auto

Write-Host "`nDone." -ForegroundColor Green
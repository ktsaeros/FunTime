# ===== Dock & Display Inventory (PS 5.1 compatible) =====
"== GPU Driver ==";
Get-PnpDevice -Class Display |
  Select-Object -ExpandProperty InstanceId |
  ForEach-Object {
    $id = $_
    $ver = (Get-PnpDeviceProperty -InstanceId $id -KeyName 'DEVPKEY_Device_DriverVersion' -ErrorAction SilentlyContinue).Data
    "{0}  Driver={1}" -f $id, $ver
  }

"`n== Possible Dock Devices (by name/VID) ==";
# Lenovo common VID: 17EF; DisplayLink: 17E9; Realtek USB GbE shows as USB\VID_0BDA; Intel TB/USB4 parts vary
$vidRegex = 'VID_17EF|VID_17E9|VID_0BDA|Thunderbolt|USB4|DisplayLink|Dock'
Get-CimInstance Win32_PnPEntity |
  Where-Object {
    $_.Name -match 'Dock|Thunderbolt|USB4|DisplayLink' -or
    $_.PNPDeviceID -match $vidRegex
  } |
  Select-Object Name, Manufacturer, PNPDeviceID, Status |
  Sort-Object Name |
  Format-Table -Auto

"`n== USB4 / Thunderbolt nodes ==";
Get-PnpDevice | Where-Object { $_.FriendlyName -match 'USB4|Thunderbolt' } |
  Format-Table Status,Class,FriendlyName,InstanceId -Auto

"`n== Network Adapters (USB vs PCIe) ==";
Get-PnpDevice -Class Net |
  Select-Object Status, Class, FriendlyName, InstanceId |
  Sort-Object FriendlyName |
  Format-Table -Auto
# Tip: a NIC showing InstanceId beginning with 'USB\VID_' (e.g., Realtek USB GbE) is through the dock.

"`n== Monitors & Connections ==";
# Map connection types from WmiMonitorConnectionParams.VideoOutputTechnology
$vtMap = @{
  0="Uninitialized";1="Other";2="VGA/HD15";3="S-Video";4="Composite";5="Component";6="DVI";
  8="HDMI";9="LVDS";11="SDI";12="DisplayPort External";13="DisplayPort Embedded";
  15="Miracast";16="Internal";17="USB-C DisplayPort Alt";18="Embedded DisplayPort";19="DVI Embedded"
}
$cons = Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorConnectionParams -ErrorAction SilentlyContinue
$ids  = Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID -ErrorAction SilentlyContinue

$monList = foreach($c in $cons){
  $inst = $c.InstanceName
  $code = [int]$c.VideoOutputTechnology
  if ($vtMap.ContainsKey($code)) { $tech = $vtMap[$code] } else { $tech = "$code" }
  $m = $ids | Where-Object { $_.InstanceName -eq $inst }
  $mfg = ($m.ManufacturerName | ForEach-Object {[char]$_}) -join ''
  $prod= ($m.UserFriendlyName | ForEach-Object {[char]$_}) -join ''
  [pscustomobject]@{
    InstanceName = $inst
    Connection   = $tech
    Manufacturer = $mfg.Trim()
    Model        = $prod.Trim()
  }
}
$monList | Sort-Object Model | Format-Table -Auto

"`n== Current Display Modes (per EDID basic dims) ==";
Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorBasicDisplayParams -ErrorAction SilentlyContinue |
  Select-Object InstanceName, MaxHorizontalImageSize, MaxVerticalImageSize |
  Format-Table -Auto

"`nDone."
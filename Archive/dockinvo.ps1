# --- Basic GPU driver version ---
"== GPU Driver ==";
Get-PnpDevice -Class Display |
  Select-Object -ExpandProperty InstanceId |
  ForEach-Object {
    $id = $_
    $ver = (Get-PnpDeviceProperty -InstanceId $id -KeyName 'DEVPKEY_Device_DriverVersion' -ErrorAction SilentlyContinue).Data
    "{0}  Driver={1}" -f $id, $ver
  }

# --- Look for a Lenovo/DisplayLink/Thunderbolt dock by vendor IDs & names ---
"`n== Possible Dock Devices ==";
$dockHints = Get-CimInstance Win32_PnPEntity |
  Where-Object {
    $_.Name -match 'Dock|Thunderbolt|USB4|DisplayLink|Realtek.*GbE|I219-V' -or
    $_.PNPDeviceID -match 'VID_17EF|VID_17E9|VID_17AA|VID_17AF|VID_17A0|VID_17CB' # Lenovo VIDs commonly 17EF
  } |
  Select-Object Name, Manufacturer, PNPDeviceID, Status
$dockHints | Sort-Object Name | Format-Table -Auto

# --- Show USB4 / Thunderbolt chain (if present) ---
"`n== USB4 / Thunderbolt ==";
Get-PnpDevice | Where-Object { $_.FriendlyName -match 'USB4|Thunderbolt' } |
  Format-Table Status,Class,FriendlyName,InstanceId -Auto

# --- Network adapters: built-in PCIe vs USB (dock) ---
"`n== Network Adapters ==";
Get-PnpDevice -Class Net |
  Select-Object Status, Class, FriendlyName, InstanceId |
  Sort-Object FriendlyName |
  Format-Table -Auto

# --- Monitors: EDID + connection technology (HDMI/DP/eDP/etc.) ---
"`n== Monitors & Connections ==";
$vtMap = @{
  0="Uninitialized";1="Other";2="HD15/VGA";3="SVideo";4="Composite";5="Component";6="DVI";8="HDMI";
  9="LVDS";10="DJPN";11="SDI";12="DisplayPort External";13="DisplayPort Embedded";14="UDD";15="Miracast";
  16="Internal";17="USB-C DisplayPort Alt";18="Embedded DisplayPort";19="DVI Embedded"
}
# Connection params (root\wmi)
$cons = Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorConnectionParams -ErrorAction SilentlyContinue
# Human labels from EDID
$ids  = Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID -ErrorAction SilentlyContinue

$cons | ForEach-Object {
  $inst = $_.InstanceName
  # THIS IS THE CORRECTED BLOCK FOR POWERSHELL 5.1
  if ($vtMap.ContainsKey([int]$_.VideoOutputTechnology)) {
      $tech = $vtMap[[int]$_.VideoOutputTechnology]
  } else {
      $tech = $_.VideoOutputTechnology
  }
  $match = $ids | Where-Object { $_.InstanceName -eq $inst }
  $mfg = ($match.ManufacturerName | ForEach-Object {[char]$_}) -join ''
  $prod= ($match.UserFriendlyName | ForEach-Object {[char]$_}) -join ''
  [pscustomobject]@{
    InstanceName = $inst
    Connection   = $tech
    Manufacturer = $mfg.Trim()
    Model        = $prod.Trim()
  }
} | Sort-Object Model | Format-Table -Auto

# --- Active signal modes (resolution/Hz) ---
"`n== Current Display Modes ==";
Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorBasicDisplayParams -ErrorAction SilentlyContinue |
  Select-Object InstanceName, MaxHorizontalImageSize, MaxVerticalImageSize
(Get-DisplayResolution) 2>$null | Out-Null
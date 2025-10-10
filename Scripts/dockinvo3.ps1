# Monitors with hardware location paths (PS 5.1 safe)
$monitors = Get-PnpDevice -Class Monitor -Status OK |
  Select-Object FriendlyName, InstanceId, LocationPaths

"`n== Monitors + LocationPaths =="
foreach ($m in $monitors) {
  $paths = @($m.LocationPaths) -join "`n  "
  $via = if ($paths -match 'USB|USBROOT') { 'DOCK/USB' } else { 'DIRECT/PCI' }
  "{0}`n  InstanceId: {1}`n  Via: {2}`n  Paths:`n  {3}`n" -f $m.FriendlyName, $m.InstanceId, $via, $paths
}

# Also dump raw connection tech if available
"`n== Connection Technology (best-effort) =="
Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorConnectionParams -ErrorAction SilentlyContinue |
  Select-Object InstanceName, VideoOutputTechnology
$base = "C:\Program Files (x86)\Advanced Monitoring Agent"
$edrLog = Join-Path $base "featureres\logs\msp-lwt-edr-module.log"
$disc   = Join-Path $base "featureres\msp_lwt_edr_discovery.json"
$agentLogDir = Join-Path $base "logs"

# 1) Stop AMA cleanly (with timeout), then start it
$svc = Get-Service "Advanced Monitoring Agent" -ErrorAction Stop
if ($svc.Status -ne 'Stopped') {
  Stop-Service "Advanced Monitoring Agent" -Force
try {
  $svc.WaitForStatus('Stopped','00:02:00')
} catch {
  Write-Warning "The '$agent' service did not stop within the 2-minute timeout."
}
Start-Service "Advanced Monitoring Agent"

# 2) Clear previous EDR discovery artifacts (optional but clean)
Remove-Item $disc -ErrorAction SilentlyContinue
Remove-Item $edrLog -ErrorAction SilentlyContinue

# 3) Wait up to 5 minutes for the EDR module to (re)create its log, tail if it appears
$appeared = $false
for ($i=0; $i -lt 150; $i++) {  # 150 x 2s = 5 minutes
  if (Test-Path $edrLog) { $appeared = $true; break }
  Start-Sleep -Seconds 2
}

if ($appeared) {
  Write-Host "`nEDR module log detected. Tailing..."
  Get-Content $edrLog -Tail 100 -Wait
} else {
  Write-Warning "EDR module log did not appear within 5 minutes."
  Write-Host "`nShowing recent core agent logs instead:"
  Get-ChildItem $agentLogDir -File | Sort LastWriteTime -Descending | Select -First 5 |
    ForEach-Object { "`n== $($_.Name) =="; Get-Content $_.FullName -Tail 120 }
}
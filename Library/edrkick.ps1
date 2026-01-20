param(
  [switch]$ForceReboot = $false,
  [int]$WaitMinutes = 8
)

# --- 1. RMM Service Reset ---
$agent = "Advanced Monitoring Agent"
Write-Host "--- RMM & EDR KICKSTART ---" -ForegroundColor Cyan

if (Get-Service $agent -ErrorAction SilentlyContinue) {
    Write-Host "Restarting RMM Agent..." -ForegroundColor Yellow
    Restart-Service $agent -Force
} else {
    Write-Warning "RMM Agent service not found."
}

# --- 2. SentinelOne / EDR Checks ---
$base   = Join-Path "${env:ProgramFiles(x86)}" "Advanced Monitoring Agent"
$edrLog = Join-Path $base "featureres\logs\msp-lwt-edr-module.log"
$disc   = Join-Path $base "featureres\msp_lwt_edr_discovery.json"

Write-Host "Clearing EDR discovery artifacts to force check-in..." -ForegroundColor Yellow
Remove-Item $disc -ErrorAction SilentlyContinue
Remove-Item $edrLog -ErrorAction SilentlyContinue

Write-Host "Monitoring log for $WaitMinutes minutes..." -ForegroundColor Cyan
$deadline = (Get-Date).AddMinutes($WaitMinutes)

while ((Get-Date) -lt $deadline) {
    if (Test-Path $edrLog) {
        $content = Get-Content $edrLog -Tail 1 -ErrorAction SilentlyContinue
        Write-Host "Log Activity: $content" -ForegroundColor Gray
        if ($content -match 'successfully|status code 0') {
            Write-Host "`nSUCCESS: EDR installed/verified." -ForegroundColor Green
            break
        }
    }
    Start-Sleep 3
}

# --- 3. Reboot Logic ---
$pending = (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending")
if ($pending) {
    Write-Host "`nWARNING: A Windows Update reboot is PENDING." -ForegroundColor Red
    if ($ForceReboot) {
        Restart-Computer -Force
    } else {
        $ans = Read-Host "Do you want to reboot now? (y/N)"
        if ($ans -eq 'y') { Restart-Computer -Force }
    }
} else {
    Write-Host "`nNo reboot required." -ForegroundColor Green
}
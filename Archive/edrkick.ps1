param(
  [switch]$RebootIfPending = $true,  # auto-reboot if Windows reports a pending reboot
  [switch]$ForceReboot = $false,      # always reboot at the end
  [int]$WaitMinutes = 8              # how long to wait for install/logs
)

# ==================[ 1. PRE-FLIGHT CHECKS ]==================
# Ensure script is running as Administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Error "This script requires Administrator privileges. Please run it in an elevated PowerShell window."; exit 9
}

# Ensure modern security protocols are available for downloads
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Ensure the Windows Installer service is running
$msi = Get-Service msiserver -ErrorAction SilentlyContinue
if ($msi -and $msi.Status -eq 'Stopped') {
    Write-Host "Windows Installer service was stopped. Starting it now..."
    Start-Service msiserver -ErrorAction SilentlyContinue
}

# ==================[ VARIABLE DEFINITIONS ]==================
$base = Join-Path "${env:ProgramFiles(x86)}" "Advanced Monitoring Agent"
$edrLog = Join-Path $base "featureres\logs\msp-lwt-edr-module.log"
$disc   = Join-Path $base "featureres\msp_lwt_edr_discovery.json"
$agent  = "Advanced Monitoring Agent"

function Test-PendingReboot {
  $paths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
  )
  foreach ($p in $paths) { if (Test-Path $p) { return $true } }
  $pn = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
  $val = (Get-ItemProperty -Path $pn -Name PendingFileRenameOperations -ErrorAction SilentlyContinue)
  return [bool]$val
}

# ==================[ 1. RESTART AGENT SERVICE ]==================
Write-Host "Attempting to restart the '$agent' service..."
try {
    $svc = Get-Service $agent -ErrorAction Stop
    if ($svc.Status -ne 'Stopped') {
      $svc = Stop-Service $agent -Force -PassThru
      try { $svc.WaitForStatus('Stopped','00:02:00') } catch { Write-Warning "The '$agent' service did not stop within the 2-minute timeout." }
    }
} catch {
    Write-Warning "Could not query the '$agent' service: $($_.Exception.Message)"
}
Start-Service $agent

# ==================[ 2. CLEANUP & MONITORING ]==================
Write-Host "Clearing previous discovery artifacts..."
Remove-Item $disc -ErrorAction SilentlyContinue
Remove-Item $edrLog -ErrorAction SilentlyContinue

Write-Host "Waiting up to $WaitMinutes minutes for the EDR log to be created..."
$deadline = (Get-Date).AddMinutes($WaitMinutes)
while (-not (Test-Path $edrLog) -and (Get-Date) -lt $deadline) { Start-Sleep 2 }

if (-not (Test-Path $edrLog)) {
  Write-Warning "EDR log not created. Check RMM site assignment, licensing, and proxy/firewall settings."
  exit 1
}

Write-Host "Log file detected. Monitoring for installation status..."
$success = $false
$fail = $false
$fs = $sr = $null # Initialize variables

try {
  # Prime the buffer to read only new content
  $fs = [System.IO.File]::Open($edrLog, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
  $sr = New-Object System.IO.StreamReader($fs)
  $sr.BaseStream.Seek(0, [System.IO.SeekOrigin]::End) | Out-Null

  $stopAt = (Get-Date).AddMinutes($WaitMinutes)
  while ((Get-Date) -lt $stopAt -and -not $success -and -not $fail) {
    Start-Sleep -Milliseconds 500
    while (-not $sr.EndOfStream) {
      $line = $sr.ReadLine()
      Write-Host $line
      if ($line -match 'SentinelInstaller returned with status code 0|has been installed successfully') { $success = $true }
      elseif ($line -match 'status code\s+[1-9]\d*' -and ($line -notmatch ' 0$')) { $fail = $true }
    }
  }
}
finally {
  # This block GUARANTEES the file handles are closed, even if an error occurs
  if ($sr) { $sr.Close() }
  if ($fs) { $fs.Close() }
}

# ==================[ 3. REPORTING & REBOOT ]==================
if ($success) {
  Write-Host "`n✅ SentinelOne install success detected."
} elseif ($fail) {
  Write-Warning "❌ Installer returned a non-zero exit. Check connectivity/proxy and RMM site token."
  exit 2
} else {
  Write-Warning "Timed out waiting for success/fail status in the log. Check the log and RMM console."
  exit 3
}

$pending = Test-PendingReboot
if ($ForceReboot -or ($RebootIfPending -and $pending)) {
  Write-Host "Rebooting to finalize protection (Forced: $ForceReboot, Pending Reboot Detected: $pending)..."
  Restart-Computer -Force
} else {
  Write-Host "No reboot required or forced. Pending reboot status: $pending"
}
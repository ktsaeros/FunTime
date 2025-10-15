<#
.SYNOPSIS
  Safe disk cleanup for remote PCs (N-able friendly) with -WhatIf/-Confirm.

.DESCRIPTION
  - Logs actions to %TEMP%\disk_cleanup_log.txt and prints a final summary.
  - Conservative by default; enable deeper steps with switches.
  - Handles missing services/paths gracefully.
  - Supports -WhatIf / -Confirm via ShouldProcess wrappers.

.PARAMETER TargetDrive
  Drive letter to measure (default: C)

.PARAMETER DisableHibernate
  Disable hibernation (frees hiberfil.sys)

.PARAMETER CleanMgr
  Run cleanmgr.exe /autoclean (legacy but effective)

.PARAMETER ClearWUCache
  Clear Windows Update download cache

.PARAMETER ClearTemp
  Clear user and system temp folders (thorough, includes hidden files)

.PARAMETER ComponentCleanup
  DISM /StartComponentCleanup (safe)

.PARAMETER DeepComponentCleanup
  DISM /StartComponentCleanup /ResetBase (irreversible)

.PARAMETER RemoveOptionalFeatures
  Disable Windows Media Player and Fax Client

.PARAMETER EmptyRecycleBin
  Empty Recycle Bin for the executing user across mounted drives

.PARAMETER PurgeDellSARemediation
  Delete Dell SupportAssist SARemediation snapshots backup contents

.PARAMETER TouchNableFileCache
  Stop/clear/start “File Cache Service Agent” cache if present

.PARAMETER ReportShadowsOnly
  Report VSS shadow storage usage (no deletions)

.PARAMETER ShrinkShadowStorage
  Cap VSS ShadowStorage to 10% on each fixed, formatted local drive
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
  [ValidatePattern('^[A-Za-z]$')]
  [string]$TargetDrive = 'C',

  [switch]$DisableHibernate,
  [switch]$CleanMgr,
  [switch]$ClearWUCache,
  [switch]$ClearTemp,
  [switch]$ComponentCleanup,
  [switch]$DeepComponentCleanup,
  [switch]$RemoveOptionalFeatures,
  [switch]$EmptyRecycleBin,
  [switch]$PurgeDellSARemediation,
  [switch]$TouchNableFileCache,
  [switch]$ReportShadowsOnly,
  [switch]$ShrinkShadowStorage
)

# ---------- Defaults then override with provided switches ----------
# Safe defaults (opt-out)
$DisableHibernate     = $true
$CleanMgr             = $true
$ClearWUCache         = $true
$ClearTemp            = $true
$ComponentCleanup     = $true
$TouchNableFileCache  = $true
$ReportShadowsOnly    = $true
# Aggressive/destructive (opt-in)
$DeepComponentCleanup   = $false
$RemoveOptionalFeatures = $false
$EmptyRecycleBin        = $false
$PurgeDellSARemediation = $false
$ShrinkShadowStorage    = $false

# Apply any caller-provided switches
foreach ($key in $PSBoundParameters.Keys) {
  $param = $PSCmdlet.MyInvocation.MyCommand.Parameters[$key]
  if ($null -ne $param -and $param.ParameterType.Name -eq 'SwitchParameter') {
    Set-Variable -Name $key -Value $PSBoundParameters[$key]
  }
}

# Compute effective enabled switches for logging
$__switchNames = @('DisableHibernate','CleanMgr','ClearWUCache','ClearTemp','ComponentCleanup','DeepComponentCleanup','RemoveOptionalFeatures','EmptyRecycleBin','PurgeDellSARemediation','TouchNableFileCache','ReportShadowsOnly','ShrinkShadowStorage')
$__enabled = @()
foreach ($__n in $__switchNames) { if (Get-Variable -Name $__n -ValueOnly) { $__enabled += $__n } }

# ---------- Setup & helpers ----------
# --- Safe ShouldProcess wrapper (works even when run via IEX/irm where $PSCmdlet may be null) ---
function _Should([string]$target, [string]$action) {
  try {
    if ($PSBoundParameters.ContainsKey('WhatIf') -or $WhatIfPreference) { return $false }
  } catch { }
  if ($null -ne $PSCmdlet) {
    try { return _Should($target, $action) } catch { return $true }
  }
  return $true
}

$ErrorActionPreference = 'Stop'
$logDir = 'C:\Aeros'
if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$logFile = Join-Path $logDir ("disk_cleanup_{0}_{1}.txt" -f $env:COMPUTERNAME, $timestamp)
$scriptStart = Get-Date

function Write-Log {
  param([string]$Message)
  $line = '{0:u}  {1}' -f (Get-Date), $Message
  Write-Output $line
  Add-Content -Path $logFile -Value $line
}

function Try-Run {
  param([scriptblock]$Block, [string]$What)
  try { & $Block; Write-Log "OK: $What" }
  catch { Write-Log "WARN: $What -> $($_.Exception.Message)" }
}

function Get-FreeGB([string]$drive) {
  $d = Get-PSDrive -Name $drive.TrimEnd(':')
  if (-not $d) { return [double]::NaN }
  [math]::Round($d.Free / 1GB, 2)
}

function Service-StopSafe([string]$name) {
  $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
  if ($svc) {
    if (_Should($name, "Stop service")) {
      Try-Run { Stop-Service -Name $name -Force -ErrorAction Stop } "Stop-Service $name"
    }
  } else { Write-Log "INFO: Service '$name' not found" }
}
function Service-StartSafe([string]$name) {
  $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
  if ($svc) {
    if (_Should($name, "Start service")) {
      Try-Run { Start-Service -Name $name -ErrorAction Stop } "Start-Service $name"
    }
  } else { Write-Log "INFO: Service '$name' not found" }
}

function Remove-PathSafe([string]$path) {
  if (Test-Path $path) {
    if (_Should($path, "Remove")) {
      Try-Run { Remove-Item -Path $path -Recurse -Force -ErrorAction Stop } "Remove $path"
    }
  } else { Write-Log "INFO: Path not found: $path" }
}

function Get-RecycleBinSizeBytes {
  # Rely only on .Size to avoid locale parsing; may report 0 for some items.
  try {
    $sh = New-Object -ComObject Shell.Application
    $rb = $sh.NameSpace(10) # Recycle Bin
    if (-not $rb) { return 0 }
    $sum = 0
    $rb.Items() | ForEach-Object {
      try { if ($_.Size) { $sum += [int64]$_.Size } } catch { }
    }
    return $sum
  } catch { return 0 }
}

function Empty-RecycleBinSafe {
  # Clears the executing user's Recycle Bin across mounted drives.
  # Cross-profile purges are intentionally NOT performed here.
  $drives = (Get-PSDrive -PSProvider FileSystem | Select-Object -ExpandProperty Name)
  if (_Should("Recycle Bin", "Clear on drives: $($drives -join ',')")) {
    Try-Run { Clear-RecycleBin -Force -ErrorAction SilentlyContinue -DriveLetter $drives } "Empty Recycle Bin (executing user)"
  }
}

# ---------- Preconditions ----------
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Output "ERROR: Must run as Administrator."
  exit 1
}

Remove-Item -Path $logFile -ErrorAction SilentlyContinue
Write-Log "===== Disk Cleanup started (host: $env:COMPUTERNAME, user: $env:USERNAME) ====="
Write-Log ("Params: TargetDrive={0}; Switches: {1}" -f $TargetDrive, ($__enabled -join ', '))

$startFree = Get-FreeGB $TargetDrive
Write-Log ("Start free space on {0}: {1} GB" -f $TargetDrive, $startFree)

# ---------- Actions ----------

# 1) Disable Hibernate
if ($DisableHibernate) {
  if (_Should("Hibernation", "Disable")) {
    Try-Run { powercfg.exe /hibernate off | Out-Null } "Disable hibernation"
  }
} else { Write-Log "SKIP: Disable hibernation" }

# 2) CleanMgr (legacy)
if ($CleanMgr) {
  $cm = Join-Path $env:WINDIR 'System32\cleanmgr.exe'
  if (Test-Path $cm) {
    if (_Should("CleanMgr", "Run /autoclean")) {
      Try-Run { Start-Process -FilePath $cm -ArgumentList '/autoclean' -NoNewWindow -Wait } "Run cleanmgr /autoclean"
    }
  } else {
    Write-Log "INFO: cleanmgr.exe not found; skipping (deprecated on some builds)."
  }
} else { Write-Log "SKIP: CleanMgr" }

# 3) N-able File Cache (if present)
if ($TouchNableFileCache) {
  Service-StopSafe 'File Cache Service Agent'
  Remove-PathSafe 'C:\ProgramData\MspPlatform\FileCacheServiceAgent\cache\*'
  Service-StartSafe 'File Cache Service Agent'
} else { Write-Log "SKIP: N-able File Cache handling" }

# 4) Windows Update cache
if ($ClearWUCache) {
  Service-StopSafe 'wuauserv'
  Service-StopSafe 'bits'
  Remove-PathSafe "$env:WINDIR\SoftwareDistribution\Download\*"
  Service-StartSafe 'wuauserv'
  Service-StartSafe 'bits'
} else { Write-Log "SKIP: Windows Update cache" }

# 5) Temp folders (thorough, includes hidden)
if ($ClearTemp) {
  $tempPaths = @("$env:TEMP", "$env:WINDIR\Temp")
  foreach ($path in $tempPaths) {
    if (_Should($path, "Clear contents (hidden+system, recursive)")) {
      Try-Run {
        Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue |
          Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
      } "Clear contents of $path"
    }
  }
} else { Write-Log "SKIP: Temp folders" }

# 6) Optional Features
if ($RemoveOptionalFeatures) {
  if (_Should("WindowsMediaPlayer", "Disable feature")) {
    Try-Run { Disable-WindowsOptionalFeature -Online -FeatureName WindowsMediaPlayer -NoRestart -ErrorAction Stop } "Disable WindowsMediaPlayer"
  }
  if (_Should("FaxServicesClientPackage", "Disable feature")) {
    Try-Run { Disable-WindowsOptionalFeature -Online -FeatureName FaxServicesClientPackage -NoRestart -ErrorAction Stop } "Disable FaxServicesClientPackage"
  }
} else { Write-Log "SKIP: Remove optional features" }

# 7) Component store cleanup
if ($ComponentCleanup) {
  if (_Should("DISM StartComponentCleanup", "Run")) {
    Try-Run { Dism.exe /Online /Cleanup-Image /StartComponentCleanup | Out-Null } "DISM StartComponentCleanup"
  }
} else { Write-Log "SKIP: DISM StartComponentCleanup" }

if ($DeepComponentCleanup) {
  if (_Should("DISM ResetBase", "Run (irreversible)")) {
    Try-Run { Dism.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase | Out-Null } "DISM ResetBase (irreversible)"
  }
} else { Write-Log "SKIP: DISM ResetBase" }

# 8) Dell SARemediation backup purge (optional)
if ($PurgeDellSARemediation) {
  $saPath = 'C:\ProgramData\Dell\SARemediation\SystemRepair\Snapshots\Backup'
  Remove-PathSafe "$saPath\*"
} else { Write-Log "SKIP: Dell SARemediation purge" }

# 9) Recycle Bin: report (and optionally empty)
$rbBytesBefore = Get-RecycleBinSizeBytes
$rbGB = [math]::Round($rbBytesBefore / 1GB, 2)
if ($rbGB -ge 1) { Write-Log "NOTICE: Recycle Bin (executing user) approx $rbGB GB" }
else { Write-Log "INFO: Recycle Bin (executing user) approx $rbGB GB" }

if ($EmptyRecycleBin) {
  Empty-RecycleBinSafe
} else {
  Write-Log "SKIP: Empty Recycle Bin (technician/user approval required)"
}

# 10) Shadow storage report only (no deletions by default)
if ($ReportShadowsOnly) {
  if (_Should("VSS ShadowStorage", "Report usage")) {
    Try-Run { vssadmin list shadowstorage | ForEach-Object { Write-Log $_ } } "Report VSS shadow storage"
  }
} else {
  Write-Log "INFO: Shadow storage deletion is disabled by default. Handle case-by-case."
}

# 11) Shrink VSS Shadow Storage (optional, 10% cap per fixed drive)
if ($ShrinkShadowStorage) {
  $fixedDrives = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3 AND FileSystem != NULL"
  foreach ($drive in $fixedDrives) {
    $driveLetter = $drive.DeviceID
    $target = "VSS ShadowStorage on $driveLetter"
    $action = "Resize to max 10% of volume size"
    if (_Should($target, $action)) {
      Try-Run {
        $exe  = 'vssadmin.exe'
        $args = "Resize ShadowStorage /For=$driveLetter /On=$driveLetter /MaxSize=10%"
        Start-Process -FilePath $exe -ArgumentList $args -NoNewWindow -Wait
      } "Shrink shadow storage for $driveLetter"
    }
  }
} else {
  Write-Log "SKIP: Shrink VSS Shadow Storage"
}

# 12) CSC presence (Offline Files cache)
$CSCPath = 'C:\Windows\CSC'
if (Test-Path $CSCPath) {
  Write-Log "NOTICE: CSC folder present at $CSCPath (Offline Files cache). Can be large; do NOT delete blindly. Typically requires reboot to reinitialize."
} else {
  Write-Log "INFO: CSC folder not present."
}

# ---------- Summary ----------
$endFree = Get-FreeGB $TargetDrive
$delta = [math]::Round(($endFree - $startFree), 2)

$summary = @()
$summary += ('Free space on {0}: was {1} GB' -f $TargetDrive, $startFree)
$summary += "Ran low disk space triage procedure"
$summary += "Recycle Bin (pre): ~${rbGB} GB (executing user)"
$summary += ('Free space on {0}: now {1} GB  (delta {2} GB)' -f $TargetDrive, $endFree, $delta)
$summary += "Elapsed: $([int]((Get-Date)-$scriptStart).TotalSeconds) sec"

$summaryText = ($summary -join [Environment]::NewLine)

# Append summary and then output the complete log
Add-Content -Path $logFile -Value ([Environment]::NewLine + "===== SUMMARY =====" + [Environment]::NewLine + $summaryText)

Write-Output "===== Full Log from $logFile ====="
Write-Output (Get-Content -Path $logFile -Raw)
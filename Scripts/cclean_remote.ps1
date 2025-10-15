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
  [switch]$ShrinkShadowStorage,
  [switch]$ReportFolderSizes,
  [switch]$ReportPostMetrics
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
$ReportFolderSizes    = $true
$ReportFolderSizes    = $true
$ReportPostMetrics    = $true
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
$__switchNames = @(
  'DisableHibernate','CleanMgr','ClearWUCache','ClearTemp','ComponentCleanup',
  'DeepComponentCleanup','RemoveOptionalFeatures','EmptyRecycleBin','PurgeDellSARemediation',
  'TouchNableFileCache','ReportShadowsOnly','ShrinkShadowStorage',
  'ReportFolderSizes','ReportPostMetrics'
)
$__enabled = @()
foreach ($__n in $__switchNames) { if (Get-Variable -Name $__n -ValueOnly) { $__enabled += $__n } }

# ---------- Setup & helpers ----------
# --- Safe ShouldProcess wrapper (works even when run via IEX/irm where $PSCmdlet may be null) ---
function _Should([string]$target, [string]$action) {
  try {
    if ($PSBoundParameters.ContainsKey('WhatIf') -or $WhatIfPreference) { return $false }
  } catch { }
  if ($null -ne $PSCmdlet) {
    try { return $PSCmdlet.ShouldProcess($target, $action) } catch { return $true }
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

function Get-PrettySize([Int64]$bytes) {
  if ($bytes -lt 1KB) { return "$bytes B" }
  elseif ($bytes -lt 1MB) { return ("{0:N2} KB" -f ($bytes/1KB)) }
  elseif ($bytes -lt 1GB) { return ("{0:N2} MB" -f ($bytes/1MB)) }
  else { return ("{0:N2} GB" -f ($bytes/1GB)) }
}

function Get-FolderSizeBytes([string]$Path) {
  try {
    if (-not (Test-Path -LiteralPath $Path)) { return 0 }
    $sum = 0
    Get-ChildItem -LiteralPath $Path -Force -Recurse -ErrorAction SilentlyContinue |
      ForEach-Object { if (-not $_.PSIsContainer) { $sum += $_.Length } }
    return [Int64]$sum
  } catch { return 0 }
}

function Resolve-SID([string]$sid) {
  try {
    $objSID = New-Object System.Security.Principal.SecurityIdentifier($sid)
    return ($objSID.Translate([System.Security.Principal.NTAccount])).Value
  } catch { return $sid }
}

function Report-FolderSizes {
  param(
    [string[]]$FixedFolders = @('C:\Aeros','C:\CCS')
  )
  Write-Log "===== Folder size inventory (Aeros/CCS/Downloads) ====="

  $items = New-Object System.Collections.Generic.List[object]

  # Fixed folders: C:\Aeros, C:\CCS
  foreach ($p in $FixedFolders) {
    $sz = Get-FolderSizeBytes -Path $p
    Write-Log ("DETAIL: {0} size {1}" -f $p, (Get-PrettySize $sz))
    $items.Add([pscustomobject]@{ Type='Folder'; User=''; Path=$p; SizeBytes=$sz })
  }

  # Downloads for all user profiles under C:\Users (keep Public & Administrator; skip Default profiles)
  $profiles = Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue |
              Where-Object { $_.Name -notin @('Default','Default User','All Users') }

  foreach ($prof in $profiles) {
    $dl = Join-Path $prof.FullName 'Downloads'
    if (Test-Path -LiteralPath $dl) {
      $dsz = Get-FolderSizeBytes -Path $dl
      Write-Log ("DETAIL: Downloads for {0} size {1} ({2})" -f $prof.Name, (Get-PrettySize $dsz), $dl)
      $items.Add([pscustomobject]@{ Type='Downloads'; User=$prof.Name; Path=$dl; SizeBytes=$dsz })
    } else {
      Write-Log ("INFO: Downloads not found for {0} ({1})" -f $prof.Name, $dl)
    }
  }

  # Totals
  $aerosBytes = ($items | Where-Object { $_.Path -eq 'C:\Aeros' }     | Measure-Object SizeBytes -Sum).Sum
  $ccsBytes   = ($items | Where-Object { $_.Path -eq 'C:\CCS' }       | Measure-Object SizeBytes -Sum).Sum
  $dlBytes    = ($items | Where-Object { $_.Type -eq 'Downloads' }    | Measure-Object SizeBytes -Sum).Sum
  $grandBytes = ($items | Measure-Object SizeBytes -Sum).Sum

  Write-Log ("TOTAL: C:\Aeros   {0}" -f (Get-PrettySize $aerosBytes))
  Write-Log ("TOTAL: C:\CCS     {0}" -f (Get-PrettySize $ccsBytes))
  Write-Log ("TOTAL: Downloads  {0}" -f (Get-PrettySize $dlBytes))
  Write-Log ("TOTAL: Grand      {0}" -f (Get-PrettySize $grandBytes))

  # Return an object with totals for the summary
  [pscustomobject]@{
    AerosBytes     = [int64]$aerosBytes
    CcsBytes       = [int64]$ccsBytes
    DownloadsBytes = [int64]$dlBytes
    GrandBytes     = [int64]$grandBytes
  }
}

function Report-AllRecycleBins {
  $fixed = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3 AND FileSystem != NULL"
  foreach ($d in $fixed) {
    $rb = Join-Path $d.DeviceID '$Recycle.Bin'
    if (-not (Test-Path -LiteralPath $rb)) {
      Write-Log "INFO: Recycle Bin path not found on $($d.DeviceID)"
      continue
    }
    $total = Get-FolderSizeBytes -Path $rb
    Write-Log ("DETAIL: Recycle Bin on {0} total {1}" -f $d.DeviceID, (Get-PrettySize $total))

    # Per-user breakdown (SID folder names)
    Get-ChildItem -LiteralPath $rb -Force -ErrorAction SilentlyContinue |
      Where-Object { $_.PSIsContainer } |
      ForEach-Object {
        $sid = $_.Name
        $owner = Resolve-SID $sid
        $sz = Get-FolderSizeBytes -Path $_.FullName
        Write-Log ("  - {0}: {1}" -f $owner, (Get-PrettySize $sz))
      }
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

# ===== Baseline inventory (pre-clean) =====
Write-Log "===== Baseline inventory (pre-clean) ====="

# 1) Folder sizes (Aeros/CCS/Downloads)
if ($ReportFolderSizes) {
  $folderReportPre = Report-FolderSizes
}




# 2) Recycle Bin (executing user approx) + per-drive/SID breakdown
Write-Log "===== Recycle Bin inventory ====="
$rbBytesPre = Get-RecycleBinSizeBytes
$rbGBPre = [math]::Round($rbBytesPre / 1GB, 2)
if ($rbGBPre -ge 1) { Write-Log "NOTICE: Recycle Bin (executing user) approx $rbGBPre GB" }
else { Write-Log "INFO: Recycle Bin (executing user) approx $rbGBPre GB" }
Report-AllRecycleBins

# 3) System caches (Dell SARemediation + CSC)
Write-Log "===== System caches (Dell SAR, CSC) ====="
$saBase   = 'C:\ProgramData\Dell\SARemediation'
$saBackup = 'C:\ProgramData\Dell\SARemediation\SystemRepair\Snapshots\Backup'
if (Test-Path $saBase) {
  $saSize = Get-FolderSizeBytes -Path $saBase
  Write-Log ("DETAIL: Dell SARemediation at {0}, size {1}" -f $saBase, (Get-PrettySize $saSize))
  if (Test-Path $saBackup) {
    $bkSize = Get-FolderSizeBytes -Path $saBackup
    Write-Log ("DETAIL:   Backup folder size {0}" -f (Get-PrettySize $bkSize))
  } else {
    Write-Log "INFO:   Backup folder not found."
  }
} else {
  Write-Log "INFO: Dell SARemediation folder not found."
}

$CSCPath = 'C:\Windows\CSC'
if (Test-Path $CSCPath) {
  $csize = Get-FolderSizeBytes -Path $CSCPath
  Write-Log ("NOTICE: CSC present at {0}, size {1}. Do NOT delete blindly; reinit typically requires reboot." -f $CSCPath, (Get-PrettySize $csize))
} else {
  Write-Log "INFO: CSC folder not present."
}

# 4) VSS ShadowStorage (baseline)
Write-Log "===== VSS Shadow Storage (baseline) ====="
Try-Run {
  (vssadmin list shadowstorage) -split "`n" | ForEach-Object { Write-Log $_ }
} "Report VSS shadow storage (baseline)"

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






if ($EmptyRecycleBin) {
  Empty-RecycleBinSafe
} else {
  Write-Log "SKIP: Empty Recycle Bin (technician/user approval required)"
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



# ===== Post-clean snapshot (optional) =====
if ($ReportPostMetrics) {
  Write-Log "===== Post-clean snapshot ====="
  $rbBytesPost = Get-RecycleBinSizeBytes
  $rbGBPost = [math]::Round($rbBytesPost / 1GB, 2)
  Write-Log ("INFO: Recycle Bin (executing user) now approx {0} GB" -f $rbGBPost)
  Report-AllRecycleBins

  if (Test-Path $saBase) {
    $saSize2 = Get-FolderSizeBytes -Path $saBase
    Write-Log ("DETAIL: Dell SARemediation now {0}" -f (Get-PrettySize $saSize2))
    if (Test-Path $saBackup) {
      $bkSize2 = Get-FolderSizeBytes -Path $saBackup
      Write-Log ("DETAIL:   Backup folder now {0}" -f (Get-PrettySize $bkSize2))
    }
  }

  if (Test-Path $CSCPath) {
    $csize2 = Get-FolderSizeBytes -Path $CSCPath
    Write-Log ("DETAIL: CSC now {0}" -f (Get-PrettySize $csize2))
  }

  Try-Run {
    (vssadmin list shadowstorage) -split "`n" | ForEach-Object { Write-Log $_ }
  } "Report VSS shadow storage (post)"
}

if ($ReportPostMetrics -and $ReportFolderSizes) {
  Write-Log "===== Post-clean folder sizes ====="
  $folderReportPost = Report-FolderSizes
}

# ---------- Summary ----------
$endFree = Get-FreeGB $TargetDrive
$delta = [math]::Round(($endFree - $startFree), 2)

$summary = @()
$summary += ('Free space on {0}: was {1} GB' -f $TargetDrive, $startFree)
$summary += 'Ran low disk space triage procedure'
$summary += ('Recycle Bin (pre): ~{0} GB (executing user)' -f $rbGBPre)
$summary += ('Free space on {0}: now {1} GB  (delta {2} GB)' -f $TargetDrive, $endFree, $delta)
$summary += ('Elapsed: {0} sec' -f [int]((Get-Date)-$scriptStart).TotalSeconds)

if ($ReportFolderSizes -and $null -ne $folderReportPre) {
  $summary += ('Folders (pre): C:\Aeros {0}, C:\CCS {1}, Downloads {2}' -f `
               (Get-PrettySize $folderReportPre.AerosBytes), `
               (Get-PrettySize $folderReportPre.CcsBytes), `
               (Get-PrettySize $folderReportPre.DownloadsBytes))
}

$summaryText = ($summary -join [Environment]::NewLine)

# Append summary and then output the complete log
Add-Content -Path $logFile -Value ([Environment]::NewLine + "===== SUMMARY =====" + [Environment]::NewLine + $summaryText)

Write-Output "===== Full Log from $logFile ====="
Write-Output (Get-Content -Path $logFile -Raw)
#Requires -Version 5.1
<# ============================
   Power Stability Quick Report (PS5-safe, remote-friendly)
   - Filters noise (no FilterManager/CldFlt; hides Kernel-Processor-Power ID 55)
   - Boot→shutdown cycles with uptime seconds
   - Fault hints (WHEA / Kernel-Processor-Power minus 55 / Kernel-Thermal if present)
   - UPS/Battery status + AC/DC power source changes
   - Windows Update summary + restart reasons
   ============================ #>

# ---- Settings ----
$lookbackDays = 14
$since        = (Get-Date).AddDays(-$lookbackDays)
$sinceHints   = (Get-Date).AddDays(-3)

Write-Output ("=== Power Stability Report (last {0} days) ===" -f $lookbackDays)
try {
  $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
             ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) { Write-Output "Note: Running non-elevated; some System log entries may be hidden." }
} catch { }
Write-Output ""

# ---------- Last Boot (multi-source fallback) ----------
$lastBoot = $null
try {
  $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
  $lastBoot = [Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime)
} catch {
  try {
    $os = Get-WmiObject Win32_OperatingSystem -ErrorAction Stop
    $lastBoot = [Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime)
  } catch {
    try {
      $lb = Get-WinEvent -FilterHashtable @{LogName='System'; Id=6005} -MaxEvents 1 -ErrorAction Stop
      $lastBoot = $lb.TimeCreated
    } catch { }
  }
}
$lbText = if ($lastBoot) { $lastBoot } else { '(unavailable)' }
Write-Output ("Last Boot Time: {0}" -f $lbText)
Write-Output ""

# ---------- Helpers ----------
function Get-ByProvider {
  param([string]$Provider,[int[]]$Ids,[datetime]$Start)
  try {
    Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName=$Provider; Id=$Ids; StartTime=$Start} -ErrorAction Stop
  } catch { @() }
}
function Get-ByIds {
  param([int[]]$Ids,[datetime]$Start)
  try {
    Get-WinEvent -FilterHashtable @{LogName='System'; Id=$Ids; StartTime=$Start} -ErrorAction Stop
  } catch { @() }
}
function Provider-Exists {
  param([string]$Name)
  try { $null -ne (Get-WinEvent -ListProvider $Name -ErrorAction Stop) } catch { $false }
}

# ---------- Gather events (noise filtered, with fallback) ----------
$events = @()
$events += Get-ByProvider -Provider 'EventLog'                               -Ids @(6005,6006,6008) -Start $since
$events += Get-ByProvider -Provider 'Microsoft-Windows-Eventlog'             -Ids @(6005,6006,6008) -Start $since
$events += Get-ByProvider -Provider 'Microsoft-Windows-Kernel-Power'         -Ids @(41,42,107)      -Start $since
$events += Get-ByProvider -Provider 'Microsoft-Windows-Power-Troubleshooter' -Ids @(1)              -Start $since
$events += Get-ByProvider -Provider 'USER32'                               -Ids @(1074)          -Start $since

if (-not $events -or $events.Count -eq 0) {
  $all = Get-ByIds -Ids @(6005,6006,6008,41,42,107,1) -Start $since
  $events = $all | Where-Object {
    $_.ProviderName -ne 'Microsoft-Windows-FilterManager' -and
    $_.ProviderName -ne 'FilterManager'
  }
}
if (-not $events -or $events.Count -eq 0) {
  Write-Output "No matching power/boot events found in the last $lookbackDays days."
  Write-Output "Try: Run PowerShell as Administrator or increase lookbackDays."
  Write-Output "=== End of report ==="; return
}


# ---------- Unified power timeline (columnar, merges 1074 with shutdown) ----------

function Get-InitiatorAndReason {
  param($ev)  # expects a USER32 1074 event
  $who = 'System/Service'; $isUser = $false
  if ($ev.Message -match 'process .*TrustedInstaller') { $who = 'TrustedInstaller (Windows Update)' }
  elseif ($ev.Message -match 'by user\s+([^\r\n]+)')   { $who = "User: $($Matches[1])"; $isUser = $true }
  elseif ($ev.Message -match 'on behalf of user\s+([^\r\n]+?)\s+for the following reason:') { $who = "On behalf: $($Matches[1])" }
  elseif ($ev.Message -match 'on behalf of user\s+([^\r\n]+)') { $who = "On behalf: $($Matches[1])" }
  $reason = $null; if ($ev.Message -match 'for the following reason:\s*([^\r\n]+)') { $reason = $Matches[1] }
  $stype  = $null; if ($ev.Message -match 'Shutdown Type:\s*([^\r\n]+)')          { $stype  = $Matches[1] }
  [pscustomobject]@{ Who = $who; IsUser = $isUser; Reason = $reason; SType = $stype }
}

$evAll   = $events | Sort-Object TimeCreated
$ev1074  = $evAll  | Where-Object { $_.ProviderName -eq 'USER32' -and $_.Id -eq 1074 }
$evShut  = $evAll  | Where-Object { ($_.Id -eq 6006) -and ($_.ProviderName -in @('EventLog','Microsoft-Windows-Eventlog')) }
$evStart = $evAll  | Where-Object { ($_.Id -eq 6005) -and ($_.ProviderName -in @('EventLog','Microsoft-Windows-Eventlog')) }
$evSleep = $evAll  | Where-Object { $_.ProviderName -eq 'Microsoft-Windows-Kernel-Power' -and $_.Id -eq 42  }
$evResum = $evAll  | Where-Object { $_.ProviderName -eq 'Microsoft-Windows-Kernel-Power' -and $_.Id -eq 107 }
$evWake = $evAll | Where-Object {
  $_.Id -eq 1 -and (
    ($_.ProviderName -like '*Power-Troubleshooter*') -or
    ($_.Message -match '(?i)\bWake Source\b|\bWake Reason\b')
  )
}
$evUnexp = $evAll  | Where-Object {
  ($_.Id -eq 6008 -and $_.ProviderName -in @('EventLog','Microsoft-Windows-Eventlog')) -or
  ($_.ProviderName -eq 'Microsoft-Windows-Kernel-Power' -and $_.Id -eq 41)
}

# Pair 1074 → next shutdown within 2 hours
$pendingShut = [System.Collections.Generic.List[object]]::new()
$evShut | ForEach-Object { [void]$pendingShut.Add($_) }
$rows = New-Object System.Collections.Generic.List[object]

foreach ($t in $ev1074) {
  $meta = Get-InitiatorAndReason $t
  $completedAt = ''
  foreach ($s in $pendingShut) {
    if ($s.TimeCreated -gt $t.TimeCreated) {
      $delta = New-TimeSpan -Start $t.TimeCreated -End $s.TimeCreated
      if ($delta.TotalHours -le 2) { $completedAt = $s.TimeCreated; [void]$pendingShut.Remove($s); break }
    }
  }
  $rows.Add([pscustomobject]@{
    Timestamp      = $t.TimeCreated
    'Event type'   = 'Shutdown/Restart requested (USER32 1074)'
    'Initiated by' = $meta.Who
    Reason         = $meta.Reason
    Type           = $meta.SType
    'Completed at' = $completedAt
    Message        = ($t.Message -split "`r?`n")[0]
  })
}

# Shutdowns with no prior request
foreach ($s in $pendingShut) {
  $rows.Add([pscustomobject]@{
    Timestamp      = $s.TimeCreated
    'Event type'   = 'Shutdown (no prior request)'
    'Initiated by' = 'Unknown'
    Reason         = ''
    Type           = ''
    'Completed at' = ''
    Message        = ($s.Message -split "`r?`n")[0]
  })
}

# Startup/Sleep/Resume/Wake/Unexpected
foreach ($e in $evStart) {
  $rows.Add([pscustomobject]@{
    Timestamp      = $e.TimeCreated; 'Event type'='Startup'; 'Initiated by'=''; Reason=''; Type=''; 'Completed at'=''; Message=($e.Message -split "`r?`n")[0]
  })
}
foreach ($e in $evSleep) {
  $sr = ''; if ($e.Message -match 'Sleep Reason:\s*([^\r\n]+)') { $sr = $Matches[1] }
  $rows.Add([pscustomobject]@{
    Timestamp      = $e.TimeCreated; 'Event type'='Sleep'; 'Initiated by'=''; Reason=$sr; Type=''; 'Completed at'=''; Message=($e.Message -split "`r?`n")[0]
  })
}
foreach ($e in $evResum) {
  $rows.Add([pscustomobject]@{
    Timestamp      = $e.TimeCreated; 'Event type'='Resume'; 'Initiated by'=''; Reason=''; Type=''; 'Completed at'=''; Message=($e.Message -split "`r?`n")[0]
  })
}
# --- Wake (Power-Troubleshooter / ID 1): extract Wake Source (+ optional text) into Reason ---
foreach ($e in $evWake) {
  $ws  = $null   # e.g., "Device -USB Keyboard" or "Timer - Windows Update"
  $wst = $null   # optional "Wake Source Text: ..." line on some systems

# Fallback: derive wake from Resume when no Power-Troubleshooter event was found
if ( ($rows | Where-Object { $_.'Event type' -like 'Wake*' }).Count -eq 0 -and $evResum.Count -gt 0 ) {
  foreach ($e in $evResum) {
    $rows.Add([pscustomobject]@{
      Timestamp      = $e.TimeCreated
      'Event type'   = 'Wake (derived from Resume)'
      'Initiated by' = ''
      Reason         = 'Resume logged; no Power-Troubleshooter wake source'
      Type           = ''
      'Completed at' = ''
      Message        = ($e.Message -split "`r?`n")[0]
    })
  }
}

  # Parse the event message lines
  ($e.Message -split "`r?`n") | ForEach-Object {
    if (-not $ws  -and $_ -match 'Wake Source(?: \(.*\))?:\s*(.+)') { $ws  = $Matches[1].Trim() }
    if (-not $wst -and $_ -match 'Wake Source Text:\s*(.+)')       { $wst = $Matches[1].Trim() }
  }

  # Build one Reason string (no ternary)
  $parts = @()
  if ($ws)  { $parts += $ws }      # e.g., "Device -USB Keyboard"
  if ($wst) { $parts += $wst }     # e.g., "Power Button"
  $reason = if ($parts.Count -gt 0) { $parts -join '; ' } else { 'Wake source not reported' }

  $rows.Add([pscustomobject]@{
    Timestamp      = $e.TimeCreated
    'Event type'   = 'Wake'
    'Initiated by' = ''
    Reason         = $reason       # <-- fills the Reason column in your table
    Type           = ''
    'Completed at' = ''
    Message        = ($e.Message -split "`r?`n")[0]
  })
}
foreach ($e in $evUnexp) {
  $etype = if ($e.Id -eq 41) { 'Kernel-Power 41 (unexpected power loss)' } else { 'Unexpected Shutdown (6008)' }
  $rows.Add([pscustomobject]@{
    Timestamp      = $e.TimeCreated; 'Event type'=$etype; 'Initiated by'='N/A'; Reason=''; Type=''; 'Completed at'=''; Message=($e.Message -split "`r?`n")[0]
  })
}

# === Print unified timeline (auto-adjust to console width) ===
function Show-Timeline {
  param([Parameter(Mandatory=$true)]$Rows)

  # Safely detect console width (fallback to 120 if not available)
  $width = 120
  try {
    if ($Host -and $Host.UI -and $Host.UI.RawUI) {
      $width = [int]$Host.UI.RawUI.BufferSize.Width
      if ($width -lt 20) { $width = 120 }
    }
  } catch { $width = 120 }

  Write-Output "=== Unified power timeline (requests merged with completions) ==="

  if ($width -ge 180) {
    # WIDE: full table
    ($Rows | Sort-Object Timestamp |
      Format-Table -Wrap `
        @{ Label = 'Timestamp';    Expression = { $_.Timestamp } },
        @{ Label = 'Event type';   Expression = { $_.'Event type' } },
        @{ Label = 'Initiated by'; Expression = { $_.'Initiated by' } },
        @{ Label = 'Reason';       Expression = { $_.Reason } },
        @{ Label = 'Type';         Expression = { $_.Type } },
        @{ Label = 'Completed';    Expression = { $_.'Completed at' } },
        @{ Label = 'Message';      Expression = { $_.Message } } |
      Out-String -Width $width) | Write-Output

  } elseif ($width -ge 130) {
    # MEDIUM: drop Message to keep table tidy
    ($Rows | Sort-Object Timestamp |
      Format-Table -Wrap `
        @{ Label = 'Timestamp';    Expression = { $_.Timestamp } },
        @{ Label = 'Event type';   Expression = { $_.'Event type' } },
        @{ Label = 'Initiated by'; Expression = { $_.'Initiated by' } },
        @{ Label = 'Reason';       Expression = { $_.Reason } },
        @{ Label = 'Type';         Expression = { $_.Type } },
        @{ Label = 'Completed';    Expression = { $_.'Completed at' } } |
      Out-String -Width $width) | Write-Output

  } else {
    # NARROW: list view (everything readable, no horizontal squeezing)
    ($Rows | Sort-Object Timestamp |
      Select-Object Timestamp,'Event type','Initiated by',Reason,Type,'Completed at',Message |
      Format-List |
      Out-String -Width $width) | Write-Output
  }

  Write-Output ""
}

Show-Timeline -Rows $rows


# ---------- Boot → Shutdown cycles with uptime ----------
$boots    = $normalized | Where-Object { $_.EventType -eq 'Startup' }
$endTypes = @('Shutdown','Unexpected Shutdown','Kernel-Power 41 (power loss)')
$cycles = foreach ($b in $boots) {
  $end = $normalized | Where-Object { $_.TimeCreated -gt $b.TimeCreated -and $_.EventType -in $endTypes } | Select-Object -First 1
  New-Object PSObject -Property @{
    BootTime      = $b.TimeCreated
    EndTime       = if ($end) { $end.TimeCreated } else { $null }
    EndType       = if ($end) { $end.EventType }  else { $null }
    UptimeSeconds = if ($end) { [int]([timespan]($end.TimeCreated - $b.TimeCreated)).TotalSeconds } else { $null }
  }
}
Write-Output "=== Boot → Shutdown cycles (first end-event after each boot) ==="
$cycles | Select-Object BootTime, EndTime, EndType, UptimeSeconds | Format-Table -AutoSize
Write-Output ""
$short = $cycles | Where-Object { $_.UptimeSeconds -and $_.UptimeSeconds -lt 180 }
if ($short) {
  Write-Output "⚠ Detected very short uptimes (< 3 minutes) after boot:"
  $short | Select-Object BootTime, EndTime, EndType, UptimeSeconds | Format-Table -AutoSize
  Write-Output ""

}
# --- Quick interpretation near short uptimes ---
if ($short -and $short.Count -gt 1) {
  $min = ($short | Measure-Object -Property UptimeSeconds -Minimum).Minimum
  Write-Output '=== Quick interpretation ==='
  Write-Output ("Multiple very short uptimes detected. Shortest was {0} seconds." -f $min)
  Write-Output 'This pattern usually indicates power delivery or thermal protection tripping.'
  Write-Output 'Use: wall-outlet bypass, swap power cable/UPS/brick, BIOS idle test watching CPU temps.'
  Write-Output ''
}
# Hint if shorts correlate with Windows Update restarts in the last 24h
try {
  $ti = Get-WinEvent -FilterHashtable @{ LogName='System'; Id=1074; StartTime=(Get-Date).AddDays(-14) } -ErrorAction Stop |
        Where-Object { $_.Message -match 'process .*TrustedInstaller' }
  if ($short -and $short.Count -gt 0 -and $ti) {
    $likelyWU = $false
    foreach ($s in $short) {
      foreach ($e in $ti) {
        if ([math]::Abs((New-TimeSpan -Start $s.EndTime -End $e.TimeCreated).TotalHours) -le 24) { $likelyWU = $true; break }
      }
      if ($likelyWU) { break }
    }
    if ($likelyWU) {
      Write-Output "Note: Short uptimes appear within ~24h of TrustedInstaller-initiated restarts; likely Windows Update activity."
      Write-Output ""
    }
  }
} catch { }

# ---------- Current power settings (minutes) ----------
Write-Output "=== Current power settings ==="
function Get-IndexedMinutes { param([string]$line)
  if (-not $line) { return $null }
  $raw = $line.Split(':')[-1].Trim()
  if ($raw -match '^0x') { [convert]::ToInt32($raw,16) } else { [int]$raw }
}
$schemeGuid = $null
try { $schemeGuid = (powercfg /getactivescheme | Select-String 'Power Scheme GUID:\s+([\w-]+)').Matches[0].Groups[1].Value } catch { }
$sleepAC=$sleepDC=$hibAC=$hibDC=$null
if ($schemeGuid) {
  $sleep = powercfg /query $schemeGuid SUB_SLEEP STANDBYIDLE
  $hiber = powercfg /query $schemeGuid SUB_SLEEP HIBERNATEIDLE
  $sleepAC = Get-IndexedMinutes (($sleep | Select-String 'Current AC Power Setting Index').Line)
  $sleepDC = Get-IndexedMinutes (($sleep | Select-String 'Current DC Power Setting Index').Line)
  $hibAC   = Get-IndexedMinutes (($hiber | Select-String 'Current AC Power Setting Index').Line)
  $hibDC   = Get-IndexedMinutes (($hiber | Select-String 'Current DC Power Setting Index').Line)
  [PSCustomObject]@{
    ActiveSchemeGUID = $schemeGuid
    Sleep_AC_Min     = $sleepAC
    Sleep_DC_Min     = $sleepDC
    Hibernate_AC_Min = $hibAC
    Hibernate_DC_Min = $hibDC
  } | Format-List
} else { Write-Output "Active scheme: (couldn’t parse)" }
Write-Output ""
Write-Output "Supported sleep states (powercfg /a):"
powercfg /a
Write-Output ""

if ($schemeGuid -and ( ($sleepAC -gt 0) -or ($sleepDC -gt 0) -or ($hibAC -gt 0) -or ($hibDC -gt 0) )) {
  Write-Output "Tip: To disable sleep/hibernate on this scheme:"
  Write-Output "  powercfg /change standby-timeout-ac 0"
  Write-Output "  powercfg /change standby-timeout-dc 0"
  Write-Output "  powercfg /hibernate off"
  Write-Output ""
}

# ---------- Fault hints (WHEA / Kernel-Processor-Power / Kernel-Thermal) ----------
Write-Output "=== Fault hints (last 3 days) ==="

$whea = Get-WinEvent -FilterHashtable @{ LogName='System'; ProviderName='Microsoft-Windows-WHEA-Logger'; StartTime=$sinceHints } -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, Id, LevelDisplayName, Message
if ($whea) { Write-Output "--- WHEA-Logger ---"; $whea | Select-Object TimeCreated, Id, LevelDisplayName | Format-Table -AutoSize; Write-Output "" }

$kpp = Get-WinEvent -FilterHashtable @{ LogName='System'; ProviderName='Microsoft-Windows-Kernel-Processor-Power'; StartTime=$sinceHints } -ErrorAction SilentlyContinue |
  Where-Object { $_.Id -ne 55 } |  # hide capability spam
  Select-Object TimeCreated, Id, Message
if ($kpp) { Write-Output "--- Kernel-Processor-Power ---"; $kpp | Select-Object TimeCreated, Id, Message | Format-Table -Wrap; Write-Output "" }

if (Provider-Exists 'Microsoft-Windows-Kernel-Thermal') {
  $kth = Get-WinEvent -FilterHashtable @{ LogName='System'; ProviderName='Microsoft-Windows-Kernel-Thermal'; StartTime=$sinceHints } -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message
  if ($kth) { Write-Output "--- Kernel-Thermal ---"; $kth | Select-Object TimeCreated, Id, Message | Format-Table -Wrap; Write-Output "" }
} else {
  Write-Output "--- Kernel-Thermal --- (provider not present on this system)"
  Write-Output ""
}

# ---------- UPS / Battery status ----------
Write-Output "=== UPS / Battery status (last 14 days) ==="
# If a USB/HID UPS is connected, it often appears as a 'Battery' device.
$bat = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue
if ($bat) {
  $bat | Select-Object Name, Status, BatteryStatus, EstimatedChargeRemaining, DesignVoltage | Format-Table -AutoSize
} else {
  Write-Output "No Battery/UPS reported via Win32_Battery."
}
# AC/DC power source change events (helpful for UPS switching to battery)
$kpPowerSrc = Get-WinEvent -FilterHashtable @{ LogName='System'; ProviderName='Microsoft-Windows-Kernel-Power'; Id=105; StartTime=$since } -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, Id, Message
if ($kpPowerSrc) {
  Write-Output "--- Kernel-Power (power source changes, e.g., AC↔battery) ---"
  $kpPowerSrc | Select-Object TimeCreated, Id, Message | Format-Table -Wrap
  Write-Output ""
}
# APC/PowerChute events (if installed)
$apc = @()
if (Provider-Exists 'APC Data Service') {
  try {
    $apc = Get-WinEvent -FilterHashtable @{ LogName='Application'; ProviderName='APC Data Service'; StartTime=$since } -ErrorAction Stop |
      Select-Object TimeCreated, Id, LevelDisplayName, Message
  } catch {
    $apc = @()
  }
}
if ($apc) {
  Write-Output '--- APC UPS (Application log) ---'
  $apc | Format-Table -Wrap
  Write-Output ''
}
# ---------- Windows Update + Restart reasons ----------
Write-Output "=== Windows Update (last 14 days) ==="
$wu = @()
# Preferred channel:
try {
  $wu += Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-WindowsUpdateClient/Operational'; Id = @(19,20); StartTime=$since } -ErrorAction Stop
} catch { }
# Fallback to System log:
try {
  $wu += Get-WinEvent -FilterHashtable @{ LogName='System'; ProviderName='Microsoft-Windows-WindowsUpdateClient'; Id = @(19,20); StartTime=$since } -ErrorAction Stop
} catch { }

if ($wu) {
  $wu | Sort-Object TimeCreated | ForEach-Object {
    $status = if ($_.Id -eq 19) { 'Installed OK' } elseif ($_.Id -eq 20) { 'Install FAILED' } else { 'Other' }
    [pscustomobject]@{
      TimeCreated = $_.TimeCreated
      Id          = $_.Id
      Status      = $status
      Title       = ($_.Message -split "`r?`n")[0]
    }
  } | Format-Table TimeCreated, Id, Status, Title -Wrap
} else {
  Write-Output "No Windows Update client events found in the lookback window."
}
Write-Output ""
Write-Output "=== OS / Build info ==="
try {
  $ci = Get-ComputerInfo
  $cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
  $displayVersion = $cv.DisplayVersion    # e.g., 24H2 (preferred on Win 11/late Win10)
  if (-not $displayVersion) { $displayVersion = $cv.ReleaseId }  # older Win10 fallback
  $build = "{0}.{1}" -f $cv.CurrentBuild, $cv.UBR
  [pscustomobject]@{
    OSName          = $ci.OsName
    Edition         = $cv.EditionID
    DisplayVersion  = $displayVersion    # e.g., "24H2"
    ProductName     = $cv.ProductName    # e.g., "Windows 11 Pro"
    Build           = $build             # e.g., "26100.1234"
    BuildLab        = $cv.BuildLabEx
  } | Format-List
} catch {
  Write-Output "Could not read OS/build information."
}
Write-Output ""
Write-Output "Recent hotfixes (Get-HotFix):"
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10 Source, Description, HotFixID, InstalledOn | Format-Table -AutoSize
Write-Output ""
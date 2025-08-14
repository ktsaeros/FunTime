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

# ---------- Normalize ----------
$normalized = $events | Sort-Object TimeCreated | ForEach-Object {
  $etype = switch -Regex ("$($_.ProviderName)|$($_.Id)") {
    'EventLog\|6005' { 'Startup' }
    'EventLog\|6006' { 'Shutdown' }
    'EventLog\|6008' { 'Unexpected Shutdown' }
    'Microsoft-Windows-Eventlog\|6005' { 'Startup' }
    'Microsoft-Windows-Eventlog\|6006' { 'Shutdown' }
    'Microsoft-Windows-Eventlog\|6008' { 'Unexpected Shutdown' }
    'Microsoft-Windows-Kernel-Power\|41'  { 'Kernel-Power 41 (power loss)' }
    'Microsoft-Windows-Kernel-Power\|42'  { 'Sleep' }
    'Microsoft-Windows-Kernel-Power\|107' { 'Resume' }
    'Microsoft-Windows-Power-Troubleshooter\|1' { 'Wake' }
    default { "Other ($($_.ProviderName) ID $($_.Id))" }
  }
  $wakeSource = $null
  if ($_.ProviderName -eq 'Microsoft-Windows-Power-Troubleshooter' -and $_.Id -eq 1) {
    $wakeSource = ($_.Message -split "`r?`n" | Where-Object { $_ -match 'Wake Source' } | ForEach-Object { $_.Trim() }) -join '; '
    if (-not $wakeSource) { $wakeSource = 'Wake Source: (not reported)' }
  }
  New-Object PSObject -Property @{
    TimeCreated = $_.TimeCreated
    Provider    = $_.ProviderName
    Id          = $_.Id
    EventType   = $etype
    Detail      = if ($wakeSource) { $wakeSource } else { $null }
  }
}

Write-Output "=== Timeline (noise filtered) ==="
$normalized | Select-Object TimeCreated, EventType, Detail | Format-Table -AutoSize
Write-Output ""

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
# --- Quick interpretation near short uptimes ---
if ($short) {
  $min = ($short | Measure-Object -Property UptimeSeconds -Minimum).Minimum
  Write-Output '=== Quick interpretation ==='
  Write-Output ("Multiple very short uptimes detected. Shortest was {0} seconds." -f $min)
  Write-Output 'This pattern usually indicates power delivery or thermal protection tripping.'
  Write-Output 'Use: wall-outlet bypass, swap power cable/UPS/brick, BIOS idle test watching CPU temps.'
  Write-Output ''
}
}

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
  } catch { $apc = @() }
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
      TimeCreated = $_.TimeCreated;
      Id          = $_.Id;
      Status      = $status;
      Title       = ($_.Message -split "`r?`n")[0]
    }
  } | Format-Table -AutoSize
} else {
  Write-Output "No Windows Update client events found in the lookback window."
}
Write-Output ""

Write-Output "Recent hotfixes (Get-HotFix):"
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10 Source, Description, HotFixID, InstalledOn | Format-Table -AutoSize
Write-Output ""

Write-Output "=== Restart reasons (last 14 days, Event ID 1074) ==="
try {
  Get-WinEvent -FilterHashtable @{ LogName='System'; Id=1074; StartTime=$since } -ErrorAction Stop |
    Select-Object @(
      @{Name='TimeCreated';Expression={$_.TimeCreated}},
      @{Name='InitiatedBy';Expression={
          if ($_.Message -match 'process .*TrustedInstaller') { 'TrustedInstaller (Windows Update)' }
          elseif ($_.Message -match 'by user\s+([^\r\n]+)') { $Matches[1] }
          else { 'System/Service' }
      }},
      @{Name='Message';Expression={$_.Message}}
    ) | Format-Table -Wrap
  Write-Output ("Multiple very short uptimes detected. Shortest was {0} seconds." -f $min)
  Write-Output "This pattern usually indicates power delivery or thermal protection tripping."
  Write-Output "Use: wall-outlet bypass, swap power cable/UPS/brick, BIOS idle test watching CPU temps."
  Write-Output ""
}
Write-Output "=== End of report ==="
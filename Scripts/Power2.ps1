<# ============================
   Power Stability Quick Report
   - Filters noise (no FilterManager/CldFlt)
   - Clear timeline with uptime between boots and shutdowns
   - Pulls WHEA / thermal / power throttling hints
   - Shows active sleep/hibernate timeouts + supported sleep states
   ============================ #>

$ErrorActionPreference = 'Stop'
$lookbackDays = 14
$since = (Get-Date).AddDays(-$lookbackDays)

Write-Output ("=== Power Stability Report (last {0} days) ===" -f $lookbackDays)
Write-Output ""

# --------------------------------------------
# Section 0: Last boot & quick state
# --------------------------------------------
try {
  $os = Get-CimInstance Win32_OperatingSystem
  $lastBoot = ([Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime))
  Write-Output ("Last Boot Time: {0}" -f $lastBoot)
} catch {
  Write-Output "Last Boot Time: (unavailable)"
}
Write-Output ""

# --------------------------------------------
# Section 1: Focused Power/Boot Timeline
#   Providers and IDs:
#   - EventLog: 6005 (Startup), 6006 (Shutdown), 6008 (Unexpected Shutdown)
#   - Kernel-Power: 41 (Unexpected Restart/Power loss), 42 (Sleep), 107 (Resume)
#   - Power-Troubleshooter: 1 (Wake)   [provider-filtered; no FilterManager noise]
# --------------------------------------------
$events = @()

$events += Get-WinEvent -FilterHashtable @{
  LogName='System'; ProviderName='EventLog'; Id= @(6005,6006,6008); StartTime=$since
}
$events += Get-WinEvent -FilterHashtable @{
  LogName='System'; ProviderName='Microsoft-Windows-Kernel-Power'; Id= @(41,42,107); StartTime=$since
}
$events += Get-WinEvent -FilterHashtable @{
  LogName='System'; ProviderName='Microsoft-Windows-Power-Troubleshooter'; Id= 1; StartTime=$since
}

# Normalize & label
$normalized = $events | Sort-Object TimeCreated | ForEach-Object {
  $etype = switch -Regex ("$($_.ProviderName)|$($_.Id)") {
    'EventLog\|6005' { 'Startup' }
    'EventLog\|6006' { 'Shutdown' }
    'EventLog\|6008' { 'Unexpected Shutdown' }
    'Microsoft-Windows-Kernel-Power\|41'  { 'Kernel-Power 41 (power loss)' }
    'Microsoft-Windows-Kernel-Power\|42'  { 'Sleep' }
    'Microsoft-Windows-Kernel-Power\|107' { 'Resume' }
    'Microsoft-Windows-Power-Troubleshooter\|1' { 'Wake' }
    default { "Other ($($_.ProviderName) ID $($_.Id))" }
  }

  # Extract wake source when present
  $wakeSource = $null
  if ($_.ProviderName -eq 'Microsoft-Windows-Power-Troubleshooter' -and $_.Id -eq 1) {
    $wakeSource = ($_.Message -split "`r?`n" | Where-Object { $_ -match 'Wake Source' } | ForEach-Object { $_.Trim() }) -join '; '
    if (-not $wakeSource) { $wakeSource = 'Wake Source: (not reported)' }
  }

  [PSCustomObject]@{
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

# --------------------------------------------
# Section 1b: Boot → Shutdown cycles with Uptime
#   For each Startup, find the next end-event (Shutdown, Unexpected, or KP-41)
# --------------------------------------------
$boots = $normalized | Where-Object { $_.EventType -eq 'Startup' }
$endTypes = @('Shutdown','Unexpected Shutdown','Kernel-Power 41 (power loss)')
$cycles = foreach ($b in $boots) {
  $end = $normalized | Where-Object {
    $_.TimeCreated -gt $b.TimeCreated -and $_.EventType -in $endTypes
  } | Select-Object -First 1
  [PSCustomObject]@{
    BootTime      = $b.TimeCreated
    EndTime       = $end.TimeCreated
    EndType       = $end.EventType
    UptimeSeconds = if ($end) { [int]([timespan]($end.TimeCreated - $b.TimeCreated)).TotalSeconds } else { $null }
  }
}

Write-Output "=== Boot → Shutdown cycles (first end-event after each boot) ==="
$cycles | Select-Object BootTime, EndTime, EndType, UptimeSeconds | Format-Table -AutoSize
Write-Output ""

# Highlight any very short uptimes (e.g., < 180 seconds)
$short = $cycles | Where-Object { $_.UptimeSeconds -and $_.UptimeSeconds -lt 180 }
if ($short) {
  Write-Output "⚠ Detected very short uptimes (< 3 minutes) after boot:"
  $short | Select-Object BootTime, EndTime, EndType, UptimeSeconds | Format-Table -AutoSize
  Write-Output ""
}

# --------------------------------------------
# Section 2: Current Power Settings (minutes) + Supported Sleep States
#   Note: STANDBYIDLE/HIBERNATEIDLE indexes are minutes already (no /60)
# --------------------------------------------
Write-Output "=== Current power settings ==="

function Get-IndexedMinutes {
  param([string]$line)
  if (-not $line) { return $null }
  $hex = $line.Split(':')[-1].Trim()
  if ($hex -match '^0x') { return [convert]::ToInt32($hex,16) } else { return [int]$hex }
}

# Active scheme GUID
$schemeGuid = $null
try {
  $schemeGuid = (powercfg /getactivescheme | Select-String 'Power Scheme GUID:\s+([\w-]+)').Matches[0].Groups[1].Value
} catch {}

if ($schemeGuid) {
  # Sleep (STANDBYIDLE)
  $sleep = powercfg /query $schemeGuid SUB_SLEEP STANDBYIDLE
  $sleepAC = Get-IndexedMinutes (($sleep | Select-String 'Current AC Power Setting Index').Line)
  $sleepDC = Get-IndexedMinutes (($sleep | Select-String 'Current DC Power Setting Index').Line)

  # Hibernate (HIBERNATEIDLE)
  $hiber = powercfg /query $schemeGuid SUB_SLEEP HIBERNATEIDLE
  $hibAC = Get-IndexedMinutes (($hiber | Select-String 'Current AC Power Setting Index').Line)
  $hibDC = Get-IndexedMinutes (($hiber | Select-String 'Current DC Power Setting Index').Line)

  [PSCustomObject]@{
    ActiveSchemeGUID = $schemeGuid
    Sleep_AC_Min     = $sleepAC
    Sleep_DC_Min     = $sleepDC
    Hibernate_AC_Min = $hibAC
    Hibernate_DC_Min = $hibDC
  } | Format-List
} else {
  Write-Output "Active scheme: (couldn’t parse)"
}

Write-Output ""
Write-Output "Supported sleep states (powercfg /a):"
powercfg /a
Write-Output ""

# Helpful hint if any timeouts are non-zero
if ($schemeGuid -and ( ($sleepAC -gt 0) -or ($sleepDC -gt 0) -or ($hibAC -gt 0) -or ($hibDC -gt 0) )) {
  Write-Output "Tip: To disable sleep/hibernate on this scheme:"
  Write-Output "  powercfg /change standby-timeout-ac 0"
  Write-Output "  powercfg /change standby-timeout-dc 0"
  Write-Output "  powercfg /hibernate off"
  Write-Output ""
}

# --------------------------------------------
# Section 3: Fault Hints (Thermal / Firmware Throttle / WHEA)
# --------------------------------------------
Write-Output "=== Fault hints (last 3 days) ==="
$sinceHints = (Get-Date).AddDays(-3)

# WHEA (hardware error logs)
$whea = Get-WinEvent -FilterHashtable @{
  LogName='System'; ProviderName='Microsoft-Windows-WHEA-Logger'; StartTime=$sinceHints
} -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, Id, LevelDisplayName, Message

if ($whea) {
  Write-Output "--- WHEA-Logger ---"
  $whea | Select-Object TimeCreated, Id, LevelDisplayName | Format-Table -AutoSize
  Write-Output ""
}

# Kernel-Processor-Power (thermal/firmware throttling hints like ID 37)
$kpp = Get-WinEvent -FilterHashtable @{
  LogName='System'; ProviderName='Microsoft-Windows-Kernel-Processor-Power'; StartTime=$sinceHints
} -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, Id, Message

if ($kpp) {
  Write-Output "--- Kernel-Processor-Power ---"
  $kpp | Select-Object TimeCreated, Id, Message | Format-Table -Wrap
  Write-Output ""
}

# Kernel-Thermal
$kth = Get-WinEvent -FilterHashtable @{
  LogName='System'; ProviderName='Microsoft-Windows-Kernel-Thermal'; StartTime=$sinceHints
} -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, Id, Message

if ($kth) {
  Write-Output "--- Kernel-Thermal ---"
  $kth | Select-Object TimeCreated, Id, Message | Format-Table -Wrap
  Write-Output ""
}

# --------------------------------------------
# Section 4: Quick Interpretation
# --------------------------------------------
$veryShort = $short | Measure-Object -Property UptimeSeconds -Minimum
if ($veryShort.Count -gt 0) {
  Write-Output "=== Quick interpretation ==="
  Write-Output ("Multiple very short uptimes detected. Shortest was {0} seconds." -f $veryShort.Minimum)
  Write-Output "This pattern usually indicates power delivery or thermal protection tripping."
  Write-Output "Use: wall-outlet bypass, swap power cable/UPS/brick, BIOS idle test watching CPU temps."
  Write-Output ""
}

Write-Output "=== End of report ==="
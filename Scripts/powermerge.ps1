#Requires -Version 5.1
<# =====================================================
   Power Report (Events + Power Settings) — PS 5.1 SAFE
   - Recent power-related events
   - Current sleep/hibernate settings (seconds→minutes aware)
   - Hibernate availability check
   - Recommendation block for Kevin's desired config:
       AC: no sleep (monitor 20m), DC: sleep 15m (monitor 5m), HIBERNATE OFF
   ===================================================== #>

# ---------------- Utilities ----------------
function Provider-Exists {
  param([string]$Name)
  try { [bool](Get-WinEvent -ListProvider $Name -ErrorAction Stop) } catch { $false }
}

# ---------------- Section 1: Recent power events (last 14 days) ----------------
$lookbackDays = 14
$since        = (Get-Date).AddDays(-$lookbackDays)
Write-Output ("=== Recent power events (last {0} days) ===" -f $lookbackDays)

$ids = 1,42,107,6005,6006,6008
Get-WinEvent -FilterHashtable @{ LogName='System'; Id=$ids; StartTime=$since } -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, ProviderName, Id, Message |
  Sort-Object TimeCreated |
  Format-Table -Wrap

Write-Output ""

# ---------------- Section 2: Current Power Settings ----------------
Write-Output "=== Current power settings ==="

# 2a. Active scheme GUID
$schemeGuid = powercfg /getactivescheme |
  Select-String 'Power Scheme GUID:\s+([\w-]+)' |
  ForEach-Object { $_.Matches[0].Groups[1].Value }

if ($schemeGuid) {
  # 2b. Query Sleep (STANDBYIDLE) and Hibernate (HIBERNATEIDLE)
  $sleepSettings     = powercfg /query $schemeGuid SUB_SLEEP STANDBYIDLE
  $hibernateSettings = powercfg /query $schemeGuid SUB_SLEEP HIBERNATEIDLE

  # 2c. Display raw GUIDs/aliases
  Write-Output ("Sleep after RAW: {0}" -f (($sleepSettings | Select-String 'Power Setting GUID').Line.Trim()))
  Write-Output ("Hibernate after RAW: {0}" -f (($hibernateSettings | Select-String 'Power Setting GUID').Line.Trim()))

  # 2d. Determine units (Seconds vs Minutes) for sleep
  $units = 'Seconds'
  $um = ($sleepSettings | Select-String -Pattern 'Possible Settings units:\s+(\w+)' -AllMatches).Matches
  if ($um.Count -gt 0) { $units = $um[0].Groups[1].Value }

  # 2e. Parse current indices (hex) for AC/DC sleep and hibernate
  $sleepAChex = ($sleepSettings | Select-String 'Current AC Power Setting Index').Line.Split(':')[-1].Trim()
  $sleepDChex = ($sleepSettings | Select-String 'Current DC Power Setting Index').Line.Split(':')[-1].Trim()
  $hibAChex   = ($hibernateSettings | Select-String 'Current AC Power Setting Index').Line.Split(':')[-1].Trim()
  $hibDChex   = ($hibernateSettings | Select-String 'Current DC Power Setting Index').Line.Split(':')[-1].Trim()

  function HexToMinutes([string]$hex, [string]$unitsName) {
    if (-not $hex) { return $null }
    $val = [convert]::ToInt32($hex,16)
    if ($unitsName -ieq 'Seconds') { return [int][math]::Round($val / 60.0) }
    return $val
  }

  $sleepACmin = HexToMinutes $sleepAChex $units
  $sleepDCmin = HexToMinutes $sleepDChex $units
  $hibACmin   = HexToMinutes $hibAChex   'Minutes'  # Hibernate typically reports in minutes
  $hibDCmin   = HexToMinutes $hibDChex   'Minutes'

  Write-Output ("Sleep after (minutes)  AC/DC: {0} / {1}" -f ($sleepACmin -ne $null ? $sleepACmin : 'unknown'), ($sleepDCmin -ne $null ? $sleepDCmin : 'unknown'))
  Write-Output ("Hibernate after (min)  AC/DC: {0} / {1}" -f ($hibACmin   -ne $null ? $hibACmin   : 'unknown'), ($hibDCmin   -ne $null ? $hibDCmin   : 'unknown'))
} else {
  Write-Output "Could not determine active power scheme."
}

Write-Output ""

# ---------------- Section 3: Hibernate availability ----------------
function Get-HibernateEnabled {
  $text = (powercfg /a 2>$null) -join "`n"
  if (-not $text) { return $false }  # conservative default
  if ($text -match 'Hibernate has been disabled' `
      -or $text -match 'Hibernate is not available' `
      -or $text -match 'The hibernate file has not been initialized' `
      -or $text -match 'Hibernation has not been enabled') {
    return $false
  }
  return ($text -match '(^|\n)\s*Hibernate(\r|\n|$)')
}
$hibEnabled = Get-HibernateEnabled
Write-Output ("Hibernate enabled: {0}" -f $hibEnabled)
Write-Output ""

# ---------------- Section 4: Recommendation ----------------
# Kevin's preferred config:
#   AC: standby/sleep 0 (never), monitor 20
#   DC: standby/sleep 15,   monitor 5
#   Hibernate: OFF
$recommendOneLiner = 'powercfg /change standby-timeout-ac 0; powercfg /change standby-timeout-dc 15; powercfg /change monitor-timeout-ac 20; powercfg /change monitor-timeout-dc 5; powercfg /hibernate off'

# Only recommend if: hibernate is ON OR AC sleep > 0
if ($schemeGuid) {
  # Recompute $sleepACmin if missing
  if ($sleepACmin -eq $null -or $sleepDCmin -eq $null) {
    $sleepACmin = $null; $sleepDCmin = $null
    try {
      $sleepSettings = powercfg /query $schemeGuid SUB_SLEEP STANDBYIDLE
      $units = 'Seconds'
      $um = ($sleepSettings | Select-String -Pattern 'Possible Settings units:\s+(\w+)' -AllMatches).Matches
      if ($um.Count -gt 0) { $units = $um[0].Groups[1].Value }
      $sleepAChex = ($sleepSettings | Select-String 'Current AC Power Setting Index').Line.Split(':')[-1].Trim()
      $sleepDChex = ($sleepSettings | Select-String 'Current DC Power Setting Index').Line.Split(':')[-1].Trim()
      $sleepACmin = HexToMinutes $sleepAChex $units
      $sleepDCmin = HexToMinutes $sleepDChex $units
    } catch { }
  }

  if ($hibEnabled -or ($sleepACmin -ne $null -and $sleepACmin -gt 0)) {
    Write-Output "Recommendation: To match preferred settings, run (as Administrator):"
    Write-Output ("  {0}" -f $recommendOneLiner)
    Write-Output ""
  }
}

# ---------------- Section 5: Extra diagnostics (optional) ----------------
Write-Output "=== Sleep availability (/a) ==="
powercfg /a | Out-String | Write-Output

Write-Output ""
Write-Output "=== End of report ==="

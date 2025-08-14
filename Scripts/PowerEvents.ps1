# ============================================
# Section 1: Recent Power Events (last 14 days)
# ============================================
Write-Output 'Recent power events:'
Get-WinEvent -FilterHashtable @{
    LogName   = 'System'
    Id        = @(1,42,107,6005,6006,6008)
    StartTime = (Get-Date).AddDays(-14)
} |
    Select-Object `
        TimeCreated, `
        @{Name='EventType';Expression={
            switch ($_.Id) {
                6005 { 'Startup' }
                6006 { 'Shutdown' }
                6008 { 'Unexpected Shutdown' }
                1    { 'Wake' }
                42   { 'Sleep' }
                107  { 'Resume' }
                default { "ID $($_.Id)" }
            }
        }}, `
        Message

Write-Output ''  # spacer

# ============================================
# Section 2: Current Power Settings
# ============================================
Write-Output 'Current power settings:'

# 2a. Get the active power scheme GUID
$schemeGuid = powercfg /getactivescheme |
    Select-String 'Power Scheme GUID: ([\w-]+)' |
    ForEach-Object { $_.Matches[0].Groups[1].Value }

# 2b. Query the Sleep (STANDBYIDLE) and Hibernate (HIBERNATEIDLE) settings
$sleepSettings     = powercfg /query $schemeGuid SUB_SLEEP STANDBYIDLE
$hibernateSettings = powercfg /query $schemeGuid SUB_SLEEP HIBERNATEIDLE

# 2c. Parse & display Sleep settings
Write-Output "Sleep after GUID: $($sleepSettings | Select-String 'Power Setting GUID' | ForEach-Object { $_.Line.Trim() })"
Write-Output "Friendly name:     $($sleepSettings | Select-String 'GUID Alias'        | ForEach-Object { $_.Line.Trim() })"
$acHex = ($sleepSettings | Select-String 'Current AC Power Setting Index').Line.Split(':')[-1].Trim()
$dcHex = ($sleepSettings | Select-String 'Current DC Power Setting Index').Line.Split(':')[-1].Trim()
$acMin = [convert]::ToInt32($acHex,16) / 60
$dcMin = [convert]::ToInt32($dcHex,16) / 60
Write-Output ("  Plugged In/AC: {0} minutes" -f $acMin)
Write-Output ("  On Battery/DC: {0} minutes" -f $dcMin)
Write-Output ''  # spacer

# 2d. Parse & display Hibernate settings
Write-Output "Hibernate after GUID: $($hibernateSettings | Select-String 'Power Setting GUID' | ForEach-Object { $_.Line.Trim() })"
Write-Output "Friendly name:       $($hibernateSettings | Select-String 'GUID Alias'        | ForEach-Object { $_.Line.Trim() })"
$hacHex = ($hibernateSettings | Select-String 'Current AC Power Setting Index').Line.Split(':')[-1].Trim()
$hdcHex = ($hibernateSettings | Select-String 'Current DC Power Setting Index').Line.Split(':')[-1].Trim()
$hacMin = [convert]::ToInt32($hacHex,16) / 60
$hdcMin = [convert]::ToInt32($hdcHex,16) / 60
Write-Output ("  Plugged In/AC: {0} minutes" -f $hacMin)
Write-Output ("  On Battery/DC: {0} minutes" -f $hdcMin)
Write-Output ''  # spacer

# ============================================
# Section 3: Recommend Updated Power Settings
# ============================================

function Get-StandbyTimeoutMinutes {
    # Returns @{ AC = <int or $null>; DC = <int or $null> } in MINUTES.
    $result = @{ AC = $null; DC = $null }

    $out = powercfg /query SCHEME_CURRENT SUB_SLEEP STANDBYIDLE 2>$null
    if (-not $out) { return $result }

    # Determine units (Seconds or Minutes)
    $units = 'Seconds'
    $unitsMatch = ($out | Select-String -Pattern 'Possible Settings units:\s+(\w+)' -AllMatches).Matches
    if ($unitsMatch.Count -gt 0) { $units = $unitsMatch[0].Groups[1].Value }

    # Parse hex indices
    $acHexMatch = ($out | Select-String -Pattern 'Current AC Power Setting Index:\s+0x([0-9A-Fa-f]+)' -AllMatches).Matches
    $dcHexMatch = ($out | Select-String -Pattern 'Current DC Power Setting Index:\s+0x([0-9A-Fa-f]+)' -AllMatches).Matches

    if ($acHexMatch.Count -gt 0) {
        $acVal = [int]("0x" + $acHexMatch[0].Groups[1].Value)
        if ($units -ieq 'Seconds') {
            $result.AC = [int][math]::Round($acVal / 60.0)
        } else {
            $result.AC = $acVal
        }
    }

    if ($dcHexMatch.Count -gt 0) {
        $dcVal = [int]("0x" + $dcHexMatch[0].Groups[1].Value)
        if ($units -ieq 'Seconds') {
            $result.DC = [int][math]::Round($dcVal / 60.0)
        } else {
            $result.DC = $dcVal
        }
    }

    # Fallback for localized "Plugged In / On Battery"
    if ($null -eq $result.AC) {
        $m = [regex]::Match(($out -join "`n"), 'Plugged In:\s+(\d+)\s+minutes')
        if ($m.Success) { $result.AC = [int]$m.Groups[1].Value }
    }
    if ($null -eq $result.DC) {
        $m = [regex]::Match(($out -join "`n"), 'On Battery:\s+(\d+)\s+minutes')
        if ($m.Success) { $result.DC = [int]$m.Groups[1].Value }
    }

    return $result
}

function Get-HibernateEnabled {
    # True if Hibernate is enabled; False if disabled/not available.
    $text = (powercfg /a 2>$null) -join "`n"
    if (-not $text) { return $false }  # conservative default

    # Treat any of these as DISABLED
    if ($text -match 'Hibernate has been disabled' `
        -or $text -match 'Hibernate is not available' `
        -or $text -match 'The hibernate file has not been initialized' `
        -or $text -match 'Hibernation has not been enabled') {
        return $false
    }

    # If a line literally lists "Hibernate" among available states, treat as enabled
    return ($text -match '(^|\n)\s*Hibernate(\r|\n|$)')
}

# --- Fetch current values (in MINUTES)
$timeouts   = Get-StandbyTimeoutMinutes
$acMin      = $timeouts.AC
$dcMin      = $timeouts.DC
$hibEnabled = Get-HibernateEnabled

# --- Debug print (PS 5.1-safe)
Write-Output "Current power settings:"
$acText = if ($acMin -ne $null) { $acMin } else { 'unknown' }
$dcText = if ($dcMin -ne $null) { $dcMin } else { 'unknown' }
Write-Output ("  Sleep after (AC/DC): {0} / {1} minutes" -f $acText, $dcText)
Write-Output "  Hibernate enabled: $hibEnabled"

# --- Recommend fix if:
# 1. Hibernate is ON
# 2. AC sleep > 0 (don’t want it sleeping while plugged in)
# 3. DC sleep is 0 or less than 15 minutes
if (
    $hibEnabled -or
    ($acMin -ne $null -and $acMin -gt 0) -or
    ($dcMin -ne $null -and ($dcMin -eq 0 -or $dcMin -lt 15))
) {
    Write-Output "⚠ Recommended power setting adjustments detected:"
    if ($hibEnabled) { Write-Output " - Hibernate is enabled (recommended OFF)" }
    if ($acMin -gt 0) { Write-Output " - AC sleep timeout is > 0 (recommended 0)" }
    if ($dcMin -eq 0) { Write-Output " - DC sleep timeout is 0 (recommended 30 min)" }
    elseif ($dcMin -lt 15) { Write-Output " - DC sleep timeout is less than 15 min (recommended 30 min)" }

    Write-Output ""
    Write-Output "To apply recommended settings (hibernate OFF, AC no-sleep, DC sleep 30 min, monitor timeouts), run (as Admin):"
    Write-Output "  powercfg /change standby-timeout-ac 0; powercfg /change standby-timeout-dc 30; powercfg /change monitor-timeout-ac 20; powercfg /change monitor-timeout-dc 5; powercfg /hibernate off"
}
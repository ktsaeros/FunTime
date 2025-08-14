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
Write-Output ("  Plugged In: {0} minutes" -f $acMin)
Write-Output ("  On Battery: {0} minutes" -f $dcMin)
Write-Output ''  # spacer

# 2d. Parse & display Hibernate settings
Write-Output "Hibernate after GUID: $($hibernateSettings | Select-String 'Power Setting GUID' | ForEach-Object { $_.Line.Trim() })"
Write-Output "Friendly name:       $($hibernateSettings | Select-String 'GUID Alias'        | ForEach-Object { $_.Line.Trim() })"
$hacHex = ($hibernateSettings | Select-String 'Current AC Power Setting Index').Line.Split(':')[-1].Trim()
$hdcHex = ($hibernateSettings | Select-String 'Current DC Power Setting Index').Line.Split(':')[-1].Trim()
$hacMin = [convert]::ToInt32($hacHex,16) / 60
$hdcMin = [convert]::ToInt32($hdcHex,16) / 60
Write-Output ("  Plugged In: {0} minutes" -f $hacMin)
Write-Output ("  On Battery: {0} minutes" -f $hdcMin)
Write-Output ''  # spacer

# ============================================
# Section 3: Recommend Updated Power Settings
# ============================================

function Get-StandbyTimeoutMinutes {
    # Returns a hashtable: @{ AC = <int>; DC = <int> } or $nulls if unknown
    $result = @{ AC = $null; DC = $null }
    $out = powercfg /query SCHEME_CURRENT SUB_SLEEP STANDBYIDLE 2>$null
    if (-not $out) { return $result }

    # Newer Windows format (preferred)
    $acMin = ($out | Select-String -Pattern 'Plugged In:\s+(\d+)\s+minutes').Matches |
             ForEach-Object { [int]$_.Groups[1].Value } | Select-Object -First 1
    $dcMin = ($out | Select-String -Pattern 'On Battery:\s+(\d+)\s+minutes').Matches |
             ForEach-Object { [int]$_.Groups[1].Value } | Select-Object -First 1

    # Legacy fallback (hex indices)
    if ($null -eq $acMin) {
        $acHex = ($out | Select-String -Pattern 'Current AC Power Setting Index:\s+0x([0-9A-Fa-f]+)').Matches |
                 ForEach-Object { $_.Groups[1].Value } | Select-Object -First 1
        if ($acHex) { $acMin = [int]("0x$acHex") }
    }
    if ($null -eq $dcMin) {
        $dcHex = ($out | Select-String -Pattern 'Current DC Power Setting Index:\s+0x([0-9A-Fa-f]+)').Matches |
                 ForEach-Object { $_.Groups[1].Value } | Select-Object -First 1
        if ($dcHex) { $dcMin = [int]("0x$dcHex") }
    }

    $result.AC = $acMin
    $result.DC = $dcMin
    return $result
}

function Get-HibernateEnabled {
    # True if Hibernate is enabled; false if disabled
    $a = powercfg /a 2>$null
    if (-not $a) { return $false }  # conservative
    return -not ($a | Select-String -SimpleMatch 'Hibernate has been disabled')
}

# --- Fetch current values
$timeouts    = Get-StandbyTimeoutMinutes
$acMin       = $timeouts.AC
$dcMin       = $timeouts.DC
$hibEnabled  = Get-HibernateEnabled

# --- Debug print (optional)
Write-Output "Current power settings:"
Write-Output "  Sleep after (AC/DC): $acMin / $dcMin minutes"
Write-Output "  Hibernate enabled: $hibEnabled"

# --- Trigger if Hibernate is ON or AC sleep > 0
if ($hibEnabled -or ($acMin -gt 0)) {
    Write-Output "Hibernate is ON or AC sleep timeout is > 0."
    Write-Output "To apply recommended settings (hibernate OFF, AC no-sleep; DC sleeps after 15 min; display timeouts), run:"
    Write-Output "  powercfg /change standby-timeout-ac 0; powercfg /change standby-timeout-dc 15; powercfg /change monitor-timeout-ac 20; powercfg /change monitor-timeout-dc 5; powercfg /hibernate off"
}
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
# Section 3: Auto-Disable Sleep if Needed
# ============================================
if ( ($acMin -gt 0) -or ($dcMin -gt 0) -or ($hacMin -gt 0) -or ($hdcMin -gt 0) ) {
    Write-Output 'One or more power‐timeout settings is non-zero. To disable all sleep/hibernate, run:'
    Write-Output '  powercfg /change standby-timeout-ac 0; powercfg /change standby-timeout-dc 0; powercfg /hibernate off'
}
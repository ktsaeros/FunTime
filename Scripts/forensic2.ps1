<#
.SYNOPSIS
    Aeros IT Forensic Health Audit (v6.0 - Robust Power Update)
    - FIXED: Power Config now uses text scraping (bypassing GUID errors on Dell Micros).
    - ADDED: USB Selective Suspend check.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'SilentlyContinue'
$LookbackDays = 14
$StartDate = (Get-Date).AddDays(-$LookbackDays)

# --- Helper: Visuals ---
function Write-Section { param([string]$Title) Write-Host "`n=== $Title ===" -ForegroundColor Cyan }

# --- Helper: Power Config (Robust "Dump & Scrape" Method) ---
function Get-DetailedPowerConfig {
    $chassis = ((Get-CimInstance Win32_SystemEnclosure).ChassisTypes | ForEach-Object {
        switch ($_) { 3{'Desktop'} 6{'Mini Tower'} 8{'Portable'} 9{'Laptop'} 10{'Notebook'} default{"Code $_"} }
    }) -join ', '

    $report = [ordered]@{ ComputerName = $env:COMPUTERNAME; Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm"); Chassis = $chassis }
    
    # Registry Checks
    $report.Reg_S0_Override = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name PlatformAoAcOverride).PlatformAoAcOverride
    $report.Reg_FastStartup = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name HiberbootEnabled).HiberbootEnabled
    
    # SCRAPE METHOD: Dump all config once, then regex match. Reliable on all machines.
    $pcfgDump = powercfg /q | Out-String

    function Get-ScrapedVal ($guid) {
        # Finds the GUID, looks ahead for the AC Setting Index
        if ($pcfgDump -match "$guid[\s\S]+?Current AC Power Setting Index:\s+0x([0-9a-fA-F]+)") {
            return [convert]::ToInt32($Matches[1], 16)
        }
        return -1
    }

    # GUIDs
    $guidLink = "ee12f906-25ea-4e32-9679-880e263438db" # PCIe Link State
    $guidDisk = "6738e2c4-e8a5-459e-b6a6-0b92ed98b3aa" # Turn off hard disk
    $guidUSB  = "48e6b7a6-50f5-4782-a5d4-53bb8f07e226" # USB Selective Suspend
    $guidMon  = "3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e" # Monitor Timeout

    $linkVal = Get-ScrapedVal $guidLink
    $diskVal = Get-ScrapedVal $guidDisk
    $usbVal  = Get-ScrapedVal $guidUSB
    $monVal  = Get-ScrapedVal $guidMon

    $report['Disk_Turn_Off']   = if ($diskVal -eq 0) { "Never (Good)" } elseif ($diskVal -eq -1) { "Unknown" } else { "$diskVal sec" }
    $report['PCIe_Link_State'] = switch ($linkVal) { 0 {'Off (Good)'} 1 {'Moderate'} 2 {'Max Savings (Risk)'} default {'Unknown'} }
    $report['USB_Sel_Suspend'] = switch ($usbVal) { 0 {'Disabled (Good)'} 1 {'Enabled (Risk)'} default {'Unknown'} }
    $report['Monitor_AC']      = if ($monVal -ne -1) { $monVal / 60 } else { "Managed/GPO" }

    # S0/S3 Availability
    $avail = (powercfg /a 2>$null) -join "`n"
    $report['S0_Available'] = [bool]($avail -match 'Standby \(S0 Low Power Idle\)')
    $report['S3_Available'] = [bool]($avail -match 'Standby \(S3\)')

    $nicStatus = @()
    Get-NetAdapter -Physical | Where {$_.Status -eq 'Up'} | ForEach {
        $wol = ($_ | Get-NetAdapterAdvancedProperty -DisplayName 'Wake on Magic Packet').DisplayValue
        $ps  = ($_ | Get-NetAdapterPowerManagement).AllowComputerToTurnOffDevice
        $nicStatus += "$($_.Name) [WOL:$wol | PwrSave:$ps]"
    }
    $report['NIC_Status'] = $nicStatus -join '; '
    return $report
}

# --- 1. SYSTEM IDENTITY ---
Write-Section "SYSTEM IDENTITY"
$cs = Get-CimInstance Win32_ComputerSystem; $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$Report = [ordered]@{ Hostname=$env:COMPUTERNAME; Model="$($cs.Manufacturer) $($cs.Model)"; OSName=$cv.ProductName; DisplayVersion=$cv.DisplayVersion; Uptime=((Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).ToString() }
$Report | Format-List

# --- 2. BOOT/SHUTDOWN CYCLES ---
Write-Section "BOOT -> SHUTDOWN CYCLES (Last $LookbackDays Days)"
$events = Get-WinEvent -FilterHashtable @{LogName='System'; Id=@(6005,6006,6008,41); StartTime=$StartDate}
if ($events) {
    $norm = $events | Sort TimeCreated | ForEach { [PSCustomObject]@{Time=$_.TimeCreated; Type=switch($_.Id){6005{'Startup'}6006{'Shutdown'}6008{'Unexpected'}41{'Dirty Shutdown'}default{'Other'}}} }
    $boots = $norm | Where {$_.Type -eq 'Startup'}
    foreach ($b in $boots) {
        $end = $norm | Where {$_.Time -gt $b.Time -and $_.Type -ne 'Startup'} | Select -First 1
        [PSCustomObject]@{ Boot=$b.Time; End=if($end){$end.Time}else{'Running'}; EndType=if($end){$end.Type}else{'Running'}; Secs=if($end){[int]([timespan]($end.Time-$b.Time)).TotalSeconds}else{$null} }
    } | Format-Table -AutoSize | Out-String | Write-Host
} else { Write-Host "No boot events." -ForegroundColor Gray }

# --- 3. RESTART REASONS ---
Write-Section "RESTART REASONS (Last $LookbackDays Days)"
$restarts = Get-WinEvent -FilterHashtable @{LogName='System'; Id=1074; StartTime=$StartDate}
if ($restarts) {
    foreach ($evt in $restarts) {
        $msg = $evt.Message
        $user = if ($msg -match "User:\s+(?<U>.+?)\s") { $Matches['U'] } else { "Unknown" }
        if ($user -like "*AUTHORITY\SYSTEM*") { $user = "SYSTEM (Auto)" }
        [PSCustomObject]@{ Time=$evt.TimeCreated; Action=if($msg -match "Shutdown Type:\s+(?<T>\w+)"){$Matches['T']}else{"?"}; User=$user; Process=if($msg -match "Process\s+(?<P>.+?)\s"){$Matches['P']}else{"?"} }
    } | Format-Table -AutoSize | Out-String | Write-Host
} else { Write-Host "No planned restarts." -ForegroundColor Gray }

# --- 4. STORAGE ---
Write-Section "STORAGE & CONTROLLERS"
Get-PhysicalDisk | Select FriendlyName, MediaType, HealthStatus, FirmwareVersion | Format-Table -AutoSize | Out-String | Write-Host

# Calculate Power Config for checks
$Pwr = Get-DetailedPowerConfig 

$nvme = Get-PhysicalDisk | Where {$_.FriendlyName -match "Samsung.*9[89]0" -or $_.MediaType -eq 'SSD'}
if ($nvme) {
    if ($Pwr['PCIe_Link_State'] -match 'Max Savings|Moderate') { Write-Host "WARNING: NVMe PCIe set to '$($Pwr['PCIe_Link_State'])'. Risk of drop!" -ForegroundColor Red }
    if ($Pwr['Disk_Turn_Off'] -notmatch 'Never|Unknown' -and $Pwr['Disk_Turn_Off'] -ne '-1 sec') { Write-Host "WARNING: Disk Sleep is enabled ($($Pwr['Disk_Turn_Off'])). Set to 0." -ForegroundColor Yellow }
    if ($Pwr['USB_Sel_Suspend'] -match 'Enabled') { Write-Host "WARNING: USB Selective Suspend is ENABLED. Risk for backups." -ForegroundColor Yellow }
}

if (Get-PhysicalDisk | Where {$_.FriendlyName -match "Samsung.*9[89]0"}) { Write-Host "NOTICE: Samsung 980/990 Pro detected. Check Firmware." -ForegroundColor Yellow }
$errs = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName=@('stornvme','disk','Ntfs','WHEA-Logger'); StartTime=$StartDate}
if ($errs) { Write-Host "CRITICAL: Found $($errs.Count) Storage Errors." -ForegroundColor Red; $errs | Select -First 5 TimeCreated,Message | Format-List | Out-String | Write-Host } 
else { Write-Host "Storage logs clean." -ForegroundColor Green }

# --- 5. POWER CONFIG ---
Write-Section "CURRENT POWER CONFIGURATION"
$Pwr | Format-List | Out-String | Write-Host

# --- 6. CRASH/UPDATES ---
Write-Section "UPDATES & CRASH CONFIG"
Get-HotFix | Sort InstalledOn -Desc | Select -First 5 Source,HotFixID,InstalledOn | Format-Table -AutoSize | Out-String | Write-Host
if ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl').CrashDumpEnabled -eq 0) { Write-Host "Enabling Crash Dumps..." -ForegroundColor Yellow; Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name CrashDumpEnabled -Value 1 -Force } 
else { Write-Host "Crash dumps enabled." -ForegroundColor Green }

# --- 7. DATA FILES ---
Write-Section "OFFICE DATA FILES"
Get-ChildItem C:\Users -Directory | ForEach {
    $u = $_.Name; $paths = @("$($_.FullName)\AppData\Local\Microsoft\Outlook", "$($_.FullName)\Documents\Outlook Files")
    foreach ($p in $paths) { if (Test-Path $p) { Get-ChildItem $p -Recurse -Include *.pst,*.ost | ForEach { [PSCustomObject]@{User=$u; Size="{0:N0} MB" -f ($_.Length/1MB); File=$_.Name} } } }
} | Format-Table -AutoSize | Out-String | Write-Host

Write-Section "AUDIT COMPLETE"
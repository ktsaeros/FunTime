<#
.SYNOPSIS
    Aeros IT Forensic Health Audit (v5.5)
    - FIXED: "Empty Pipe" error in Restart Reasons (captured loop output to variable).
    - INCLUDES: All previous hardware, power, user, and office audits.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'SilentlyContinue'
$LookbackDays = 14
$StartDate = (Get-Date).AddDays(-$LookbackDays)

# --- Helper: Visuals ---
function Write-Section {
    param([string]$Title)
    Write-Host "`n=== $Title ===" -ForegroundColor Cyan
}

# --- Helper: Office Version ---
function Get-OfficeVersionInfo {
    $results = [ordered]@{ Office_C2R_Version=$null; Office_C2R_SKU=$null; Outlook_MSI_Version=$null }
    try {
        $c2r = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration' -ErrorAction Stop
        $results.Office_C2R_Version = $c2r.ClientVersionToReport
        $results.Office_C2R_SKU     = $c2r.ProductReleaseIds
    } catch {}
    $msi = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' | Get-ItemProperty | Where-Object { $_.DisplayName -like 'Microsoft Outlook *' -and $_.DisplayVersion -notlike "16.0.*" } | Select -First 1
    if ($msi) { $results.Outlook_MSI_Version = "$($msi.DisplayName) v$($msi.DisplayVersion)" }
    
    if ($results.Office_C2R_Version) { "C2R v$($results.Office_C2R_Version) ($($results.Office_C2R_SKU))" }
    elseif ($results.Outlook_MSI_Version) { $results.Outlook_MSI_Version }
    else { "Not Detected" }
}

# --- Helper: Power Configuration (Polished) ---
function Get-DetailedPowerConfig {
    $chassis = ((Get-CimInstance Win32_SystemEnclosure -ErrorAction SilentlyContinue).ChassisTypes | ForEach-Object {
        switch ($_) { 3{'Desktop'} 6{'Mini Tower'} 8{'Portable'} 9{'Laptop'} 10{'Notebook'} 14{'Sub-Notebook'} default{"Code $_"} }
    }) -join ', '

    $report = [ordered]@{
        ComputerName = $env:COMPUTERNAME
        Timestamp    = (Get-Date).ToString("yyyy-MM-dd HH:mm")
        Chassis      = $chassis
    }
    $report.Reg_S0_Override = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name PlatformAoAcOverride -ErrorAction SilentlyContinue).PlatformAoAcOverride
    $report.Reg_FastStartup = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name HiberbootEnabled -ErrorAction SilentlyContinue).HiberbootEnabled
    
    $schemeGuid = (powercfg /getactivescheme 2>$null | Select-String 'Power Scheme GUID:\s+([\w-]+)').Matches[0].Groups[1].Value
    if ($schemeGuid) {
        function Get-IndexedMinutes { param([string]$Subgroup,[string]$Setting)
            $raw = powercfg /query $schemeGuid $Subgroup $Setting 2>$null; $text = $raw -join "`n"
            $acLine = $text | Select-String 'Current AC Power Setting Index'
            $dcLine = $text | Select-String 'Current DC Power Setting Index'
            
            # Helper to parse and round
            $parse = { param($l) 
                if ($l -match '0x([0-9a-fA-F]+)') { 
                    $val = [convert]::ToInt32($Matches[1],16) / 60
                    if ($val -lt 0.1 -and $val -gt 0) { "0 (Forced)" } else { "{0:N0}" -f $val }
                } else { "Managed/Hidden (GPO)" }
            }
            return @{AC=(&$parse $acLine); DC=(&$parse $dcLine)}
        }
        
        $monitor   = Get-IndexedMinutes '4f971e89-eebd-4455-a8de-9e59040e7347' '3c0bc021-c8a8-4e07-a973-6b14b0a7e52a'
        $sleep     = Get-IndexedMinutes '238c9fa8-0aad-41ed-83f4-97be242c8f20' '94ac6d29-73ce-41a6-809f-6363ba21b47e'
        $lidAction = Get-IndexedMinutes '4f971e89-eebd-4455-a8de-9e59040e7347' '5ca83367-6e45-459f-a27b-476b1d01c936'
        
        $actionMap = @{ 0='Do nothing'; 1='Sleep'; 2='Hibernate'; 3='Shut down'; 4='Turn off display' }
        $resolve = { param([string]$v) if($v -match '^\d+$' -and $actionMap.ContainsKey([int]$v)){ $actionMap[[int]$v] } else { $v } }

        $report['Monitor_AC']    = $monitor.AC
        $report['Monitor_DC']    = $monitor.DC
        $report['Sleep_AC']      = $sleep.AC
        $report['Sleep_DC']      = $sleep.DC
        $report['Lid_Action_AC'] = &$resolve $lidAction.AC
        $report['Lid_Action_DC'] = &$resolve $lidAction.DC
    }

    $avail = (powercfg /a 2>$null) -join "`n"
    $report['S0_Available']        = [bool]($avail -match 'Standby \(S0 Low Power Idle\)')
    $report['S3_Available']        = [bool]($avail -match 'Standby \(S3\)')
    $report['Hibernate_Available'] = [bool]($avail -notmatch 'Hibernate is not available|Hibernate has been disabled')

    $nicStatus = @()
    Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where {$_.Status -eq 'Up'} | ForEach {
        $wol = ($_ | Get-NetAdapterAdvancedProperty -DisplayName 'Wake on Magic Packet' -ErrorAction SilentlyContinue).DisplayValue
        $ps  = ($_ | Get-NetAdapterPowerManagement -ErrorAction SilentlyContinue).AllowComputerToTurnOffDevice
        $nicStatus += "$($_.Name) [WOL:$wol | PwrSave:$ps]"
    }
    $report['NIC_Status'] = $nicStatus -join '; '
    return $report
}

# --- 1. SYSTEM IDENTITY ---
Write-Section "SYSTEM IDENTITY"
try {
    $cs = Get-CimInstance Win32_ComputerSystem
    $cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $office = Get-OfficeVersionInfo
    $displayVersion = $cv.DisplayVersion; if (!$displayVersion) { $displayVersion = $cv.ReleaseId }
    
    $Report = [ordered]@{
        Hostname       = $env:COMPUTERNAME
        Model          = "$($cs.Manufacturer) $($cs.Model)"
        OSName         = $cv.ProductName
        DisplayVersion = $displayVersion
        Build          = "{0}.{1}" -f $cv.CurrentBuild, $cv.UBR
        Uptime         = ((Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).ToString()
        Office_Version = $office
    }
    $Report | Format-List
} catch { Write-Host "Error: $_" -ForegroundColor Red }

# --- 2. BOOT/SHUTDOWN CYCLES ---
Write-Section "BOOT -> SHUTDOWN CYCLES (Last $LookbackDays Days)"
$events = Get-WinEvent -FilterHashtable @{LogName='System'; Id=@(6005,6006,6008,41); StartTime=$StartDate} -ErrorAction SilentlyContinue
if ($events) {
    $norm = $events | Sort TimeCreated | ForEach {
        $t = switch ($_.Id) { 6005{'Startup'} 6006{'Shutdown'} 6008{'Unexpected'} 41{'Dirty Shutdown'} default{'Other'} }
        [PSCustomObject]@{Time=$_.TimeCreated; Type=$t}
    }
    $boots = $norm | Where {$_.Type -eq 'Startup'}
    $cycles = foreach ($b in $boots) {
        $end = $norm | Where {$_.Time -gt $b.Time -and $_.Type -ne 'Startup'} | Select -First 1
        $uptime = if ($end) { [int]([timespan]($end.Time - $b.Time)).TotalSeconds } else { $null }
        [PSCustomObject]@{ Boot=$b.Time; End=if($end){$end.Time}else{'Running'}; EndType=if($end){$end.Type}else{'Running'}; Secs=$uptime }
    }
    $cycles | Format-Table -AutoSize | Out-String | Write-Host
    if ($short = $cycles | Where {$_.Secs -lt 180 -and $_.Secs}) {
        Write-Host "WARNING: Rapid reboot loop detected (< 3 mins uptime)!" -ForegroundColor Yellow
        $short | Format-Table -AutoSize | Out-String | Write-Host
    }
} else { Write-Host "No boot events." -ForegroundColor Gray }

# --- 3. RESTART REASONS ---
Write-Section "RESTART REASONS (Last $LookbackDays Days)"
$restarts = Get-WinEvent -FilterHashtable @{LogName='System'; Id=1074; StartTime=$StartDate} -ErrorAction SilentlyContinue
if ($restarts) {
    # FIX: Assigned loop to variable first to avoid "Empty Pipe" error
    $parsedRestarts = foreach ($evt in $restarts) {
        $user='Unknown'; $proc='Unknown'; $code='Unknown'; $type='Unknown'
        if ($evt.Message -match "on behalf of user\s+(?<User>.+?)\s+for") { $user = $Matches['User'] } 
        elseif ($evt.Message -match "User:\s+(?<User>.+?)\s") { $user = $Matches['User'] }
        if ($evt.Message -match "The process\s+(?<Process>.+?)\s+has") { 
            $proc = if ($Matches['Process'] -match "\\([^\\]+\.exe)") { $Matches[1] } else { $Matches['Process'] } 
        }
        if ($evt.Message -match "Reason Code:\s+(?<Code>0x[0-9a-fA-F]+)") { $code = $Matches['Code'] }
        if ($evt.Message -match "Shutdown Type:\s+(?<Type>\w+)") { $type = $Matches['Type'] }
        if ($user -like "*AUTHORITY\SYSTEM*") { $user = "SYSTEM (Auto)" }
        [PSCustomObject]@{ Time=$evt.TimeCreated; Action=$type; 'User / Initiator'=$user; Process=$proc; Code=$code }
    } 
    $parsedRestarts | Format-Table -AutoSize | Out-String | Write-Host
} else { Write-Host "No planned restarts." -ForegroundColor Gray }

# --- 4. STORAGE ---
Write-Section "STORAGE & CONTROLLERS"
Get-PhysicalDisk | Select FriendlyName, MediaType, HealthStatus, FirmwareVersion | Format-Table -AutoSize | Out-String | Write-Host
if (Get-PhysicalDisk | Where {$_.FriendlyName -match "Samsung.*9[89]0"}) { Write-Host "NOTICE: Samsung 980/990 Pro detected. Check Firmware." -ForegroundColor Yellow }
$errs = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName=@('stornvme','disk','Ntfs','WHEA-Logger'); StartTime=$StartDate} -ErrorAction SilentlyContinue
if ($errs) { Write-Host "CRITICAL: Found $($errs.Count) Storage Errors." -ForegroundColor Red; $errs | Select -First 5 TimeCreated,Message | Format-List | Out-String | Write-Host } 
else { Write-Host "Storage logs clean." -ForegroundColor Green }

# --- 5. RMM ---
Write-Section "RMM & SECURITY"
@('SentinelAgent', 'SentinelStaticEngine', 'Magon', 'AdvancedMonitoringAgent', 'WinAgent') | ForEach {
    $s = Get-Service $_ -ErrorAction SilentlyContinue
    if ($s) { Write-Host "$($s.Name): $($s.Status)" -ForegroundColor (if($s.Status -eq 'Running'){'Green'}else{'Red'}) }
}

# --- 6. ENV ---
Write-Section "ENVIRONMENT (UPS/HEAT)"
$bat = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue
if ($bat) { $bat | Select Name,Status,BatteryStatus,EstimatedChargeRemaining | Format-Table -AutoSize | Out-String | Write-Host }
else { Write-Host "No Battery detected." -ForegroundColor Gray }
$heat = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Kernel-Thermal'; StartTime=$StartDate} -ErrorAction SilentlyContinue
if ($heat) { Write-Host "WARNING: Thermal Throttling!" -ForegroundColor Red; $heat | Select -First 3 TimeCreated,Message | Format-Table -AutoSize | Out-String | Write-Host } 
else { Write-Host "Thermals normal." -ForegroundColor Green }

# --- 7. POWER CONFIG ---
Write-Section "CURRENT POWER CONFIGURATION"
try { Get-DetailedPowerConfig | Format-List | Out-String | Write-Host } catch { Write-Host "Audit Error: $_" -ForegroundColor Red }

# --- 8. CRASH/UPDATES ---
Write-Section "UPDATES & CRASH CONFIG"
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { Write-Host "Reboot PENDING." -ForegroundColor Yellow }
Write-Host "Recent Hotfixes:"
Get-HotFix | Sort InstalledOn -Desc | Select -First 5 Source,HotFixID,InstalledOn | Format-Table -AutoSize | Out-String | Write-Host
if ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl').CrashDumpEnabled -eq 0) {
    Write-Host "Enabling Crash Dumps..." -ForegroundColor Yellow
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name CrashDumpEnabled -Value 1 -Force
} else { Write-Host "Crash dumps enabled." -ForegroundColor Green }

# --- 9. USERS ---
Write-Section "USER PROFILES"
$cs = Get-CimInstance Win32_ComputerSystem
$dom = if ($cs.PartOfDomain) { $cs.Domain } else { $null }
$adminSid = ([System.Security.Principal.NTAccount]"$env:COMPUTERNAME\Administrator").Translate([System.Security.Principal.SecurityIdentifier]).Value -replace '-500$',''
$admins = try { ([ADSI]"WinNT://$env:COMPUTERNAME/Administrators,group").Members() | ForEach { (New-Object System.Security.Principal.SecurityIdentifier($_.Properties['objectSid'].Value,0)).Value } } catch {}

Get-CimInstance Win32_UserProfile | Where {$_.LocalPath -like 'C:\Users\*' -and !$_.Special} | ForEach {
    $sid = $_.SID
    $type = if ($sid -like "$adminSid-*") { 'Local' } elseif ($dom) { $dom } else { 'Workgroup' }
    $isAdmin = if ($admins -contains $sid) { 'Yes' } elseif ($type -ne 'Local') { 'Unknown (Domain Group?)' } else { 'No' }
    [PSCustomObject]@{ Profile=$_.LocalPath; Type=$type; Admin=$isAdmin }
} | Sort Profile | Format-Table -AutoSize | Out-String | Write-Host

# --- 10. DATA ---
Write-Section "OFFICE DATA FILES"
$ext = @('pst','ost','nst'); $files = @()
Get-ChildItem C:\Users -Directory -ErrorAction SilentlyContinue | ForEach {
    $u = $_.Name
    $paths = @("$($_.FullName)\AppData\Local\Microsoft\Outlook", "$($_.FullName)\Documents\Outlook Files")
    foreach ($p in $paths) {
        if (Test-Path $p) { Get-ChildItem $p -Recurse -Include "*.$($ext -join ', *.')" -ErrorAction SilentlyContinue | ForEach {
            $sz="{0:N0} MB" -f ($_.Length/1MB); $files += [PSCustomObject]@{User=$u; Size=$sz; Date=$_.LastWriteTime.ToString('yyyy-MM-dd'); Path=$_.FullName}
        }}
    }
}
if ($files) { $files | Sort Date -Desc | Format-Table User,Size,Date,Path -AutoSize | Out-String | Write-Host } 
else { Write-Host "No data files found." -ForegroundColor Gray }

Write-Section "AUDIT COMPLETE"
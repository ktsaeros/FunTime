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
        Build          = "{0
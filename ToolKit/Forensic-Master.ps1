<#
.SYNOPSIS
    AEROS FORENSIC MASTER REPORT (v1.0)
    Merged from: Forensic4, Power3, NetworkCheckSlim, Battery.
    Provides a "State of the Union" snapshot for a workstation.
#>

$ErrorActionPreference = 'SilentlyContinue'
$LookbackDays = 14
$StartDate = (Get-Date).AddDays(-$LookbackDays)

function Write-Section { param([string]$Title) Write-Host "`n=== $Title ===" -ForegroundColor Cyan }

# --- 1. SYSTEM IDENTITY ---
Write-Section "SYSTEM IDENTITY"
$cs = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem
$bio = Get-CimInstance Win32_Bios

[pscustomobject]@{
    Hostname       = $env:COMPUTERNAME
    Model          = "$($cs.Manufacturer) $($cs.Model)"
    OS             = "$($os.Caption) ($($os.OSArchitecture))"
    Build          = $os.Version
    Uptime         = ((Get-Date) - $os.LastBootUpTime).ToString()
    BIOS           = "$($bio.SMBIOSBIOSVersion) ($($bio.ReleaseDate))"
    LastBoot       = $os.LastBootUpTime
} | Format-List | Out-String | Write-Host

# --- 2. POWER & BATTERY ---
Write-Section "POWER & BATTERY HEALTH"

# Battery Check (Mini Version of battery.ps1)
$batt = Get-CimInstance Win32_Battery
if ($batt) {
    foreach ($b in $batt) {
        Write-Host "Battery: $($b.Name)" -ForegroundColor Green
        Write-Host "  - Status:       $($b.BatteryStatus) (2=AC, 1=Discharging)"
        Write-Host "  - Charge:       $($b.EstimatedChargeRemaining)%"
        if ($b.DesignCapacity -and $b.FullChargeCapacity) {
            $health = [math]::Round(($b.FullChargeCapacity / $b.DesignCapacity) * 100, 1)
            Write-Host "  - Health:       $health% (Wear Level)"
        }
    }
} else {
    Write-Host "No Battery Detected (Desktop Mode)" -ForegroundColor Gray
}

# Crash/Reboot History (From Power3)
$unclean = Get-WinEvent -FilterHashtable @{LogName='System'; Id=41; StartTime=$StartDate} -ErrorAction SilentlyContinue
if ($unclean) { 
    Write-Host "CRITICAL: Found $($unclean.Count) Unclean Shutdowns (Event 41) in last $LookbackDays days." -ForegroundColor Red
    $unclean | Select-Object -First 3 TimeCreated, Message | Format-Table -AutoSize | Out-String | Write-Host
} else {
    Write-Host "Power Stability: Excellent (No unclean shutdowns detected)." -ForegroundColor Green
}

# --- 3. STORAGE HEALTH ---
Write-Section "STORAGE & DRIVES"
$drives = Get-PhysicalDisk | Select-Object FriendlyName, MediaType, HealthStatus, OperationalStatus, @{N='SizeGB';E={[math]::Round($_.Size/1GB,0)}}
$drives | Format-Table -AutoSize | Out-String | Write-Host

# Check for Disk Errors
$diskErrs = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName=@('disk','stornvme','Ntfs'); StartTime=$StartDate} -ErrorAction SilentlyContinue
if ($diskErrs) {
    Write-Host "WARNING: Found $($diskErrs.Count) Disk Errors!" -ForegroundColor Red
    $diskErrs | Select-Object -First 5 TimeCreated, ProviderName, Message | Format-Table -AutoSize | Out-String | Write-Host
} else {
    Write-Host "Disk Event Logs: Clean" -ForegroundColor Green
}

# --- 4. NETWORK STABILITY (The "Slim" Logic) ---
Write-Section "NETWORK RELIABILITY (Last $LookbackDays Days)"
# Define Network Event IDs
$idsNet = @{ LinkDown=27; DNSFail=1014; DHCPFail=1001 }
$netEvts = Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$StartDate} -ErrorAction SilentlyContinue | Where-Object { $_.Id -in $idsNet.Values }

if ($netEvts) {
    $dns = ($netEvts | Where-Object {$_.Id -eq 1014}).Count
    $link = ($netEvts | Where-Object {$_.Id -eq 27}).Count
    $dhcp = ($netEvts | Where-Object {$_.Id -eq 1001}).Count
    
    Write-Host "  - DNS Timeouts:   $dns" -ForegroundColor $(if($dns -gt 10){'Red'}else{'Yellow'})
    Write-Host "  - Link Drops:     $link" -ForegroundColor $(if($link -gt 5){'Red'}else{'Yellow'})
    Write-Host "  - DHCP Errors:    $dhcp"
    
    if ($dns -gt 20 -or $link -gt 10) {
        Write-Host "  >> DIAGNOSIS: Network appears unstable." -ForegroundColor Red
    } else {
        Write-Host "  >> DIAGNOSIS: Occasional noise, likely stable." -ForegroundColor Green
    }
} else {
    Write-Host "No major network errors found." -ForegroundColor Green
}

# --- 5. SECURITY AGENTS ---
Write-Section "SECURITY & RMM AGENTS"
$agents = @('SentinelAgent', 'TMBMServer', 'Sysmon64', 'Advanced Monitoring Agent')
foreach ($a in $agents) {
    $svc = Get-Service -Name $a -ErrorAction SilentlyContinue
    if ($svc) {
        $color = if ($svc.Status -eq 'Running') {'Green'} else {'Red'}
        Write-Host "$($svc.DisplayName): $($svc.Status)" -ForegroundColor $color
    } else {
        Write-Host "$a: NOT INSTALLED" -ForegroundColor Gray
    }
}

# --- 6. WINDOWS UPDATES ---
Write-Section "RECENT UPDATES"
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5 HotFixID, InstalledOn | Format-Table -AutoSize | Out-String | Write-Host

Write-Host "`n=== AUDIT COMPLETE ===" -ForegroundColor Cyan
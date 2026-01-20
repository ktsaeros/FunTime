# Windows Printer Environment Auditor (v5.1)
# --------------------------------------------------------
[CmdletBinding(SupportsShouldProcess=$true)]
param([switch]$Purge)

if ($Purge -and -not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Administrative privileges are required for -Purge."
    return
}

Write-Host "`n--- [1] Active Printer Configuration ---" -ForegroundColor Cyan

$portCache = Get-PrinterPort | Group-Object Name -AsHashTable -AsString
$driverCache = Get-PrinterDriver | Group-Object Name -AsHashTable -AsString

$allPrinters = Get-Printer | ForEach-Object {
    $p = $_
    $o = $portCache[$p.PortName]
    $d = $driverCache[$p.DriverName]
    
    # 1. Resolve WSD/IP/Host
    $potentialIP = "Zzz"; $hostName = "N/A"
    if ($p.PortName -match "WSD-") {
        $wsdUuid = $p.PortName -replace "^WSD-",""
        $dev = Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -like "*$wsdUuid*" } | Select-Object -First 1
        if ($dev) {
            $addr = Get-PnpDeviceProperty -InstanceId $dev.InstanceId -KeyName "DEVPKEY_Device_Address" -ErrorAction SilentlyContinue
            $fr   = Get-PnpDeviceProperty -InstanceId $dev.InstanceId -KeyName "DEVPKEY_Device_FriendlyName" -ErrorAction SilentlyContinue
            if ($addr.Data) { $potentialIP = $addr.Data }
            if ($fr.Data)   { $hostName    = $fr.Data }
        }
    } elseif ($o -and $o.PrinterHostAddress) { $potentialIP = $o.PrinterHostAddress }

    if ($p.PortName -match "USB|LPT|nul|SHRFAX") { $potentialIP = "Local" }

    # 2. Optimized String Logic
    $truncName = if ($p.Name.Length -gt 22) { $p.Name.Substring(0,19) + "..." } else { $p.Name }
    $rawP = $p.PortName -replace '^IP_', ''
    $truncPort = if ($rawP.Length -gt 22) { $rawP.Substring(0,19) + "..." } else { $rawP }
    $truncDrv  = if ($p.DriverName.Length -gt 22) { $p.DriverName.Substring(0,19) + "..." } else { $p.DriverName }
    $truncHost = if ($hostName.Length -gt 15) { $hostName.Substring(0,12) + "..." } else { $hostName }

    $drvVer = if ($d -and $d.MajorVersion -eq 4) { "V4 (Class)" } elseif ($d -and $d.MajorVersion -eq 3) { "V3 (OEM)" } else { "Unknown" }
    $proto = if ($o -and $o.Protocol -eq 1) { "RAW" } elseif ($o -and $o.Protocol -eq 2) { "LPR" } else { "N/A" }

    # 3. Exclusive Sorting Logic
    $isWSD = $p.PortName -match "WSD"
    $isLex = $p.PrintProcessor -match "LMU0"
    $isXPS = $p.DriverName -match "XPS"
    $isVirt = $p.Name -match "OneNote|PDF|XPS|Fax|Webex|ABS|Microsoft|Send To"
    
    $group = if ($isWSD -or $isLex -or ($isXPS -and -not $isVirt)) { "Action" } elseif ($isVirt) { "Virtual" } else { "Stable" }

    [PSCustomObject]@{
        Name       = $truncName
        FullDriver = $p.DriverName
        Port       = $truncPort
        "IP?"      = $potentialIP
        Host       = $truncHost
        Driver     = $truncDrv
        Ver        = $drvVer
        Proc       = $p.PrintProcessor
        Proto      = $proto
        SNMP       = if ($o) { $o.SNMPEnabled } else { $false }
        TableGroup = $group
    }
}

# --- Section 1: Display Tables ---
Write-Host "`n--- [1.1] Action Required (Stability Alerts) ---" -ForegroundColor Red
$allPrinters | Where-Object { $_.TableGroup -eq "Action" } | 
    Select-Object Name, Port, "IP?", Host, Driver, Ver, Proc, SNMP | ft -AutoSize

Write-Host "--- [1.2] Stable Hardware (TCP/IP & USB) ---" -ForegroundColor Green
$allPrinters | Where-Object { $_.TableGroup -eq "Stable" } | 
    Select-Object Name, Port, Driver, Ver, Proc, Proto, SNMP | ft -AutoSize

Write-Host "--- [1.3] Virtual & Low Priority ---" -ForegroundColor Gray
$allPrinters | Where-Object { $_.TableGroup -eq "Virtual" } | 
    Select-Object Name, Port, Driver, Ver, Proc | ft -AutoSize

# --- [2] System Discovery Audit ---
Write-Host "`n--- [2] System Discovery Settings ---" -ForegroundColor Cyan
$Reg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Network\" -ErrorAction SilentlyContinue
$fdPH = Get-Service -Name "fdPHost" -ErrorAction SilentlyContinue
if ($Reg.AutoSetupEnabled -eq 1 -or $fdPH.Status -eq "Running") { Write-Host "[!] ALERT: Discovery Hijacking Risk active." -ForegroundColor Red }
else { Write-Host "Success: Discovery settings hardened." -ForegroundColor Green }

# --- [3] Driver Store Audit (Cleaned Environment Column) ---
Write-Host "`n--- [3] Driver Store: Unused Assets ---" -ForegroundColor Red
$activeD = $allPrinters.FullDriver
$unusedD = Get-PrinterDriver | Where-Object { $activeD -notcontains $_.Name -and $_.Name -notmatch "Microsoft|Remote|PDF|OneNote|XPS" }
if ($unusedD) {
    # Removed 'Environment' column as it is typically redundant for single-architecture fleets
    $unusedD | Select-Object Name, MajorVersion | ft
    if ($Purge) {
        foreach ($drv in $unusedD) {
            if ($PSCmdlet.ShouldProcess($drv.Name, "Remove-PrinterDriver")) {
                try { Remove-PrinterDriver -Name $drv.Name -ErrorAction Stop; Write-Host "Removed: $($drv.Name)" -F Green }
                catch { Write-Warning "Failed to remove '$($drv.Name)': $($_.Exception.Message)" }
            }
        }
    }
}

# --- [4] Recommendations ---
Write-Host "--- [4] Remediation Recommendations ---" -ForegroundColor Cyan
if ($allPrinters.TableGroup -contains "Action") { Write-Host "[!] WSD-PROOFING: Use 'IP?' column to re-install via TCP/IP Device type." -ForegroundColor Yellow }
if ($allPrinters.Proc -match "LMU0") { Write-Host "[!] LEX-PROC: Change Print Processor to 'winprint' for stability." -ForegroundColor Yellow }
if (($allPrinters | Where-Object { $_.SNMP -eq $true }).Count -gt 0) { Write-Host "[!] SNMP: Disable 'SNMP Status Enabled' in Port settings." -ForegroundColor Yellow }


# --- [5] Recent Print History & Quick Print Audit ---
Write-Host "`n--- [5] Recent Print History (Last 24 Hours) ---" -ForegroundColor Yellow

# Check if logging is even enabled
$logCheck = Get-WinEvent -ListLog Microsoft-Windows-PrintService/Operational
if (-not $logCheck.IsEnabled) {
    Write-Host "[!] ALERT: History logging is DISABLED. Future jobs will not be tracked." -ForegroundColor Red
    Write-Host "Action: Run 'wevtutil sl Microsoft-Windows-PrintService/Operational /e:true' to begin monitoring." -ForegroundColor Gray
} else {
    $events = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PrintService/Operational';ID=307;StartTime=(Get-Date).AddDays(-1)} -ErrorAction SilentlyContinue
    if ($events) {
        $events | Select-Object TimeCreated, 
            @{N='User';E={$_.Properties[2].Value}}, 
            @{N='Document';E={
                if($_.Properties[1].Value -eq "Print Document"){"Quick Print"}
                else{$_.Properties[1].Value}}}, 
            @{N='Printer';E={$_.Properties[4].Value}}, 
            @{N='Pages';E={$_.Properties[7].Value}} | 
        Format-Table -AutoSize
    } else {
        Write-Host "No print jobs recorded in the last 24 hours." -ForegroundColor Gray
    }
}
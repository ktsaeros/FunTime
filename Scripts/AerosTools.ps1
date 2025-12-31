<#
.SYNOPSIS
    AEROS IT TOOLBOX (v3.0)
    Interactive Menu + Renamed Functions.
#>

# ==============================================================================
#  SECTION 1: HARDWARE & DIAGNOSTICS
# ==============================================================================

function Get-RAM {
    <# .SYNOPSIS Shows physical memory slots, speeds, and types. #>
    Write-Host "--- RAM ANALYSIS ---" -ForegroundColor Cyan
    $MEMORY_TYPES = @('Unknown','Other','Unknown','DRAM','EDRAM','VRAM','SRAM','ROM','FLASH','EEPROM','FEPROM','EPROM','CDRAM','3DRAM','SDRAM','SGRAM','RDRAM','DDR','DDR2','DDR2 FB-DIMM','Reserved','Reserved','Reserved','DDR3','FBD2','DDR4','LPDDR','LPDDR2','LPDDR3','LPDDR4','Logical non-volatile device','HBM','HBM2','DDR5','LPDDR5')
    $TYPE_DETAILS = @('Reserved','Other','Unknown','Fast-paged','Static column','Pseudo-static','RAMBUS','Synchronous','CMOS','EDO','Window DRAM','Cache DRAM','Non-volatile','Registered','Unbuffered','LRDIMM')

    function Decode-TypeDetail { param([int]$flags) $names = 0..15 | Where-Object { $flags -band (1 -shl $_) } | ForEach-Object { $TYPE_DETAILS[$_] }; return "0x{0:X2} ({1})" -f $flags, ($names -join ' | ') }
    function Decode-FormFactor { param([int]$code) switch ($code) { 8 { 'DIMM' } 12 { 'SODIMM' } default { "Unknown($code)" } } }
    function Decode-MemoryType { param([int]$smbiosCode, [string]$formFactor)
        $map = @{ 20='DDR'; 21='DDR2'; 22='DDR2 FB-DIMM'; 24='DDR3'; 26='DDR4'; 34='DDR5'; 27='LPDDR'; 28='LPDDR2'; 29='LPDDR3'; 30='LPDDR4'; 35='LPDDR5' }
        $label = $map[$smbiosCode]
        if ($null -ne $label -and $formFactor -eq 'DIMM' -and $label -like 'LPDDR*') { if ($smbiosCode -ge 34) { $label = 'DDR5' } else { $label = 'DDR4' } }
        if (-not $label) { $label = "Unknown($smbiosCode)" }
        return $label
    }

    $array = Get-CimInstance Win32_PhysicalMemoryArray
    $modules = Get-CimInstance Win32_PhysicalMemory
    $totalSlots = $array.MemoryDevices; $usedSlots = $modules.Count
    $installedGB = if ($modules) { [math]::Round(($modules | Measure-Object Capacity -Sum).Sum / 1GB, 2) } else { 0 }

    $report = $modules | ForEach-Object {
        [PSCustomObject]@{ Channel=($_.DeviceLocator -split '-')[0]; Manufacturer=$_.Manufacturer; BankLabel=$_.BankLabel; DeviceLocator=$_.DeviceLocator; FormFactor=Decode-FormFactor -code $_.FormFactor; CapacityGB=[math]::Round($_.Capacity/1GB,2); SpeedMTs=$_.ConfiguredClockSpeed; MemoryType=Decode-MemoryType -smbiosCode $_.SMBIOSMemoryType -formFactor (Decode-FormFactor -code $_.FormFactor); SerialNumber=$_.SerialNumber }
    }
    Write-Host "Max Supported:    $($array.MaxCapacity / 1MB) GB"
    Write-Host ("Slots:            {0} Total, {1} Used" -f $totalSlots, $usedSlots)
    Write-Host "Installed:        $installedGB GB"
    
    $channels = $report.Channel | Sort-Object -Unique
    Write-Host "`nPer-channel summary:"
    foreach ($prop in 'Manufacturer','BankLabel','DeviceLocator','CapacityGB','SpeedMTs','MemoryType') {
        $pairs = $channels | ForEach-Object { $val = ($report | Where-Object Channel -eq $_ | Select-Object -ExpandProperty $prop); "$_=$val" }
        Write-Host ("{0,-15}: {1}" -f $prop, ($pairs -join ','))
    }
}

function Get-Dock {
    <# .SYNOPSIS Lists Docks, USB4/Thunderbolt, and Monitor connections. #>
    Write-Host "--- DOCK & DISPLAY AUDIT ---" -ForegroundColor Cyan
    
    Write-Host "`n== GPU Driver ==" -ForegroundColor Yellow
    Get-PnpDevice -Class Display | ForEach-Object {
        $ver = (Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName 'DEVPKEY_Device_DriverVersion' -ErrorAction SilentlyContinue).Data
        "{0}  Driver={1}" -f $_.InstanceId, $ver
    }

    Write-Host "`n== Possible Dock Devices ==" -ForegroundColor Yellow
    Get-CimInstance Win32_PnPEntity | Where-Object { $_.Name -match 'Dock|Thunderbolt|USB4|DisplayLink|Realtek.*GbE|I219-V' -or $_.PNPDeviceID -match 'VID_17EF|VID_17E9|VID_17AA|VID_17AF|VID_17A0|VID_17CB' } | Select-Object Name, Manufacturer, Status | Format-Table -Auto | Out-Host

    Write-Host "`n== Monitors & Connections ==" -ForegroundColor Yellow
    $vtMap = @{ 0="Uninitialized";1="Other";2="HD15/VGA";3="SVideo";4="Composite";5="Component";6="DVI";8="HDMI";9="LVDS";12="DP Ext";13="DP Emb";16="Internal";17="USB-C DP Alt" }
    $cons = Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorConnectionParams -ErrorAction SilentlyContinue
    $ids  = Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID -ErrorAction SilentlyContinue

    $cons | ForEach-Object {
        $inst = $_.InstanceName
        $tech = if ($vtMap.ContainsKey([int]$_.VideoOutputTechnology)) { $vtMap[[int]$_.VideoOutputTechnology] } else { $_.VideoOutputTechnology }
        $match = $ids | Where-Object { $_.InstanceName -eq $inst }
        $mfg = ($match.ManufacturerName | ForEach-Object {[char]$_}) -join ''; $prod= ($match.UserFriendlyName | ForEach-Object {[char]$_}) -join ''
        [pscustomobject]@{ Connection = $tech; Manufacturer = $mfg.Trim(); Model = $prod.Trim() }
    } | Format-Table -Auto | Out-Host
}

function Get-Battery {
    <# .SYNOPSIS Lists Laptop Batteries and UPS status. #>
    Write-Host "--- BATTERY/UPS AUDIT ---" -ForegroundColor Cyan
    $ac = [pscustomobject]@{ OnAC=$true; Pct=0 }
    try {
        Add-Type -AssemblyName System.Windows.Forms; $ps = [System.Windows.Forms.SystemInformation]::PowerStatus
        $ac = [pscustomobject]@{ OnAC=($ps.PowerLineStatus -eq 'Online'); Pct=[math]::Round($ps.BatteryLifePercent * 100, 0) }
    } catch {}

    Write-Host "Power Source: " -NoNewline
    if ($ac.OnAC) { Write-Host "AC Power (Plugged In)" -ForegroundColor Green } else { Write-Host "BATTERY" -ForegroundColor Red }
    Write-Host "Charge Level: $($ac.Pct)%"

    $bats = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue
    if ($bats) {
        $bats | Select-Object Name, Status, EstimatedChargeRemaining, EstimatedRunTime, PNPDeviceID | Format-Table -Auto | Out-Host
    } else { Write-Host "No Battery/UPS detected via WMI." -ForegroundColor Gray }
}

function Start-UPSLog {
    <# .SYNOPSIS Starts a blocking loop to log UPS transitions to CSV. #>
    param([int]$Interval=2, [string]$Csv="C:\ProgramData\UPS\ups_log.csv")
    Write-Host "--- UPS LOGGER (Ctrl+C to Stop) ---" -ForegroundColor Cyan
    Write-Host "Logging every $Interval seconds to: $Csv"
    Add-Type -AssemblyName System.Windows.Forms
    if (!(Test-Path (Split-Path $Csv))) { New-Item -ItemType Directory -Path (Split-Path $Csv) -Force | Out-Null }
    $last = $null
    while ($true) {
        $ps = [System.Windows.Forms.SystemInformation]::PowerStatus
        $state = $ps.PowerLineStatus.ToString()
        if ($state -ne $last) {
            $row = [pscustomobject]@{ Time=(Get-Date).ToString("u"); State=$state; Pct=$ps.BatteryLifePercent }
            $row | Export-Csv $Csv -Append -NoTypeInformation -Force
            Write-Host "[$($row.Time)] Transition: $state ($($row.Pct*100)%)" -ForegroundColor Yellow
            $last = $state
        }
        Start-Sleep -Seconds $Interval
    }
}

# ==============================================================================
#  SECTION 2: FORENSICS & HEALTH
# ==============================================================================

function Get-SystemHealth {
    <# .SYNOPSIS The "Forensic4" Deep Audit (Storage, Boot, Crashes). #>
    param([int]$Days=14)
    Write-Host "--- SYSTEM HEALTH AUDIT ---" -ForegroundColor Cyan
    $StartDate = (Get-Date).AddDays(-$Days)

    # 1. Identity
    $cs = Get-CimInstance Win32_ComputerSystem; $os = Get-CimInstance Win32_OperatingSystem
    Write-Host "System: $($cs.Manufacturer) $($cs.Model)"
    Write-Host "Uptime: $((Get-Date) - $os.LastBootUpTime)"
    
    # 2. Boot Cycles
    Write-Host "`n[Boot History ($Days Days)]" -ForegroundColor Yellow
    $evts = Get-WinEvent -FilterHashtable @{LogName='System'; Id=@(6005,6006,6008,41); StartTime=$StartDate} -ErrorAction SilentlyContinue
    if ($evts) {
        $evts | Select-Object TimeCreated, Id, @{n='Type';e={switch($_.Id){6005{'Start'}6006{'Stop'}6008{'Unexpected'}41{'Dirty'}default{'Other'}}}} | Format-Table -Auto | Out-Host
    } else { Write-Host "No boot events found." -ForegroundColor Gray }

    # 3. Storage
    Write-Host "`n[Storage Health]" -ForegroundColor Yellow
    Get-PhysicalDisk | Select FriendlyName, MediaType, HealthStatus, FirmwareVersion | Format-Table -Auto | Out-Host
    $errs = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName=@('stornvme','disk','Ntfs','WHEA-Logger'); StartTime=$StartDate} -ErrorAction SilentlyContinue
    if ($errs) { Write-Host "CRITICAL: Found $($errs.Count) Storage Errors." -ForegroundColor Red; $errs | Select -First 5 TimeCreated,Message | Format-List | Out-Host } 
    else { Write-Host "Storage logs clean." -ForegroundColor Green }
}

function Get-Printers {
    <# .SYNOPSIS WSDIP4 - Audits printers for WSD ports and Drivers. #>
    Write-Host "--- PRINTER AUDIT ---" -ForegroundColor Cyan
    $printers = Get-Printer
    $printers | ForEach-Object {
        $type = if ($_.PortName -match "WSD") { "WSD (Bad)" } elseif ($_.PortName -match "IP_") { "TCP/IP (Good)" } else { "Local/Virt" }
        [PSCustomObject]@{ Name=$_.Name; Driver=$_.DriverName; Port=$_.PortName; Type=$type }
    } | Sort-Object Type | Format-Table -Auto | Out-Host
    
    Write-Host "`nRecommendations:" -ForegroundColor Yellow
    if ($printers.PortName -match "WSD") { Write-Host "[!] Found WSD Ports. Reinstall these using Standard TCP/IP." -ForegroundColor Red }
    else { Write-Host "[OK] No WSD ports detected." -ForegroundColor Green }
}

function Get-Office {
    <# .SYNOPSIS Audits Outlook Versions, Accounts, and PST/OST files. #>
    Write-Host "--- OFFICE/OUTLOOK AUDIT ---" -ForegroundColor Cyan
    
    # 1. Install Type
    $c2r = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration' -ErrorAction SilentlyContinue
    if ($c2r) { Write-Host "Install: Click-to-Run (Version: $($c2r.ClientVersionToReport))" -ForegroundColor Green }
    else { Write-Host "Install: MSI/Legacy or None" -ForegroundColor Yellow }

    # 2. Files
    Write-Host "`n[Data Files]" -ForegroundColor Yellow
    $users = Get-ChildItem "C:\Users" -Directory | Where Name -notin 'Public','Default'
    foreach ($u in $users) {
        $paths = @("$($u.FullName)\AppData\Local\Microsoft\Outlook", "$($u.FullName)\Documents\Outlook Files")
        foreach ($p in $paths) {
            if (Test-Path $p) {
                Get-ChildItem $p -Include *.pst,*.ost -Recurse | ForEach-Object {
                    [PSCustomObject]@{ User=$u.Name; File=$_.Name; SizeMB=[math]::Round($_.Length/1MB,0); Modified=$_.LastWriteTime }
                } | Format-Table -Auto | Out-Host
            }
        }
    }
}

function Get-Drives {
    <# .SYNOPSIS Scans registry for mapped drives. #>
    param([switch]$IncludeLive=$true)
    Write-Host "--- DRIVE MAP AUDIT ---" -ForegroundColor Cyan
    $results = @()
    $profiles = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' | ForEach-Object {
        $sid = $_.PSChildName; $pip = (Get-ItemProperty $_.PSPath -EA SilentlyContinue).ProfileImagePath
        if ($pip) { [PSCustomObject]@{ SID=$sid; Path=[Environment]::ExpandEnvironmentVariables($pip); User=($pip -split '\\')[-1] } }
    }
    foreach ($p in $profiles) {
        $hive = "HKLM:\TempHive_$($p.SID)"; $ntuser = Join-Path $p.Path 'NTUSER.DAT'
        if (Test-Path $ntuser) {
            & reg.exe load "HKLM\TempHive_$($p.SID)" $ntuser *> $null
            $netKey = "$hive\Network"
            if (Test-Path $netKey) {
                Get-ChildItem $netKey | ForEach-Object {
                    $rp = (Get-ItemProperty $_.PSPath -EA SilentlyContinue).RemotePath
                    if ($rp) { $results += [PSCustomObject]@{ User=$p.User; Drive=$_.PSChildName; Path=$rp; Source="Registry" } }
                }
            }
            & reg.exe unload "HKLM\TempHive_$($p.SID)" *> $null
        }
    }
    if ($IncludeLive) {
        Get-CimInstance -ClassName Win32_MappedLogicalDisk | ForEach-Object {
            $results += [PSCustomObject]@{ User=$env:USERNAME; Drive=$_.DeviceID.TrimEnd(':'); Path=$_.ProviderName; Source="LiveSession" }
        }
    }
    if ($results) { $results | Select-Object User,Drive,Path,Source | Format-Table -Auto | Out-Host } 
    else { Write-Host "No mapped drives found." -ForegroundColor Gray }
}

function Get-Users {
    <# .SYNOPSIS Audit who has logged in. #>
    Write-Host "--- USER PROFILE AUDIT ---" -ForegroundColor Cyan
    Get-CimInstance Win32_UserProfile | Where-Object { $_.LocalPath -like 'C:\Users\*' -and -not $_.Special } | ForEach-Object {
        $uName = ($_.LocalPath -split '\\')[-1]
        [PSCustomObject]@{ User=$uName; Path=$_.LocalPath; SID=$_.SID; LastUse=$_.LastUseTime }
    } | Format-Table -Auto | Out-Host
}

# ==============================================================================
#  SECTION 3: CONFIGURATION & MAINTENANCE
# ==============================================================================

function Get-PowerAudit {
    <# .SYNOPSIS Audits Sleep, Fast Startup, and S0 Modern Standby. #>
    Write-Host "--- POWER AUDIT ---" -ForegroundColor Cyan
    $p = 'HKLM:\SYSTEM\CurrentControlSet\Control\Power'
    $s = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power'
    $s0 = (Get-ItemProperty $p -Name PlatformAoAcOverride -ErrorAction SilentlyContinue).PlatformAoAcOverride
    $fs = (Get-ItemProperty $s -Name HiberbootEnabled -ErrorAction SilentlyContinue).HiberbootEnabled
    Write-Host "Registry Settings:" -ForegroundColor Yellow
    Write-Host "  S0 Override (AoAc): $(if ($s0 -ne $null) { $s0 } else { 'Default' }) (0=Disabled/Good)"
    Write-Host "  Fast Startup:       $(if ($fs -ne $null) { $fs } else { 'Default' }) (0=Disabled/Good)"
    Write-Host "`nAvailability:" -ForegroundColor Yellow
    powercfg /a | Select-String "Standby"
}

function Set-Power {
    <# .SYNOPSIS Enforces High Perf (Desktop) or Balanced (Laptop). #>
    param([switch]$ForceReboot)
    Write-Host "--- POWER ENFORCE ---" -ForegroundColor Cyan
    
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name HiberbootEnabled -Value 0 -Force
    Write-Host "[OK] Fast Startup Disabled." -ForegroundColor Green
    
    New-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name PlatformAoAcOverride -Value 0 -PropertyType DWord -Force | Out-Null
    Write-Host "[OK] S0 Modern Standby Disabled (Reg Key Set)." -ForegroundColor Green
    
    $isLaptop = (Get-CimInstance Win32_SystemEnclosure).ChassisTypes -in 8,9,10,14
    if ($isLaptop) {
        powercfg /s 381b4222-f694-41f0-9685-ff5bb260df2e # Balanced
        Write-Host "[OK] Applied BALANCED plan (Laptop)." -ForegroundColor Green
    } else {
        powercfg /s 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c # High Perf
        Write-Host "[OK] Applied HIGH PERFORMANCE plan (Desktop)." -ForegroundColor Green
        powercfg /change monitor-timeout-ac 20
        powercfg /change standby-timeout-ac 0
        powercfg /h off
    }
    
    if ($ForceReboot) { Restart-Computer -Force -TimeOut 5 }
    else { Write-Host "`nNOTE: Reboot required for S0/FastStartup changes to take effect." -ForegroundColor Yellow }
}

function Enable-BitLocker {
    <# .SYNOPSIS Enables BitLocker (UsedSpaceOnly) and escrows key. #>
    param([string]$Drive='C:')
    Write-Host "--- BITLOCKER ENFORCEMENT ---" -ForegroundColor Cyan
    $tpm = Get-Tpm; if (-not $tpm.TpmReady) { Write-Error "TPM Not Ready."; return }
    $RegKey = 'HKLM:\SOFTWARE\AerosIT\BitLocker\C'; if (-not (Test-Path $RegKey)) { New-Item -Path $RegKey -Force | Out-Null }

    $bv = Get-BitLockerVolume -MountPoint $Drive
    if ($bv.ProtectionStatus -eq 'Off') {
        Write-Host "Enabling BitLocker on $Drive..." -ForegroundColor Yellow
        Enable-BitLocker -MountPoint $Drive -TpmProtector -SkipHardwareTest -UsedSpaceOnly -EncryptionMethod XTSAes256
        Start-Sleep -Seconds 5
        $key = (Get-BitLockerVolume -MountPoint $Drive).KeyProtector | Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword'} | Select -First 1
        if ($key) {
            New-ItemProperty -Path $RegKey -Name 'RecoveryPassword' -Value $key.RecoveryPassword -Force | Out-Null
            Write-Host "SUCCESS. Key saved to Registry." -ForegroundColor Green
            Write-Host "KEY: $($key.RecoveryPassword)" -ForegroundColor Gray
        }
    } else { Write-Host "BitLocker is already enabled." -ForegroundColor Green }
}

function New-Scanner {
    <# .SYNOPSIS Creates 'scans' user and share. #>
    param([string]$User="scans", [string]$Password="scans")
    Write-Host "--- SCANNER SETUP ---" -ForegroundColor Cyan
    if (Get-LocalUser -Name $User -ErrorAction SilentlyContinue) { Set-LocalUser -Name $User -Password (ConvertTo-SecureString $Password -AsPlainText -Force) }
    else { New-LocalUser -Name $User -Password (ConvertTo-SecureString $Password -AsPlainText -Force) -Description "SMB Scan Account" | Out-Null }
    
    $reg = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
    if (!(Test-Path $reg)) { New-Item -Path $reg -Force | Out-Null }
    New-ItemProperty -Path $reg -Name $User -Value 0 -PropertyType DWORD -Force | Out-Null

    $Path = "C:\Scans"; if (!(Test-Path $Path)) { New-Item -Path $Path -ItemType Directory | Out-Null }
    $acl = Get-Acl $Path; $rule = New-Object System.Security.AccessControl.FileSystemAccessRule $User,"FullControl","ContainerInherit,ObjectInherit","None","Allow"
    $acl.AddAccessRule($rule); Set-Acl $Path $acl
    
    if (!(Get-SmbShare -Name "Scans" -ErrorAction SilentlyContinue)) { New-SmbShare -Name "Scans" -Path $Path -FullAccess $User -Description "Scanner" | Out-Null }
    Write-Host "Complete. Share: \\$env:COMPUTERNAME\Scans" -ForegroundColor Green
}

# ==============================================================================
#  SECTION 4: CLEANUP & UNINSTALL
# ==============================================================================

function Uninstall-CyberCNS {
    <# .SYNOPSIS Removes CyberCNS. #>
    Write-Host "--- REMOVING CYBERCNS ---" -ForegroundColor Magenta
    $services = @("cybercnsagent", "cybercnsagentv2", "cybercnsagentmonitor")
    foreach ($s in $services) {
        Stop-Service $s -ErrorAction SilentlyContinue
        sc.exe delete $s | Out-Null
        Write-Host "Removed Service: $s"
    }
    Remove-Item "C:\Program Files (x86)\CyberCNSAgent" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Files Deleted." -ForegroundColor Green
}

function Uninstall-Heartbeat {
    <# .SYNOPSIS Removes 'Aeros Heartbeat' task. #>
    Write-Host "--- REMOVING HEARTBEAT ---" -ForegroundColor Magenta
    Unregister-ScheduledTask -TaskName "Aeros Heartbeat" -Confirm:$false -ErrorAction SilentlyContinue
    Get-ScheduledTask | Where-Object {$_.TaskName -match 'Heartbeat'} | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item "C:\Aeros\Heartbeat" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Tasks and files removed." -ForegroundColor Green
}

# ==============================================================================
#  INTERACTIVE MENU
# ==============================================================================
function Start-Aeros {
    while ($true) {
        Clear-Host
        Write-Host "+----------------------------------------+" -ForegroundColor Cyan
        Write-Host "|          AEROS IT TOOLBOX v3.0         |" -ForegroundColor Cyan
        Write-Host "+----------------------------------------+" -ForegroundColor Cyan
        Write-Host "| HARDWARE                               |" -ForegroundColor Gray
        Write-Host "|  1. Get-RAM       (RAM Slots & Type)   |"
        Write-Host "|  2. Get-Dock      (Docks & Monitors)   |"
        Write-Host "|  3. Get-Battery   (Health & UPS)       |"
        Write-Host "|  4. Start-UPSLog  (Log Transitions)    |"
        Write-Host "|                                        |"
        Write-Host "| FORENSICS                              |" -ForegroundColor Gray
        Write-Host "|  5. Get-SystemHealth (Storage/Boot)    |"
        Write-Host "|  6. Get-Printers  (WSD & Drivers)      |"
        Write-Host "|  7. Get-Office    (Outlook Versions)   |"
        Write-Host "|  8. Get-Drives    (Mapped Drives)      |"
        Write-Host "|  9. Get-Users     (Profiles Audit)     |"
        Write-Host "|                                        |"
        Write-Host "| MAINTENANCE                            |" -ForegroundColor Gray
        Write-Host "| 10. Get-PowerAudit (Audit Config)      |"
        Write-Host "| 11. Set-Power      (Enforce Perf)      |"
        Write-Host "| 12. Enable-BitLocker (Enforce)         |"
        Write-Host "| 13. New-Scanner    (Create SMB User)   |"
        Write-Host "|                                        |"
        Write-Host "| CLEANUP                                |" -ForegroundColor Gray
        Write-Host "| 14. Uninstall-CyberCNS                 |"
        Write-Host "| 15. Uninstall-Heartbeat                |"
        Write-Host "+----------------------------------------+" -ForegroundColor Cyan
        Write-Host "  Q. Quit" -ForegroundColor Yellow
        
        $sel = Read-Host "`nSelect an option"
        
        switch ($sel) {
            '1'  { Get-RAM; pause }
            '2'  { Get-Dock; pause }
            '3'  { Get-Battery; pause }
            '4'  { Start-UPSLog }
            '5'  { Get-SystemHealth; pause }
            '6'  { Get-Printers; pause }
            '7'  { Get-Office; pause }
            '8'  { Get-Drives; pause }
            '9'  { Get-Users; pause }
            '10' { Get-PowerAudit; pause }
            '11' { Set-Power; pause }
            '12' { Enable-BitLocker; pause }
            '13' { New-Scanner; pause }
            '14' { Uninstall-CyberCNS; pause }
            '15' { Uninstall-Heartbeat; pause }
            'Q'  { return }
            'q'  { return }
        }
    }
}
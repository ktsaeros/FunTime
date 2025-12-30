<#
.SYNOPSIS
    AEROS IT TOOLBOX (v1.0)
    Combined utilities for Hardware, Security, and Forensics.
    
    CONTENTS:
    1. Get-AerosRAM         - Detailed Memory analysis
    2. Get-AerosDock        - Docking station & Monitor inventory
    3. Get-AerosDrives      - Mapped network drive audit
    4. Get-AerosUsers       - User profile & Admin audit
    5. Enable-AerosBitLocker- Enforce BitLocker + Escrow Key
    6. New-AerosScanner     - Setup SMB Scanner User & Share
#>

# ==============================================================================
#  1. HARDWARE: RAM AUDIT (formerly RAM.ps1)
# ==============================================================================
function Get-AerosRAM {
    <# .SYNOPSIS Shows physical memory slots, speeds, and types. #>
    Write-Host "--- AEROS RAM ANALYSIS ---" -ForegroundColor Cyan
    
    # Mapping tables
    $MEMORY_TYPES = @('Unknown','Other','Unknown','DRAM','EDRAM','VRAM','SRAM','ROM','FLASH','EEPROM','FEPROM','EPROM','CDRAM','3DRAM','SDRAM','SGRAM','RDRAM','DDR','DDR2','DDR2 FB-DIMM','Reserved','Reserved','Reserved','DDR3','FBD2','DDR4','LPDDR','LPDDR2','LPDDR3','LPDDR4','Logical non-volatile device','HBM','HBM2','DDR5','LPDDR5')
    $TYPE_DETAILS = @('Reserved','Other','Unknown','Fast-paged','Static column','Pseudo-static','RAMBUS','Synchronous','CMOS','EDO','Window DRAM','Cache DRAM','Non-volatile','Registered','Unbuffered','LRDIMM')

    function Decode-TypeDetail { param([int]$flags)
        $names = 0..15 | Where-Object { $flags -band (1 -shl $_) } | ForEach-Object { $TYPE_DETAILS[$_] }
        return "0x{0:X2} ({1})" -f $flags, ($names -join ' | ')
    }
    function Decode-FormFactor { param([int]$code)
        switch ($code) { 8 { 'DIMM' } 12 { 'SODIMM' } default { "Unknown($code)" } }
    }
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

    # Report Construction
    $report = $modules | ForEach-Object {
        [PSCustomObject]@{
            Channel       = ($_.DeviceLocator -split '-')[0]
            Manufacturer  = $_.Manufacturer
            BankLabel     = $_.BankLabel
            DeviceLocator = $_.DeviceLocator
            FormFactor    = Decode-FormFactor -code $_.FormFactor
            CapacityGB    = [math]::Round($_.Capacity/1GB,2)
            SpeedMTs      = $_.ConfiguredClockSpeed
            MemoryType    = Decode-MemoryType -smbiosCode $_.SMBIOSMemoryType -formFactor (Decode-FormFactor -code $_.FormFactor)
            TypeDetail    = Decode-TypeDetail -flags $_.TypeDetail
            SerialNumber  = $_.SerialNumber
        }
    }

    # Output Summary
    Write-Host "Maximum supported:    $($array.MaxCapacity / 1MB) GB"
    Write-Host ("Physical slots:       {0} slots, {1} used" -f $totalSlots, $usedSlots)
    Write-Host "Currently installed:  $installedGB GB"
    
    # Per Channel Output
    $channels = $report.Channel | Sort-Object -Unique
    Write-Host "`nPer-channel summary:"
    foreach ($prop in 'Manufacturer','BankLabel','DeviceLocator','CapacityGB','SpeedMTs','MemoryType') {
        $pairs = $channels | ForEach-Object { $val = ($report | Where-Object Channel -eq $_ | Select-Object -ExpandProperty $prop); "$_=$val" }
        Write-Host ("{0,-15}: {1}" -f $prop, ($pairs -join ','))
    }
    Write-Host ""
}

# ==============================================================================
#  2. HARDWARE: DOCKS & MONITORS (formerly dockinvo.ps1)
# ==============================================================================
function Get-AerosDock {
    <# .SYNOPSIS Lists Docks, USB4/Thunderbolt, and Monitor connections. #>
    Write-Host "--- AEROS DOCK & DISPLAY AUDIT ---" -ForegroundColor Cyan
    
    Write-Host "`n== GPU Driver ==" -ForegroundColor Yellow
    Get-PnpDevice -Class Display | ForEach-Object {
        $ver = (Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName 'DEVPKEY_Device_DriverVersion' -ErrorAction SilentlyContinue).Data
        "{0}  Driver={1}" -f $_.InstanceId, $ver
    }

    Write-Host "`n== Possible Dock Devices ==" -ForegroundColor Yellow
    Get-CimInstance Win32_PnPEntity | Where-Object {
        $_.Name -match 'Dock|Thunderbolt|USB4|DisplayLink|Realtek.*GbE|I219-V' -or $_.PNPDeviceID -match 'VID_17EF|VID_17E9|VID_17AA|VID_17AF|VID_17A0|VID_17CB'
    } | Select-Object Name, Manufacturer, Status | Format-Table -Auto | Out-Host

    Write-Host "`n== Monitors & Connections ==" -ForegroundColor Yellow
    $vtMap = @{ 0="Uninitialized";1="Other";2="HD15/VGA";3="SVideo";4="Composite";5="Component";6="DVI";8="HDMI";9="LVDS";12="DP Ext";13="DP Emb";16="Internal";17="USB-C DP Alt" }
    
    $cons = Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorConnectionParams -ErrorAction SilentlyContinue
    $ids  = Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID -ErrorAction SilentlyContinue

    $cons | ForEach-Object {
        $inst = $_.InstanceName
        $tech = if ($vtMap.ContainsKey([int]$_.VideoOutputTechnology)) { $vtMap[[int]$_.VideoOutputTechnology] } else { $_.VideoOutputTechnology }
        $match = $ids | Where-Object { $_.InstanceName -eq $inst }
        $mfg = ($match.ManufacturerName | ForEach-Object {[char]$_}) -join ''
        $prod= ($match.UserFriendlyName | ForEach-Object {[char]$_}) -join ''
        [pscustomobject]@{ Connection = $tech; Manufacturer = $mfg.Trim(); Model = $prod.Trim() }
    } | Format-Table -Auto | Out-Host
}

# ==============================================================================
#  3. FORENSICS: MAPPED DRIVES (formerly map.ps1)
# ==============================================================================
function Get-AerosDrives {
    <# .SYNOPSIS Scans registry for mapped drives (Persistent) and Live Session. #>
    param([switch]$IncludeLive=$true)
    Write-Host "--- AEROS DRIVE MAP AUDIT ---" -ForegroundColor Cyan
    
    $results = @()
    # 1. Registry Scan (Persistent)
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

    # 2. Live Scan (Current Session)
    if ($IncludeLive) {
        Get-CimInstance -ClassName Win32_MappedLogicalDisk | ForEach-Object {
            $results += [PSCustomObject]@{ User=$env:USERNAME; Drive=$_.DeviceID.TrimEnd(':'); Path=$_.ProviderName; Source="LiveSession" }
        }
    }
    
    if ($results) { $results | Select-Object User,Drive,Path,Source | Format-Table -Auto | Out-Host } 
    else { Write-Host "No mapped drives found." -ForegroundColor Gray }
}

# ==============================================================================
#  4. FORENSICS: USER PROFILES (formerly users.ps1)
# ==============================================================================
function Get-AerosUsers {
    <# .SYNOPSIS Audit who has logged in and if they are Admin. #>
    Write-Host "--- AEROS USER PROFILE AUDIT ---" -ForegroundColor Cyan

    $adminMembers = @()
    try {
        $grp = [ADSI]"WinNT://$env:COMPUTERNAME/Administrators,group"
        $grp.Members() | ForEach-Object { $adminMembers += $_.Name }
    } catch {
        $adminMembers += ((& net localgroup Administrators) | Select -Skip 6 | Select -SkipLast 2)
    }

    Get-CimInstance Win32_UserProfile | Where-Object { $_.LocalPath -like 'C:\Users\*' -and -not $_.Special } | ForEach-Object {
        $uName = ($_.LocalPath -split '\\')[-1]
        $isAdmin = if ($adminMembers -contains $uName -or $adminMembers -contains "$env:COMPUTERNAME\$uName") { 'Yes' } else { 'No/Group' }
        [PSCustomObject]@{ User=$uName; Admin=$isAdmin; Path=$_.LocalPath; SID=$_.SID }
    } | Format-Table -Auto | Out-Host
}

# ==============================================================================
#  5. SECURITY: BITLOCKER (formerly btlon.ps1)
# ==============================================================================
function Enable-AerosBitLocker {
    <# .SYNOPSIS Enables BitLocker (UsedSpaceOnly) and escrows key to Registry. #>
    param([string]$Drive='C:')
    
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrator')) {
        Write-Warning "Must run as Administrator."; return
    }
    Write-Host "--- AEROS BITLOCKER ENFORCEMENT ---" -ForegroundColor Cyan

    $tpm = Get-Tpm; if (-not $tpm.TpmReady) { Write-Error "TPM Not Ready."; return }
    $RegKey = 'HKLM:\SOFTWARE\AerosIT\BitLocker\C'; if (-not (Test-Path $RegKey)) { New-Item -Path $RegKey -Force | Out-Null }

    $bv = Get-BitLockerVolume -MountPoint $Drive
    if ($bv.ProtectionStatus -eq 'Off') {
        Write-Host "Enabling BitLocker on $Drive..." -ForegroundColor Yellow
        Enable-BitLocker -MountPoint $Drive -TpmProtector -SkipHardwareTest -UsedSpaceOnly -EncryptionMethod XTSAes256
        
        # Capture Key
        Start-Sleep -Seconds 5
        $key = (Get-BitLockerVolume -MountPoint $Drive).KeyProtector | Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword'} | Select -First 1
        if ($key) {
            New-ItemProperty -Path $RegKey -Name 'RecoveryPassword' -Value $key.RecoveryPassword -Force | Out-Null
            Write-Host "SUCCESS. Key saved to Registry." -ForegroundColor Green
            Write-Host "KEY: $($key.RecoveryPassword)" -ForegroundColor Gray
        }
    } else {
        Write-Host "BitLocker is already enabled." -ForegroundColor Green
    }
}

# ==============================================================================
#  6. SETUP: SCANNER USER (formerly scanner.ps1)
# ==============================================================================
function New-AerosScanner {
    <# .SYNOPSIS Creates 'scans' user, C:\Scans folder, and Share. #>
    param([string]$User="scans", [string]$Password="scans")
    
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrator')) {
        Write-Warning "Must run as Administrator."; return
    }
    Write-Host "--- AEROS SCANNER SETUP ---" -ForegroundColor Cyan

    # 1. User
    if (Get-LocalUser -Name $User -ErrorAction SilentlyContinue) {
        Write-Host "User '$User' exists. Resetting password..." -ForegroundColor Yellow
        Set-LocalUser -Name $User -Password (ConvertTo-SecureString $Password -AsPlainText -Force)
    } else {
        Write-Host "Creating user '$User'..." -ForegroundColor Green
        New-LocalUser -Name $User -Password (ConvertTo-SecureString $Password -AsPlainText -Force) -Description "SMB Scan Account" | Out-Null
    }
    Set-LocalUser -Name $User -PasswordNeverExpires $true

    # 2. Hide from Login
    $reg = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
    if (!(Test-Path $reg)) { New-Item -Path $reg -Force | Out-Null }
    New-ItemProperty -Path $reg -Name $User -Value 0 -PropertyType DWORD -Force | Out-Null

    # 3. Share
    $Path = "C:\Scans"; if (!(Test-Path $Path)) { New-Item -Path $Path -ItemType Directory | Out-Null }
    $acl = Get-Acl $Path
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule $User,"FullControl","ContainerInherit,ObjectInherit","None","Allow"
    $acl.AddAccessRule($rule); Set-Acl $Path $acl
    
    if (!(Get-SmbShare -Name "Scans" -ErrorAction SilentlyContinue)) {
        New-SmbShare -Name "Scans" -Path $Path -FullAccess $User -Description "Scanner" | Out-Null
    }
    Write-Host "Scanner Setup Complete. Path: \\$env:COMPUTERNAME\Scans" -ForegroundColor Green
}

# ==============================================================================
#  MENU SYSTEM (Runs on Load)
# ==============================================================================
function Show-AerosMenu {
    Clear-Host
    Write-Host "╔════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║           AEROS IT TOOLBOX v1.0            ║" -ForegroundColor Cyan
    Write-Host "╠════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║  1. Get-AerosRAM       (Hardware Audit)    ║" -ForegroundColor Gray
    Write-Host "║  2. Get-AerosDock      (Monitor/Dock Info) ║" -ForegroundColor Gray
    Write-Host "║  3. Get-AerosDrives    (Mapped Drives)     ║" -ForegroundColor Gray
    Write-Host "║  4. Get-AerosUsers     (Profile Audit)     ║" -ForegroundColor Gray
    Write-Host "║  5. Enable-AerosBitLocker (Security)       ║" -ForegroundColor Gray
    Write-Host "║  6. New-AerosScanner   (Setup SMB User)    ║" -ForegroundColor Gray
    Write-Host "╚════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host " Type a command above to start." -ForegroundColor Yellow
}

# Auto-show menu when loaded
Show-AerosMenu
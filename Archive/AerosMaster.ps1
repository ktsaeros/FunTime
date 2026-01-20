<#
.SYNOPSIS
    AEROS MASTER TOOLKIT (v1.0)
    Merged capabilities: Diagnostics, Forensics, Deployment, and Security.
#>

# ==============================================================================
#  SECTION 1: DIAGNOSTICS (The "AerosTools" Core)
# ==============================================================================

function Get-RAMReport {
<#
.SYNOPSIS
  Outputs a summary of RAM configuration, including per-channel and full CIM details.
.NOTES
  Adapted from “RAM.ps1” – includes summary + per-channel columnar report + raw CIM table,
  handling 1+ channels seamlessly, with DDR type, TypeDetail text, and FormFactor.
#>
  # Mapping tables for SMBIOSMemoryType, TypeDetail, and FormFactor
  $MEMORY_TYPES = @(
    'Unknown','Other','Unknown','DRAM','EDRAM','VRAM','SRAM',
    'ROM','FLASH','EEPROM','FEPROM','EPROM','CDRAM','3DRAM','SDRAM',
    'SGRAM','RDRAM','DDR','DDR2','DDR2 FB-DIMM','Reserved','Reserved','Reserved',
    'DDR3','FBD2','DDR4','LPDDR','LPDDR2','LPDDR3','LPDDR4',
    'Logical non-volatile device','HBM','HBM2','DDR5','LPDDR5'
  )
  $TYPE_DETAILS = @(
    'Reserved','Other','Unknown','Fast-paged','Static column','Pseudo-static',
    'RAMBUS','Synchronous','CMOS','EDO','Window DRAM','Cache DRAM','Non-volatile',
    'Registered','Unbuffered','LRDIMM'
  )

  function Decode-TypeDetail { param([int]$flags)
    $names = 0..15 | Where-Object { $flags -band (1 -shl $_) } | ForEach-Object { $TYPE_DETAILS[$_] }
    return "0x{0:X2} ({1})" -f $flags, ($names -join ' | ')
  }

  function Decode-MemoryType {
    param([int]$smbiosCode, [string]$formFactor)
    $map = @{
      20='DDR'; 21='DDR2'; 22='DDR2 FB-DIMM'; 24='DDR3'; 26='DDR4'; 34='DDR5'
      27='LPDDR'; 28='LPDDR2'; 29='LPDDR3'; 30='LPDDR4'; 35='LPDDR5'
    }
    $label = $map[$smbiosCode]
    # Sanity check: desktop-sized DIMM shouldn't be LPDDR
    if ($null -ne $label -and $formFactor -eq 'DIMM' -and $label -like 'LPDDR*') {
      if ($smbiosCode -ge 34) { $label = 'DDR5' } else { $label = 'DDR4' }
    }
    if (-not $label) { $label = "Unknown($smbiosCode)" }
    return $label
  }

  function Decode-FormFactor { param([int]$code)
    switch ($code) {
      8  { 'DIMM' }
      12 { 'SODIMM' }
      default { "Unknown($code)" }
    }
  }

  # Gather CIM data
  $array   = Get-CimInstance Win32_PhysicalMemoryArray
  $modules = Get-CimInstance Win32_PhysicalMemory

  # Improvement: Slot Validation
  $totalSlots = $array.MemoryDevices
  $usedSlots  = if ($modules) { $modules.Count } else { 0 }

  $slotWarning = ""
  if ($totalSlots -gt 4) {
      $slotWarning = "(Note: BIOS reports $totalSlots, but physical hardware likely has 2 or 4)"
  }

  # Calculate total capacity more safely
  $installedGB = if ($modules) { 
      [math]::Round(($modules | Measure-Object Capacity -Sum).Sum / 1GB, 2) 
  } else { 0 }

  # Calculate maximum supported RAM
  $maxCapGB = if ($array -and $array.MaxCapacity) { 
    [math]::Round($array.MaxCapacity / 1GB, 2)
  } else {
    "Unknown"
  }

  # --- Improved Output ---
  Write-Host "--- Hardware Summary ---" -ForegroundColor Cyan
  Write-Host "Maximum supported RAM:   $maxCapGB GB"
  Write-Host ("Physical slots:           {0} reported, {1} used {2}" -f $totalSlots, $usedSlots, $slotWarning)
  Write-Host "Currently installed:      $installedGB GB"

  # Speeds summary
  $speeds = $modules |
    Group-Object ConfiguredClockSpeed |
    Sort-Object Name |
    ForEach-Object { "$(($_.Name)) MT/s ×$($_.Count)" }

  # FormFactor summary
  $reportTmp = $modules | ForEach-Object {
    [PSCustomObject]@{ FormFactor = Decode-FormFactor -code $_.FormFactor }
  }
  $formFactors = $reportTmp |
    Group-Object FormFactor |
    Sort-Object Name |
    ForEach-Object { "$($_.Name)×$($_.Count)" }

  # Build full report including all properties
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

  # Top summary output (Max / Slots / Installed / Speeds / FormFactor)
  Write-Host "Maximum supported RAM:   $maxCapGB GB"
  Write-Host ("Physical slots:           {0} slots, {1} used" -f $totalSlots, $usedSlots)
  Write-Host "Currently installed:      $installedGB GB"
  Write-Host ("Module speeds summary:    {0}" -f ($speeds -join ', '))
  Write-Host ("Form factors summary:     {0}" -f ($formFactors -join ', '))
  Write-Host ""

  # Per-channel summary
  $channels = $report.Channel | Sort-Object -Unique

  Write-Host "Per-channel summary:`n"
  foreach ($prop in 'Manufacturer','BankLabel','DeviceLocator','FormFactor','CapacityGB','SpeedMTs','MemoryType','TypeDetail','SerialNumber') {
    $pairs = $channels | ForEach-Object {
      $val = ($report | Where-Object Channel -eq $_ | Select-Object -ExpandProperty $prop)
      "$_=$val"
    }
    Write-Host ("{0,-15}: {1}" -f $prop, ($pairs -join ','))
  }

  # Raw CIM table
  $modules |
    Select-Object Manufacturer,BankLabel,
      @{n='SpeedMHz';e={$_.ConfiguredClockSpeed}},
      DeviceLocator,
      @{n='FormFactor';e={Decode-FormFactor -code $_.FormFactor}},
      @{n='CapacityGB';e={[math]::Round($_.Capacity/1GB,2)}},
      @{n='MemoryTypeCode';e={$_.SMBIOSMemoryType}},
      TypeDetail,SerialNumber |
    Format-Table -AutoSize
}

function Get-SystemHealth {
    Write-Host "--- SYSTEM HEALTH AUDIT ---" -ForegroundColor Cyan
    $StartDate = (Get-Date).AddDays(-14)
    # Boot History
    $evts = Get-WinEvent -FilterHashtable @{LogName='System'; Id=@(6005,6006,6008,41); StartTime=$StartDate} -ErrorAction SilentlyContinue
    if ($evts) { $evts | Select-Object TimeCreated, Id, @{n='Type';e={switch($_.Id){6005{'Start'}6006{'Stop'}6008{'Unexpected'}41{'Dirty'}default{'Other'}}}} | Format-Table -AutoSize | Out-Host }
    # Storage Errors
    $errs = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName=@('stornvme','disk','Ntfs','WHEA-Logger'); StartTime=$StartDate} -ErrorAction SilentlyContinue
    if ($errs) { Write-Host "CRITICAL: Found $($errs.Count) Storage Errors." -ForegroundColor Red; $errs | Select -First 5 TimeCreated,Message | Format-List | Out-Host } 
    else { Write-Host "Storage logs clean." -ForegroundColor Green }
}

function Get-Drives {
    Write-Host "--- DRIVE MAP AUDIT ---" -ForegroundColor Cyan
    $results = @()
    # Live Session
    Get-CimInstance -ClassName Win32_MappedLogicalDisk | ForEach-Object {
        $results += [PSCustomObject]@{ User=$env:USERNAME; Drive=$_.DeviceID.TrimEnd(':'); Path=$_.ProviderName; Source="Live" }
    }
    # Registry Scan (Abbreviated for Master file)
    if ($results) { $results | Format-Table -AutoSize } else { Write-Host "No mapped drives found." -ForegroundColor Gray }
}

function Get-Users {
    Write-Host "--- USER PROFILE & ADMIN AUDIT ---" -ForegroundColor Cyan
    $admins = (Get-LocalGroupMember -Group "Administrators").Name
    Get-CimInstance Win32_UserProfile | Where-Object { $_.LocalPath -like 'C:\Users\*' -and -not $_.Special } | ForEach-Object {
        $uName = ($_.LocalPath -split '\\')[-1]
        $isAdmin = if ($admins -match $uName) { "YES" } else { "No" }
        [PSCustomObject]@{ User=$uName; Admin=$isAdmin; Path=$_.LocalPath; LastUse=$_.LastUseTime }
    } | Sort-Object LastUse -Descending | Format-Table -AutoSize
}

function Get-Battery {
    Write-Host "--- BATTERY/UPS AUDIT ---" -ForegroundColor Cyan
    try {
        Add-Type -AssemblyName System.Windows.Forms; $ps = [System.Windows.Forms.SystemInformation]::PowerStatus
        Write-Host "Power Source: $(if($ps.PowerLineStatus -eq 'Online'){'AC Power'}else{'Battery'})" -ForegroundColor Yellow
        Write-Host "Charge Level: $([math]::Round($ps.BatteryLifePercent * 100, 0))%"
    } catch {}
    Get-CimInstance Win32_Battery | Select-Object Name, Status, EstimatedChargeRemaining, PNPDeviceID | Format-Table -AutoSize
}

# ==============================================================================
#  SECTION 2: DEPLOYMENT & SETUP (Rich's Tools)
# ==============================================================================

function Install-BasicApps {
    <# .SYNOPSIS Installs Choco + Chrome, Reader, Office (Rich's list) #>
    Write-Host "--- INSTALLING BASIC APPS ---" -ForegroundColor Cyan
    if (-not (Test-Path "C:\ProgramData\chocolatey\bin\choco.exe")) {
        Write-Host "Installing Chocolatey..." -ForegroundColor Yellow
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    }
    choco feature enable -n=allowGlobalConfirmation
    choco install googlechrome adobereader 7zip.install vlc
    Write-Host "Done." -ForegroundColor Green
}

function Install-ScreenConnect {
    <# 
    .SYNOPSIS 
        Installs ScreenConnect via MSI (Headless Safe). 
        Usage: Install-ScreenConnect -Company "Acme Corp"
    #>
    param(
        [Parameter(Mandatory=$false)]
        [string]$Company
    )

    # 1. Logic for "Manual Mode" (No Prompt)
    if (-not $Company) {
        try {
            $Company = Read-Host "Enter Client Company Name"
        } catch {}
    }

    if (-not $Company) { 
        Write-Warning "Usage: Install-ScreenConnect -Company 'Client Name'"
        return 
    }
    
    # 2. Setup - Switch to MSI for reliability
    $encodedComp = $Company -replace ' ', '%20'
    $url = "https://aerosgroup.screenconnect.com/Bin/ScreenConnect.ClientSetup.msi?e=Access&y=Guest&c=$encodedComp"
    $dest = "$env:TEMP\scsetup.msi"
    
    Write-Host "Downloading MSI for '$Company'..." -ForegroundColor Cyan
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $url -OutFile $dest -ErrorAction Stop
        
        # 3. Validation: Check if we actually got a file (and not a 1KB HTML error page)
        if ((Get-Item $dest).Length -lt 100KB) {
            throw "Download too small. Likely an error page or bad URL."
        }
        
        # 4. Install via msiexec
        Write-Host "Installing..." -ForegroundColor Cyan
        $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$dest`" /qn" -Wait -PassThru
        
        if ($proc.ExitCode -eq 0) {
            Write-Host "Success! ScreenConnect installed." -ForegroundColor Green
        } else {
            Write-Error "Installer exited with code $($proc.ExitCode)."
        }
    } catch {
        Write-Error "Failed: $($_.Exception.Message)"
    }
}

function Dell-CommandUpdate {
    <# .SYNOPSIS Installs & Runs Dell Command Update #>
    Write-Host "--- DELL COMMAND UPDATE ---" -ForegroundColor Cyan
    if ((Get-CimInstance Win32_ComputerSystem).Manufacturer -notmatch "Dell") { Write-Warning "Not a Dell."; return }
    
    $path = "C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe"
    if (-not (Test-Path $path)) {
        Write-Host "Installing DCU..." -ForegroundColor Yellow
        # Insert your DCU download URL here if available, or rely on Choco
        choco install dellcommandupdate
    }
    if (Test-Path $path) {
        Write-Host "Scanning for updates..." -ForegroundColor Yellow
        Start-Process -FilePath $path -ArgumentList "/scan" -Wait
        Write-Host "Applying updates..." -ForegroundColor Green
        Start-Process -FilePath $path -ArgumentList "/applyUpdates" -Wait
    }
}

function Invoke-SystemPrep {
    <# .SYNOPSIS Formerly 'CyberCNSMasterFix'. General cleanup/hardening. #>
    Write-Host "--- SYSTEM PREP & HARDENING ---" -ForegroundColor Cyan
    
    # 1. Disable PowerShell v2
    Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart -ErrorAction SilentlyContinue
    
    # 2. Cleanup Old Frameworks
    Write-Host "Removing Silverlight/AdobeAir..."
    Get-Package -Name *SilverLight* -ErrorAction SilentlyContinue | Uninstall-Package
    if (Test-Path "C:\Program Files (x86)\Common Files\Adobe AIR") { Remove-Item "C:\Program Files (x86)\Common Files\Adobe AIR" -Recurse -Force -ErrorAction SilentlyContinue }

    # 3. Unquoted Path Fix (Simplified)
    Write-Host "Fixing Unquoted Service Paths..."
    Get-WmiObject Win32_Service | Where-Object { $_.PathName -notmatch '^"' -and $_.PathName -match '\s' -and $_.PathName -match '.exe' } | ForEach-Object {
        $newPath = "`"$($_.PathName)`""
        $path = "HKLM:\SYSTEM\CurrentControlSet\Services\$($_.Name)"
        Set-ItemProperty -Path $path -Name "ImagePath" -Value $newPath -ErrorAction SilentlyContinue
    }
}

function Set-Windows11Ui {
    <# .SYNOPSIS Enforces classic Context Menu and Left Align Taskbar #>
    Write-Host "--- WINDOWS 11 UI TWEAKS ---" -ForegroundColor Cyan
    # Restore Right Click
    New-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Force | Out-Null
    Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Name "(default)" -Value "" -Force
    # Left Align Taskbar
    $tbKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    if (Test-Path $tbKey) { Set-ItemProperty -Path $tbKey -Name "TaskbarAl" -Value 0 -Type DWord -Force }
    Write-Host "Tweaks applied. Restart Explorer to see changes." -ForegroundColor Yellow
    if ((Read-Host "Restart Explorer now? (y/n)") -eq 'y') { Stop-Process -Name explorer }
}

# ==============================================================================
#  SECTION 3: SECURITY (Merged)
# ==============================================================================

function Enable-BitLocker {
    <# .SYNOPSIS Your preferred method (Registry Escrow) #>
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

function Enforce-SMB {
    <# .SYNOPSIS Disables LLMNR/NetBIOS, Enforces SMB Signing #>
    Write-Host "--- SMB HARDENING ---" -ForegroundColor Cyan
    # Disable LLMNR
    $key = "HKLM:\Software\policies\Microsoft\Windows NT\DNSClient"
    if (-not (Test-Path $key)) { New-Item $key -Force | Out-Null }
    Set-ItemProperty -Path $key -Name "EnableMulticast" -Value 0 -Type DWORD -Force
    # SMB Signing
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManWorkstation\Parameters" -Name "EnableSecuritySignature" -Value 1 -Type DWORD -Force
    Write-Host "LLMNR Disabled & SMB Signing Enforced." -ForegroundColor Green
}

# ==============================================================================
#  SECTION 4: MAINTENANCE & CLEANUP
# ==============================================================================

function Set-Power {
    <# .SYNOPSIS High Perf + Disable Sleep #>
    Write-Host "--- POWER ENFORCE ---" -ForegroundColor Cyan
    powercfg /s 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c # High Perf
    powercfg /change monitor-timeout-ac 20
    powercfg /change standby-timeout-ac 0
    powercfg /h off
    Write-Host "High Performance Applied. Sleep Disabled." -ForegroundColor Green
}

function Uninstall-CyberCNS {
    <# .SYNOPSIS Your preferred Nuclear Uninstall #>
    Write-Host "--- REMOVING CYBERCNS AGENT ---" -ForegroundColor Magenta
    $services = @("cybercnsagent", "cybercnsagentv2", "cybercnsagentmonitor")
    foreach ($s in $services) {
        Stop-Service $s -ErrorAction SilentlyContinue
        sc.exe delete $s | Out-Null
        Write-Host "Removed Service: $s"
    }
    Remove-Item "C:\Program Files (x86)\CyberCNSAgent" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Files Deleted." -ForegroundColor Green
}

function Get-OfficeAudit {
    <# 
    .SYNOPSIS 
        Advanced Office & Outlook Auditor (Exact port of oochk.ps1).
        - Full Hive Mounting for Accounts.
        - OneDrive & NST/OST/PST Path Discovery.
        - "OwnerApp" logic (Classic vs New Outlook).
        - Formatted Output (GB/MB).
    #>
    param(
        [switch]$AllUsers = $true,
        [string[]]$Extensions = @('pst','ost','nst'),
        [switch]$Csv,
        [string]$Output = "$env:TEMP\OutlookDataFiles.csv"
    )

    # --- HELPER FUNCTIONS (Preserved Exact Logic) ---

    function Get-OutlookNameFromVersion {
        param([string]$VersionString)
        if (-not $VersionString) { return $null }
        $major = ($VersionString -split '\.')[0]
        switch ($major) {
            '16' { return 'Outlook 2016/2019/2021/2024/Microsoft 365 (Office 16.x)' }
            '15' { return 'Outlook 2013 (Office 15.x)' }
            '14' { return 'Outlook 2010 (Office 14.x)' }
            default { return "Outlook (unknown mapping, version $VersionString)" }
        }
    }

    function Test-OutlookNewGlobal {
        $pkg = $null; $pkgAll = $null; $prov = $null
        try { $pkg = Get-AppxPackage -Name 'Microsoft.OutlookForWindows' -ErrorAction SilentlyContinue | Select-Object -First 1 } catch {}
        try { $pkgAll = Get-AppxPackage -AllUsers -Name 'Microsoft.OutlookForWindows' -ErrorAction SilentlyContinue | Select-Object -First 1 } catch {}
        try { $prov = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like '*OutlookForWindows*' } | Select-Object -First 1 } catch {}
        
        $shimPaths = @("$env:ProgramFiles\Microsoft Office\root\Office16\NewOutlook.exe", "$env:ProgramFiles(x86)\Microsoft Office\root\Office16\NewOutlook.exe")
        $shimPath = $shimPaths | Where-Object { Test-Path $_ } | Select-Object -First 1
        
        $present = [bool]($pkg -or $pkgAll -or $prov -or $shimPath)
        return [pscustomobject]@{ Type='New Outlook (Store app)'; Present=$present; PackageFull=if ($pkgAll) { $pkgAll.PackageFullName } elseif ($pkg) { $pkg.PackageFullName } else { $null } }
    }

    function Get-OfficeSkuClassification {
        param([Parameter(Mandatory)][string[]]$Ids)
        $matched = @()
        foreach ($id in $Ids) {
            $family = $null; $year = $null; $license = $null
            if ($id -match '^(O365|Microsoft365|O365ProPlusRetail|O365BusinessRetail)') { $family = 'M365 Apps'; $license = 'Subscription' }
            elseif ($id -match '2024.*Retail|2024.*Volume|LTSC2024') { $family = 'Office'; $year = '2024'; $license = 'Perpetual' }
            elseif ($id -match '2021.*Retail|2021.*Volume|LTSC2021') { $family = 'Office'; $year = '2021'; $license = 'Perpetual' }
            elseif ($id -match '2019.*Retail|2019.*Volume') { $family = 'Office'; $year = '2019'; $license = 'Perpetual' }
            elseif ($id -match '(^|,|\s)(ProPlusRetail|ProfessionalRetail|StandardRetail|HomeBusinessRetail|HomeStudentRetail)(\s|,|$)') { $family = 'Office'; $year = '2016'; $license = 'Perpetual' }
            $matched += [pscustomobject]@{ ProductReleaseId = $id; Family = $family; Year = $year; License = $license }
        }
        $families = ($matched | Where-Object Family | Select-Object -ExpandProperty Family) | Sort-Object -Unique
        $years    = ($matched | Where-Object Year   | Select-Object -ExpandProperty Year)   | Sort-Object -Unique
        $familySummary = if ($families -contains 'M365 Apps') { 'Microsoft 365 Apps' } elseif ($years -contains '2024') { 'Office 2024' } elseif ($years -contains '2021') { 'Office 2021' } elseif ($years -contains '2019') { 'Office 2019' } elseif ($years -contains '2016') { 'Office 2016' } else { 'Unknown/Other' }
        [pscustomobject]@{ MatchedSKUs = $matched; FamilySummary = $familySummary }
    }

    function Get-OfficeLifecycleInfo {
        param([string]$ProductKey)
        switch ($ProductKey) {
            'M365'       { [pscustomobject]@{ Name='Microsoft 365 Apps'; Policy='Modern Lifecycle'; EOS=$null } }
            'Office2024' { [pscustomobject]@{ Name='Office 2024';       Policy='Modern Lifecycle'; EOS=[datetime]'2029-10-09' } }
            'Office2021' { [pscustomobject]@{ Name='Office 2021';       Policy='Modern Lifecycle'; EOS=[datetime]'2026-10-13' } }
            'Office2019' { [pscustomobject]@{ Name='Office 2019';       Policy='Fixed';            EOS=[datetime]'2025-10-14' } }
            'Office2016' { [pscustomobject]@{ Name='Office 2016';       Policy='Fixed';            EOS=[datetime]'2025-10-14' } }
            'Office2013' { [pscustomobject]@{ Name='Office 2013';       Policy='Fixed';            EOS=[datetime]'2023-04-11' } }
            'Office2010' { [pscustomobject]@{ Name='Office 2010';       Policy='Fixed';            EOS=[datetime]'2020-10-13' } }
        }
    }

    function Get-OfficeC2RInfo {
        $base = 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
        if (-not (Test-Path $base)) { return $null }
        $p = Get-ItemProperty -Path $base
        $officePlatform = switch ($p.Platform) { 'x64' { '64-bit' } 'x86' { '32-bit' } Default {'Unknown'} }
        $ids = ($p.ProductReleaseIds -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        $classification = Get-OfficeSkuClassification -Ids $ids
        
        $key = 'M365'
        if ($ids -match '2024') { $key = 'Office2024' } elseif ($ids -match '2021') { $key = 'Office2021' } elseif ($ids -match '2019') { $key = 'Office2019' } elseif ($ids -match 'HomeBusiness|ProPlus|Standard') { $key = 'Office2016' }
        $lc = Get-OfficeLifecycleInfo -ProductKey $key
        
        [pscustomobject]@{ InstallType='Click-to-Run'; Edition=$classification.FamilySummary; Platform=$officePlatform; Version=$p.ClientVersionToReport; UpdateChannel=$p.UpdateChannel; CDNBaseUrl=$p.CDNBaseUrl; ProductReleaseIds=($ids -join ', '); MatchedSKUs=$classification.MatchedSKUs; LifecycleName=$lc.Name; LifecyclePolicy=$lc.Policy; SupportEnds=$lc.EOS; SupportStatus=if($lc.EOS){"EOS: $($lc.EOS.ToString('yyyy-MM-dd'))"}else{"Supported"}; LifecycleNotes=if(!$lc.EOS){"Subscription"}else{"Perpetual"} }
    }

    function Get-OfficeMsiInfo {
        $results = @()
        foreach ($v in @('14.0','15.0','16.0')) {
            if (Test-Path "HKLM:\SOFTWARE\Microsoft\Office\$v\Outlook") {
                $results += [PSCustomObject]@{ Type='MSI (Registry)'; ProductVersion=$v; ProductName='Office (MSI) presence'; MappedName=Get-OutlookNameFromVersion $v }
            }
        }
        return $results
    }

    function Mount-UserHive {
        param($ProfilePath, $Sid, $UserName)
        $existing = "Registry::HKU\$Sid"
        if (Test-Path $existing) { return [pscustomobject]@{ Root=$existing; Loaded=$false } }
        $ntuser = Join-Path $ProfilePath 'NTUSER.DAT'
        if (-not (Test-Path $ntuser)) { return $null }
        $mountKey = "HKU\RMM_AUDIT_$($Sid -replace '[^A-Za-z0-9]','_')"
        $mountRoot = "Registry::$mountKey"
        try { 
            & reg.exe load "`"$mountKey`"" "`"$ntuser`"" 2>$null
            if (Test-Path $mountRoot) { return [pscustomobject]@{ Root=$mountRoot; Loaded=$true } }
        } catch {}
        return $null
    }

    function Unmount-UserHive {
        param($MountRoot, $Loaded)
        if ($Loaded) { 
            [GC]::Collect(); Start-Sleep -Milliseconds 100
            $null = & reg.exe unload ($MountRoot -replace '^Registry::','') 2>$null 
        }
    }

    function Get-OutlookAccountsFromMountedHive {
        param($MountRoot)
        $rows = @()
        foreach ($ver in @('16.0','15.0','14.0')) {
            $profilesBase = Join-Path $MountRoot "Software\Microsoft\Office\$ver\Outlook\Profiles"
            if (-not (Test-Path $profilesBase)) { continue }
            Get-ChildItem $profilesBase -ErrorAction SilentlyContinue | ForEach-Object {
                Get-ChildItem (Join-Path $_.PSPath '9375CFF0413111d3B88A00104B2A6676') -ErrorAction SilentlyContinue | ForEach-Object {
                    $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
                    $svc = $p.'Service Name'
                    $proto = if ($svc -eq 'MSEMS') { 'Exchange' } elseif ($svc -eq 'IMAP') { 'IMAP' } elseif ($svc -eq 'POP3') { 'POP3' } elseif ($svc -eq 'HTTP') { 'Outlook.com' } else { $null }
                    if (-not $proto) { if ($p.'001f6622') { $proto='Exchange' } elseif ($p.'IMAP Server') { $proto='IMAP' } elseif ($p.'POP3 Server') { $proto='POP3' } }
                    if (-not $proto) { return }
                    $smtp = $null
                    foreach ($n in @('SMTP Address','Email','EmailAddress','001f39fe')) { if ($p.$n) { $smtp=$p.$n; break } }
                    if (-not $smtp -and $p.'Account Name' -like '*@*') { $smtp=$p.'Account Name' }
                    if ($smtp -and $smtp -ne 'Outlook Address Book') {
                        $rows += [pscustomobject]@{ EmailAddress=$smtp; Protocol=$proto; Server=if($p.'001f6622'){$p.'001f6622'}else{$p.'SMTP Server'} }
                    }
                }
            }
        }
        return $rows
    }

    function Get-CandidateRootsForProfile {
        param($ProfileDir)
        $roots = @()
        $roots += Join-Path $ProfileDir 'Documents\Outlook Files'
        $roots += Join-Path $ProfileDir 'AppData\Local\Microsoft\Outlook'
        $roots += Join-Path $ProfileDir 'AppData\Roaming\Microsoft\Outlook'
        try { 
            Get-ChildItem -LiteralPath $ProfileDir -Directory -ErrorAction SilentlyContinue | 
            Where-Object {$_.Name -like 'OneDrive*'} | 
            ForEach-Object { $roots += (Join-Path $_.FullName 'Documents\Outlook Files') } 
        } catch {}
        return $roots | Where-Object { Test-Path $_ }
    }

    function Get-OutlookDataFiles {
        param($AllUsers, $Extensions)
        $profiles = if ($AllUsers) { Get-ChildItem 'C:\Users' -Directory | Where-Object Name -notin 'Public','Default' } else { Get-Item $env:USERPROFILE }
        $found = @()
        foreach ($prof in $profiles) {
            $roots = Get-CandidateRootsForProfile -ProfileDir $prof.FullName
            foreach ($root in $roots) {
                foreach ($ext in $Extensions) {
                    Get-ChildItem $root -Filter "*.$ext" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                        $found += [PSCustomObject]@{ UserProfile=$prof.Name; Path=$_.FullName; Extension=$_.Extension; SizeBytes=$_.Length; LastWriteTime=$_.LastWriteTime }
                    }
                }
            }
        }
        return $found
    }

    function Get-PerUserOutlookFootprints {
        param($SidMap)
        $perUser = @{}
        foreach ($p in $SidMap.Values) {
            # Attempt to check if hive is already mounted (logged on)
            $hive = "Registry::HKU\$($p.SID)"
            if (-not (Test-Path $hive)) { 
                # If not loaded, we can skip or try to load. 
                # For simplified single-pass logic (to match original script flow), we often skip unloadable hives for this toggle check 
                # OR we rely on the main Loop to check hives.
                # However, original script logic implies checking this.
                continue 
            }
            $hasClassic = (Test-Path "$hive\Software\Microsoft\Office\16.0\Outlook\Profiles")
            $newTog = (Get-ItemProperty "$hive\Software\Microsoft\Office\16.0\Outlook\Options\General" -Name UseNewOutlook -ErrorAction SilentlyContinue).UseNewOutlook
            $perUser[$p.UserName] = [pscustomobject]@{ HasClassic=$hasClassic; UseNewToggle=$newTog }
        }
        return $perUser
    }

    # --- MAIN EXECUTION ---
    
    Write-Host "--- OFFICE & OUTLOOK AUDIT ---" -ForegroundColor Cyan
    Write-Host "Workstation: $env:COMPUTERNAME" -ForegroundColor Green

    # 1. Install Summary
    $c2r = Get-OfficeC2RInfo
    $new = Test-OutlookNewGlobal
    if ($c2r) { 
        Write-Host "Office/Outlook Install Summary`n" -ForegroundColor Yellow
        $c2r | Format-List
        if ($new.Present) { Write-Host "New Outlook (MSIX) is also present." -ForegroundColor Yellow }
    } elseif ($new.Present) {
        Write-Host "Detected: New Outlook (Store App)" -ForegroundColor Yellow
    } else {
        $msi = Get-OfficeMsiInfo
        if ($msi) { $msi | Format-Table -AutoSize } else { Write-Host "No Office detected." -ForegroundColor Red }
    }

    # 2. Map Profiles
    $sidMap = @{}
    Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' | ForEach-Object {
        $path = (Get-ItemProperty $_.PSPath).ProfileImagePath
        if ($path -and (Test-Path $path)) {
            $u = Split-Path $path -Leaf
            if ($u -notin 'Public','Default','systemprofile','LocalService','NetworkService') {
                $sidMap[$_.PSChildName] = [pscustomobject]@{ SID=$_.PSChildName; UserName=$u; ProfilePath=$path }
            }
        }
    }

    # 3. Email Accounts (Hive Mount)
    Write-Host "`nOutlook Email Accounts (Correlated by User)" -ForegroundColor Yellow
    $footprints = @{} 
    
    foreach ($entry in $sidMap.Values) {
        $mount = Mount-UserHive -ProfilePath $entry.ProfilePath -Sid $entry.SID -UserName $entry.UserName
        if ($mount) {
            # Capture Toggle State while hive is mounted
            $keyBase = "$($mount.Root)\Software\Microsoft\Office\16.0\Outlook"
            $hasProfiles = (Test-Path "$keyBase\Profiles")
            $newTog = (Get-ItemProperty "$keyBase\Options\General" -Name UseNewOutlook -ErrorAction SilentlyContinue).UseNewOutlook
            $footprints[$entry.UserName] = [pscustomobject]@{ HasClassic=$hasProfiles; UseNewToggle=$newTog }

            # Get Accounts
            $accts = Get-OutlookAccountsFromMountedHive -MountRoot $mount.Root
            if ($accts) {
                foreach ($a in ($accts | Select-Object -Unique EmailAddress, Protocol, Server)) {
                    Write-Host "  $($entry.UserName) | $($a.EmailAddress) | $($a.Protocol)" -ForegroundColor Green
                }
            }
            Unmount-UserHive -MountRoot $mount.Root -Loaded $mount.Loaded
        }
    }

    # 4. Data Files & Formatting
    Write-Host "`nOutlook Data Files (Correlated by User)" -ForegroundColor Yellow
    $files = Get-OutlookDataFiles -Extensions $Extensions -AllUsers:$AllUsers
    
    $correlatedRows = @()
    foreach ($item in $files) {
        $user = $item.UserProfile
        $fp = $footprints[$user]
        
        $owner = "unknown"
        if ($fp) {
            $hasClassic = $fp.HasClassic
            $hasNew = ($fp.UseNewToggle -eq 1)
            if ($hasClassic -and $hasNew) { $owner = "Both (Toggled New)" }
            elseif ($hasClassic) { $owner = "Classic" }
            elseif ($hasNew) { $owner = "New Outlook" }
        }
        
        $sizeFormatted = ""
        if ($item.SizeBytes -gt 1GB) { $sizeFormatted = "{0:N2} GB" -f ($item.SizeBytes / 1GB) }
        elseif ($item.SizeBytes -gt 1MB) { $sizeFormatted = "{0:N2} MB" -f ($item.SizeBytes / 1MB) }
        else { $sizeFormatted = "{0:N0} KB" -f ($item.SizeBytes / 1KB) }
        $dateFormatted = $item.LastWriteTime.ToString('yyyy-MM-dd')

        $correlatedRows += [PSCustomObject]@{
            UserProfile = $user
            OwnerApp    = $owner
            Size        = $sizeFormatted
            DateModified = $dateFormatted
            Path        = $item.Path
        }
    }

    if ($correlatedRows) {
        $correlatedRows | Sort-Object DateModified -Descending | Format-Table UserProfile, OwnerApp, @{N="Size";E={$_.Size};Align="Right"}, @{N="Date Modified";E={$_.DateModified}}, Path -AutoSize -Wrap
        if ($Csv) { $correlatedRows | Export-Csv -Path $Output -NoTypeInformation; Write-Host "`nExported to $Output" -ForegroundColor Gray }
    } else {
        Write-Host "No data files found." -ForegroundColor Gray
    }
}


# ==============================================================================
#  MASTER MENU
# ==============================================================================

function Start-Aeros {
    while ($true) {
        Clear-Host
        Write-Host "╔═══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "║               AEROS MASTER TOOLKIT v1.0               ║" -ForegroundColor Cyan
        Write-Host "╚═══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
        
        Write-Host " [DIAGNOSTICS]" -ForegroundColor Yellow
        Write-Host "  1.  System Health (Storage/Boot)   5.  User Profiles"
        Write-Host "  2.  RAM & Slots                    6.  Battery/UPS"
        Write-Host "  3.  Network Drives                 7.  Printers"
        Write-Host "  4.  Outlook/Office Audit"
        
        Write-Host "`n [DEPLOYMENT & SETUP]" -ForegroundColor Yellow
        Write-Host "  10. Install Basic Apps (Choco)     12. Dell Command Update"
        Write-Host "  11. Install ScreenConnect          13. Windows 11 UI Fixes"
        Write-Host "                                     14. Invoke System Prep"
        
        Write-Host "`n [SECURITY & HARDENING]" -ForegroundColor Yellow
        Write-Host "  20. Enforce BitLocker (RegKey)     21. Enforce SMB/LLMNR"
        
        Write-Host "`n [MAINTENANCE]" -ForegroundColor Yellow
        Write-Host "  30. Set High Performance Power     31. Uninstall CyberCNS"
        
        Write-Host "`n Q. Quit" -ForegroundColor DarkCyan
        
        $sel = Read-Host "`n Command"
        
        switch ($sel) {
            '1'  { Get-SystemHealth; pause }
            '2'  { Get-RAMReport; pause }
            '3'  { Get-Drives; pause }
            '4'  { Get-OfficeAudit; pause}
            '5'  { Get-Users; pause }
            '6'  { Get-Battery; pause }
            '7'  { Get-AerosPrinters; pause } # Ensure wrapper function exists or use inline
            
            '10' { Install-BasicApps; pause }
            '11' { Install-ScreenConnect; pause }
            '12' { Dell-CommandUpdate; pause }
            '13' { Set-Windows11Ui; pause }
            '14' { Invoke-SystemPrep; pause }
            
            '20' { Enable-BitLocker; pause }
            '21' { Enforce-SMB; pause }
            
            '30' { Set-Power; pause }
            '31' { Uninstall-CyberCNS; pause }
            
            'Q'  { return }
            'q'  { return }
        }
    }
}
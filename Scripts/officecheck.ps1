<# 
.SYNOPSIS
    outlook_office_audit_final.ps1
    Runs from SYSTEM (RMM) to audit all user profiles.
    1.  Prints Workstation and Primary User at the top.
    2.  Detects Office C2R (with SKU/Lifecycle) and MSI installs.
    3.  Detects "New Outlook" (MSIX).
    4.  Finds all user email accounts (Exchange/IMAP/POP3) by loading NTUSER.DAT hives.
    5.  Finds all PST/OST/NST files with size and modification date.
    6.  Correlates files to the user's primary app (Classic vs. New).
#>

[CmdletBinding()]
param(
    [switch]$AllUsers = $true, # Kept for consistency, but new account logic always scans all
    [string[]]$Extensions = @('pst','ost','nst'),
    [switch]$Csv,
    [string]$Output = "$env:TEMP\OutlookDataFiles.csv"
)

#region Helper Functions
# -----------------------------
# Helper: Outlook Version Mapping
# -----------------------------
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

# --- NEW HELPER: Decodes Registry Binary Values ---
function Convert-RegValueToString {
    param($Value)
    if ($Value -is [string]) {
        return $Value
    }
    if ($Value -is [byte[]]) {
        try {
            # Try to decode as Unicode (UTF-16 LE), trimming null terminators
            return [System.Text.Encoding]::Unicode.GetString($Value).TrimEnd([char]0)
        } catch {
            return $null # Failed to decode
        }
    }
    return $null
}
#endregion

#region Machine-Wide Install Detection
# -----------------------------
# Outlook Flavor Detectors (Machine-Wide)
# -----------------------------
function Test-OutlookNewGlobal {
    $pkg = $null
    $pkgAll = $null
    $prov = $null
    try { $pkg = Get-AppxPackage -Name 'Microsoft.OutlookForWindows' -ErrorAction SilentlyContinue | Select-Object -First 1 } catch {}
    try { $pkgAll = Get-AppxPackage -AllUsers -Name 'Microsoft.OutlookForWindows' -ErrorAction SilentlyContinue | Select-Object -First 1 } catch {}
    if (-not $pkg -and -not $pkgAll) {
        try { $pkgAll = Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '*OutlookForWindows*' } | Select-Object -First 1 } catch {}
    }
    try { $prov = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like '*OutlookForWindows*' } | Select-Object -First 1 } catch {}
    $shimPaths = @(
        "$env:ProgramFiles\Microsoft Office\root\Office16\NewOutlook.exe",
        "$env:ProgramFiles(x86)\Microsoft Office\root\Office16\NewOutlook.exe"
    )
    $shimPath = $shimPaths | Where-Object { Test-Path $_ } | Select-Object -First 1
    $present = [bool]($pkg -or $pkgAll -or $prov -or $shimPath)
    return [pscustomobject]@{
        Type           = 'New Outlook (Store app)'
        Present        = $present
        PackageFull    = if ($pkgAll) { $pkgAll.PackageFullName } elseif ($pkg) { $pkg.PackageFullName } else { $null }
    }
}

# --- C2R Sku/Lifecycle Detection ---
function Get-OfficeSkuClassification {
    param([Parameter(Mandatory)][string[]]$Ids)
    $matched = @()
    foreach ($id in $Ids) {
        $family = $null; $year = $null; $license = $null
        if ($id -match '^(O365|Microsoft365|O365ProPlusRetail|O365BusinessRetail)') {
            $family = 'M365 Apps'; $license = 'Subscription'
        }
        elseif ($id -match '2024.*Retail|2024.*Volume|LTSC2024') {
            $family = 'Office'; $year = '2024'; $license = 'Perpetual'
        }
        elseif ($id -match '2021.*Retail|2021.*Volume|LTSC2021') {
            $family = 'Office'; $year = '2021'; $license = 'Perpetual'
        }
        elseif ($id -match '2019.*Retail|2019.*Volume') {
            $family = 'Office'; $year = '2019'; $license = 'Perpetual'
        }
        elseif ($id -match '(^|,|\s)(ProPlusRetail|ProfessionalRetail|StandardRetail|HomeBusinessRetail|HomeStudentRetail)(\s|,|$)') {
            $family = 'Office'; $year = '2016'; $license = 'Perpetual'
        }
        $matched += [pscustomobject]@{ ProductReleaseId = $id; Family = $family; Year = $year; License = $license }
    }
    $families = ($matched | Where-Object Family | Select-Object -ExpandProperty Family) | Sort-Object -Unique
    $years    = ($matched | Where-Object Year   | Select-Object -ExpandProperty Year)   | Sort-Object -Unique
    $isM365 = $families -contains 'M365 Apps'; $is2016 = $years -contains '2016'; $is2019 = $years -contains '2019'; $is2021 = $years -contains '2021'; $is2024 = $years -contains '2024'
    $familySummary =
        if     ($isM365) { 'Microsoft 365 Apps' }
        elseif ($is2024) { 'Office 2024 (Perpetual)' }
        elseif ($is2021) { 'Office 2021 (Perpetual/LTSC)' }
        elseif ($is2019) { 'Office 2019 (Perpetual)' }
        elseif ($is2016) { 'Office 2016 (Perpetual C2R)' }
        else             { 'Unknown/Other' }
    [pscustomobject]@{ MatchedSKUs = $matched; FamilySummary = $familySummary }
}

function Get-OfficeLifecycleInfo {
    param([Parameter(Mandatory)][ValidateSet('M365','Office2016','Office2019','Office2021','Office2024','Office2013','Office2010')][string]$ProductKey)
    switch ($ProductKey) {
        'M365'       { [pscustomobject]@{ Name='Microsoft 365 Apps'; Policy='Modern Lifecycle (continuous)'; EOS=$null;              Notes='Subscription; serviced while in support.' } }
        'Office2024' { [pscustomobject]@{ Name='Office 2024';       Policy='Modern Lifecycle (5 years, no extended)'; EOS=[datetime]'2029-10-09'; Notes='Home & Business/Home editions' } }
        'Office2021' { [pscustomobject]@{ Name='Office 2021';       Policy='Modern Lifecycle (5 years, no extended)'; EOS=[datetime]'2026-10-13'; Notes='Home & Business/Home/Professional' } }
        'Office2019' { [pscustomobject]@{ Name='Office 2019';       Policy='Fixed (5 + 2)';                         EOS=[datetime]'2025-10-14'; Notes='Support ended Oct 14, 2025' } }
        'Office2016' { [pscustomobject]@{ Name='Office 2016';       Policy='Fixed (5 + 5)';                         EOS=[datetime]'2025-10-14'; Notes='Support ended Oct 14, 2025' } }
        'Office2013' { [pscustomobject]@{ Name='Office 2013';       Policy='Fixed (5 + 5)';                         EOS=[datetime]'2023-04-11'; Notes='Unsupported' } }
        'Office2010' { [pscustomobject]@{ Name='Office 2010';       Policy='Fixed (5 + 5)';                         EOS=[datetime]'2020-10-13'; Notes='Unsupported' } }
    }
}

function Add-LifecycleSummary {
    param([Parameter(Mandatory)] [pscustomobject]$OfficeInfo, [Parameter(Mandatory)] [string[]]$Ids)
    if (-not $OfficeInfo) { return $null }
    if     ($OfficeInfo.Edition -like 'Microsoft 365*') { $key = 'M365' }
    elseif ($OfficeInfo.Edition -like 'Office 2024*')   { $key = 'Office2024' }
    elseif ($OfficeInfo.Edition -like 'Office 2021*')   { $key = 'Office2021' }
    elseif ($OfficeInfo.Edition -like 'Office 2019*')   { $key = 'Office2019' }
    elseif ($OfficeInfo.Edition -like 'Office 2016*')   { $key = 'Office2016' }
    else {
        if     ($Ids -match '2024') { $key = 'Office2024' }
        elseif ($Ids -match '2021') { $key = 'Office2021' }
        elseif ($Ids -match '2019') { $key = 'Office2019' }
        elseif ($Ids -match 'HomeBusinessRetail|ProPlusRetail|ProfessionalRetail|StandardRetail') { $key = 'Office2016' }
        else   { $key = 'M365' }
    }
    $lc = Get-OfficeLifecycleInfo -ProductKey $key
    $today = Get-Date
    $supportEnds = $null
    $status = 'In support (subscription)'
    if ($lc.EOS) {
        $supportEnds = $lc.EOS.ToString('yyyy-MM-dd')
        $daysLeft = [math]::Floor(($lc.EOS - $today).TotalDays)
        if     ($daysLeft -lt 0)   { $status = 'Unsupported' }
        elseif ($daysLeft -le 180) { $status = "Nearing EOL ($daysLeft days left)" }
        else                       { $status = "Supported ($daysLeft days left)" }
    }
    Add-Member -InputObject $OfficeInfo -NotePropertyName LifecycleName   -NotePropertyValue $lc.Name     -Force
    Add-Member -InputObject $OfficeInfo -NotePropertyName LifecyclePolicy -NotePropertyValue $lc.Policy   -Force
    Add-Member -InputObject $OfficeInfo -NotePropertyName SupportEnds     -NotePropertyValue $supportEnds -Force
    Add-Member -InputObject $OfficeInfo -NotePropertyName SupportStatus   -NotePropertyValue $status      -Force
    Add-Member -InputObject $OfficeInfo -NotePropertyName LifecycleNotes  -NotePropertyValue $lc.Notes    -Force
    return $OfficeInfo
}

function Get-OfficeC2RInfo {
    $base = 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
    if (-not (Test-Path $base)) { return $null }
    $p = Get-ItemProperty -Path $base
    $ids = ($p.ProductReleaseIds -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    $classification = Get-OfficeSkuClassification -Ids $ids
    $info = [pscustomobject]@{
        InstallType       = 'Click-to-Run'
        Edition           = $classification.FamilySummary
        Version           = $p.ClientVersionToReport
        UpdateChannel     = $p.UpdateChannel
        CDNBaseUrl        = $p.CDNBaseUrl
        ProductReleaseIds = ($ids -join ', ')
        MatchedSKUs       = $classification.MatchedSKUs
    }
    $info = Add-LifecycleSummary -OfficeInfo $info -Ids $ids
    return $info
}

# --- Fallback: MSI/Legacy Detection ---
function Get-OfficeMsiInfo {
    $results = @()
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\OUTLOOK.EXE',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\OUTLOOK.EXE'
    )
    $items = $(foreach ($key in $paths) {
        $p = Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
        if ($p -and $p.'(default)') { $p.'(default)' } elseif ($p -and $p.Path) { $p.Path }
    }) | Where-Object { $_ } | Sort-Object -Unique
    foreach ($exe in $items) {
        if (Test-Path -LiteralPath $exe) {
            try {
                $fv = (Get-Item $exe).VersionInfo
                $results += [PSCustomObject]@{ Type = 'Outlook Classic (AppPath)'; ExecutablePath = $exe; ProductVersion = $fv.ProductVersion; ProductName = $fv.ProductName; MappedName = Get-OutlookNameFromVersion $fv.ProductVersion }
            } catch {
                $results += [PSCustomObject]@{ Type = 'Outlook Classic (AppPath)'; ExecutablePath = $exe; ProductVersion = 'N/A'; ProductName = 'Error reading version'; MappedName = $null }
            }
        }
    }
    $uninstallPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    try {
        $apps = Get-ItemProperty -Path $uninstallPaths -ErrorAction SilentlyContinue
        foreach ($app in $apps) {
            if ($app.PSObject.Properties.Name -contains 'DisplayName') {
                $name = $app.DisplayName
                if ($name -like '*Microsoft Office*' -and $name -match '2010|2013|2016|2019|2021|2024') {
                     $results += [PSCustomObject]@{ Type = 'MSI (Uninstall Key)'; ExecutablePath = $app.InstallLocation; ProductVersion = $app.DisplayVersion; ProductName = $name; MappedName = $name }
                }
            }
        }
    } catch { }
    foreach ($v in @('14.0','15.0','16.0')) {
        $msi = Get-Item -LiteralPath "HKLM:\SOFTWARE\Microsoft\Office\$v\Outlook" -ErrorAction SilentlyContinue
        $msiWow = Get-Item -LiteralPath "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\$v\Outlook" -ErrorAction SilentlyContinue
        if ($msi -or $msiWow) {
            $results += [PSCustomObject]@{ Type = 'MSI Footprint (Registry)'; ExecutablePath = $null; ProductVersion = $v; ProductName = 'Office (MSI) presence'; MappedName = Get-OutlookNameFromVersion $v }
        }
    }
    if ($results) { return $results | Sort-Object ProductName, Type -Unique }
    else { return $null }
}
#endregion

#region Per-User Logic (RMM Safe)
# -------------------------------------
# Per-User Correlation Logic (File Owner)
# -------------------------------------
function Get-PerUserOutlookFootprints {
    param([Parameter(Mandatory)][object[]]$ProfileSidMap)
    $perUser = @{}
    foreach ($p in $ProfileSidMap.Values) {
        # Check if the user's hive is loaded (it should be)
        $hiveRoot = "Registry::HKU\$($p.SID)"
        if (-not (Test-Path $hiveRoot)) {
            # This can happen if the hive failed to load, skip this user
            continue
        }

        if ($p.UserName -in @('Public','Default','Default User','All Users','defaultuser0','WDAGUtilityAccount')) { continue }
        
        $versions = @()
        foreach ($v in @('14.0','15.0','16.0')) {
            $key = "$hiveRoot\Software\Microsoft\Office\$v\Outlook\Profiles"
            if (Test-Path -LiteralPath $key) { $versions += $v }
        }
        
        $newOutlook = $false
        try {
            $appxRegPath = "$hiveRoot\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages"
            if (Test-Path $appxRegPath) {
                if (Get-ChildItem $appxRegPath -Name -ErrorAction SilentlyContinue | Where-Object { $_ -like '*Microsoft.OutlookForWindows*' }) {
                    $newOutlook = $true
                }
            }
        } catch { }
        
        $classicToggleKey = "$hiveRoot\Software\Microsoft\Office\16.0\Outlook\Options\General"
        $useNewOutlook = $null 
        if (Test-Path -LiteralPath $classicToggleKey) {
            try {
                $useNewOutlook = (Get-ItemProperty -LiteralPath $classicToggleKey -Name 'UseNewOutlook' -ErrorAction SilentlyContinue).UseNewOutlook
            } catch {}
        }
        
        $perUser[$p.UserName] = [pscustomobject]@{ 
            SID = $p.SID
            Versions = $versions
            HasNewOutlook = $newOutlook
            UsingNewOutlookToggle = $useNewOutlook 
        }
    }
    $perUser
}

# --- RMM-Safe Account Enumeration (via Hive Loading) ---

function Mount-UserHive {
    param(
        [Parameter(Mandatory)][string]$ProfilePath,
        [Parameter(Mandatory)][string]$Sid,
        [Parameter(Mandatory)][string]$UserName
    )
    $existing = "Registry::HKU\$Sid"
    if (Test-Path $existing) {
        return [pscustomobject]@{ Root = $existing; Loaded = $false }
    }
    $ntuser = Join-Path $ProfilePath 'NTUSER.DAT'
    if (-not (Test-Path $ntuser)) { return $null }
    
    $mountKey = "HKU\RMM_AUDIT_$($Sid -replace '[^A-Za-z0-9]','_')"
    $mountRoot = "Registry::$mountKey"

    try {
        & reg.exe unload "`"$mountKey`"" 2>$null
        & reg.exe load "`"$mountKey`"" "`"$ntuser`"" 2>$null
        if (Test-Path $mountRoot) {
            return [pscustomobject]@{ Root = $mountRoot; Loaded = $true }
        }
    } catch {
        $errMsg = $_.Exception.Message
        #Write-Warning "Failed to load hive ${ntuser}: $errMsg"
    }
    return $null
}

function Unmount-UserHive {
    param([Parameter(Mandatory)][string]$MountRoot, [Parameter(Mandatory)][bool]$Loaded)
    if (-not $Loaded) { return } 
    try {
        [GC]::Collect() 
        Start-Sleep -Milliseconds 100
        $null = & reg.exe unload ($MountRoot -replace '^Registry::','') 2>$null
    } catch {
        #Write-Warning "Failed to unload hive $MountRoot. It may be in use. $($_.Exception.Message)"
    }
}

function Get-OutlookAccountsFromMountedHive {
    param([Parameter(Mandatory)][string]$MountRoot)

    $versions = @('16.0','15.0','14.0') 
    $rows = @()

    foreach ($ver in $versions) {
        $profilesBase = Join-Path $MountRoot "Software\Microsoft\Office\$ver\Outlook\Profiles"
        if (-not (Test-Path $profilesBase)) { continue }

        Get-ChildItem $profilesBase -ErrorAction SilentlyContinue | ForEach-Object {
            $profileKey = $_.PSPath
            $acctContainer = Join-Path $profileKey '9375CFF0413111d3B88A00104B2A6676'
            if (-not (Test-Path $acctContainer)) { return }

            Get-ChildItem $acctContainer -ErrorAction SilentlyContinue | ForEach-Object {
                $acctKeyPath = $_.PSPath
                try { $p = Get-ItemProperty -LiteralPath $acctKeyPath -ErrorAction Stop } catch { return }

                # --- Protocol Detection (Handles REG_BINARY) ---
                $protocol = $null
                $server = $null
                $svc = Convert-RegValueToString -Value $p.'Service Name' # Check for Service Name first
                
                if ($svc -eq 'MSEMS') {
                    $protocol = 'Exchange'
                    $server = Convert-RegValueToString -Value $p.'001f6622' # Exchange Server DN
                } elseif ($svc -eq 'IMAP') {
                     $protocol = 'IMAP'
                     $server = Convert-RegValueToString -Value $p.'IMAP Server'
                     if (-not $server) { $server = Convert-RegValueToString -Value $p.'001f3a21' }
                } elseif ($svc -eq 'POP3') {
                    $protocol = 'POP3'
                    $server = Convert-RegValueToString -Value $p.'POP3 Server'
                    if (-not $server) { $server = Convert-RegValueToString -Value $p.'001f3a1f' }
                } elseif ($svc -eq 'HTTP' -or (Convert-RegValueToString -Value $p.'Account Type') -eq 'http') {
                    $protocol = 'Outlook.com/Hotmail'
                    $server = Convert-RegValueToString -Value $p.'001f3a28' # HTTP Server URL
                }
                
                # --- Fallback: Check for server keys if ServiceName was not present/useful ---
                if (-not $protocol) {
                    if (Convert-RegValueToString -Value $p.'001f6622') { # Exchange Server DN
                        $protocol = 'Exchange'
                        $server = Convert-RegValueToString -Value $p.'001f6622'
                    } elseif (Convert-RegValueToString -Value $p.'001f3a21') { # IMAP Server
                        $protocol = 'IMAP'
                        $server = Convert-RegValueToString -Value $p.'IMAP Server'
                        if (-not $server) { $server = Convert-RegValueToString -Value $p.'001f3a21' }
                    } elseif (Convert-RegValueToString -Value $p.'001f3a1f') { # POP3 Server
                        $protocol = 'POP3'
                        $server = Convert-RegValueToString -Value $p.'POP3 Server'
                        if (-not $server) { $server = Convert-RegValueToString -Value $p.'001f3a1f' }
                    }
                }

                # --- FILTER 1: If we *still* couldn't find a protocol, it's not a mail account. ---
                if (-not $protocol) { return }

                # --- Get Email Address (Handles REG_BINARY) ---
                $smtp = $null
                foreach ($n in @('SMTP Address','Smtp Address','Email','EmailAddress', '001f39fe')) {
                    if ($p.PSObject.Properties.Name -contains $n) { 
                        $smtp = Convert-RegValueToString -Value $p.$n
                        if ($smtp) { break }
                    }
                }
                if (-not $smtp) {
                    $name = $null
                    foreach ($n in @('Account Name','AccountName')) {
                        if ($p.PSObject.Properties.Name -contains $n) {
                           $name = Convert-RegValueToString -Value $p.$n
                           if ($name -like '*@*') { $smtp = $name; break }
                        }
                    }
                }
                if (-not $smtp) { 
                    $name = Convert-RegValueToString -Value $p.'Account Name'
                    if ($name) { $smtp = $name } # Final fallback
                }
                
                if (-not $smtp -or $smtp -eq 'Outlook Address Book') { return }

                # --- Get SMTP Server (for non-Exchange) (Handles REG_BINARY) ---
                if ($protocol -ne 'Exchange') {
                    $smtpServer = $null
                    foreach ($n in @('SMTP Server', '001f6740')) {
                         if ($p.PSObject.Properties.Name -contains $n) {
                            $smtpServer = Convert-RegValueToString -Value $p.$n
                            if ($smtpServer) { break }
                         }
                    }
                    
                    if ($smtpServer) {
                        if ($server -and $server -ne $smtpServer) { $server = "$server (SMTP: $smtpServer)" }
                        elseif (-not $server) { $server = $smtpServer }
                    }
                }
                # --- End Get Server ---

                $rows += [pscustomobject]@{
                    Profile     = (Split-Path $profileKey -Leaf)
                    EmailAddress= $smtp
                    Protocol    = $protocol
                    Server      = $server
                }
            }
        }
    }
    return $rows
}

# --- All-users wrapper: RMM-safe ---
function Get-OutlookAccountsAllUsers {
    $profileList = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    $rows = @()
    
    # Get all SIDs first
    $allSids = Get-ChildItem $profileList -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSChildName
    
    # Create a simple mapping of SID to UserName
    $sidMap = @{}
    
    foreach ($sid in $allSids) {
        try { $props = Get-ItemProperty -LiteralPath (Join-Path $profileList $sid) -ErrorAction Stop } catch { continue }
        $profilePath = $props.ProfileImagePath
        if (-not $profilePath) { continue }
        $leaf = Split-Path $profilePath -Leaf
        if ($leaf -in @('Default','Default User','All Users','Public','systemprofile','LocalService','NetworkService','defaultuser0','WDAGUtilityAccount')) { continue }
        if (-not (Test-Path $profilePath)) { continue }
        
        $sidMap[$sid] = [pscustomobject]@{
            SID = $sid
            UserName = $leaf
            ProfilePath = $profilePath
        }
    }

    # Now mount/scan
    foreach ($entry in $sidMap.Values) {
        $mount = Mount-UserHive -ProfilePath $entry.ProfilePath -Sid $entry.SID -UserName $entry.UserName
        if (-not $mount) {
            #Write-Warning "Could not load hive for $($entry.UserName) ($($entry.ProfilePath))"
            continue 
        }

        try {
            $userRows = Get-OutlookAccountsFromMountedHive -MountRoot $mount.Root
            foreach ($r in $userRows) {
                $rows += [pscustomobject]@{
                    UserProfile = $entry.UserName
                    EmailAddress= $r.EmailAddress
                    Protocol    = $r.Protocol
                    Server      = $r.Server
                }
            }
        } finally {
            Unmount-UserHive -MountRoot $mount.Root -Loaded:$mount.Loaded
        }
    }

    return $rows | Sort-Object UserProfile, EmailAddress, Protocol -Unique
}
#endregion

#region Data File Scanner
# ---------------------------------------
# Data File Scanner
# ---------------------------------------
function Get-CandidateRootsForProfile {
    param([Parameter(Mandatory)][string]$ProfileDir)
    $roots = @()
    $roots += Join-Path $profileDir 'Documents\Outlook Files'
    $roots += Join-Path $profileDir 'AppData\Local\Microsoft\Outlook'
    $roots += Join-Path $profileDir 'AppData\Roaming\Microsoft\Outlook'
    try {
        $oneDriveDirs = Get-ChildItem -LiteralPath $profileDir -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like 'OneDrive*' }
        foreach ($od in $oneDriveDirs) {
            $roots += (Join-Path $od.FullName 'Documents\Outlook Files')
        }
    } catch {}
    $roots += Join-Path $profileDir 'AppData\Local\Packages\Microsoft.OutlookForWindows_8wekyb3d8bbwe\LocalCache'
    $roots += Join-Path $profileDir 'AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\LocalState\Indexed\LiveComm'
    return $roots | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Container) } | Sort-Object -Unique
}

function Get-OutlookDataFiles {
    param(
        [string[]]$Extensions = @('pst','ost','nst'),
        [switch]$AllUsers = $true
    )
    $profiles = @()
    if ($AllUsers) {
        $profiles = Get-ChildItem -LiteralPath 'C:\Users' -Directory -ErrorAction Silentlycontinue |
            Where-Object { $_.Name -notin @('Public','Default','Default User','All Users','defaultuser0','WDAGUtilityAccount') } |
            Select-Object -ExpandProperty FullName
    } else {
        if ($env:USERPROFILE -and (Test-Path -LiteralPath $env:USERPROFILE)) { $profiles = @($env:USERPROFILE) }
    }
    if (-not $profiles) {
        Write-Warning "No user profiles found to scan."
        return $null
    }

    $found = New-Object System.Collections.Generic.List[object]
    foreach ($profile in $profiles) {
        $roots = Get-CandidateRootsForProfile -ProfileDir $profile
        foreach ($root in $roots) {
            foreach ($ext in $Extensions) {
                try {
                    Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue -Filter "*.$ext" |
                        ForEach-Object {
                            $found.Add([PSCustomObject]@{
                                UserProfile   = Split-Path $profile -Leaf
                                Path          = $_.FullName
                                Extension     = $_.Extension.TrimStart('.').ToLowerInvariant()
                                SizeBytes     = $_.Length
                                LastWriteTime = $_.LastWriteTime
                            })
                        }
                } catch {
                    Write-Warning "Error scanning $root : $($_.Exception.Message)"
                }
            }
        }
    }
    return $found
}
#endregion

# =====================================================================
# MAIN EXECUTION
# =====================================================================

# --- Get Profile map (needed for both Accounts and Files) ---
$profileList = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
$sidMapForFiles = @{}
Get-ChildItem $profileList -ErrorAction SilentlyContinue | ForEach-Object {
    try { 
        $sid = $_.PSChildName
        $props = Get-ItemProperty -LiteralPath $_.PsPath -ErrorAction Stop 
        $profilePath = $props.ProfileImagePath
        $leaf = Split-Path $profilePath -Leaf
        if ($leaf -and $profilePath -and (Test-Path $profilePath) -and $leaf -notin @('Default','Default User','All Users','Public','systemprofile','LocalService','NetworkService','defaultuser0','WDAGUtilityAccount')) {
             $sidMapForFiles[$sid] = [pscustomobject]@{
                SID = $sid
                UserName = $leaf
                ProfilePath = $profilePath
             }
        }
    } catch {}
}

# --- Find Files (must run *before* hive loading) ---
$foundFiles = Get-OutlookDataFiles -Extensions $Extensions -AllUsers:$AllUsers

# --- Find Most Recent User for Header ---
$primaryUser = 'N/A'
if ($foundFiles.Count -gt 0) {
    # Filter out null LastWriteTime objects just in case
    $mostRecentFile = $foundFiles | Where-Object { $_.LastWriteTime } | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($mostRecentFile) {
        $primaryUser = $mostRecentFile.UserProfile
    }
}

# --- Print Header ---
Write-Host "Workstation: $($env:COMPUTERNAME)" -ForegroundColor Green
Write-Host "Primary User: $primaryUser" -ForegroundColor Green


# 1. Detect Machine-Wide Installs
Write-Host "`n=== Office/Outlook Install Summary ===`n" -ForegroundColor Cyan
$officeInfo = Get-OfficeC2RInfo
$newOutlook = Test-OutlookNewGlobal

if ($officeInfo) {
    Add-Member -InputObject $officeInfo -NotePropertyName OutlookNewPresent -NotePropertyValue $newOutlook.Present -Force
    Add-Member -InputObject $officeInfo -NotePropertyName OutlookNewPackage -NotePropertyValue $newOutlook.PackageFull -Force
    $officeInfo | Format-List
    if ($officeInfo.MatchedSKUs) {
        $officeInfo.MatchedSKUs | Format-Table
    }
} else {
    Write-Host "No Click-to-Run (C2R) installation detected. Looking for MSI/Legacy installs..." -ForegroundColor Yellow
    $msiInfo = Get-OfficeMsiInfo
    if ($msiInfo) {
        $msiInfo | Format-Table -AutoSize
    } else {
        Write-Host "No C2R or MSI Office installations found." -ForegroundColor Red
    }
}
if ($newOutlook.Present -and !$officeInfo) {
    Write-Host "`n--- New Outlook (Standalone) ---" -ForegroundColor Cyan
    $newOutlook | Format-List Type, Present, PackageFull
}

# 2. Find and Display Email Accounts (RMM-Safe)
Write-Host "`n=== Outlook Email Accounts (Correlated by User) ===`n" -ForegroundColor Cyan
# This function loads/unloads hives, so it must run *before* Get-PerUserOutlookFootprints
$accounts = Get-OutlookAccountsAllUsers

if ($accounts.Count -eq 0) {
    Write-Host "  (No accounts found in user profile registries)"
} else {
    $accounts | Format-Table UserProfile, EmailAddress, Protocol, Server -AutoSize -Wrap
}


# 3. Find Files and Correlate by User
Write-Host "`n=== Outlook Data Files (Correlated by User) ===`n" -ForegroundColor Cyan
# Now that hives are unloaded, we can run the file correlation logic
$perUser = Get-PerUserOutlookFootprints -ProfileSidMap $sidMapForFiles
# $foundFiles is already populated from the header logic

if ($foundFiles.Count -eq 0) {
    Write-Host "  (none)"
} else {
    $correlatedRows = foreach ($item in $foundFiles) {
        $user = $item.UserProfile
        $info = $perUser[$user]
        
        $owner = 'unknown' 
        if ($info) {
            $hasClassic = ($info.Versions.Count -gt 0)
            $hasNew     = $info.HasNewOutlook
            if ($hasClassic -and $hasNew) {
                if ($info.UsingNewOutlookToggle -eq 1) { $owner = "New Outlook" }
                elseif ($info.UsingNewOutlookToggle -eq 0) { $owner = "Classic" }
                else { $owner = "Classic" }
            } elseif ($hasClassic) {
                $owner = "Classic" 
            } elseif ($hasNew) {
                $owner = "New Outlook" 
            }
        }
        
        $sizeFormatted = ""
        if ($item.SizeBytes -gt 1GB) { $sizeFormatted = "{0:N2} GB" -f ($item.SizeBytes / 1GB) }
        elseif ($item.SizeBytes -gt 1MB) { $sizeFormatted = "{0:N2} MB" -f ($item.SizeBytes / 1MB) }
        elseif ($item.SizeBytes -gt 0) { $sizeFormatted = "{0:N0} KB" -f ($item.SizeBytes / 1KB) }
        else { $sizeFormatted = "0 KB" }
        
        $dateFormatted = "N/A"
        if ($item.LastWriteTime) {
            $dateFormatted = $item.LastWriteTime.ToString('yyyy-MM-dd')
        }

        [PSCustomObject]@{
            UserProfile = $user
            OwnerApp    = $owner
            Size        = $sizeFormatted
            DateModified = $dateFormatted
            Path        = $item.Path
            Extension     = $item.Extension
            SizeBytes     = $item.SizeBytes
            LastWriteTime = $item.LastWriteTime
        }
    }
    
    $correlatedRows | Sort-Object LastWriteTime -Descending | Format-Table UserProfile, OwnerApp, @{Name="Size"; Expression={$_.Size}; Alignment="Right"}, @{Name="Date Modified"; Expression={$_.DateModified}}, Path -AutoSize -Wrap
    
    if ($Csv) {
        try {
            $correlatedRows | Sort-Object LastWriteTime -Descending | Export-Csv -NoTypeInformation -Path $Output
            Write-Host "`nCSV written to: $Output" -ForegroundColor Green
        } catch {
            Write-Warning "Failed to write CSV: $($_.Exception.Message)"
        }
    }
}

<#
.SYNOPSIS
    Aeros Master Storage Audit (Unified v5.4)
    Fixes: Added UTF-8 Output Encoding to fix "garbage" border characters.
    Safety: Uses single quotes to prevent Master Loader parsing errors.
#>

# --- FORCE UTF-8 OUTPUT FOR FANCY BORDERS ---
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# --- DISCOVERY & HEADERS ---
$cs = Get-CimInstance Win32_ComputerSystem
$isDomainJoined = [bool]$cs.PartOfDomain
$domainName = if ($isDomainJoined) { $cs.Domain } else { 'Workgroup' }
$bootTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$localAdminSid = ([System.Security.Principal.NTAccount]"$env:COMPUTERNAME\Administrator").Translate([System.Security.Principal.SecurityIdentifier]).Value
$machineSidBase = $localAdminSid -replace '-500$',''

Write-Host '╔═══════════════════════════════════════════════════════╗' -ForegroundColor Cyan
Write-Host '║           AEROS CONSOLIDATED STORAGE AUDIT            ║' -ForegroundColor Cyan
Write-Host '╚═══════════════════════════════════════════════════════╝' -ForegroundColor Cyan
Write-Host " Host: $($env:COMPUTERNAME) | Domain: $domainName | Last Boot: $bootTime" -ForegroundColor Gray

# Faster folder sizing using .NET COM object
function Get-FolderSizeGB ($path) {
    if (-not (Test-Path $path)) { return 0 }
    try {
        $objFSO = New-Object -ComObject Scripting.FileSystemObject
        $size = $objFSO.GetFolder($path).Size
        return [math]::Round($size / 1GB, 2)
    } catch { return 0 }
}

# --- SECTION 1: ACCOUNT AND PROFILE AUDIT ---
Write-Host "`n--- [SECTION 1: ACCOUNT AND PROFILE AUDIT] ---" -ForegroundColor Cyan
$localUsers = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True"
$profiles   = Get-CimInstance Win32_UserProfile | Where-Object { $_.LocalPath -like 'C:\Users\*' -and -not $_.Special }
$results = @()

foreach ($user in $localUsers) {
    $profMatch = $profiles | Where-Object { $_.SID -eq $user.SID }
    $isAdmin = 'No'
    try {
        $grp = [ADSI]"WinNT://$env:COMPUTERNAME/Administrators,group"
        foreach ($member in $grp.Members()) {
            $mPath = $member.GetType().InvokeMember('ADsPath','GetProperty',$null,$member,$null)
            if ($mPath -like "*/$($user.Name)") { $isAdmin = 'Yes'; break }
        }
    } catch {}

    $lastUsed = if ($profMatch) { $profMatch.LastUseTime } else { $null }
    $isStale = if ($lastUsed -and $lastUsed -lt (Get-Date).AddDays(-90)) { 'STALE' } else { '' }
    
    $results += [pscustomobject]@{
        Username    = $user.Name
        Domain      = 'Local'
        Admin       = $isAdmin
        Status      = if ($user.Disabled) { 'Disabled' } else { 'Enabled' }
        Size_GB     = if ($profMatch) { Get-FolderSizeGB $profMatch.LocalPath } else { 0 }
        LastUsed    = if ($lastUsed) { $lastUsed } else { 'Never' }
        Flag        = $isStale
    }
}

foreach ($prof in $profiles) {
    if ($prof.SID -notlike "$machineSidBase-*") {
        $uName = $prof.LocalPath -split '\\' | Select-Object -Last 1
        $lastUsed = $prof.LastUseTime
        $isStale = if ($lastUsed -and $lastUsed -lt (Get-Date).AddDays(-90)) { 'STALE' } else { '' }

        $results += [pscustomobject]@{
            Username    = $uName
            Domain      = $domainName
            Admin       = 'Unknown'
            Status      = 'Domain Profile'
            Size_GB     = Get-FolderSizeGB $prof.LocalPath
            LastUsed    = if ($lastUsed) { $lastUsed } else { 'Unknown' }
            Flag        = $isStale
        }
    }
}
$results | Sort-Object Size_GB -Descending | Format-Table -AutoSize

# --- SECTION 2: DEEP MAPPED DRIVE AUDIT ---
Write-Host "`n--- [SECTION 2: MAPPED DRIVES (ALL PROFILES)] ---" -ForegroundColor Cyan
$driveResults = @()
foreach ($p in $profiles) {
    $sid = $p.SID
    $ntuser = Join-Path $p.LocalPath 'NTUSER.DAT'
    $loadedRoot = "Registry::HKEY_USERS\$sid\Network"
    $tempHive   = "TempHive_$sid"
    $usingHKU = Test-Path $loadedRoot

    if (-not $usingHKU -and (Test-Path $ntuser)) { & reg.exe load "HKLM\$tempHive" $ntuser *> $null }
    try {
        $key = if ($usingHKU) { $loadedRoot } else { "HKLM:\$tempHive\Network" }
        if (Test-Path $key) {
            Get-ChildItem $key | ForEach-Object {
                $rp = (Get-ItemProperty $_.PSPath -EA SilentlyContinue).RemotePath
                if ($rp) { $driveResults += [PSCustomObject]@{ Account = ($p.LocalPath -split '\\')[-1]; Drive = $_.PSChildName; Path = $rp } }
            }
        }
    }
    finally { if (-not $usingHKU) { & reg.exe unload "HKLM\$tempHive" *> $null } }
}
if ($driveResults) { $driveResults | Format-Table -AutoSize } else { Write-Host '   No mapped drives found.' -ForegroundColor Gray }

# --- SECTION 3: LOCAL NETWORK SHARES AND PERMISSIONS ---
Write-Host "`n--- [SECTION 3: LOCAL NETWORK SHARES AND PERMISSIONS] ---" -ForegroundColor Cyan
$shares = Get-SmbShare | Where-Object { $_.Name -notmatch '(\$|Users)' }

$shareReport = foreach ($s in $shares) {
    $exists = Test-Path $s.Path
    
    # Use -f format operator to avoid complex interpolation quotes
    $permObjects = Get-SmbShareAccess -Name $s.Name
    $permString = if ($permObjects) {
        ($permObjects | ForEach-Object { '{0} ({1})' -f $_.AccountName, $_.AccessRight }) -join ' | '
    } else {
        'None / Inherited'
    }

    [pscustomobject]@{
        ShareName   = $s.Name
        Status      = if ($exists) { 'OK' } else { '[!] ORPHANED' }
        Path        = $s.Path
        Permissions = $permString
    }
}
$shareReport | Format-List ShareName, Status, Path, Permissions
<#
.SYNOPSIS
  Enumerate mapped network drives for every Windows user profile.

.DESCRIPTION
  For each folder in C:\Users (excluding built-in profiles), this script:
    1. Determines the user’s SID.
    2. Loads their NTUSER.DAT hive under HKLM\TempHive_<SID>.
    3. Reads the Network key (where mapped drives live) and pulls RemotePath.
    4. Unloads the hive.
  Outputs a table of User (SID), DriveLetter, and RemotePath.

.NOTES
  - Must be run elevated (SYSTEM or Admin).
  - Tested on Windows Server 2019 / 2022 and Windows 10 / 11.
#>

# List all real user profiles
$skip = 'Public','Default','Default User','All Users'
$profiles = Get-ChildItem -Path 'C:\Users' -Directory |
            Where-Object { $skip -notcontains $_.Name }

# Container for results
$all = foreach ($p in $profiles) {
    # Grab the folder's owner SID
    try {
        $sid = (Get-Acl -Path $p.FullName).Owner.Split('\')[-1]
    } catch {
        Write-Warning "Cannot determine SID for $($p.Name): $_"
        continue
    }

    $hiveName = "TempHive_$sid"
    $ntuser   = Join-Path $p.FullName 'NTUSER.DAT'

    if (-not (Test-Path $ntuser)) {
        Write-Verbose "No NTUSER.DAT for $($p.Name), skipping."
        continue
    }

    # Load the user hive
    try {
        & reg.exe load "HKLM\$hiveName" $ntuser | Out-Null
    } catch {
        Write-Warning "Failed to load hive for $($p.Name) ($sid): $_"
        continue
    }

    # Query mapped drives under that hive
    $keyPath = "Registry::HKEY_LOCAL_MACHINE\$hiveName\Network"
    if (Test-Path $keyPath) {
        Get-ChildItem -Path $keyPath | ForEach-Object {
            $letter = $_.PSChildName
            $props  = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                User        = $sid
                DriveLetter = $letter
                RemotePath  = $props.RemotePath
            }
        }
    }

    # Always unload the hive
    & reg.exe unload "HKLM\$hiveName" | Out-Null
}

# Present results
if ($all) {
    $all | Sort-Object User, DriveLetter |
        Format-Table -AutoSize
} else {
    Write-Output "No mapped drives found for any user."
}
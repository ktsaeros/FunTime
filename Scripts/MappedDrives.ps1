<#
.SYNOPSIS
  Enumerate mapped network drives for every Windows user profile, with verbose/debug output.

.DESCRIPTION
  - Must be run elevated (SYSTEM or Admin).
  - Walks each folder in C:\Users (skipping built-in profiles).
  - Loads the NTUSER.DAT hive, reads HKLM:\<HiveName>\Network, then unloads the hive.
  - Emits Write-Host/Write-Warning so you can see progress.
#>

#— Require elevation
If (-not ([Security.Principal.WindowsPrincipal] `
      [Security.Principal.WindowsIdentity]::GetCurrent() `
      ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator or SYSTEM!"
    Exit 1
}

#— Make sure errors don’t abort everything
$ErrorActionPreference = 'Continue'

#— Profiles to skip
$skip = 'Public','Default','Default User','All Users'

#— Gather profiles
$profiles = Get-ChildItem -Path 'C:\Users' -Directory |
            Where-Object { $skip -notcontains $_.Name }

if (-not $profiles) {
    Write-Warning "No user folders found under C:\Users!"
    Exit 1
}

#— Container for results
$results = @()

foreach ($p in $profiles) {
    Write-Host "`n=== Processing profile: $($p.Name) ==="
    $ntuser = Join-Path $p.FullName 'NTUSER.DAT'
    if (-not (Test-Path $ntuser)) {
        Write-Host "  → No NTUSER.DAT, skipping."
        continue
    }

    #— Get SID from folder ACL
    try {
        $sid = (Get-Acl $p.FullName).Owner.Split('\')[-1]
        Write-Host "  → SID = $sid"
    } catch {
        Write-Warning "  → Could not determine SID for $($p.Name): $_"
        continue
    }

    $hiveName = "TempHive_$sid"
    #— Load the hive
    Write-Host "  → Loading hive as HKLM:\$hiveName"
    try {
        reg.exe load "HKLM\$hiveName" $ntuser 2>&1 | ForEach-Object { Write-Host "    [reg] $_" }
    } catch {
        Write-Warning "  → Failed to load hive: $_"
        continue
    }

    #— Check for mapped drives
    $networkKey = "HKLM:\$hiveName\Network"
    if (Test-Path $networkKey) {
        Get-ChildItem $networkKey | ForEach-Object {
            $letter = $_.PSChildName
            $props  = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            $remote = $props.RemotePath
            Write-Host "    → Found: $letter  =>  $remote"
            $results += [PSCustomObject]@{
                Profile     = $p.Name
                SID         = $sid
                DriveLetter = $letter
                RemotePath  = $remote
            }
        }
    } else {
        Write-Host "    → No mapped drives in registry for this user."
    }

    #— Unload the hive
    Write-Host "  → Unloading hive"
    reg.exe unload "HKLM\$hiveName" 2>&1 | ForEach-Object { Write-Host "    [reg] $_" }
}

#— Final output
if ($results.Count -gt 0) {
    Write-Host "`n=== Summary of all mapped drives ===`n"
    $results |
      Sort-Object Profile,DriveLetter |
      Format-Table -AutoSize
} else {
    Write-Host "`nNo mapped drives were found for any user."
}
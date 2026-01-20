<#
.SYNOPSIS
  List mapped network drives for local profiles, including users currently logged on.

.NOTES
  Run as Administrator (reads NTUSER.DAT hives). 
#>

param(
  [switch]$LocalOnly,    # only show COMPUTERNAME\user accounts
  [switch]$AsObject,     # output PSCustomObjects instead of strings
  [switch]$IncludeLive   # also include current-session (non-persistent) mappings
)

$ErrorActionPreference = 'Continue'

# Profiles to skip by leaf folder name
$skip = 'Public','Default','Default User','All Users','WDAGUtilityAccount'

# Build profile map from ProfileList (SID -> ProfilePath -> NTAccount)
$profiles = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' |
  ForEach-Object {
    $sid  = $_.PSChildName
    $pip  = (Get-ItemProperty $_.PSPath -EA SilentlyContinue).ProfileImagePath
    if (-not $pip) { return }
    $path = [Environment]::ExpandEnvironmentVariables($pip)
    if (-not (Test-Path $path)) { return }
    $leaf = Split-Path $path -Leaf
    if ($skip -contains $leaf) { return }

    $acct = $sid
    try {
      $acct = (New-Object System.Security.Principal.SecurityIdentifier($sid)
              ).Translate([System.Security.Principal.NTAccount]).Value
    } catch { }

    $scope = if ($acct -like "$env:COMPUTERNAME\*") { 'Local' } else { 'Domain' }

    [PSCustomObject]@{
      SID         = $sid
      Account     = $acct
      User        = ($acct -split '\\')[-1]
      ProfilePath = $path
      Scope       = $scope
    }
  }

if ($LocalOnly) {
  $profiles = $profiles | Where-Object { $_.Scope -eq 'Local' }
}

$results = foreach ($p in $profiles) {
  $loadedRoot = "Registry::HKEY_USERS\$($p.SID)\Network"
  $tempHive   = "TempHive_$($p.SID)"
  $tempRoot   = "HKLM:\$tempHive\Network"
  $ntuser     = Join-Path $p.ProfilePath 'NTUSER.DAT'

  $usingHKU = $false
  if (Test-Path $loadedRoot) {
    $usingHKU = $true
  }
  elseif (Test-Path $ntuser) {
    # Try to load the hive if not already mounted
    & reg.exe load "HKLM\$tempHive" $ntuser *> $null
    if (-not (Test-Path "HKLM:\$tempHive")) {
      Write-Warning "Could not load hive for $($p.Account) ($($p.SID)). It may already be in use."
      continue
    }
  }
  else {
    continue
  }

  try {
    $key = if ($usingHKU) { $loadedRoot } else { $tempRoot }
    if (Test-Path $key) {
      Get-ChildItem $key | ForEach-Object {
        $drv = $_.PSChildName
        $rp  = (Get-ItemProperty $_.PSPath -EA SilentlyContinue).RemotePath
        if ($rp) {
          [PSCustomObject]@{
            Account = $p.Account
            User    = $p.User
            Scope   = $p.Scope
            SID     = $p.SID
            Drive   = $drv
            Path    = $rp
            Source  = if ($usingHKU) { 'HKU' } else { 'NTUSER.DAT' }
          }
        }
      }
    }
  }
  finally {
    if (-not $usingHKU) {
      & reg.exe unload "HKLM\$tempHive" *> $null
    }
  }
}

# Optional: include *live* session mappings (covers non-persistent net use)
if ($IncludeLive) {
  try {
    Get-CimInstance -ClassName Win32_MappedLogicalDisk -EA Stop | ForEach-Object {
      [PSCustomObject]@{
        Account = "$env:COMPUTERNAME\$env:USERNAME"
        User    = $env:USERNAME
        Scope   = 'CurrentSession'
        SID     = $null
        Drive   = $_.DeviceID.TrimEnd(':')
        Path    = $_.ProviderName
        Source  = 'LiveSession'
      }
    } | ForEach-Object { $results += $_ }
  } catch { }
}

# De-duplicate and output
$results = $results | Sort-Object Account,Drive,Path -Unique

if ($AsObject) {
  $results | Sort-Object Account,Drive
}
else {
  if ($results) {
    $results | Sort-Object Account,Drive |
      ForEach-Object {
        "{0} : {1} => {2}" -f $_.Account, $_.Drive, $_.Path
      }
  }
  else {
    "No mapped drives found for any user."
  }
}
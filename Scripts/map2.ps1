<# 
.SYNOPSIS
  List mapped network drives for local profiles.

.NOTES
  Run as Administrator (loads NTUSER.DAT hives).
#>

param(
  [switch]$LocalOnly,   # only show COMPUTERNAME\user accounts
  [switch]$AsObject     # output PSCustomObjects instead of strings
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
  $nt = Join-Path $p.ProfilePath 'NTUSER.DAT'
  if (-not (Test-Path $nt)) { continue }

  $hive = "TempHive_$($p.SID)"

  # Load hive (suppress stdout/stderr)
  & reg.exe load "HKLM\$hive" $nt *> $null

  try {
    $key = "HKLM:\$hive\Network"
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
          }
        }
      }
    }
  }
  finally {
    # Always try to unload (suppress noise)
    & reg.exe unload "HKLM\$hive" *> $null
  }
}

# De-duplicate and output
$results = $results | Sort-Object Account,Drive,Path -Unique

if ($AsObject) {
  $results | Sort-Object Account,Drive
}
else {
  if ($results) {
    $results | Sort-Object Account,Drive |
      ForEach-Object { "{0} : {1} => {2}" -f $_.Account, $_.Drive, $_.Path }
  }
  else {
    "No mapped drives found for any user."
  }
}
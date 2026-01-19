<# Disable OneDrive in Office (keep Office sign-in)
   Defaults: Hide OneDrive Personal + OneDrive for Business. Keep SharePoint Sites.
   Optional: add -DisableSharePointSites to hide SharePoint Online too.
   Optional: add -OrgOnly to allow only work/school sign-in (no personal MSA).
#>

param(
  [switch]$DisableSharePointSites,
  [switch]$OrgOnly
)

$pol  = 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common'
$pref = 'HKCU:\Software\Microsoft\Office\16.0\Common'

# Ensure keys exist in both hives
foreach ($root in @($pol,$pref)) {
  foreach ($k in @('\Internet','\General','\SignIn')) {
    New-Item -Path ($root + $k) -Force | Out-Null
  }
}

# --- OnlineStorage bitmask ---
# 1  = Disable OneDrive Personal
# 64 = Disable OneDrive for Business
# 32 = Disable SharePoint Online (Sites)
$mask = 1 -bor 64         # 65 = hide ODP + ODB
if ($DisableSharePointSites) { $mask = $mask -bor 32 }  # add Sites if requested

# Write to Policies + Preferences (some builds honor either)
foreach ($root in @($pol,$pref)) {
  New-ItemProperty -Path ($root + '\Internet') -Name 'OnlineStorage' -PropertyType DWord -Value $mask -Force | Out-Null
  New-ItemProperty -Path ($root + '\General')  -Name 'SkyDriveSignInOption' -PropertyType DWord -Value 0 -Force | Out-Null
}

# Keep Office sign-in allowed (remove a hard block if it exists)
foreach ($root in @($pol,$pref)) {
  $val = Get-ItemProperty -Path ($root + '\SignIn') -Name 'SignInOptions' -ErrorAction SilentlyContinue
  if ($null -ne $val -and $val.SignInOptions -eq 3) {
    Remove-ItemProperty -Path ($root + '\SignIn') -Name 'SignInOptions' -Force
  }
  if ($OrgOnly) {
    # 2 = org (work/school) accounts only; prevents personal MSA sign-in
    New-ItemProperty -Path ($root + '\SignIn') -Name 'SignInOptions' -PropertyType DWord -Value 2 -Force | Out-Null
  }
}

# Show results
$osPol  = (Get-ItemProperty "$pol\Internet").OnlineStorage
$osPref = (Get-ItemProperty "$pref\Internet").OnlineStorage
Write-Host "OnlineStorage (Policies)  : $osPol"
Write-Host "OnlineStorage (Preferences): $osPref"
Write-Host "Mask $mask => OneDrive hidden (personal+business). Sites hidden: $($DisableSharePointSites.IsPresent)"
Write-Host ""
Write-Host "Done. Close ALL Office apps, then re-open (or run: gpupdate /target:user /force)."
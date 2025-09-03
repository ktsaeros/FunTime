<#
Sets machine-wide defaults (still user-changeable):

On battery  -> Sleep   for: Power button, Sleep button, Lid close
Plugged in  -> Do nothing for: Power button, Sleep button, Lid close

Run as Admin or SYSTEM. Windows PowerShell 5.1 friendly.
#>

$ErrorActionPreference = 'Stop'

# Subgroup + setting GUIDs
$SUB = '4f971e89-eebd-4455-a8de-9e59040e7347' # Power buttons and lid
$SETTINGS = @{
  'Power button' = '7648efa3-dd9c-4e3e-b566-50f929386280'  # PBUTTONACTION
  'Sleep button' = '96996bc0-ad50-47ec-923b-6f41874dd9eb'  # SBUTTONACTION
  'Lid close'    = '5ca83367-6e45-459f-a27b-476b1d01c936'  # LIDACTION
}

# 1) Ensure no local policy is forcing values (so users can change later)
$policyBase = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\$SUB"
foreach ($g in $SETTINGS.Values) {
  $k = Join-Path $policyBase $g
  if (Test-Path $k) { Remove-Item -Path $k -Recurse -Force }
}

# 2) Enumerate all installed power schemes
$schemes = @()
(powercfg /L) | ForEach-Object {
  if ($_ -match 'GUID:\s*([0-9a-fA-F-]+)\s+\(') { $schemes += $matches[1] }
}
if (-not $schemes) { throw "No power schemes found." }

# Desired indices: 0=Do nothing, 1=Sleep
$AC = 0  # plugged in
$DC = 1  # on battery

# 3) Set values on every scheme (machine context)
foreach ($scheme in $schemes) {
  foreach ($guid in $SETTINGS.Values) {
    powercfg -setacvalueindex $scheme $SUB $guid $AC | Out-Null
    powercfg -setdcvalueindex $scheme $SUB $guid $DC | Out-Null
  }
}

# 4) Re-apply the active scheme so changes take effect immediately
$active = (powercfg /getactivescheme) -replace '.*GUID:\s*([0-9a-fA-F-]+).*','$1'
powercfg -setactive $active | Out-Null

Write-Host "Baseline applied to $($schemes.Count) plan(s): On battery=Sleep, Plugged in=Do nothing (user can still change)." -ForegroundColor Green
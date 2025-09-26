<#
  Clear-Office-CloudRecents.ps1
  Purpose: Remove OneDrive/SharePoint "Recents/Favorites" from Office UI for the current user.
  Effects:
    - Closes Word/Excel/PowerPoint
    - Removes OneDrive Personal as a Connected Service (if present)
    - Clears MRU + Place MRU for Word/Excel/PowerPoint (Recent files & Favorite folders)
    - Resets per-app "Open/Save" caches
    - Optional: -HardSignOut also clears Office identity tokens (you will need to sign in again)
  Safe for Office 2016/2019/2021/M365 (16.0). PowerShell 5.1 compatible.
#>

param(
  [switch]$HardSignOut  # include to remove all Office identities too
)

$ErrorActionPreference = 'SilentlyContinue'
$ver = '16.0'  # Office 2016+ path

# 1) Close Office apps
Get-Process winword, excel, powerpnt -ErrorAction SilentlyContinue | Stop-Process -Force

# 2) Remove OneDrive - Personal from "Connected Services" (per-user)
#    Office stores connected cloud services under these Internet caches.
$svcRoots = @(
  "HKCU:\Software\Microsoft\Office\$ver\Common\Internet\WebServiceCache",
  "HKCU:\Software\Microsoft\Office\$ver\Common\Internet\Server Cache",
  "HKCU:\Software\Microsoft\Office\$ver\Common\Internet\ServiceProviderCache"
)
foreach ($root in $svcRoots) {
  if (Test-Path $root) {
    Get-ChildItem $root | ForEach-Object {
      $blob = (Get-ItemProperty $_.PSPath).PSObject.Properties.Value -join ' '
      if ($blob -match '(?i)OneDrive|SkyDrive|live\.com|onedrive\.com') {
        Remove-Item $_.PSPath -Recurse -Force
      }
    }
  }
}

# 3) Clear MRUs (Recent files & Favorite "Places") for Word/Excel/PowerPoint
$apps = @('Word','Excel','PowerPoint')
foreach ($app in $apps) {
  $base = "HKCU:\Software\Microsoft\Office\$ver\$app"
  Remove-Item "$base\File MRU"  -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item "$base\Place MRU" -Recurse -Force -ErrorAction SilentlyContinue
}

# 4) Reset Open/Save backstage caches
$openFind = "HKCU:\Software\Microsoft\Office\$ver\Common\Open Find"
Remove-Item "$openFind\Microsoft Office Word"        -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "$openFind\Microsoft Office Excel"       -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "$openFind\Microsoft Office PowerPoint"  -Recurse -Force -ErrorAction SilentlyContinue

# 5) Remove Office’s Recent shortcuts (the old .lnk cache)
$officeRecent = Join-Path $env:APPDATA 'Microsoft\Office\Recent'
if (Test-Path $officeRecent) { Remove-Item (Join-Path $officeRecent '*') -Force -Recurse }

# 6) Optional: hard sign-out of Office identities (use only if you want to purge the old account)
if ($HardSignOut) {
  $idRoot = "HKCU:\Software\Microsoft\Office\$ver\Common\Identity"
  if (Test-Path $idRoot) { Remove-Item $idRoot -Recurse -Force }
  # This signs you out of Office apps; you will be prompted to sign in again later.
}

Write-Host "Done. Launch Word/Excel now—Recents/Favorites should be clear and OneDrive service detached."
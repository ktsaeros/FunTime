<# 
   .SYNOPSIS 
   Recover mapped drives for a user by loading their registry hive offline. 
   Run as SYSTEM (RMM). 
#>
param([string]$TargetUser)

if (-not $TargetUser) {
    Write-Error "Please specify a username. Usage: .\Audit-UserDrives.ps1 -TargetUser 'jdoe'"
    return
}

# 1) Lookup SID
$pl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
$sid = Get-ChildItem $pl | Where-Object { (Get-ItemProperty $_.PSPath).ProfileImagePath -match "\\$TargetUser$" } | Select-Object -ExpandProperty PSChildName

if (-not $sid) { Write-Error "Could not find profile SID for user: $TargetUser"; return }

$ntuser = "C:\Users\$TargetUser\NTUSER.DAT"
if (-not (Test-Path $ntuser)) { Write-Error "No NTUSER.DAT found at $ntuser"; return }

$hive = "TempHive_$sid"
reg.exe load "HKLM\$hive" $ntuser 2>$null

Write-Host "--- MAPPED DRIVES FOR $TargetUser ---" -ForegroundColor Cyan
$key = "HKLM:\$hive\Network"
if (Test-Path $key) {
    Get-ChildItem $key | ForEach-Object {
        [PSCustomObject]@{
            DriveLetter = $_.PSChildName
            RemotePath  = (Get-ItemProperty $_.PSPath).RemotePath
        }
    } | Format-Table -AutoSize
} else {
    Write-Output "No persistent mapped drives found."
}

reg.exe unload "HKLM\$hive" 2>$null
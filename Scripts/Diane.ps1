# Run elevated (SYSTEM/Admin)
$profile = 'Diane'
# 1) Lookup her SID from ProfileList
$pl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
$sid = Get-ChildItem $pl |
       Where-Object { (Get-ItemProperty $_.PSPath).ProfileImagePath -eq "C:\Users\$profile" } |
       Select-Object -ExpandProperty PSChildName

if (-not $sid) {
    Write-Error "Could not find SID for C:\Users\$profile"
    return
}

$ntuser = "C:\Users\$profile\NTUSER.DAT"
if (-not (Test-Path $ntuser)) {
    Write-Error "No NTUSER.DAT found for $profile"
    return
}

$hive = "TempHive_$sid"
reg.exe load "HKLM\$hive" $ntuser 2>$null

$key = "HKLM:\$hive\Network"
if (Test-Path $key) {
    Get-ChildItem $key | ForEach-Object {
        $drv = $_.PSChildName
        $rp  = (Get-ItemProperty $_.PSPath).RemotePath
        [PSCustomObject]@{
            User        = "$profile ($sid)"
            DriveLetter = $drv
            RemotePath  = $rp
        }
    } | Format-Table -AutoSize
} else {
    Write-Output "No persistent mapped drives under Network for $profile."
}

reg.exe unload "HKLM\$hive" 2>$null
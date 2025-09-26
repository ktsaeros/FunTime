# =======================
# Apply + Verify Power + Screensaver rows (Run as Admin)
# =======================

# --- Power GUIDs ---
$SUB_BUTTONS='4f971e89-eebd-4455-a8de-9e59040e7347'
$LIDACTION='5ca83367-6e45-459f-a27b-476b1d01c936'
$PBUTTON='7648efa3-dd9c-4e3e-b566-50f929386280'
$SBUTTON='96996bc0-ad50-47ec-923b-6f41874dd9eb'
$SUB_VIDEO='7516B95F-F776-4464-8C53-06167F40CC99'; $VIDEOIDLE='3C0BC021-C8A8-4E07-A973-6B14CBCB2B7E'
$SUB_SLEEP='238C9FA8-0AAD-41ED-83F4-97BE242C8F20'; $STANDBYIDLE='29F6C1DB-86DA-48C5-9FDB-F2B67B1F44DA'
$HIBERIDLE='9D7815A6-7EE4-497E-8888-515A05F02364'

# --- Helpers: scheme & value query/format ---
$scheme=(powercfg /getactivescheme) -replace '.*GUID:\s*([0-9a-fA-F-]+).*','$1'
function Get-Idx($sub,$set){
  $q=(powercfg /query $scheme $sub $set | Out-String)
  $ac=if($q -match 'Current AC Power Setting Index:\s*(0x[0-9A-Fa-f]+)'){[Convert]::ToInt32($Matches[1],16)} else {$null}
  $dc=if($q -match 'Current DC Power Setting Index:\s*(0x[0-9A-Fa-f]+)'){[Convert]::ToInt32($Matches[1],16)} else {$null}
  ,@($ac,$dc)
}
function Map-Action($v){ if($null -eq $v){'N/A'} else {switch($v){0{'Do nothing'}1{'Sleep'}2{'Hibernate'}3{'Shut down'} default{"$v"}}}}
function AsMinutesSmart($v){
  if ($null -eq $v) { 'N/A' }
  elseif ($v -eq 0) { 'Never' }
  elseif ($v -ge 120 -and ($v % 60 -eq 0)) { '{0} min' -f ($v/60) } else { '{0} min' -f $v }
}
function AsDisplay($v){
  if ($null -eq $v) { 'N/A' }
  elseif ($v -eq 0) { 'Never' }
  elseif ($v -ge 120) { '{0} min' -f [math]::Round($v/60) } else { '{0} sec' -f $v }
}

# --- Screensaver helpers ---
# Map SID -> username via ProfileList; for temp hive return last folder name as fallback
function Resolve-UserFromSid($sid){
  try {
    $p = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid" -ErrorAction Stop
    if ($p.ProfileImagePath) { return Split-Path $p.ProfileImagePath -Leaf }
  } catch {}
  if ($sid -match 'TempUserHive') { return '(TempUser)' }
  return $sid
}
function Read-SSV ($userRoot) {
  $deskKey = "Registry::$userRoot\Control Panel\Desktop"
  $sid = ($userRoot -replace '^HKEY_USERS\\','')
  $who = Resolve-UserFromSid $sid
  $active=$null; $exe=$null; $to=$null
  if (Test-Path $deskKey) {
    $p = Get-ItemProperty -Path $deskKey -ErrorAction SilentlyContinue
    $active = $p.'ScreenSaveActive'
    $exe    = $p.'SCRNSAVE.EXE'
    $to     = $p.'ScreenSaveTimeOut'
  }
  [pscustomobject]@{ Sid=$sid; User=$who; Active=$active; EXE=$exe; Timeout=$to }
}
function Disable-SSV ($userRoot) {
  $deskKey = "Registry::$userRoot\Control Panel\Desktop"
  if (-not (Test-Path $deskKey)) { New-Item -Path $deskKey -Force | Out-Null }
  Set-ItemProperty -Path $deskKey -Name ScreenSaveActive  -Value '0'  -Type String
  Set-ItemProperty -Path $deskKey -Name SCRNSAVE.EXE      -Value ''   -Type String
  Set-ItemProperty -Path $deskKey -Name ScreenSaveTimeOut -Value '0'  -Type String
}
function Format-SS-Timeout($active,$to){
  if ($null -eq $active -and $null -eq $to) { return 'N/A' }
  if ("$active" -ne '1' -or [int]($to|?{$_}) -eq 0) { return 'Disabled' }
  try {
    $sec = [int]$to
    if ($sec -ge 60 -and ($sec % 60 -eq 0)) { return ('{0} min' -f ($sec/60)) }
    elseif ($sec -ge 60) { return ('{0} min' -f [math]::Round($sec/60)) }
    else { return ('{0} sec' -f $sec) }
  } catch { return 'N/A' }
}

# Build power table WITH optional screensaver rows appended
function Build-Table($disp,$sleep,$hib,$lid,$pbtn,$sbtn,$ssRows){
  $rows = @(
    [pscustomobject]@{Setting='Turn off display';  AC=AsDisplay $disp[0];  DC=AsDisplay $disp[1];  Description='Idle time before display turns off'}
    [pscustomobject]@{Setting='Sleep (idle)';      AC=AsMinutesSmart $sleep[0]; DC=AsMinutesSmart $sleep[1]; Description='Idle time before system sleeps'}
    [pscustomobject]@{Setting='Hibernate (idle)';  AC=AsMinutesSmart $hib[0];   DC=AsMinutesSmart $hib[1];   Description='Idle time before system hibernates'}
    [pscustomobject]@{Setting='Lid close';         AC=Map-Action $lid[0];  DC=Map-Action $lid[1];  Description='Action when lid is closed'}
    [pscustomobject]@{Setting='Power button';      AC=Map-Action $pbtn[0]; DC=Map-Action $pbtn[1]; Description='Action when power button pressed'}
    [pscustomobject]@{Setting='Sleep button';      AC=Map-Action $sbtn[0]; DC=Map-Action $sbtn[1]; Description='Action when sleep button pressed'}
  )
  if ($ssRows) { $rows += $ssRows }
  return $rows
}

# Create HKU: if missing
if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
  New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
}

# Enumerate loaded hives; if none, load most-recent profile
$hives = Get-ChildItem HKU:\ -ErrorAction SilentlyContinue | Where-Object {
  $_.Name -match 'S-1-5-21-' -and $_.Name -notmatch 'Classes$'
}
$tempHive = $null
if (-not $hives) {
  $profileEntry = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' |
    Get-ItemProperty | Where-Object { $_.ProfileImagePath -like 'C:\Users\*' } |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if ($profileEntry -and (Test-Path ($profileEntry.ProfileImagePath + '\NTUSER.DAT'))) {
    $tempHive = 'HKU\TempUserHive'
    reg load $tempHive ($profileEntry.ProfileImagePath + '\NTUSER.DAT') | Out-Null
    $hives = Get-Item 'Registry::HKEY_USERS\TempUserHive'
  }
}

# Unhide in case OEM hid power button/lid settings
foreach($g in @($LIDACTION,$PBUTTON,$SBUTTON)){ powercfg -attributes $SUB_BUTTONS $g -ATTRIB_HIDE | Out-Null }

# --- Capture PREVIOUS power values ---
$prev_disp = Get-Idx $SUB_VIDEO   $VIDEOIDLE
$prev_sleep= Get-Idx $SUB_SLEEP   $STANDBYIDLE
$prev_hib  = Get-Idx $SUB_SLEEP   $HIBERIDLE
$prev_lid  = Get-Idx $SUB_BUTTONS $LIDACTION
$prev_pbtn = Get-Idx $SUB_BUTTONS $PBUTTON
$prev_sbtn = Get-Idx $SUB_BUTTONS $SBUTTON

# Screensaver PREVIOUS rows -> one row per user ("Screensaver (username)")
$ssPrevObjs = @()
if ($hives -is [System.Array]) { foreach($h in $hives){ $ssPrevObjs += Read-SSV $h.Name } }
elseif ($hives) { $ssPrevObjs += Read-SSV $hives.Name }
$ssPrevRows = @()
foreach($o in $ssPrevObjs){
  $label = "Screensaver ($($o.User))"
  $val   = Format-SS-Timeout $o.Active $o.Timeout
  $ssPrevRows += [pscustomobject]@{Setting=$label; AC=$val; DC=$val; Description='Screensaver timeout for user'}
}

$previousTable = Build-Table $prev_disp $prev_sleep $prev_hib $prev_lid $prev_pbtn $prev_sbtn $ssPrevRows

# --- APPLY DESIRED POWER SETTINGS ---
powercfg -setacvalueindex SCHEME_CURRENT $SUB_BUTTONS $LIDACTION 0
powercfg -setdcvalueindex SCHEME_CURRENT $SUB_BUTTONS $LIDACTION 1
powercfg -setacvalueindex SCHEME_CURRENT $SUB_BUTTONS $PBUTTON 0
powercfg -setdcvalueindex SCHEME_CURRENT $SUB_BUTTONS $PBUTTON 1
powercfg -setacvalueindex SCHEME_CURRENT $SUB_BUTTONS $SBUTTON 0
powercfg -setdcvalueindex SCHEME_CURRENT $SUB_BUTTONS $SBUTTON 1
powercfg /setacvalueindex SCHEME_CURRENT $SUB_VIDEO $VIDEOIDLE 1800
powercfg /setdcvalueindex SCHEME_CURRENT $SUB_VIDEO $VIDEOIDLE 600
powercfg /setacvalueindex SCHEME_CURRENT $SUB_SLEEP $STANDBYIDLE 0
powercfg /setdcvalueindex SCHEME_CURRENT $SUB_SLEEP $STANDBYIDLE 30
powercfg /change standby-timeout-ac 0
powercfg /change standby-timeout-dc 30
powercfg -S SCHEME_CURRENT | Out-Null

# Disable screensavers for each hive (after we captured previous)
$ssCurrObjs = @()
if ($hives -is [System.Array]) {
  foreach($h in $hives){ Disable-SSV $h.Name; $ssCurrObjs += Read-SSV $h.Name }
} elseif ($hives) {
  Disable-SSV $hives.Name; $ssCurrObjs += Read-SSV $hives.Name
}

# --- Capture CURRENT power values ---
$curr_disp = Get-Idx $SUB_VIDEO   $VIDEOIDLE
$curr_sleep= Get-Idx $SUB_SLEEP   $STANDBYIDLE
$curr_hib  = Get-Idx $SUB_SLEEP   $HIBERIDLE
$curr_lid  = Get-Idx $SUB_BUTTONS $LIDACTION
$curr_pbtn = Get-Idx $SUB_BUTTONS $PBUTTON
$curr_sbtn = Get-Idx $SUB_BUTTONS $SBUTTON

# Screensaver CURRENT rows
$ssCurrRows = @()
foreach($o in $ssCurrObjs){
  $label = "Screensaver ($($o.User))"
  $val   = Format-SS-Timeout $o.Active $o.Timeout
  $ssCurrRows += [pscustomobject]@{Setting=$label; AC=$val; DC=$val; Description='Screensaver timeout for user'}
}

$currentTable = Build-Table $curr_disp $curr_sleep $curr_hib $curr_lid $curr_pbtn $curr_sbtn $ssCurrRows

# --- Print both tables ---
Write-Host "`nPrevious settings (captured before changes):" -ForegroundColor Cyan
$previousTable | Format-Table -AutoSize

Write-Host "`nCurrent settings (after apply):" -ForegroundColor Green
$currentTable  | Format-Table -AutoSize

# Unload temp hive if used
if ($tempHive) { reg unload $tempHive | Out-Null; Write-Host "`n(Unloaded temporary user hive.)" }
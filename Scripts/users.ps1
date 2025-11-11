# === Profile Path / Local vs Domain / Admin (Yes/No/Unknown) ===

# 1) Get the "machine SID base" (local accounts share this root; Administrator ends in -500)
$localAdminSid = ([System.Security.Principal.NTAccount]"$env:COMPUTERNAME\Administrator").
  Translate([System.Security.Principal.SecurityIdentifier]).Value
$machineSidBase = $localAdminSid -replace '-500$',''

# 2) Read members of the local Administrators group (WinNT provider)
$adminMembers = @()
try {
  $grp = [ADSI]"WinNT://$env:COMPUTERNAME/Administrators,group"
  $grp.Members() | ForEach-Object {
    $path   = $_.GetType().InvokeMember('ADsPath','GetProperty',$null,$_,$null)
    $member = [ADSI]$path
    $sid    = $null
    try {
      $sidBytes = $member.Properties['objectSid'].Value
      if ($sidBytes) { $sid = (New-Object System.Security.Principal.SecurityIdentifier($sidBytes,0)).Value }
    } catch {}
    $adminMembers += [pscustomobject]@{
      Sid   = $sid
      Class = $member.Class  # User or Group
      Name  = $member.Name
    }
  }
} catch {
  # Fallback if ADSI fails: best-effort parse of 'net localgroup Administrators'
  $names = (& net localgroup Administrators) 2>$null |
           Select-Object -SkipWhile {$_ -notmatch '^-+$'} | Select-Object -Skip 1 |
           Where-Object { $_ -and $_ -notmatch 'The command completed successfully' }
  foreach ($n in $names) {
    $adminMembers += [pscustomobject]@{ Sid=$null; Class='unknown'; Name=$n.Trim() }
  }
}

$adminUserSids  = $adminMembers | Where-Object { $_.Class -eq 'User'  -and $_.Sid } | ForEach-Object Sid
$adminGroupSeen = $adminMembers | Where-Object { $_.Class -eq 'Group' } | Measure-Object | Select-Object -ExpandProperty Count

# 3) Walk profiles on disk (who has used this PC)
$rows = Get-CimInstance Win32_UserProfile |
  Where-Object { $_.LocalPath -like 'C:\Users\*' -and -not $_.Special } |
  ForEach-Object {
    $sid = $_.SID

    # Local vs Domain: compare SID root against machine SID base
    $type = if ($sid -like "$machineSidBase-*") { 'Local' } else { 'Domain' }

    # Admin determination:
    #  - YES if this exact SID is directly in local Administrators
    #  - UNKNOWN if not direct, but Admins contains groups (could be admin via domain group)
    #  - otherwise NO
    $admin =
      if ($adminUserSids -contains $sid) { 'Yes' }
      elseif ($type -eq 'Domain' -and $adminGroupSeen -gt 0) { 'Unknown' }  # needs DC to fully expand
      else { 'No' }

    [pscustomobject]@{
      ProfilePath = $_.LocalPath
      Type        = $type            # Local or Domain
      Admin       = $admin           # Yes / No / Unknown
    }
  }

$rows | Sort-Object ProfilePath | Format-Table -AutoSize
# To export:
# $rows | Export-Csv "$env:USERPROFILE\Desktop\pc_user_audit.csv" -NoTypeInformation
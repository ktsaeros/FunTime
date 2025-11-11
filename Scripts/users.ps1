# === Profile Path / [Local or <DOMAIN>] / Admin (Yes/No/Unknown) ===

# Domain info (works as SYSTEM, too)
$cs = Get-CimInstance Win32_ComputerSystem
$IsDomainJoined = [bool]$cs.PartOfDomain
$DomainName     = if ($IsDomainJoined) { $cs.Domain } else { $null }

# 1) Machine SID "root" (local accounts share this base; local Administrator ends with -500)
$localAdminSid = ([System.Security.Principal.NTAccount]"$env:COMPUTERNAME\Administrator").
  Translate([System.Security.Principal.SecurityIdentifier]).Value
$machineSidBase = $localAdminSid -replace '-500$',''

# 2) Members of local Administrators
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
  # Fallback if ADSI fails: parse 'net localgroup Administrators'
  $names = (& net localgroup Administrators) 2>$null |
           Select-Object -SkipWhile {$_ -notmatch '^-+$'} | Select-Object -Skip 1 |
           Where-Object { $_ -and $_ -notmatch 'The command completed successfully' }
  foreach ($n in $names) {
    $adminMembers += [pscustomobject]@{ Sid=$null; Class='unknown'; Name=$n.Trim() }
  }
}

$adminUserSids  = $adminMembers | Where-Object { $_.Class -eq 'User'  -and $_.Sid } | ForEach-Object Sid
$adminGroupSeen = ($adminMembers | Where-Object { $_.Class -eq 'Group' }).Count

# 3) Enumerate user profiles (who has used this PC)
$rows = Get-CimInstance Win32_UserProfile |
  Where-Object { $_.LocalPath -like 'C:\Users\*' -and -not $_.Special } |
  ForEach-Object {
    $sid = $_.SID

    # Type: 'Local' if SID shares the machine SID root; otherwise the actual domain, or 'Workgroup'
    $type =
      if ($sid -like "$machineSidBase-*") { 'Local' }
      elseif ($IsDomainJoined) { $DomainName }
      else { 'Workgroup' }

    # Admin:
    #  - Yes if SID directly in local Administrators
    #  - Unknown if non-Local and Administrators contains groups (could be admin via domain group we can’t expand offline)
    #  - No otherwise
    $admin =
      if ($adminUserSids -contains $sid) { 'Yes' }
      elseif ($type -ne 'Local' -and $adminGroupSeen -gt 0) { 'Unknown' }
      else { 'No' }

    [pscustomobject]@{
      ProfilePath = $_.LocalPath
      Local_Domain        = $type      # 'Local' or '<your.domain.tld>' or 'Workgroup'
      Admin       = $admin     # Yes / No / Unknown
    }
  }

$rows | Sort-Object ProfilePath | Format-Table -AutoSize

# Export (optional):
# $rows | Export-Csv "$env:USERPROFILE\Desktop\pc_user_audit.csv" -NoTypeInformation
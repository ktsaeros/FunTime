$cs=Get-WmiObject Win32_ComputerSystem; $dom=$cs.Domain; Write-Output ("DomainJoined: {0}  Domain: {1}`n" -f $cs.PartOfDomain,$dom);
Write-Output 'Local users:'; try{ Get-LocalUser | Select-Object @{n='Name';e={$_.Name}} | Sort-Object Name | Format-Table -AutoSize } catch { Get-WmiObject Win32_UserAccount -Filter ("LocalAccount=True AND Domain='{0}'" -f $env:COMPUTERNAME) | Select-Object @{n='Name';e={$_.Name}} | Sort-Object Name | Format-Table -AutoSize }; Write-Output '';
Write-Output 'Profiles found (from HKLM:\...\ProfileList):';
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' |
  Where-Object {$_.PSChildName -like 'S-1-5-21-*'} |
  ForEach-Object {
    $sid=$_.PSChildName; $path=$_.GetValue('ProfileImagePath');
    try { $nt = ([Security.Principal.SecurityIdentifier]$sid).Translate([Security.Principal.NTAccount]).Value } catch { $nt=$null }
    $scope = if($nt -like "$($env:COMPUTERNAME)\*"){'Local (profile)'} elseif($cs.PartOfDomain -and $nt -like "$dom\*"){'Domain (profile)'} else {'Unknown (profile)'}
    [pscustomobject]@{ User=($nt ? $nt : "<unresolved SID: $sid>"); Scope=$scope; ProfilePath=$path }
  } | Sort-Object Scope,User | Format-Table -AutoSize
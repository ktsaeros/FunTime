$cs=Get-WmiObject Win32_ComputerSystem; $domName=if($cs.PartOfDomain){$cs.Domain}else{'(workgroup)'}; 
Write-Output ("DomainJoined: {0}  Domain: {1}" -f $cs.PartOfDomain,$domName); Write-Output '';

Write-Output 'Local users:'; 
try { Get-LocalUser | Select-Object @{n='Name';e={$_.Name}} | Sort-Object Name | Format-Table -AutoSize }
catch { Get-WmiObject Win32_UserAccount -Filter ("LocalAccount=True AND Domain='{0}'" -f $env:COMPUTERNAME) | Select-Object @{n='Name';e={$_.Name}} | Sort-Object Name | Format-Table -AutoSize }
Write-Output '';

Write-Output 'Domain users with local profiles (have signed in):';
$acctList = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' |
  Where-Object {$_.PSChildName -like 'S-1-5-21-*'} |
  ForEach-Object { try { ([Security.Principal.SecurityIdentifier]$_.PSChildName).Translate([Security.Principal.NTAccount]).Value } catch { $null } } |
  Where-Object { $_ };
if($cs.PartOfDomain) {
  $acctList | Where-Object { $_ -like "$($cs.Domain)\*" } |
    ForEach-Object { $_.Split('\')[-1] } |
    Sort-Object |
    ForEach-Object { [pscustomobject]@{Name=$_} } |
    Format-Table -AutoSize
} else { Write-Output '(not domain-joined)' }
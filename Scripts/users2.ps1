$cs = Get-WmiObject Win32_ComputerSystem
$domDns = $cs.Domain
$domNet = ($domDns -replace '\..*$','')   # NETBIOS-style guess, e.g. CMC from cmc.local
Write-Output ("DomainJoined: {0}  Domain(DNS): {1}  Domain(NETBIOS): {2}`n" -f $cs.PartOfDomain,$domDns,$domNet)

Write-Output 'Local users:'
try {
  Get-LocalUser | Select-Object @{n='Name';e={$_.Name}} | Sort-Object Name | Format-Table -AutoSize
} catch {
  Get-WmiObject Win32_UserAccount -Filter ("LocalAccount=True AND Domain='{0}'" -f $env:COMPUTERNAME) |
    Select-Object @{n='Name';e={$_.Name}} | Sort-Object Name | Format-Table -AutoSize
}
Write-Output ''

Write-Output 'Domain users with local profiles (have signed in):'
$profiles = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' |
  Where-Object { $_.PSChildName -like 'S-1-5-21-*' } |
  ForEach-Object {
    $sid  = $_.PSChildName
    $path = $_.GetValue('ProfileImagePath')
    $nt = $null
    try { $nt = ([Security.Principal.SecurityIdentifier]$sid).Translate([Security.Principal.NTAccount]).Value } catch { }
    $scope = 'Unknown (profile)'
    if ($nt) {
      if ($nt -like "$($env:COMPUTERNAME)\*") { $scope = 'Local (profile)' }
      elseif ($cs.PartOfDomain -and ( $nt -like "$domDns\*" -or $nt -like "$($domNet)\*" -or $nt -like "$(($domNet).ToUpper())\*" )) { $scope = 'Domain (profile)' }
    }
    [pscustomobject]@{ User = (if ($nt) { $nt } else { "<unresolved SID: $sid>" }); Scope = $scope; ProfilePath = $path }
  }

$profiles |
  Where-Object { $_.Scope -eq 'Domain (profile)' } |
  ForEach-Object { $_.User.Split('\')[-1] } |
  Sort-Object |
  ForEach-Object { [pscustomobject]@{ Name = $_ } } |
  Format-Table -AutoSize
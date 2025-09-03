<# 
.SYNOPSIS
  Show domain status, local users, and domain users who have signed in (profiles).

.NOTES
  PS v5 compatible; safe to run as NT AUTHORITY\SYSTEM (e.g., N-able Remote Background).
#>

$cs      = Get-WmiObject Win32_ComputerSystem
$domDns  = $cs.Domain
$domNet  = if ($cs.PartOfDomain -and $domDns) { ($domDns -replace '\..*$','') } else { '' }

Write-Output ("DomainJoined: {0}  Domain(DNS): {1}  Domain(NETBIOS): {2}`n" -f $cs.PartOfDomain, $domDns, $domNet)

# --- Local users ---
Write-Output 'Local users:'
try {
    Get-LocalUser |
        Select-Object @{n='Name';e={$_.Name}} |
        Sort-Object Name |
        Format-Table -AutoSize
}
catch {
    # Fallback for older boxes without Get-LocalUser
    Get-WmiObject Win32_UserAccount -Filter ("LocalAccount=True AND Domain='{0}'" -f $env:COMPUTERNAME) |
        Select-Object @{n='Name';e={$_.Name}} |
        Sort-Object Name |
        Format-Table -AutoSize
}
Write-Output ''

# --- Domain users with local profiles (i.e., have logged on) ---
Write-Output 'Domain users with local profiles (have signed in):'

$profileItems =
    Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' |
    Where-Object { $_.PSChildName -like 'S-1-5-21-*' } |
    ForEach-Object {
        $sid  = $_.PSChildName
        $path = $_.GetValue('ProfileImagePath')

        $nt = $null
        try { $nt = ([Security.Principal.SecurityIdentifier]$sid).Translate([Security.Principal.NTAccount]).Value } catch {}

        $scope = 'Unknown (profile)'
        if ($nt) {
            if ($nt -like "$($env:COMPUTERNAME)\*") {
                $scope = 'Local (profile)'
            }
            elseif ($cs.PartOfDomain -and ( $nt -like "$domDns\*" -or $nt -like "$domNet\*" -or $nt -like "$(($domNet).ToUpper())\*" )) {
                $scope = 'Domain (profile)'
            }
        }

        [pscustomobject]@{ User = $nt; Scope = $scope; ProfilePath = $path }
    }

$domainSignedIn =
    $profileItems |
    Where-Object { $_.Scope -eq 'Domain (profile)' } |
    ForEach-Object { $_.User.Split('\')[-1] } |
    Sort-Object -Unique

if ($domainSignedIn.Count -gt 0) {
    $domainSignedIn | ForEach-Object { [pscustomobject]@{ Name = $_ } } | Format-Table -AutoSize
}
else {
    Write-Output '(none found)'
}
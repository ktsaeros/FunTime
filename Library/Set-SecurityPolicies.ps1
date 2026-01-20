<#
.SYNOPSIS
    Security Policy Tweaks (Password Expiration)
#>

Write-Host "1. Set 'Aeros' Admin to Never Expire"
Write-Host "2. Set ALL Local Users to Never Expire"
$sel = Read-Host "Select Option"

if ($sel -eq '1') {
    $u = Get-LocalUser -Name "Aeros" -ErrorAction SilentlyContinue
    if ($u) {
        Set-LocalUser -Name "Aeros" -PasswordNeverExpires $true
        Write-Host "Aeros account set to never expire." -ForegroundColor Green
    } else {
        Write-Warning "User 'Aeros' not found."
    }
}
elseif ($sel -eq '2') {
    Get-LocalUser | ForEach-Object {
        Set-LocalUser -Name $_.Name -PasswordNeverExpires $true
        Write-Host "User '$($_.Name)' set to never expire." -ForegroundColor Green
    }
}
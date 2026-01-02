<#
.SYNOPSIS
    Installs Basic or Power User apps via Chocolatey.
#>

function Ensure-Choco {
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-Host "Installing Chocolatey..." -ForegroundColor Yellow
        [System.Net.ServicePointManager]::SecurityProtocol = 3072
        iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    }
}

Write-Host "1. Basic Apps (Chrome, Adobe Reader)"
Write-Host "2. Power Apps (7Zip, VLC, Notepad++, Putty, Sysinternals, Slack, IP Scanner)"
$sel = Read-Host "Select Install Package"

Ensure-Choco
choco feature enable -n=allowGlobalConfirmation

if ($sel -eq '1') {
    Write-Host "Installing Basic Apps..." -ForegroundColor Cyan
    choco install googlechrome adobereader
}
elseif ($sel -eq '2') {
    Write-Host "Installing Power Apps..." -ForegroundColor Cyan
    choco install 7zip.install vlc notepadplusplus.install putty.install sysinternals slack advanced-ip-scanner
}
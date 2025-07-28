<#
.SYNOPSIS
  Prompts for a company name, builds the ScreenConnect MSI URL, downloads & silently installs it.
#>

# 1) Prompt for company name
$company = Read-Host 'Enter Company Name'

# 2) URL-encode it (spaces → %20, etc.)
$companyEnc = [uri]::EscapeDataString($company)

# 3) Build the ScreenConnect URL
$baseUrl = 'https://aerosgroup.screenconnect.com/Bin/ScreenConnect.ClientSetup.msi?e=Access&y=Guest'
# append your encoded name plus seven empty &c= parameters
$url     = "$baseUrl&c=$companyEnc" + ('&c=' * 7)

# 4) Download to TEMP
$msiPath = Join-Path $env:TEMP 'ScreenConnect.msi'
Write-Host "Downloading ScreenConnect installer from:`n  $url" -ForegroundColor Cyan
Invoke-WebRequest -Uri $url -OutFile $msiPath -UseBasicParsing

# 5) Install silently (no UI, no reboot)
Write-Host "Installing ScreenConnect..." -ForegroundColor Cyan
Start-Process msiexec.exe `
    -ArgumentList "/i `"$msiPath`" /qn /norestart" `
    -NoNewWindow -Wait

Write-Host "Done." -ForegroundColor Green
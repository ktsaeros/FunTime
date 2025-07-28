param(
  [string]$CompanyName
)

# If the caller didn’t supply -CompanyName, fall back to prompting
if (-not $PSBoundParameters.ContainsKey('CompanyName')) {
  $CompanyName = Read-Host 'Enter Company Name'
}

# URL-encode the name (spaces → %20 etc.)
$enc = [uri]::EscapeDataString($CompanyName)

# Build the full MSI URL (with one real &c= plus seven empty slots)
$base = 'https://aerosgroup.screenconnect.com/Bin/ScreenConnect.ClientSetup.msi?e=Access&y=Guest'
$url  = "$base&c=$enc" + ('&c=' * 7)

Write-Host "Downloading ScreenConnect for “$CompanyName” from:"`n"  $url" -ForegroundColor Cyan

# Download & install
$msi = Join-Path $env:TEMP 'ScreenConnect.msi'
Invoke-WebRequest -Uri $url -OutFile $msi -UseBasicParsing
Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart" -NoNewWindow -Wait

Write-Host "✅ Installed ScreenConnect for “$CompanyName”" -ForegroundColor Green
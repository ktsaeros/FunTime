param(
  [string]$ClientName
)

# Allow interactive entry if run from menu
if (-not $ClientName) {
    $ClientName = Read-Host "Enter Client Name (for ScreenConnect)"
}
if (-not $ClientName) { return }

# URL-encode spaces
$enc = [uri]::EscapeDataString($ClientName)

# Build URL
$base = 'https://aerosgroup.screenconnect.com/Bin/ScreenConnect.ClientSetup.msi?e=Access&y=Guest'
$url  = "$base&c=$enc" + ('&c=' * 7)

# Download
$msi = Join-Path $env:TEMP 'ScreenConnect.msi'
Write-Host "Downloading Agent for '$ClientName'..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $url -OutFile $msi -UseBasicParsing

# Install
Write-Host "Installing..." -ForegroundColor Cyan
Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart" -NoNewWindow -Wait
Write-Host "Done." -ForegroundColor Green
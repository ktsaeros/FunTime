param(
    [Parameter(Mandatory=$true)]
    [string]$CompanyName
)

# URL-encode spaces, etc.
$enc = [uri]::EscapeDataString($CompanyName)

# Build full ScreenConnect URL
$base = 'https://aerosgroup.screenconnect.com/Bin/ScreenConnect.ClientSetup.msi?e=Access&y=Guest'
$url  = "$base&c=$enc" + ('&c=' * 7)

# Download MSI to TEMP
$msi = Join-Path $env:TEMP 'ScreenConnect.msi'
Invoke-WebRequest -Uri $url -OutFile $msi -UseBasicParsing

# Install silently
Start-Process msiexec.exe `
  -ArgumentList "/i `"$msi`" /qn /norestart" `
  -NoNewWindow -Wait
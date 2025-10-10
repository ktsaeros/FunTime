# Google Drive hardcoded download for PS 5.1 using Invoke-WebRequest (no System.Net.Http needed)

$Url     = "https://drive.google.com/file/d/1UoLlZYiKSUlwGwTtAc0QWCo30DM-dUIP/view?usp=sharing"
$OutFile = "C:\Aeros\AerosWin11.iso"

# ----- do not edit below this line -----

# Ensure TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Ensure target folder exists
$dir = [System.IO.Path]::GetDirectoryName($OutFile)
if (-not [string]::IsNullOrWhiteSpace($dir) -and -not (Test-Path $dir)) {
  New-Item -ItemType Directory -Path $dir -Force | Out-Null
}

function Get-DriveFileId {
  param([string]$u)
  if ($u -match '/file/d/([A-Za-z0-9_-]+)') { return $matches[1] }
  if ($u -match '[?&]id=([A-Za-z0-9_-]+)') { return $matches[1] }
  throw "Could not extract Google Drive file ID from URL: $u"
}

$FileId = Get-DriveFileId $Url
$Base   = "https://drive.google.com/uc?export=download&id=$FileId"

Write-Host "Requesting download page..."
# First request to capture cookies and (if applicable) the confirm token page
$r = Invoke-WebRequest -UseBasicParsing -Uri $Base -SessionVariable sess

# Try to extract confirm token or direct download link
$downloadUri = $Base
if ($r.Content -match 'confirm=([0-9A-Za-z_]+)') {
  $token = $matches[1]
  $downloadUri = "https://drive.google.com/uc?export=download&confirm=$token&id=$FileId"
} elseif ($r.Content -match 'href="(/uc\?export=download[^"]+)"') {
  $href = $matches[1] -replace '&amp;','&'
  $downloadUri = "https://drive.google.com$href"
}

Write-Host "Downloading to $OutFile ..."
Invoke-WebRequest -UseBasicParsing -Uri $downloadUri -OutFile $OutFile -WebSession $sess

Write-Host "Done. Saved to: $OutFile"
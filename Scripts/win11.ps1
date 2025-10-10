# PowerShell 5.1 Google Drive direct download script (with hardcoded URL and output file)
# Kevin - 2025-10-10
# Downloads a file from Google Drive (supports large files with confirm token)
# Works with links like:
#   https://drive.google.com/file/d/<FILE_ID>/view?usp=sharing
#   https://drive.google.com/uc?id=<FILE_ID>&export=download

# ======================================
# >>> SET THESE TWO VALUES <<<
$Url     = "https://drive.google.com/file/d/1UoLlZYiKSUlwGwTtAc0QWCo30DM-dUIP/view?usp=sharing"
$OutFile = "C:\Aeros\AerosWin11.iso"
# ======================================

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Get-DriveFileId {
    param([string]$u)
    if ($u -match '/file/d/([A-Za-z0-9_-]+)') { return $matches[1] }
    if ($u -match '[?&]id=([A-Za-z0-9_-]+)') { return $matches[1] }
    throw "Could not extract Google Drive file ID from URL."
}

$FileId = Get-DriveFileId $Url
$Base   = "https://drive.google.com/uc?export=download&id=$FileId"

$handler = New-Object System.Net.Http.HttpClientHandler
$handler.AllowAutoRedirect = $true
$handler.UseCookies = $true
$handler.CookieContainer = New-Object System.Net.CookieContainer

$client = New-Object System.Net.Http.HttpClient($handler)
$client.DefaultRequestHeaders.Add("User-Agent","Mozilla/5.0 (Windows NT 10.0; Win64; x64) PowerShell")

Write-Host "Fetching download link for Google Drive file..."

$first = $client.GetAsync($Base).GetAwaiter().GetResult()
$downloadUri = $first.RequestMessage.RequestUri.AbsoluteUri

if ($first.Content.Headers.ContentType -and $first.Content.Headers.ContentType.MediaType -eq 'text/html') {
    $html = $first.Content.ReadAsStringAsync().GetAwaiter().GetResult()
    if ($html -match 'confirm=([0-9A-Za-z_]+)') {
        $token = $matches[1]
        $downloadUri = "https://drive.google.com/uc?export=download&confirm=$token&id=$FileId"
    } elseif ($html -match 'href="(/uc\?export=download[^"]+)"') {
        $href = $matches[1].Replace('&amp;','&')
        $downloadUri = "https://drive.google.com$href"
    }
}

Write-Host "Downloading file..."
$request = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Get, $downloadUri)
$response = $client.SendAsync($request, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
$response.EnsureSuccessStatusCode()

$totalBytes = $response.Content.Headers.ContentLength
$inStream   = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
$outStream  = [System.IO.File]::Open($OutFile, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)

$buffer = New-Object byte[] (1MB)
$read = 0
$written = 0
$lastPct = -1

try {
    do {
        $read = $inStream.Read($buffer, 0, $buffer.Length)
        if ($read -gt 0) {
            $outStream.Write($buffer, 0, $read)
            $written += $read
            if ($totalBytes) {
                $pct = [int](($written / $totalBytes) * 100)
                if ($pct -ne $lastPct) {
                    Write-Progress -Activity "Downloading Google Drive file" -Status "$pct% ($([Math]::Round($written/1MB,1)) MB of $([Math]::Round($totalBytes/1MB,1)) MB)" -PercentComplete $pct
                    $lastPct = $pct
                }
            }
        }
    } while ($read -gt 0)
}
finally {
    $outStream.Dispose()
    $inStream.Dispose()
    $client.Dispose()
}

Write-Progress -Activity "Downloading" -Completed
Write-Host "Download complete. Saved to: $OutFile"
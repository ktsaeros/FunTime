# Win11.ps1 — minimal, self-contained Google Drive download for PS 5.1
# Works with irm/iex.  No params needed.

# --- Hard-coded values ---
$Url     = "https://drive.google.com/file/d/1UoLlZYiKSUlwGwTtAc0QWCo30DM-dUIP/view?usp=sharing"
$OutFile = "C:\Aeros\AerosWin11.iso"
# -------------------------

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try { $null = [System.Net.Http.HttpClient] } catch { Add-Type -AssemblyName System.Net.Http }

# Make sure target folder exists
$dir = [IO.Path]::GetDirectoryName($OutFile)
if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

function Get-DriveFileId {
    param([string]$u)
    if ($u -match '/file/d/([A-Za-z0-9_-]+)') { return $matches[1] }
    if ($u -match '[?&]id=([A-Za-z0-9_-]+)')   { return $matches[1] }
    throw "Could not extract Google Drive file ID from URL: $u"
}

$FileId = Get-DriveFileId $Url
$Base   = "https://drive.google.com/uc?export=download&id=$FileId"

$h = New-Object System.Net.Http.HttpClientHandler
$h.AllowAutoRedirect = $true
$h.UseCookies = $true
$h.CookieContainer = New-Object System.Net.CookieContainer

$c = New-Object System.Net.Http.HttpClient($h)
$c.DefaultRequestHeaders.Add("User-Agent","Mozilla/5.0 (Windows NT 10.0; Win64; x64) PowerShell")

Write-Host "Requesting file metadata..."
$r = $c.GetAsync($Base).GetAwaiter().GetResult()
$dl = $r.RequestMessage.RequestUri.AbsoluteUri

if ($r.Content.Headers.ContentType -and $r.Content.Headers.ContentType.MediaType -eq 'text/html') {
    $html = $r.Content.ReadAsStringAsync().GetAwaiter().GetResult()
    if ($html -match 'confirm=([0-9A-Za-z_]+)') {
        $t = $matches[1]
        $dl = "https://drive.google.com/uc?export=download&confirm=$t&id=$FileId"
    } elseif ($html -match 'href="(/uc\?export=download[^"]+)"') {
        $href = $matches[1] -replace '&amp;','&'
        $dl = "https://drive.google.com$href"
    }
}

Write-Host "Downloading to $OutFile ..."
$req  = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Get,$dl)
$res  = $c.SendAsync($req,[System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
$res.EnsureSuccessStatusCode()

$total = $res.Content.Headers.ContentLength
$inS   = $res.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
$outS  = [IO.File]::Open($OutFile,[IO.FileMode]::Create,[IO.FileAccess]::Write,[IO.FileShare]::None)

$buf = New-Object byte[] 1048576
$done = 0; $last = -1
try {
  while (($read = $inS.Read($buf,0,$buf.Length)) -gt 0) {
    $outS.Write($buf,0,$read)
    $done += $read
    if ($total) {
      $pct = [int](($done/$total)*100)
      if ($pct -ne $last) {
        Write-Progress -Activity "Downloading" -Status "$pct% ($([Math]::Round($done/1MB,1)) MB of $([Math]::Round($total/1MB,1)) MB)" -PercentComplete $pct
        $last = $pct
      }
    }
  }
}
finally { $outS.Dispose(); $inS.Dispose(); $c.Dispose() }

Write-Progress -Activity "Downloading" -Completed
Write-Host "Download complete — saved to $OutFile"
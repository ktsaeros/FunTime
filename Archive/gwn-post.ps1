<#
gwn-post.ps1 — BelMonitor verify (PS 5.1)
- Restarts BelMonitorService (unless -NoRestart)
- Finds newest .bci, BelNotify.log, History*.log (handles rotation)
- Parses History*.log for POSTw(status=200) in last 7 days (handles single and multi-line log entries)
- Connectivity checks to gwn/aws2/belarc
- Result = OK only if upload verified within past 7 days

FIXED:
1. Corrected main parser (Section 5) to handle single-line log entries.
2. Corrected fallback parser (Section 5) regex typo.
#>

[CmdletBinding()]
param(
  [switch]$NoRestart,
  [int]$TimeoutSec = 360,            # wait up to 6 min for fresh artifacts
  [int]$FreshMins  = 15,             # consider .bci "fresh" if <= this many minutes
  [int]$WarnAgeMinutes = 10080,      # 7 days; warn only if age > this (for .bci staleness display)
  [string]$OutCsv
)

function Find-Newest {
  param([string[]]$Roots,[string]$Filter)
  $hits=@()
  foreach($r in $Roots){ try{ $hits+=Get-ChildItem -Path $r -Filter $Filter -Recurse -ErrorAction SilentlyContinue -Force }catch{} }
  if($hits){ $hits | Sort-Object LastWriteTime -Descending | Select-Object -First 1 } else { $null }
}

function Format-Age {
  param([int]$Minutes)
  if ($Minutes -eq $null) { return $null }
  $ts = [TimeSpan]::FromMinutes($Minutes)
  if ($ts.TotalDays -ge 1) { '{0}d {1}h {2}m' -f [int]$ts.TotalDays, $ts.Hours, $ts.Minutes }
  elseif ($ts.TotalHours -ge 1) { '{0}h {1}m' -f [int]$ts.TotalHours, $ts.Minutes }
  else { '{0}m' -f $ts.Minutes }
}

# 1) Service + base path
$svc = Get-CimInstance Win32_Service -Filter "Name='BelMonitorService'" -ErrorAction SilentlyContinue
if (-not $svc) {
  $o = [pscustomobject]@{ ComputerName=$env:COMPUTERNAME; Result="ERROR - BelMonitorService not found" }
  if ($OutCsv) { $o | Export-Csv -Append -NoTypeInformation -Path $OutCsv }
  $o | Format-List
  exit 1
}

$binPath = ($svc.PathName -replace '^"|"$','')
$baseDir = Split-Path $binPath -Parent

# 2) Candidate roots
$candidates = @(
  $baseDir,
  "C:\Program Files (x86)\Belarc\BelMonitor",
  "C:\Program Files\Belarc\BelMonitor",
  "C:\ProgramData\Belarc\BelMonitor",
  "C:\ProgramData\SecuritySnapshot",
  "C:\Aeros"
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

# 3) Restart (unless suppressed)
if ($NoRestart) {
  # no-op
} else {
  if ($svc.State -ne 'Running') { Start-Service BelMonitorService }
  else { Restart-Service BelMonitorService -Force }
}

# 4) Poll for newest .bci / logs
$sw = [Diagnostics.Stopwatch]::StartNew()
$newestBci=$null; $logItem=$null; $histItem=$null
do {
  if(-not $newestBci){ $newestBci = Find-Newest -Roots $candidates -Filter '*.bci' }
  if(-not $logItem){   $logItem   = Find-Newest -Roots $candidates -Filter 'BelNotify.log' }
  if(-not $histItem){  $histItem  = Find-Newest -Roots $candidates -Filter 'History.log' }
  if($newestBci){ break }
  Start-Sleep 5
} while ($sw.Elapsed.TotalSeconds -lt $TimeoutSec)

# 5) Parse History*.log (handles rotation + 2-line entries)
$non200 = $null
$firstConnect = $null
$lastPostTime = $null
$lastPostHost = $null
$lastPostPath = $null
$events = @()

if ($histItem -and (Test-Path $histItem.FullName)) {
  $histDir = Split-Path $histItem.FullName -Parent
  $histFiles = Get-ChildItem -Path $histDir -Filter 'History*.log' -ErrorAction SilentlyContinue |
               Sort-Object LastWriteTime

  # stateful parse: $curTime holds timestamp from a preceding line
  $curTime = $null
  foreach ($hf in $histFiles) {
    $lines = @()
    try { $lines = Get-Content $hf.FullName -ErrorAction SilentlyContinue } catch {}
    
    foreach ($line in $lines) {

      # 1) Timestamp line only (starts a 2-line entry)
      if ($line -match '^(?<dt>\d{2}/\d{2}/\d{2,4}\s+\d{2}:\d{2}:\d{2})\s*-\s*$') {
        $curTime = $null
        foreach($f in @('MM/dd/yy HH:mm:ss','MM/dd/yyyy HH:mm:ss')) {
          try { $curTime = [datetime]::ParseExact($matches.dt,$f,$null); break } catch {}
        }
        continue # Go to next line (which should be the action)
      }

      # 2) Single-line format (timestamp + action on same line)
      #    FIX: Added logic to this block
      if ($line -match '^(?<dt>\d{2}/\d{2}/\d{2,4}\s+\d{2}:\d{2}:\d{2})\s+-\s+.*?(?<verb>GETw|POSTw)\(status=(?<code>\d{3})\)\s+(?<file>\S+)\s+(?<dir><--|-->)\s+(?<url>\S+)$') {
        
        $dt = $null
        foreach($f in @('MM/dd/yy HH:mm:ss','MM/dd/yyyy HH:mm:ss')) {
          try { $dt = [datetime]::ParseExact($matches.dt,$f,$null); break } catch {}
        }
        
        if ($dt) {
          $host = $null
          $path = $null
          try { $u = [uri]$matches.url; $host = $u.Host; $path = $u.AbsolutePath } catch {}

          $events += [pscustomobject]@{
            Time = $dt
            Verb = $matches.verb
            Code = [int]$matches.code
            File = $matches.file
            Dir  = $matches.dir
            Url  = $matches.url
            Host = $host
            Path = $path
          }
        }
        $curTime = $null # Reset curTime, this was a self-contained line
        continue # Go to next line
      }

      # 3) Action line (completes a 2-line entry)
      if ($curTime -and $line -match '^(?<verb>GETw|POSTw)\(status=(?<code>\d{3})\)\s+(?<file>\S+)\s+(?<dir><--|-->)\s+(?<url>\S+)\s*$') {
        
        $host = $null
        $path = $null
        try { $u = [uri]$matches.url; $host = $u.Host; $path = $u.AbsolutePath } catch {}

        $events += [pscustomobject]@{
          Time = $curTime
          Verb = $matches.verb
          Code = [int]$matches.code
          File = $matches.file
          Dir  = $matches.dir
          Url  = $matches.url
          Host = $host
          Path = $path
        }
        $curTime = $null # Reset curTime, 2-line entry is complete
        continue # Go to next line
      }
      
      # 4) Unrecognized line, reset $curTime just in case
      #    (prevents a timestamp from applying to an unrelated, later action line)
      if (-not ($line -match '^\s*$')) { # ignore blank lines
          $curTime = $null
      }

    } # end foreach line
  }   # end foreach file

  if ($events) {
    $non200       = ($events | Where-Object { $_.Code -ne 200 }).Count
    $firstConnect = ($events | Where-Object { $_.Verb -eq 'GETw' -and $_.File -eq 'connect.bcf' } | Select-Object -First 1).Time
    $lastPostObj  = ($events | Where-Object { $_.Verb -eq 'POSTw' -and $_.Code -eq 200 -and $_.File -like '*.bci' } |
                     Sort-Object Time | Select-Object -Last 1)
    if ($lastPostObj) {
      $lastPostTime = $lastPostObj.Time
      $lastPostHost = $lastPostObj.Host
      $lastPostPath = $lastPostObj.Path
    }
  }
}

$elapsedSec = $null
if ($firstConnect -and $lastPostTime) { $elapsedSec = [int]($lastPostTime - $firstConnect).TotalSeconds }

# --- Fallback: fast grep across History*.log for POST 200 ---
if (-not $lastPostTime -and $histItem) {
  $histDir = Split-Path $histItem.FullName -Parent
  $hits = @()
  try {
    # FIX: Corrected regex from '$begin:math:text$status=200$end:math:text$' to '\(status=200\)'
    $hits = Select-String -Path (Join-Path $histDir 'History*.log') `
      -Pattern '^(?<ts>\d{2}/\d{2}/\d{2,4}\s+\d{2}:\d{2}:\d{2})\s+-\s+POSTw\(status=200\)\s+(?<file>\S+)\s+-->\s+(?<url>\S+)' `
      -AllMatches -ErrorAction SilentlyContinue
  } catch {}

  if ($hits) {
    $last = $null
    foreach ($m in $hits.Matches) {
      $dt = $null
      foreach ($f in @('MM/dd/yy HH:mm:ss','MM/dd/yyyy HH:mm:ss')) {
        try { $dt = [datetime]::ParseExact($m.Groups['ts'].Value,$f,$null); break } catch {}
      }
      if ($dt -and ( -not $last -or $dt -gt $last.Time )) {
        $last = [pscustomobject]@{
          Time = $dt
          Url  = $m.Groups['url'].Value
        }
      }
    }
    if ($last) {
      $lastPostTime = $last.Time
      try {
        $u = [uri]$last.Url
        $lastPostHost = $u.Host
        $lastPostPath = $u.AbsolutePath
      } catch {}
    }
  }
}


# 5b) Upload status — require POST within 7 days
$uploadStatus = if ($lastPostTime) {
  $ageDays = [math]::Round(((Get-Date) - $lastPostTime).TotalDays, 1)
  if ($ageDays -le 7) {
    "SUCCESS - report uploaded {0} ({1} days ago) via {2}{3}" -f $lastPostTime, $ageDays, $lastPostHost, $lastPostPath
  } else {
    "STALE - last upload {0} ({1} days ago > 7d)" -f $lastPostTime, $ageDays
  }
} else {
  "NO UPLOAD DETECTED in History*.log (no POSTw status=200 found)"
}

# 6) Connectivity checks
$e_gwn  = (Test-NetConnection gwn.secsnapreporting.com  -Port 443 -WarningAction SilentlyContinue).TcpTestSucceeded
$e_aws2 = (Test-NetConnection aws2.secsnapreporting.com -Port 443 -WarningAction SilentlyContinue).TcpTestSucceeded
$e_bel  = (Test-NetConnection belarc.com                -Port 443 -WarningAction SilentlyContinue).TcpTestSucceeded

# 7) Result — PASS only if upload verified in last 7 days
$svc2 = Get-Service BelMonitorService -ErrorAction SilentlyContinue
$ageMin  = if ($newestBci) { [int]((Get-Date) - $newestBci.LastWriteTime).TotalMinutes } else { $null }
$ageDisp = Format-Age -Minutes $ageMin

$result =
  if ($svc2.Status -ne 'Running') { "ERROR - service not running" }
  elseif (-not $lastPostTime)     { "FAIL - no upload found in History*.log" }
  elseif (((Get-Date) - $lastPostTime).TotalDays -le 7) { "OK - upload verified within past 7 days" }
  else { "WARN - upload older than 7 days" }

# 8) Output
$out = [pscustomobject]@{
  ComputerName     = $env:COMPUTERNAME
  ServiceState     = $svc2.Status
  ServiceBinary    = $binPath
  BciFile          = if ($newestBci) { $newestBci.FullName } else { $null }
  BciTimestamp     = if ($newestBci) { $newestBci.LastWriteTime } else { $null }
  BciAgeMinutes    = $ageMin
  BciAgeDisplay    = $ageDisp
  LogPath          = if ($logItem)   { $logItem.FullName }   else { $null }
  HistoryPath      = if ($histItem)  { (Split-Path $histItem.FullName -Parent) + "\History*.log" } else { $null }
  Hist_Non200      = $non200
  Hist_Connect     = $firstConnect
  Hist_LastPost    = $lastPostTime
  Hist_UploadHost  = $lastPostHost
  Hist_UploadPath  = $lastPostPath
  Hist_ElapsedSec  = $elapsedSec
  Egress_gwn443    = $e_gwn
  Egress_aws2443   = $e_aws2
  Egress_belarc443 = $e_bel
  UploadStatus     = $uploadStatus
  Result           = $result
}

if ($OutCsv) { $out | Export-Csv -Append -NoTypeInformation -Path $OutCsv }
$out | Format-List

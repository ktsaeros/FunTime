<# 
.SYNOPSIS
  Collects Windows Event Viewer entries around a specified incident time and (optionally) runs a headless
  WinDbg/CDB analysis on a provided .dmp.

.EXAMPLE
  .\Get-IncidentEvents.ps1 -IncidentTime '2025-10-02 18:48:20' -BeforeMinutes 10 -AfterMinutes 5 `
    -DumpPath 'C:\dumps\100325-16750-01.dmp' -AnalyzeDump
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [datetime]$IncidentTime,

  [int]$BeforeMinutes = 10,
  [int]$AfterMinutes  = 5,

  [string[]]$Logs = @('System','Application'),

  [switch]$AllProviders,   # show everything in the window (not just common fault sources)
  [string]$OutDir = (Join-Path $env:USERPROFILE ("Desktop\Incident_{0:yyyyMMdd_HHmmss}" -f (Get-Date))),

  # Minidump options
  [string]$DumpPath,
  [switch]$AnalyzeDump,

  # Optional custom symbol path for dump analysis
  [string]$SymbolPath = 'srv*C:\Symbols*https://msdl.microsoft.com/download/symbols'
)

# --- Setup & helpers ---
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$windowStart = $IncidentTime.AddMinutes(-[math]::Abs($BeforeMinutes))
$windowEnd   = $IncidentTime.AddMinutes([math]::Abs($AfterMinutes))

Write-Host "Incident time: $IncidentTime"
Write-Host "Window: $($windowStart)  ->  $($windowEnd)"
Write-Host "Output: $OutDir" -ForegroundColor Cyan

function Save-Events {
  param(
    [string]$Log,
    [datetime]$Start,
    [datetime]$End,
    [string]$PathBase,
    [switch]$OnlyCommonProviders
  )

  Write-Host "Collecting $Log events..." -ForegroundColor Yellow
  $filter = @{
    LogName   = $Log
    StartTime = $Start
    EndTime   = $End
  }

  $events = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue

  if($OnlyCommonProviders){
    $providers = @(
      'Microsoft-Windows-Kernel-Power',     # 41, 42, 105
      'EventLog',                           # 6008
      'User32',                             # 1074 (planned)
      'Microsoft-Windows-WHEA-Logger',      # 1, 17, 18
      'Microsoft-Windows-Kernel-General',   # 12, 13 (time change, etc.)
      'Microsoft-Windows-Kernel-Boot',
      'Microsoft-Windows-ACPI',
      'Microsoft-Windows-Kernel-Thermal',
      'disk', 'Ntfs', 'volmgr', 'partmgr', 'storahci', 'storport'
    )
    $events = $events | Where-Object { $_.ProviderName -in $providers }
  }

  $expanded = $events | Select-Object TimeCreated, Id, LevelDisplayName,
                                    ProviderName, TaskDisplayName, OpcodeDisplayName,
                                    @{n='RecordId';e={$_.RecordId}},
                                    @{n='MachineName';e={$_.MachineName}},
                                    @{n='Message';e={$_.Message}}

  $csv = Join-Path $PathBase "$Log.csv"
  $txt = Join-Path $PathBase "$Log.txt"

  $expanded | Sort-Object TimeCreated | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csv
  $expanded | Sort-Object TimeCreated | Format-Table -AutoSize | Out-String -Width 4096 | Set-Content -Path $txt -Encoding UTF8

  # Focused views with common IDs
  $focusSets = @{
    'KernelPower_41_42_6008_1074' = { ($_.ProviderName -eq 'Microsoft-Windows-Kernel-Power' -and $_.Id -in 41,42,105) -or
                                      ($_.ProviderName -eq 'EventLog' -and $_.Id -eq 6008) -or
                                      ($_.ProviderName -eq 'User32' -and $_.Id -eq 1074) }
    'WHEA_1_17_18'                = { $_.ProviderName -eq 'Microsoft-Windows-WHEA-Logger' -and $_.Id -in 1,17,18 }
    'Disk_NTFS_VolMgr'            = { $_.ProviderName -in 'disk','Ntfs','volmgr','partmgr' }
    'Thermal_ACPI'                = { $_.ProviderName -in 'Microsoft-Windows-Kernel-Thermal','Microsoft-Windows-ACPI' }
  }

  foreach($name in $focusSets.Keys){
    $subset = $expanded | Where-Object $focusSets[$name]
    if($subset){
      $subset | Sort-Object TimeCreated |
        Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $PathBase "$($Log)_$name.csv")
    }
  }

  # Also dump raw objects for scripting follow-ups
  $json = Join-Path $PathBase "$Log.raw.json"
  $events | ConvertTo-Json -Depth 6 | Set-Content -Path $json -Encoding UTF8
}

# --- Collect events for each requested log ---
foreach($log in $Logs){
  $base = Join-Path $OutDir $log
  New-Item -ItemType Directory -Force -Path $base | Out-Null

  # Full set in the window
  Save-Events -Log $log -Start $windowStart -End $windowEnd -PathBase $base -OnlyCommonProviders:(!$AllProviders)

  # Nice quick summaries
  try{
    $summary = Get-WinEvent -FilterHashtable @{ LogName=$log; StartTime=$windowStart; EndTime=$windowEnd } `
                | Group-Object ProviderName `
                | Sort-Object Count -Descending `
                | Select-Object Name,Count
    $summary | Format-Table -AutoSize | Out-String | Set-Content (Join-Path $base "ProviderSummary.txt")
  } catch {}
}

# --- Windows reliability snapshot (optional, if available) ---
try {
  $relOut = Join-Path $OutDir 'ReliabilityHistory.txt'
  wevtutil qe Microsoft-Windows-Reliability-Operational /q:"*[System[TimeCreated[@SystemTime>='$($windowStart.ToUniversalTime().ToString("o"))' and @SystemTime<='$($windowEnd.ToUniversalTime().ToString("o"))']]]" /f:text /c:999999 | `
    Set-Content -Path $relOut -Encoding UTF8
} catch {}

# --- System minidump handling ---
if($DumpPath){
  $dumpInfo = [pscustomobject]@{
    DumpPath  = (Resolve-Path $DumpPath).Path
    Exists    = (Test-Path $DumpPath)
    SizeBytes = (if(Test-Path $DumpPath){ (Get-Item $DumpPath).Length } else { $null })
    Created   = (if(Test-Path $DumpPath){ (Get-Item $DumpPath).CreationTime } else { $null })
    SHA256    = (if(Test-Path $DumpPath){ (Get-FileHash -Algorithm SHA256 -Path $DumpPath).Hash } else { $null })
  }
  $dumpInfo | Format-List | Out-String | Set-Content -Path (Join-Path $OutDir 'DumpInfo.txt')

  if($AnalyzeDump -and (Test-Path $DumpPath)){
    Write-Host "Attempting headless dump analysis..." -ForegroundColor Cyan
    $dbgOut = Join-Path $OutDir ('DumpAnalysis_{0:yyyyMMdd_HHmmss}.txt' -f (Get-Date))

    # Try CDB first (part of Windows SDK), then WinDbgX
    $cdbCandidates = @(
      "$Env:ProgramFiles(x86)\Windows Kits\10\Debuggers\x64\cdb.exe",
      "$Env:ProgramFiles\Windows Kits\10\Debuggers\x64\cdb.exe"
    ) | Where-Object { Test-Path $_ }

    $windbgxCandidates = @(
      "$Env:LOCALAPPDATA\Microsoft\WindowsApps\WinDbgX.exe",
      "$Env:LOCALAPPDATA\Microsoft\WindowsApps\windbgx.exe"
    ) | Where-Object { Test-Path $_ }

    $dbgArgsCdb    = @("-z", "`"$DumpPath`"", "-y", "`"$SymbolPath`"", "-c", "!analyze -v; .ecxr; kv; lm; q")
    $dbgArgsWinDbg = @("-z", "`"$DumpPath`"", "-y", "`"$SymbolPath`"", "-c", "!analyze -v; .ecxr; kv; lm; q")

    $ran = $false
    if($cdbCandidates.Count -gt 0){
      & $cdbCandidates[0] @dbgArgsCdb | Tee-Object -FilePath $dbgOut
      $ran = $true
    } elseif ($windbgxCandidates.Count -gt 0) {
      & $windbgxCandidates[0] @dbgArgsWinDbg | Tee-Object -FilePath $dbgOut
      $ran = $true
    }

    if(-not $ran){
      "Debugging tools not found. Install Windows SDK (Debugging Tools) or WinDbg Preview, then re-run with -AnalyzeDump." `
        | Set-Content -Path $dbgOut -Encoding UTF8
    }
  }
}

# --- Quick on-screen summary ---
Write-Host "`nDone. Collected logs are in: $OutDir" -ForegroundColor Green
Write-Host "Files include: <System|Application>.csv/.txt, focused CSVs, raw JSON, ProviderSummary.txt."
if($DumpPath){
  Write-Host "Dump details: DumpInfo.txt. If analysis ran, see DumpAnalysis_*.txt." -ForegroundColor Green
}
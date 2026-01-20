<# 
.SYNOPSIS
  Collects logs around a specific time. 
  Interactive Mode added for AerosMaster Menu.
  v2: Fixed RMM crash, added console preview, changed path to C:\Aeros.
#>

[CmdletBinding()]
param(
  [datetime]$IncidentTime,
  [int]$BeforeMinutes = 10,
  [int]$AfterMinutes  = 5,
  [string]$BaseDir = "C:\Aeros\Incidents"
)

# --- INTERACTIVE MODE (For Menu Usage) ---
if (-not $IncidentTime -or $IncidentTime -eq [datetime]::MinValue) {
    Write-Host "--- INCIDENT LOG COLLECTOR ---" -ForegroundColor Cyan
    Write-Host "Enter the approximate time the issue occurred." -ForegroundColor Gray
    Write-Host "Examples: '14:30', '10/25 8:00 PM', or hit Enter for NOW." -ForegroundColor Gray
    
    $inputTime = Read-Host "Incident Time"
    if ([string]::IsNullOrWhiteSpace($inputTime)) {
        $IncidentTime = Get-Date
    } else {
        try {
            $IncidentTime = [datetime]$inputTime
        } catch {
            Write-Error "Could not parse time. Using current time."
            $IncidentTime = Get-Date
        }
    }
}
# ------------------------------------------

$ErrorActionPreference = 'SilentlyContinue'
$TimeStampName = $IncidentTime.ToString("yyyyMMdd_HHmmss")
$OutDir = Join-Path $BaseDir "Incident_$TimeStampName"

# Create Directory
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }

$windowStart = $IncidentTime.AddMinutes(-[math]::Abs($BeforeMinutes))
$windowEnd   = $IncidentTime.AddMinutes([math]::Abs($AfterMinutes))

Write-Host "Targeting: $IncidentTime" -ForegroundColor Yellow
Write-Host "Collecting System & Application logs ($BeforeMinutes min before, $AfterMinutes min after)..." -ForegroundColor Cyan

# 1. Collect Logs
$AllEvents = @()
foreach ($log in @('System','Application')) {
    $path = Join-Path $OutDir "$log.csv"
    
    $events = Get-WinEvent -FilterHashtable @{LogName=$log; StartTime=$windowStart; EndTime=$windowEnd} -ErrorAction SilentlyContinue 
    
    if ($events) {
        $events | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message | Export-Csv -NoTypeInformation -Path $path
        $AllEvents += $events
    }
}

# 2. Collect Reliability History (Optional context)
try {
    Get-CimInstance Win32_ReliabilityRecords -Filter "TimeGenerated >= '$($windowStart.ToString('yyyyMMddHHmmss.000000-000'))'" |
    Select TimeGenerated, SourceName, Message | 
    Export-Csv (Join-Path $OutDir "Reliability.csv")
} catch {}

Write-Host "`n[SUCCESS] Logs saved to: $OutDir" -ForegroundColor Green

# 3. Console Preview (The "Read on screen" feature)
if ($AllEvents) {
    $Criticals = $AllEvents | Where-Object { $_.LevelDisplayName -match "Error|Critical|Warning" } | Sort-Object TimeCreated
    
    if ($Criticals) {
        Write-Host "`n--- INSTANT REPLAY (Errors & Warnings) ---" -ForegroundColor Red
        $Criticals | Select-Object TimeCreated, LogName, Id, Message | Format-Table -AutoSize | Out-String | Write-Host
        Write-Host "(Full details saved to CSV)" -ForegroundColor Gray
    } else {
        Write-Host "`n[OK] No Errors or Warnings found in this time window." -ForegroundColor Green
    }
} else {
    Write-Host "`n[INFO] No events found in this time window." -ForegroundColor Gray
}
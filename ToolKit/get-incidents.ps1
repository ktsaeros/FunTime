<# 
.SYNOPSIS
  Collects logs around a specific time. 
  Interactive Mode added for AerosMaster Menu.
#>

[CmdletBinding()]
param(
  [datetime]$IncidentTime,
  [int]$BeforeMinutes = 10,
  [int]$AfterMinutes  = 5,
  [string]$OutDir = (Join-Path $env:USERPROFILE ("Desktop\Incident_{0:yyyyMMdd_HHmmss}" -f (Get-Date)))
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
    Write-Host "Targeting: $IncidentTime" -ForegroundColor Yellow
}
# ------------------------------------------

$ErrorActionPreference = 'SilentlyContinue'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$windowStart = $IncidentTime.AddMinutes(-[math]::Abs($BeforeMinutes))
$windowEnd   = $IncidentTime.AddMinutes([math]::Abs($AfterMinutes))

Write-Host "Collecting System & Application logs ($BeforeMinutes min before, $AfterMinutes min after)..." -ForegroundColor Cyan

# Define critical providers
$providers = @('Microsoft-Windows-Kernel-Power', 'EventLog', 'User32', 'Microsoft-Windows-WHEA-Logger', 'disk', 'Ntfs', 'volmgr')

foreach ($log in @('System','Application')) {
    $path = Join-Path $OutDir "$log.csv"
    Get-WinEvent -FilterHashtable @{LogName=$log; StartTime=$windowStart; EndTime=$windowEnd} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message |
    Export-Csv -NoTypeInformation -Path $path
}

# Grab Reliability History
try {
    Get-CimInstance Win32_ReliabilityRecords -Filter "TimeGenerated >= '$($windowStart.ToString('yyyyMMddHHmmss.000000-000'))'" |
    Select TimeGenerated, SourceName, Message | 
    Export-Csv (Join-Path $OutDir "Reliability.csv")
} catch {}

Write-Host "`nDone. Logs saved to: $OutDir" -ForegroundColor Green
Invoke-Item $OutDir
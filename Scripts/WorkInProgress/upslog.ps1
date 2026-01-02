<#  Save as: C:\Tools\UPS-Transition-Logger.ps1
    Usage (typical):  .\UPS-Transition-Logger.ps1 -IntervalSeconds 2 -OutCsv "C:\ProgramData\UPS\ups_log.csv"
    Optional:         .\UPS-Transition-Logger.ps1 -IntervalSeconds 5 -LogAll
#>

param(
  [int]$IntervalSeconds = 2,
  [string]$OutCsv = "C:\ProgramData\UPS\ups_log.csv",
  [switch]$LogAll
)

# --- Initialization ---
# Load once (not per-iteration)
Add-Type -AssemblyName System.Windows.Forms | Out-Null

# Ensure output directory exists
$null = New-Item -ItemType Directory -Path (Split-Path $OutCsv) -Force -ErrorAction SilentlyContinue

# --- Helpers ---
function Write-CsvRow {
  param([psobject]$obj, [string]$path)

  $canAppend = $PSVersionTable.PSVersion.Major -ge 6
  if ($canAppend) {
    $exists = Test-Path $path
    $obj | Export-Csv -Path $path -NoTypeInformation -Append:($exists) -Force
  } else {
    if (Test-Path $path) {
      # Append rows without header
      $obj | ConvertTo-Csv -NoTypeInformation | Select-Object -Skip 1 | Add-Content -Path $path
    } else {
      # First write includes header
      $obj | Export-Csv -Path $path -NoTypeInformation -Force
    }
  }
}

function Get-UpsSnapshot {
  # 1) .NET power source (Online/Offline/Unknown)
  $ps   = [System.Windows.Forms.SystemInformation]::PowerStatus
  $ac   = $ps.PowerLineStatus.ToString() # Online | Offline | Unknown
  $pct  = [math]::Round($ps.BatteryLifePercent * 100, 0)
  $minNet = if ($ps.BatteryLifeRemaining -ge 0) { [math]::Round($ps.BatteryLifeRemaining / 60, 0) } else { $null }

  # 2) WMI battery (UPS often shows up here)
  $wb = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue

  # Prefer APC by VID or name, else first available
  $dev =
    $wb | Where-Object { $_.PNPDeviceID -match 'VID_051D' -or $_.Name -match 'American Power Conversion' } |
      Select-Object -First 1
  if (-not $dev -and $wb) { $dev = $wb | Select-Object -First 1 }

  $src   = if ($dev) { $dev.Name } else { 'N/A' }
  $bstat = if ($dev) { $dev.BatteryStatus } else { $null }  # 1=Discharging, 2=AC, 3=Full, 6=Charging...

  # Use WMI EstimatedRunTime if present and >= 0, else fall back to .NET minutes
  $estWmi = if ($dev -and $null -ne $dev.EstimatedRunTime -and [int]$dev.EstimatedRunTime -ge 0) { [int]$dev.EstimatedRunTime } else { $null }
  $est    = if ($null -ne $estWmi) { $estWmi } else { $minNet }

  # Decide high-level state
  $state =
    if ($ac -eq 'Offline' -or $bstat -eq 1) { 'OnBattery' }
    elseif ($ac -eq 'Online' -or $bstat -in 2,3,6) { 'OnLine' }
    else { 'Unknown' }

  # Build object (no manual CSV string building)
  [pscustomobject]@{
    Timestamp     = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    State         = $state
    ACLine        = $ac
    Percent       = $pct
    EstMinutes    = $est
    SourceDevice  = $src
    BatteryStatus = $bstat
    RawNote       = if ($dev) { "DesignV=$($dev.DesignVoltage); Status=$($dev.Status)" } else { '' }
  }
}

# --- Main loop ---
$lastState = $null
Write-Host "UPS transition logger started. Interval: $IntervalSeconds s. Output: $OutCsv"
while ($true) {
  $snap = Get-UpsSnapshot

  $shouldWrite = $LogAll.IsPresent -or ($snap.State -ne $lastState)
  if ($shouldWrite) {
    Write-CsvRow -obj $snap -path $OutCsv
    Write-Host ("{0}  {1}  AC={2}  {3}%  {4} min  [{5}]" -f $snap.Timestamp,$snap.State,$snap.ACLine,$snap.Percent,$snap.EstMinutes,$snap.SourceDevice)
    $lastState = $snap.State
  }

  Start-Sleep -Seconds $IntervalSeconds
}
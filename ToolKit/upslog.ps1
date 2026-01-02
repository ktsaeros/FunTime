<#  
    Save as: C:\Aeros\upslog.ps1
    Role: UPS Logger & RMM Snapshot Tool
#>

param(
  [int]$IntervalSeconds = 5,
  [string]$OutCsv = "C:\Aeros\ups_log.csv",
  [switch]$LogAll,
  [switch]$Install,  # New switch to set up persistence
  [switch]$Snapshot  # Force single run (default behavior if not installing)
)

# --- Initialization ---
Add-Type -AssemblyName System.Windows.Forms | Out-Null
if (-not (Test-Path (Split-Path $OutCsv))) { New-Item -ItemType Directory -Path (Split-Path $OutCsv) -Force | Out-Null }

# --- Helpers ---
function Get-UpsSnapshot {
  $ps   = [System.Windows.Forms.SystemInformation]::PowerStatus
  $ac   = $ps.PowerLineStatus.ToString()
  $pct  = [math]::Round($ps.BatteryLifePercent * 100, 0)
  $minNet = if ($ps.BatteryLifeRemaining -ge 0) { [math]::Round($ps.BatteryLifeRemaining / 60, 0) } else { $null }

  $wb = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue
  $dev = $wb | Where-Object { $_.PNPDeviceID -match 'VID_051D' -or $_.Name -match 'American Power Conversion' } | Select-Object -First 1
  if (-not $dev -and $wb) { $dev = $wb | Select-Object -First 1 }

  $src   = if ($dev) { $dev.Name } else { 'N/A' }
  $bstat = if ($dev) { $dev.BatteryStatus } else { $null }
  $estWmi = if ($dev -and $null -ne $dev.EstimatedRunTime -and [int]$dev.EstimatedRunTime -ge 0) { [int]$dev.EstimatedRunTime } else { $null }
  $est    = if ($null -ne $estWmi) { $estWmi } else { $minNet }

  $state = if ($ac -eq 'Offline' -or $bstat -eq 1) { 'OnBattery' } elseif ($ac -eq 'Online' -or $bstat -in 2,3,6) { 'OnLine' } else { 'Unknown' }

  [pscustomobject]@{
    Timestamp     = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    State         = $state
    ACLine        = $ac
    Percent       = $pct
    EstMinutes    = $est
    SourceDevice  = $src
    BatteryStatus = $bstat
  }
}

function Write-CsvRow {
  param([psobject]$obj, [string]$path)
  $canAppend = $PSVersionTable.PSVersion.Major -ge 6
  if ($canAppend) {
    $exists = Test-Path $path
    $obj | Export-Csv -Path $path -NoTypeInformation -Append:($exists) -Force
  } else {
    if (Test-Path $path) {
      $obj | ConvertTo-Csv -NoTypeInformation | Select-Object -Skip 1 | Add-Content -Path $path
    } else {
      $obj | Export-Csv -Path $path -NoTypeInformation -Force
    }
  }
}

# --- Execution Logic ---

# 1. INSTALL MODE: Configure Scheduled Task
if ($Install) {
    $ScriptPath = "C:\Aeros\upslog.ps1"
    # Self-copy if running from temp (RMM usually downloads to Temp)
    if ($PSCommandPath -ne $ScriptPath) {
        Copy-Item $PSCommandPath $ScriptPath -Force
    }
    
    $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$ScriptPath`" -IntervalSeconds $IntervalSeconds"
    $Trigger = New-ScheduledTaskTrigger -AtStartup
    $Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0
    
    Register-ScheduledTask -TaskName "Aeros_UPS_Logger" -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force | Out-Null
    Write-Host "Success: Aeros_UPS_Logger installed to run at startup."
    exit
}

# 2. LOGGER MODE (Infinite Loop) - Only if explicitly NOT a snapshot
# We check if we are in a non-interactive session or intended for long-running
if (-not $Snapshot -and ($PSInvocation.MyCommand.Name -match "upslog.ps1")) {
   # If running simply as script, default to loop
   $lastState = $null
   Write-Host "Starting Continuous Log..."
   while ($true) {
      $snap = Get-UpsSnapshot
      $shouldWrite = $LogAll.IsPresent -or ($snap.State -ne $lastState)
      if ($shouldWrite) {
        Write-CsvRow -obj $snap -path $OutCsv
        $lastState = $snap.State
      }
      Start-Sleep -Seconds $IntervalSeconds
   }
}

# 3. SNAPSHOT MODE (Default for RMM manual run)
$snap = Get-UpsSnapshot
Write-Host ("RMM SNAPSHOT: {0} | AC: {1} | Bat: {2}% | Est: {3} min" -f $snap.State, $snap.ACLine, $snap.Percent, $snap.EstMinutes)
$snap | Format-List
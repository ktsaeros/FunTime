# === AEROS FORENSIC INVESTIGATOR v3.1 (Restored Slim) ===
# RMM 24x7 Check - 7 Day History / 24 Hour Alert
# FEATURE: Deduplicated History + PCIe Config + Reboot Attribution

$LogPath = "C:\ProgramData\Aeros\Logs\FlightData.csv"
$TempCopy = "$env:TEMP\FlightData_Analyzer.csv"

# --- CONFIGURATION ---
$HistoryDays = 7      # Visual Context
$AlertHours  = 24     # Ticket Trigger
$Diagnosis   = @()    # Collector for verdicts

Write-Host "--- SYSTEM PULSE (Alert Window: Last $AlertHours Hrs) ---"

# --- 1. STORAGE CAPACITY CHECK ---
$Vols = Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter }
foreach ($V in $Vols) {
    if ($V.SizeRemaining -lt 2GB) {
        $FreeMB = [math]::Round($V.SizeRemaining / 1MB, 0)
        Write-Host "CRITICAL SPACE: Drive $($V.DriveLetter) is FULL! ($FreeMB MB Free)" -ForegroundColor Red
        if ($V.SizeRemaining -lt 500MB) {
            $Diagnosis += "[SUSPECT] STORAGE SATURATION (Drive $($V.DriveLetter):). Drive is 100% full ($FreeMB MB free)."
        }
    }
}

# --- 2. ANALYZE FLIGHT DATA (Local Recorder) ---
if (Test-Path $LogPath) {
    try {
        Copy-Item $LogPath $TempCopy -Force -ErrorAction SilentlyContinue
        $Data = Import-Csv $TempCopy 
        if ($Data) {
            $LastEntry = [DateTime]$Data[-1].Timestamp
            $Gap = (New-TimeSpan -Start $LastEntry -End (Get-Date)).TotalMinutes
            
            if ($Gap -gt 20) {
                Write-Host "WARNING: Recorder stopped $Math::Round($Gap,0) mins ago (Possible Freeze)." -ForegroundColor Red
                $Diagnosis += "[SYMPTOM] SYSTEM FREEZE. Recorder log stopped unexpectedly."
            } else {
                Write-Host "Recorder:    Active (Last data: $LastEntry)" -ForegroundColor Green
            }

            $RecentData = $Data | Where-Object { [DateTime]$_.Timestamp -gt (Get-Date).AddHours(-$AlertHours) }
            if ($RecentData) {
                $HighCpu  = ($RecentData | Where-Object { [int]$_.CPU -gt 90 }).Count
                $HighRam  = ($RecentData | Where-Object { [int]$_.RAM -gt 90 }).Count
                $HighDisk = ($RecentData | Where-Object { [double]$_.DiskQ -gt 5.0 }).Count
                $NetDrops = ($RecentData | Where-Object { $_.Net -eq "DOWN" }).Count
                
                Write-Host "Violations:  CPU>90% [$HighCpu] | RAM>90% [$HighRam] | DiskQ>5 [$HighDisk] | NetDrops [$NetDrops]"
            }
        }
    } catch { Write-Host "Error parsing Flight Recorder CSV." }
} else { Write-Host "Flight Recorder Log missing." }

# --- 3. EVENT ANALYSIS & ATTRIBUTION ---
$Providers = @('Disk', 'Ntfs', 'stornvme', 'volmgr', 'BugCheck', 'Microsoft-Windows-Kernel-Power', 'Microsoft-Windows-WHEA-Logger', 'Microsoft-Windows-Kernel-Thermal')
$AllEvents = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName=$Providers; StartTime=(Get-Date).AddDays(-$HistoryDays); Level=1,2,3} -ErrorAction SilentlyContinue

$Shutdowns = Get-WinEvent -FilterHashtable @{LogName='System'; ID=1074; StartTime=(Get-Date).AddHours(-$AlertHours)} -ErrorAction SilentlyContinue

if ($AllEvents | Where-Object { $_.Message -match "Delayed Write Failed" }) { $Diagnosis += "[SUSPECT] EXTERNAL DRIVE FAILURE. Found 'Delayed Write Failed'." }
if ($AllEvents | Where-Object { $_.Message -match "paging operation" }) { $Diagnosis += "[SUSPECT] BOOT DRIVE INSTABILITY. Found Paging Errors." }
if ($AllEvents | Where-Object { $_.ProviderName -eq "Microsoft-Windows-WHEA-Logger" }) { $Diagnosis += "[SUSPECT] HARDWARE FAULT (WHEA)." }

# --- REBOOT FORENSICS (Last 24h) ---
$RebootEvents = $AllEvents | Where-Object { $_.Id -eq 41 -and $_.TimeCreated -gt (Get-Date).AddHours(-$AlertHours) }
if ($RebootEvents) {
    Write-Host "`n--- REBOOT FORENSICS (Last 24h) ---" -ForegroundColor Yellow
    foreach ($Reboot in $RebootEvents) {
        $RTime = $Reboot.TimeCreated
        $Clean = $Shutdowns | Where-Object { $_.TimeCreated -lt $RTime -and $_.TimeCreated -gt $RTime.AddMinutes(-5) } | Select-Object -First 1
        if ($Clean) {
            $User = if ($Clean.Message -match "user\s+([^\r\n]+)") { $Matches[1] } else { "System" }
            Write-Host "[$($RTime.ToString('HH:mm'))] REBOOT: Initiated by $User (Clean)." -ForegroundColor Green
        } else {
            Write-Host "[$($RTime.ToString('HH:mm'))] REBOOT: DIRTY SHUTDOWN (Manual Power Cycle or Crash)." -ForegroundColor Red
            $Diagnosis += "[SYMPTOM] DIRTY SHUTDOWN DETECTED."
        }
    }
}

# --- 4. CONFIG CHECK (PCIe) ---
$Scheme = (powercfg /getactivescheme).Split()[3]
$Raw = (powercfg /q $Scheme "501a4d13-42af-4429-9fd1-a8218c268e20" "ee12f906-25ea-4e32-9679-880e263438db" 2>$null | Out-String)
if ($Raw -match '0x00000002') { 
    Write-Host "`nCRITICAL CONFIG: PCIe Link State is 'Maximum Power Savings'." -ForegroundColor Red 
    $Diagnosis += "[SUSPECT] POWER CONFIG RISK. PCIe Link State is set to Max Power Savings."
}

# --- 5. PRINT HISTORY ---
# A. The Alert Zone (Last 24h)
$RecentEvents = $AllEvents | Where-Object { $_.TimeCreated -gt (Get-Date).AddHours(-$AlertHours) -and $_.Id -ne 41 }
Write-Host ""
if ($RecentEvents) {
    Write-Host "--- FLAG ALERTS (Last 24 Hrs) ---" -ForegroundColor Red
    $RecentEvents | ForEach-Object { Write-Host "[$($_.TimeCreated.ToString('HH:mm'))] [$($_.ProviderName)] $(($_.Message -split "`r?`n")[0].Trim())" }
} else {
    Write-Host "--- ALERTS (Last 24 Hrs) ---"
    Write-Host "No critical events." -ForegroundColor Green
}

# B. Historical Context (Deduplicated)
$OldEvents = $AllEvents | Where-Object { $_.TimeCreated -lt (Get-Date).AddHours(-$AlertHours) }
if ($OldEvents) {
    Write-Host "`n--- HISTORY (Previous 6 Days) ---" -ForegroundColor Gray
    Write-Host "Found $($OldEvents.Count) historical events. Showing unique patterns:"
    $OldEvents | Group-Object { "$($_.ProviderName)_$($_.Message.Substring(0, [math]::Min(50, $_.Message.Length)))" } | Select-Object -First 10 | ForEach-Object {
        $Sample = $_.Group[0]
        $Msg = ($Sample.Message -split "`r?`n")[0].Trim()
        $CountStr = if ($_.Count -gt 1) { " (Occurred $($_.Count) times)" } else { "" }
        Write-Host "[$($Sample.TimeCreated.ToString('MM-dd HH:mm'))] [$($Sample.ProviderName)] $Msg$CountStr"
    }
}

# --- 6. AUTOMATED DIAGNOSIS ---
Write-Host "`n--- AUTOMATED DIAGNOSIS ---" -ForegroundColor Cyan
if ($Diagnosis.Count -gt 0) {
    foreach ($D in ($Diagnosis | Select-Object -Unique)) { Write-Host "⚠️ $D" -ForegroundColor Yellow }
} else {
    Write-Host "✅ [OK] No specific failure patterns detected." -ForegroundColor Green
}   
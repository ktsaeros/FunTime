# === AEROS FLIGHT RECORDER v2.1 (Production) ===
# 1. Copies self to ProgramData (RMM Temp Safe)
# 2. Enforces Scheduled Task (Zombie Killer)
# 3. Hybrid Counters (PDH for accuracy, WMI for backup)
# 4. Atomic Log Rotation (Crash Safe)

$InstallDir = "C:\ProgramData\Aeros\Scripts"
$LogPath    = "C:\ProgramData\Aeros\Logs\FlightData.csv"
$TaskName   = "Aeros_FlightRecorder"
$ScriptName = "FlightRecorder.ps1"
$TargetScript = Join-Path $InstallDir $ScriptName

# --- PART 1: SELF-REPLICATION & HEALING ---
if (!(Test-Path $InstallDir)) { New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null }

# Self-Copy: Ensure we aren't running from a Temp RMM folder
# Check if $PSCommandPath exists (it might be empty if run via "EncodedCommand")
if ($PSCommandPath -and ($PSCommandPath -ne $TargetScript)) {
    Copy-Item $PSCommandPath -Destination $TargetScript -Force
}

# Task Enforcement: ALWAYS overwrite (-Force). 
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$TargetScript`""
$Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 3650)
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

# SILENT FORCE UPDATE (Fixes Broken/Zombie Tasks)
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Force | Out-Null

# --- PART 2: DATA CAPTURE ---
if (!(Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Force -Path (Split-Path $LogPath) | Out-Null }

# 1. CPU & Disk (Hybrid Approach)
try {
    # TRY PRIMARY: Get-Counter (2-second average for accuracy)
    $ProcStats = Get-Counter '\Processor(_Total)\% Processor Time','\PhysicalDisk(_Total)\Avg. Disk Queue Length' -SampleInterval 2 -MaxSamples 1 -ErrorAction Stop
    $CpuPct = [math]::Round($ProcStats.CounterSamples[0].CookedValue, 0)
    $DiskQ  = [math]::Round($ProcStats.CounterSamples[1].CookedValue, 1)
} catch {
    # FALLBACK: WMI (Instant snapshot)
    try {
        $CpuPct = (Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'").PercentProcessorTime
        $DiskQ  = (Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk -Filter "Name='_Total'").AvgDiskQueueLength
    } catch {
        $CpuPct = -1; $DiskQ = -1
    }
}

# 2. RAM & Boot Context
try {
    $os = Get-CimInstance Win32_OperatingSystem
    $RamPct = [math]::Round((($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize) * 100, 0)
    $LastBoot = $os.LastBootUpTime.ToString("MM-dd HH:mm")
} catch { 
    $RamPct = -1; $LastBoot = "Unknown" 
}

# 3. Top Process & Network
$TopProc = Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 1
$HogInfo = "$($TopProc.ProcessName)($([math]::Round($TopProc.WorkingSet / 1MB,0))MB)"
$NetStatus = if (Test-Connection 8.8.8.8 -Count 1 -Quiet) { "UP" } else { "DOWN" }

# 4. Logging & Atomic Rotation
$Time = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
$Line = "$Time,$CpuPct,$RamPct,$DiskQ,$NetStatus,$LastBoot,$HogInfo"

# Header
if (!(Test-Path $LogPath)) { "Timestamp,CPU,RAM,DiskQ,Net,LastBoot,Top_Process" | Out-File $LogPath -Encoding ascii }

# Append
$Line | Out-File $LogPath -Append -Encoding ascii

# Rotation (Atomic)
$LogFile = Get-Item $LogPath
if ($LogFile.Length -gt (10 * 1MB)) {
    try {
        $NewContent = Get-Content $LogPath -Tail 2000
        $TempLog = "$LogPath.tmp"
        "Timestamp,CPU,RAM,DiskQ,Net,LastBoot,Top_Process" | Out-File $TempLog -Encoding ascii
        $NewContent | Out-File $TempLog -Append -Encoding ascii
        Move-Item $TempLog $LogPath -Force
    } catch {
        Write-Warning "Log rotation failed (Locked?). Continuing..."
    }
}
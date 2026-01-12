# === AEROS RECORDER REMOVAL TOOL ===
$InstallDir = "C:\ProgramData\Aeros\Scripts"
$LogDir     = "C:\ProgramData\Aeros\Logs"
$TaskName   = "Aeros_FlightRecorder"

# 1. Kill the Task
try {
    $Task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($Task) {
        Write-Host "Stopping and Unregistering Task: $TaskName..." -ForegroundColor Yellow
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
    } else {
        Write-Host "Task not found."
    }
} catch {
    Write-Host "Error removing task: $_" -ForegroundColor Red
}

# 2. Remove the Script
if (Test-Path $InstallDir) {
    Write-Host "Removing Scripts..."
    Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
}

# 3. Remove the Logs (Comment out if you want to keep history)
if (Test-Path $LogDir) {
    Write-Host "Removing Logs..."
    Remove-Item $LogDir -Recurse -Force -ErrorAction SilentlyContinue
}

# 4. Cleanup Parent Folder if empty
$Parent = "C:\ProgramData\Aeros"
if ((Test-Path $Parent) -and (Get-ChildItem $Parent).Count -eq 0) {
    Remove-Item $Parent -Force
}

Write-Host "Removal Complete." -ForegroundColor Green
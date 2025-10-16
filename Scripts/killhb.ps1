# C:\Aeros\Heartbeat\uninstall_heartbeat.ps1
# Removes the scheduled task and the Aeros Heartbeat folder, regardless of UUID.

$ErrorActionPreference = 'SilentlyContinue'
$TaskName   = 'Aeros Heartbeat'
$FolderPath = 'C:\Aeros\Heartbeat'

Write-Host "Uninstalling '$TaskName' ..."

# 1) Try to delete the known task by exact name
try {
  if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "Removed scheduled task: $TaskName"
  } else {
    Write-Host "Task '$TaskName' not found by exact name."
  }
} catch { Write-Host "Note: Could not remove task '$TaskName' by name: $($_.Exception.Message)" }

# 2) Fallback: remove *any* task that calls cpc_heartbeat.ps1 or looks like a heartbeat task
try {
  $suspects = Get-ScheduledTask | Where-Object {
    ($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -match 'cpc_heartbeat\.ps1' -or
    $_.TaskName -match 'heartbeat'
  }
  foreach ($t in $suspects) {
    Unregister-ScheduledTask -TaskPath $t.TaskPath -TaskName $t.TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "Removed suspected heartbeat task: $($t.TaskName)"
  }
} catch { }

# 3) Delete the folder
if (Test-Path $FolderPath) {
  try {
    Remove-Item $FolderPath -Recurse -Force -ErrorAction Stop
    Write-Host "Deleted folder: $FolderPath"
  } catch {
    Write-Host ("Could not delete {0}: {1}" -f $FolderPath, $_.Exception.Message)
  }
} else {
  Write-Host "Folder not found: $FolderPath (already gone)"
}

Write-Host "Uninstall complete."
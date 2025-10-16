# killhb.ps1 (enhanced cleanup version)
$ErrorActionPreference = 'SilentlyContinue'
$TaskName   = 'Aeros Heartbeat'
$FolderPath = 'C:\Aeros\Heartbeat'
$RootPath   = 'C:\Aeros'

Write-Host ("Uninstalling '{0}' ..." -f $TaskName)

# 1) Remove task by exact name
try {
    $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($t) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host ("Removed scheduled task: {0}" -f $TaskName)
    } else {
        Write-Host ("Task not found by exact name: {0}" -f $TaskName)
    }
} catch {
    Write-Host ("Exact-name removal failed: {0}" -f $_.Exception.Message)
}

# 2) Remove any heartbeat-like tasks as fallback
try {
    $suspects = Get-ScheduledTask | Where-Object {
        ($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -match 'cpc_heartbeat\.ps1' -or
        $_.TaskName -match 'heartbeat'
    }
    foreach ($s in $suspects) {
        Unregister-ScheduledTask -TaskPath $s.TaskPath -TaskName $s.TaskName -Confirm:$false -ErrorAction SilentlyContinue
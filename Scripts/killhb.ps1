# killhb.ps1 (enhanced cleanup + self delete)
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
}
catch {
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
        Write-Host ("Removed suspected heartbeat task: {0}" -f $s.TaskName)
    }
}
catch {
    Write-Host ("Suspect removal failed: {0}" -f $_.Exception.Message)
}

# 3) Delete the C:\Aeros\Heartbeat folder
try {
    if (Test-Path $FolderPath) {
        Remove-Item $FolderPath -Recurse -Force -ErrorAction Stop
        Write-Host ("Deleted folder: {0}" -f $FolderPath)
    } else {
        Write-Host ("Folder not found (already gone): {0}" -f $FolderPath)
    }
}
catch {
    Write-Host ("Could not delete {0}: {1}" -f $FolderPath, $_.Exception.Message)
}

# 4) Delete related heartbeat scripts within C:\Aeros
try {
    if (Test-Path $RootPath) {
        $patternList = @(
            'cpc_heartbeat.ps1',
            'install_heartbeat.ps1'
        )

        foreach ($pattern in $patternList) {
            Get-ChildItem -Path $RootPath -Filter $pattern -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    Remove-Item $_.FullName -Force -ErrorAction Stop
                    Write-Host ("Deleted file: {0}" -f $_.FullName)
                } catch {
                    Write-Host ("Failed to delete {0}: {1}" -f $_.FullName, $_.Exception.Message)
                }
            }
        }

        Get-ChildItem -Path $RootPath -Filter 'install_hb_*.ps1' -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                Remove-Item $_.FullName -Force -ErrorAction Stop
                Write-Host ("Deleted wildcard file: {0}" -f $_.FullName)
            } catch {
                Write-Host ("Failed to delete wildcard {0}: {1}" -f $_.FullName, $_.Exception.Message)
            }
        }
    }
}
catch {
    Write-Host ("C:\Aeros cleanup failed: {0}" -f $_.Exception.Message)
}

Write-Host "Uninstall complete."

# 5) Self-delete
try {
    $self = $MyInvocation.MyCommand.Path
    Write-Host ("Self-deleting: {0}" -f $self)
    Start-Sleep -Seconds 2
    Start-Process powershell -ArgumentList "-NoProfile -WindowStyle Hidden -Command `"Start-Sleep 1; Remove-Item -Force -Path '$self'`""
}
catch {
    Write-Host ("Self-delete failed: {0}" -f $_.Exception.Message)
}
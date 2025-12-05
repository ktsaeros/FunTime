<# 
    Live-tail N-able RMM "FeatureR" logs
    Paste into PowerShell ISE and press F5
#>

# If you already know the folder, just set this and skip the auto-discovery:
# e.g. "C:\Program Files (x86)\N-able Technologies\Windows Agent\bin\FeatureR"
$PreferredFolder = $null   # or set to a full path as a string

function Get-FeatureRFolder {
    param(
        [string]$Preferred
    )

    if ($Preferred -and (Test-Path $Preferred)) {
        return (Get-Item $Preferred)
    }

    $searchRoots = @(
        'C:\Program Files',
        'C:\Program Files (x86)',
        'C:\ProgramData'
    )

    Write-Host "Searching for a folder containing 'featurer' under common roots..." -ForegroundColor Cyan

    $folder = Get-ChildItem -Path $searchRoots -Directory -Recurse -ErrorAction SilentlyContinue |
              Where-Object { $_.FullName -match 'featurer' -or $_.FullName -match 'FeatureR' } |
              Sort-Object LastWriteTime -Descending |
              Select-Object -First 1

    if (-not $folder) {
        throw "Could not find a folder with 'FeatureR' in the name. Set `$PreferredFolder to the correct path and rerun."
    }

    Write-Host "Using FeatureR folder: $($folder.FullName)" -ForegroundColor Yellow
    return $folder
}

function Get-LatestFeatureRLog {
    param(
        [string]$FolderPath
    )

    $log = Get-ChildItem -Path $FolderPath -Recurse -Include *.log -ErrorAction SilentlyContinue |
           Sort-Object LastWriteTime -Descending |
           Select-Object -First 1

    if (-not $log) {
        throw "No .log files found under $FolderPath"
    }

    Write-Host "Tailing latest log: $($log.FullName)" -ForegroundColor Green
    return $log
}

try {
    $featureRFolder = Get-FeatureRFolder -Preferred $PreferredFolder
    $latestLog      = Get-LatestFeatureRLog -FolderPath $featureRFolder.FullName

    # Tail the log like 'tail -f'
    Get-Content -Path $latestLog.FullName -Tail 50 -Wait
}
catch {
    Write-Error $_
}
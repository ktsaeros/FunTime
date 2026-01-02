<#
.SYNOPSIS
    Automated Windows Image Repair (SFC + DISM).
    Logs to C:\Aeros\repair_log.txt
#>

$LogDir = "C:\Aeros"
if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
$LogFile = "$LogDir\repair_log.txt"

function Write-Log {
    param($Msg)
    $Line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Msg
    Write-Host $Msg -ForegroundColor Cyan
    Add-Content -Path $LogFile -Value $Line
}

Write-Log "=== STARTING WINDOWS HEALTH REPAIR ==="

# 1. SFC (System File Checker)
Write-Log "Step 1: Running SFC /ScanNow..."
$sfcResult = sfc /scannow
$sfcResult | Out-File -Append -FilePath $LogFile
if ($sfcResult -match "found corrupt files and successfully repaired") {
    Write-Log "SUCCESS: SFC repaired corrupt files."
} elseif ($sfcResult -match "found corrupt files but was unable to fix") {
    Write-Log "WARNING: SFC failed to fix some files. Proceeding to DISM."
} else {
    Write-Log "INFO: SFC found no integrity violations."
}

# 2. DISM ScanHealth
Write-Log "Step 2: Running DISM CheckHealth..."
$dismCheck = Dism /Online /Cleanup-Image /CheckHealth
$dismCheck | Out-File -Append -FilePath $LogFile

# 3. DISM RestoreHealth (The heavy lifter)
Write-Log "Step 3: Running DISM RestoreHealth (This may take time)..."
$dismRestore = Dism /Online /Cleanup-Image /RestoreHealth
$dismRestore | Out-File -Append -FilePath $LogFile

Write-Log "=== REPAIR COMPLETE ==="
<#
.SYNOPSIS
    AEROS TRIAGE & CLEANUP WIZARD (v5.0)
    Combines Storage Audit, Large File Discovery, and Mult-Level Cleanup.
#>

# --- PRE-SCAN: DRIVE HEALTH ---
Clear-Host
$TargetDrive = "C"
$drive = Get-PSDrive $TargetDrive
$freeGB = [math]::Round($drive.Free / 1GB, 2)
$usedGB = [math]::Round(($drive.Used + $drive.Free) / 1GB, 2) - $freeGB

Write-Host "╔═══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║            AEROS TRIAGE & CLEANUP WIZARD              ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host " Drive $TargetDrive | Used: $usedGB GB | Free: $freeGB GB" -ForegroundColor Yellow
Write-Host "---------------------------------------------------------"

# --- OPTION 1: FORENSIC SCAN ---
Write-Host "`n [SCANNING STORAGE ARCHITECTURE...]" -ForegroundColor Gray

# 1. User Profile Sizes (Sorted Largest First)
$profiles = Get-CimInstance Win32_UserProfile | Where-Object { $_.LocalPath -like 'C:\Users\*' -and -not $_.Special }
$profTable = foreach ($p in $profiles) {
    $size = (Get-ChildItem -Path $p.LocalPath -Recurse -File -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1GB
    [pscustomobject]@{ User = ($p.LocalPath -split '\\')[-1]; 'Size(GB)' = [math]::Round($size, 2) }
}
Write-Host " [PROFILE SIZES]" -ForegroundColor Cyan
$profTable | Sort-Object 'Size(GB)' -Descending | Format-Table -AutoSize

# 2. Large File Discovery (Top 5 files > 500MB)
Write-Host " [TOP LARGE FILES (Non-System)]" -ForegroundColor Cyan
Get-ChildItem -Path "C:\Users", "C:\Aeros", "C:\CCS" -Recurse -File -ErrorAction SilentlyContinue | 
    Sort-Object Length -Descending | Select-Object -First 5 | 
    Select-Object @{N='GB';E={[math]::Round($_.Length / 1GB, 2)}}, Name, Directory | Format-Table -AutoSize

# 3. Recycle Bin Check
$sh = New-Object -ComObject Shell.Application
$rb = $sh.NameSpace(10).Items() | Measure-Object -Property Size -Sum
$rbGB = [math]::Round($rb.Sum / 1GB, 2)
Write-Host " [RECYCLE BIN]: $rbGB GB" -ForegroundColor Yellow

Write-Host "`n---------------------------------------------------------"
Write-Host " [CLEANUP LEVELS]" -ForegroundColor White
Write-Host " 1. Normal Clean (Safe: Temp, WU Cache, Component Cleanup)"
Write-Host " 2. Clean More   (+ Recycle Bin, Empty Downloads, Dell Backups)"
Write-Host " 3. Clean MOST   (+ Max Component Reset, Optional Features, Hibernate)"
Write-Host " Q. Quit"

$choice = Read-Host "`n Select Cleanup Level"

switch ($choice) {
    "1" { 
        Write-Host " Running Normal Clean..." -ForegroundColor Green
        Invoke-AerosTool "cclean.ps1" "-ClearTemp -ClearWUCache -ComponentCleanup"
    }
    "2" { 
        Write-Host " Running Deep Clean..." -ForegroundColor Green
        Invoke-AerosTool "cclean.ps1" "-ClearTemp -ClearWUCache -ComponentCleanup -EmptyRecycleBin -PurgeDellSARemediation"
        # Optional: Ask to purge Downloads
        $purgeDL = Read-Host " Also purge ALL user Download folders? (y/n)"
        if ($purgeDL -eq 'y') { Get-ChildItem "C:\Users\*\Downloads\*" -Recurse | Remove-Item -Force -Recurse }
    }
    "3" { 
        Write-Host " !!! RUNNING MAX CLEAN !!!" -ForegroundColor Red
        Invoke-AerosTool "cclean.ps1" "-ClearTemp -ClearWUCache -DeepComponentCleanup -RemoveOptionalFeatures -DisableHibernate -EmptyRecycleBin -ShrinkShadowStorage"
    }
    Default { return }
}

$newFree = [math]::Round((Get-PSDrive $TargetDrive).Free / 1GB, 2)
Write-Host "`n [COMPLETE] New Free Space: $newFree GB (Recovered: $($newFree - $freeGB) GB)" -ForegroundColor Cyan
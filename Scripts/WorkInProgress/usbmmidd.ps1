<#
.SYNOPSIS
    Professional Virtual Display Manager for Aeros Group.
    Modes: Headless (1 screen), Extend (Add 1), RemoveScreen (Minus 1), Uninstall (Full Reset)
#>
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("Headless", "Extend", "RemoveScreen", "Uninstall")]
    [string]$Mode
)

$destFolder = "C:\usbmmidd"
$rawUrl = "https://github.com/ktsaeros/FunTime/raw/main/Apps/usbmmidd_v2.zip"

function Ensure-DriverInstalled {
    if (-not (Test-Path $destFolder)) {
        Write-Host "Driver not found. Installing base driver..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $rawUrl -OutFile "$env:TEMP\usbmmidd.zip"
        Expand-Archive -Path "$env:TEMP\usbmmidd.zip" -DestinationPath "C:\" -Force
        if (Test-Path "C:\usbmmidd_v2") { Rename-Item "C:\usbmmidd_v2" "usbmmidd" }
        Set-Location $destFolder
        .\deviceinstaller64.exe install usbmmIdd.inf usbmmidd
        Start-Sleep -Seconds 2
    }
}

switch ($Mode) {
    "Headless" {
        Write-Host "--- Mode: Primary Virtual Display ---" -ForegroundColor Cyan
        Ensure-DriverInstalled
        Set-Location $destFolder
        .\deviceinstaller64.exe enableidd 1
        
        if (Get-Service "usbmmidd" -ErrorAction SilentlyContinue) { & sc.exe delete usbmmidd | Out-Null }
        & sc.exe create usbmmidd binPath= "C:\usbmmidd\deviceinstaller64.exe enableidd 1" start= auto
        
        Write-Host "SUCCESS: Display active. Use QRes to set 1080p if needed." -ForegroundColor Green
    }

    "Extend" {
        Write-Host "--- Mode: Adding One Screen ---" -ForegroundColor Cyan
        Ensure-DriverInstalled
        Set-Location $destFolder
        # Just one execution adds exactly one more monitor
        .\deviceinstaller64.exe enableidd 1
        Write-Host "SUCCESS: One additional virtual monitor added." -ForegroundColor Green
    }

    "RemoveScreen" {
        Write-Host "--- Mode: Removing One Screen ---" -ForegroundColor Yellow
        if (Test-Path $destFolder) {
            Set-Location $destFolder
            # 'enableidd 0' toggles the most recently added monitor OFF
            .\deviceinstaller64.exe enableidd 0
            Write-Host "SUCCESS: Removed the last added virtual monitor." -ForegroundColor Green
        }
    }

    "Uninstall" {
        Write-Host "--- Mode: Full System Cleanup ---" -ForegroundColor Red
        if (Get-Service "usbmmidd" -ErrorAction SilentlyContinue) { & sc.exe delete usbmmidd | Out-Null }
        if (Test-Path $destFolder) {
            Set-Location $destFolder
            .\deviceinstaller64.exe remove usbmmidd
            Set-Location C:\
            Remove-Item $destFolder -Recurse -Force
        }
        Write-Host "System fully cleaned." -ForegroundColor Green
    }
}
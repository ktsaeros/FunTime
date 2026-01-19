<#
.SYNOPSIS
    Aeros Group Virtual Display Manager v9
    Ensures persistence regardless of which mode is run first.
#>
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("Headless", "Extend", "RemoveScreen", "Uninstall")]
    [string]$Mode
)

$destFolder = "C:\usbmmidd"
$rawUrl = "https://github.com/ktsaeros/FunTime/raw/main/Apps/usbmmidd_v2.zip"

function Ensure-Persistence {
    Write-Host "Ensuring startup persistence..." -ForegroundColor Cyan
    # Always refresh the service to ensure it points to the correct path
    if (Get-Service "usbmmidd" -ErrorAction SilentlyContinue) {
        & sc.exe delete usbmmidd | Out-Null
        Start-Sleep -Seconds 1
    }
    & sc.exe create usbmmidd binPath= "C:\usbmmidd\deviceinstaller64.exe enableidd 1" start= auto | Out-Null
}

function Ensure-ToolsInstalled {
    if (Test-Path "C:\usbmmidd_v2") { Remove-Item "C:\usbmmidd_v2" -Recurse -Force }
    if (-not (Test-Path $destFolder)) { New-Item -Path $destFolder -ItemType Directory -Force }

    if (-not (Test-Path "$destFolder\deviceinstaller64.exe")) {
        Write-Host "Installing usbmmidd..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $rawUrl -OutFile "$env:TEMP\usbmmidd.zip"
        Expand-Archive -Path "$env:TEMP\usbmmidd.zip" -DestinationPath "C:\" -Force
        
        if (Test-Path "C:\usbmmidd_v2") {
            Move-Item -Path "C:\usbmmidd_v2\*" -Destination $destFolder -Force
            Remove-Item "C:\usbmmidd_v2" -Recurse -Force
        }
        
        Set-Location $destFolder
        .\deviceinstaller64.exe install usbmmIdd.inf usbmmidd
        Start-Sleep -Seconds 2
    }
    # Ensure service is created on EVERY install/run
    Ensure-Persistence
}

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Admin Required."; return
}

switch ($Mode) {
    "Headless" {
        Write-Host "--- Mode: Primary Virtual Display ---" -ForegroundColor Cyan
        Ensure-ToolsInstalled
        Set-Location $destFolder
        .\deviceinstaller64.exe enableidd 0; .\deviceinstaller64.exe enableidd 1
        Write-Host "Primary Monitor Active & Persistent." -ForegroundColor Green
    }
    "Extend" {
        Write-Host "--- Mode: Adding Monitor ---" -ForegroundColor Cyan
        Ensure-ToolsInstalled
        Set-Location $destFolder
        .\deviceinstaller64.exe enableidd 1
        Write-Host "Monitor Added & Persistent." -ForegroundColor Green
    }
    "RemoveScreen" {
        if (Test-Path "$destFolder\deviceinstaller64.exe") {
            Set-Location $destFolder
            .\deviceinstaller64.exe enableidd 0
        }
    }
    "Uninstall" {
        Write-Host "--- Mode: Full Uninstall ---" -ForegroundColor Red
        if (Get-Service "usbmmidd" -ErrorAction SilentlyContinue) { & sc.exe delete usbmmidd | Out-Null }
        if (Test-Path $destFolder) {
            Set-Location $destFolder
            .\deviceinstaller64.exe remove usbmmidd
            Set-Location C:\
            Remove-Item $destFolder -Recurse -Force
        }
        Write-Host "Fully Uninstalled." -ForegroundColor Green
    }
}
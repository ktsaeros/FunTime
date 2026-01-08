<#
    Aeros Group Virtual Display Manager (Integrated v9)
    Path: /Funtime/ToolKit/usbmmidd.ps1
#>

$destFolder = "C:\usbmmidd"
$rawUrl = "https://github.com/ktsaeros/FunTime/raw/main/Apps/usbmmidd_v2.zip"

function Ensure-Persistence {
    Write-Host "   [Display] Ensuring startup persistence..." -ForegroundColor Cyan
    
    # 1. Remove existing service if it exists to ensure a clean path
    if (Get-Service "usbmmidd" -ErrorAction SilentlyContinue) {
        Write-Host "   [Display] Refreshing existing service..." -ForegroundColor Gray
        & sc.exe delete usbmmidd | Out-Null
        Start-Sleep -Seconds 1
    }

    # 2. Create the service with the mandatory spaces after 'binPath=' and 'start='
    # Note the space: binPath= "..." and start= auto
    $createResult = & sc.exe create usbmmidd binPath= "C:\usbmmidd\deviceinstaller64.exe enableidd 1" start= auto 2>&1

    if ($LASTEXITCODE -ne 0) {
        Write-Host "   [ERROR] Service creation failed: $createResult" -ForegroundColor Red
    } else {
        Write-Host "   [SUCCESS] Persistence service created." -ForegroundColor Green
    }
}

function Ensure-ToolsInstalled {
    if (Test-Path "C:\usbmmidd_v2") { Remove-Item "C:\usbmmidd_v2" -Recurse -Force }
    if (-not (Test-Path $destFolder)) { New-Item -Path $destFolder -ItemType Directory -Force }

    if (-not (Test-Path "$destFolder\deviceinstaller64.exe")) {
        Write-Host "   [Display] Installing driver binaries..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $rawUrl -OutFile "$env:TEMP\usbmmidd.zip" -UseBasicParsing
        Expand-Archive -Path "$env:TEMP\usbmmidd.zip" -DestinationPath "C:\" -Force
        
        if (Test-Path "C:\usbmmidd_v2") {
            Move-Item -Path "C:\usbmmidd_v2\*" -Destination $destFolder -Force
            Remove-Item "C:\usbmmidd_v2" -Recurse -Force
        }
        
        Set-Location $destFolder
        .\deviceinstaller64.exe install usbmmIdd.inf usbmmidd
        Start-Sleep -Seconds 2
    }
    Ensure-Persistence
}

function Show-DisplayMenu {
    Clear-Host
    Write-Host "╔═══════════════════════════════════════════════════════╗" -ForegroundColor Magenta
    Write-Host "║           AEROS VIRTUAL DISPLAY MANAGER               ║" -ForegroundColor Magenta
    Write-Host "╚═══════════════════════════════════════════════════════╝" -ForegroundColor Magenta
    Write-Host "  1. Headless Mode (Reset to 1x Primary)"
    Write-Host "  2. Extend Mode   (Add +1 Virtual Screen)"
    Write-Host "  3. Shrink Mode   (Remove -1 Virtual Screen)"
    Write-Host "  4. Full Uninstall (Remove Driver & Service)"
    Write-Host "`n  Q. Return to Master Toolkit"
    
    $vSel = Read-Host "`n Selection"
    
    switch ($vSel) {
        '1' {
            Ensure-ToolsInstalled
            Set-Location $destFolder
            .\deviceinstaller64.exe enableidd 0; .\deviceinstaller64.exe enableidd 1
            Write-Host "   [Done] Primary Virtual Display Active." -ForegroundColor Green; pause
            Show-DisplayMenu
        }
        '2' {
            Ensure-ToolsInstalled
            Set-Location $destFolder
            .\deviceinstaller64.exe enableidd 1
            Write-Host "   [Done] Monitor Added." -ForegroundColor Green; pause
            Show-DisplayMenu
        }
        '3' {
            if (Test-Path "$destFolder\deviceinstaller64.exe") {
                Set-Location $destFolder
                .\deviceinstaller64.exe enableidd 0
                Write-Host "   [Done] Monitor Removed." -ForegroundColor Yellow; pause
            }
            Show-DisplayMenu
        }
        '4' {
            Write-Host "   [Cleanup] Removing Driver and Service..." -ForegroundColor Red
            if (Get-Service "usbmmidd" -ErrorAction SilentlyContinue) { & sc.exe delete usbmmidd | Out-Null }
            if (Test-Path $destFolder) {
                Set-Location $destFolder
                .\deviceinstaller64.exe remove usbmmidd
                Set-Location C:\
                Remove-Item $destFolder -Recurse -Force
            }
            Write-Host "   [Done] Fully Uninstalled." -ForegroundColor Green; pause
        }
        'q' { return }
        'Q' { return }
    }
}

# Auto-start the sub-menu when the script is fetched
Show-DisplayMenu
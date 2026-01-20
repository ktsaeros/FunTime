<#
.SYNOPSIS
    Dell Command | Update Wrapper
    - Checks if system is Dell.
    - Installs DCU (via Choco) if missing.
    - Runs Scan and Apply updates.
#>

$ErrorActionPreference = 'SilentlyContinue'

# 1. Vendor Check
$Model = (Get-CimInstance Win32_ComputerSystem).Model
$Manufacturer = (Get-CimInstance Win32_ComputerSystem).Manufacturer

Write-Host "System: $Manufacturer $Model" -ForegroundColor Cyan

if ($Manufacturer -notmatch "Dell") {
    Write-Warning "This is not a Dell system. Aborting."
    return
}

# 2. Check/Install DCU
$DCUPath = "C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe"

if (-not (Test-Path $DCUPath)) {
    Write-Host "Dell Command Update not found. Attempting install via Chocolatey..." -ForegroundColor Yellow
    
    # Ensure Choco exists
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-Host "Installing Chocolatey..." -ForegroundColor Gray
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    }

    # Install DCU
    choco install dellcommandupdate -y
    
    # Verify Install
    if (-not (Test-Path $DCUPath)) {
        Write-Error "Failed to install Dell Command Update."
        return
    }
}

# 3. Service Check
$SvcName = "DellClientManagementService"
$Svc = Get-Service $SvcName -ErrorAction SilentlyContinue
if ($Svc.Status -ne 'Running') {
    Write-Host "Starting Dell Management Service..." -ForegroundColor Gray
    Set-Service $SvcName -StartupType Automatic
    Start-Service $SvcName
}

# 4. Run Scan & Apply
if (Test-Path $DCUPath) {
    Write-Host "`n[1/2] Scanning for updates (this takes time)..." -ForegroundColor Cyan
    $ScanProc = Start-Process -FilePath $DCUPath -ArgumentList "/scan -outputLog=C:\ProgramData\Dell\dcu-scan.log" -Wait -PassThru -NoNewWindow
    
    if ($ScanProc.ExitCode -eq 0) {
        Write-Host "Scan Complete." -ForegroundColor Green
        
        Write-Host "`n[2/2] Applying updates..." -ForegroundColor Cyan
        $ApplyProc = Start-Process -FilePath $DCUPath -ArgumentList "/applyUpdates -reboot=enable" -Wait -PassThru -NoNewWindow
        
        if ($ApplyProc.ExitCode -eq 0) {
            Write-Host "Updates Applied Successfully." -ForegroundColor Green
        } elseif ($ApplyProc.ExitCode -eq 1) {
            Write-Host "Reboot Required to complete updates." -ForegroundColor Magenta
        } else {
            Write-Warning "Update application returned code: $($ApplyProc.ExitCode)"
        }
    } else {
        Write-Warning "Scan exited with code: $($ScanProc.ExitCode)"
    }
}
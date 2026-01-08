# Requires -RunAsAdministrator

$url = "https://www.amyuni.com/downloads/usbmmidd_v2.zip"
$zipPath = "$env:TEMP\usbmmidd_v2.zip"
$destFolder = "C:\usbmmidd"

# 1. Check for Admin rights
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as an Administrator."
    return
}

# 2. Download the file
Write-Host "Downloading usbmmidd..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $url -OutFile $zipPath

# 3. Unzip and rename
if (Test-Path $destFolder) {
    Write-Host "Destination $destFolder already exists. Cleaning up..." -ForegroundColor Yellow
    Remove-Item $destFolder -Recurse -Force
}

Write-Host "Extracting to $destFolder..." -ForegroundColor Cyan
Expand-Archive -Path $zipPath -DestinationPath "C:\"
# The zip typically extracts to a folder named 'usbmmidd_v2'
if (Test-Path "C:\usbmmidd_v2") {
    Rename-Item -Path "C:\usbmmidd_v2" -NewName "usbmmidd"
}

# 4. Install the driver
Set-Location $destFolder
Write-Host "Installing usbmmidd driver..." -ForegroundColor Cyan
.\deviceinstaller64.exe install usbmmIdd.inf usbmmidd

# 5. Enable the virtual display
Write-Host "Enabling virtual display..." -ForegroundColor Cyan
.\deviceinstaller64.exe enableidd 1

# 6. Create the Windows Service
Write-Host "Creating 'usbmmidd' service for persistent startup..." -ForegroundColor Cyan
# Using sc.exe directly as requested. Note the space after 'binPath=' is mandatory for sc.exe
& sc.exe create usbmmidd binPath= "C:\usbmmidd\deviceinstaller64.exe enableidd 1" start= auto

# 7. Start the service (optional, ensures it's running now)
Start-Service usbmmidd

Write-Host "Setup complete. Virtual monitor should now be active." -ForegroundColor Green